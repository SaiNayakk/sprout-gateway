package app.sprout.gateway;

import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import io.micrometer.tracing.propagation.Propagator;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Forwards {@code /api/<service>/...} to the owning service. In order: route, rate limit, token
 * check, strip headers a client must not set, forward through a circuit breaker, copy the reply.
 *
 * <p>Endpoints a route lists under {@code streams} are Server-Sent Events: the reply is relayed as
 * it arrives, for as long as both ends stay connected, on a virtual thread rather than a request
 * thread. Open streams are capped per client and in total.
 */
@RestController
public class ProxyController {

    private static final Logger log = LoggerFactory.getLogger(ProxyController.class);

    /** Never forwarded in either direction (RFC 9110 hop-by-hop), or set by the HTTP client itself. */
    private static final Set<String> HOP_BY_HOP = Set.of("connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
            "expect");
    /** Identity headers only the gateway may set; a client sending them is ignored. */
    private static final Set<String> SPOOFABLE = Set.of("x-user-id", "x-session-id", "x-forwarded-for",
            "x-forwarded-proto", "x-forwarded-host", "x-real-ip", "forwarded");

    private final GatewayProperties props;
    private final TokenVerifier tokens;
    private final RateLimiter limiter;
    private final MeterRegistry meters;
    private final HttpClient http;
    private final CircuitBreakerRegistry breakers;
    private final List<GatewayProperties.Route> routes;
    private final StreamSlots slots;
    private final ObjectProvider<Tracer> tracer;
    private final ObjectProvider<Propagator> propagator;

    public ProxyController(GatewayProperties props, TokenVerifier tokens, RateLimiter limiter, MeterRegistry meters,
                           ObjectProvider<Tracer> tracer, ObjectProvider<Propagator> propagator) {
        this.tracer = tracer;
        this.propagator = propagator;
        this.props = props;
        this.tokens = tokens;
        this.limiter = limiter;
        this.meters = meters;
        this.http = HttpClient.newBuilder().connectTimeout(props.connectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER).build();
        this.breakers = CircuitBreakerRegistry.of(CircuitBreakerConfig.custom()
                .slidingWindowSize(20)
                .minimumNumberOfCalls(10)
                .failureRateThreshold(50)
                .waitDurationInOpenState(Duration.ofSeconds(10))
                .permittedNumberOfCallsInHalfOpenState(3)
                .recordResult(r -> r instanceof HttpResponse<?> response && response.statusCode() >= 500)
                .build());
        GatewayProperties.Streams s = props.streams() != null ? props.streams() : new GatewayProperties.Streams(5, 500);
        this.slots = new StreamSlots(s.perClient(), s.total(), meters);
        // longest prefix wins, so /api/identity-admin can never be captured by /api/identity
        this.routes = props.routes().stream()
                .sorted(Comparator.comparingInt((GatewayProperties.Route r) -> r.prefix().length()).reversed())
                .toList();
    }

    @RequestMapping("/api/**")
    public void proxy(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String uri = req.getRequestURI();
        Optional<GatewayProperties.Route> match = routes.stream()
                .filter(r -> uri.equals(r.prefix()) || uri.startsWith(r.prefix() + "/")).findFirst();
        if (match.isEmpty()) {
            Problems.write(res, 404, "NOT_FOUND", "Not found", "There's no API at this address.", null);
            return;
        }
        GatewayProperties.Route route = match.get();
        String path = uri.substring(route.prefix().length());
        String lowerPath = path.toLowerCase(Locale.ROOT);
        if (path.isEmpty() || path.contains("..") || path.contains("//") || lowerPath.contains("%2e")
                || lowerPath.contains("%2f") || lowerPath.contains("%5c") || path.contains("\\")) {
            Problems.write(res, 404, "NOT_FOUND", "Not found", "There's no API at this address.", null);
            return;
        }
        String method = req.getMethod().toUpperCase(Locale.ROOT);
        String client = clientAddress(req);

        boolean authLimited = route.isAuthLimited(method, path);
        int perMinute = authLimited ? props.rateLimits().authPerMinute() : props.rateLimits().defaultPerMinute();
        long wait = limiter.tryAcquire(client + "|" + (authLimited ? "auth" : "default"), perMinute);
        if (wait > 0) {
            meters.counter("gateway.rate_limited", "route", route.name(), "class", authLimited ? "auth" : "default").increment();
            Problems.write(res, 429, "RATE_LIMITED", "Too many requests",
                    "Slow down and try again in " + wait + " seconds.", wait);
            return;
        }

        Optional<TokenVerifier.Caller> caller = tokens.verify(req.getHeader("Authorization"));
        if (caller.isEmpty() && !route.isPublic(method, path)) {
            meters.counter("gateway.unauthenticated", "route", route.name()).increment();
            Problems.write(res, 401, "UNAUTHENTICATED", "Sign in to continue",
                    "This needs a valid access token.", null);
            return;
        }

        if (route.isStream(method, path)) {
            stream(req, res, route, path, method, client, caller);
            return;
        }

        byte[] body = req.getInputStream().readNBytes((int) props.maxBodyBytes() + 1);
        if (body.length > props.maxBodyBytes()) {
            Problems.write(res, 413, "VALIDATION_FAILED", "Request too large",
                    "Requests can be at most " + props.maxBodyBytes() / 1024 + " KB.", null);
            return;
        }

        HttpRequest upstream = buildUpstream(req, route, path, method, body, client, caller);
        CircuitBreaker breaker = breakers.circuitBreaker(route.name());
        try {
            HttpResponse<byte[]> reply = breaker.executeCheckedSupplier(
                    () -> http.send(upstream, HttpResponse.BodyHandlers.ofByteArray()));
            copyReply(reply, res);
        } catch (CallNotPermittedException e) {
            meters.counter("gateway.upstream_errors", "route", route.name(), "kind", "circuit_open").increment();
            Problems.write(res, 503, "UPSTREAM_UNAVAILABLE", "Temporarily unavailable",
                    "This part of Sprout is recovering. Try again in a few seconds.", 10L);
        } catch (HttpConnectTimeoutException e) {
            // Never connected, so the request never arrived: certainly not done, safe to retry.
            // (Found by CHAOS-03: a killed host's address still resolves but nothing answers.)
            meters.counter("gateway.upstream_errors", "route", route.name(), "kind", "connect_timeout").increment();
            Problems.write(res, 503, "UPSTREAM_UNAVAILABLE", "Temporarily unavailable",
                    "This part of Sprout isn't reachable right now. Try again shortly.", 5L);
        } catch (HttpTimeoutException e) {
            meters.counter("gateway.upstream_errors", "route", route.name(), "kind", "timeout").increment();
            Problems.write(res, 504, "UPSTREAM_UNAVAILABLE", "Took too long",
                    "This took too long. It may still have happened, so check before retrying.", null);
        } catch (ConnectException e) {
            meters.counter("gateway.upstream_errors", "route", route.name(), "kind", "connect").increment();
            Problems.write(res, 503, "UPSTREAM_UNAVAILABLE", "Temporarily unavailable",
                    "This part of Sprout isn't reachable right now. Try again shortly.", 5L);
        } catch (Throwable e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.warn("Upstream call to {} failed", route.name(), e);
            meters.counter("gateway.upstream_errors", "route", route.name(), "kind", "other").increment();
            Problems.write(res, 502, "UPSTREAM_UNAVAILABLE", "Something went wrong",
                    "The service behind this didn't answer properly. Try again.", null);
        }
    }

    private void stream(HttpServletRequest req, HttpServletResponse res, GatewayProperties.Route route, String path,
                        String method, String client, Optional<TokenVerifier.Caller> caller) throws IOException {
        switch (slots.tryOpen(client)) {
            case CLIENT_FULL -> {
                meters.counter("gateway.streams.refused", "route", route.name(), "reason", "client").increment();
                Problems.write(res, 429, "RATE_LIMITED", "Too many open streams",
                        "Close a price stream you no longer need, then try again.", 5L);
                return;
            }
            case GATEWAY_FULL -> {
                meters.counter("gateway.streams.refused", "route", route.name(), "reason", "gateway").increment();
                Problems.write(res, 503, "UPSTREAM_UNAVAILABLE", "Temporarily unavailable",
                        "Too many people are watching prices right now. Try again shortly.", 10L);
                return;
            }
            case OPENED -> { }
        }
        boolean handedOver = false;
        try {
            HttpRequest upstream = buildUpstream(req, route, path, method, new byte[0], client, caller);
            HttpResponse<InputStream> reply;
            try {
                // the timeout covers getting the response headers; the body then flows for as long as it lasts
                reply = breakers.circuitBreaker(route.name()).executeCheckedSupplier(
                        () -> http.send(upstream, HttpResponse.BodyHandlers.ofInputStream()));
            } catch (CallNotPermittedException e) {
                Problems.write(res, 503, "UPSTREAM_UNAVAILABLE", "Temporarily unavailable",
                        "This part of Sprout is recovering. Try again in a few seconds.", 10L);
                return;
            } catch (HttpConnectTimeoutException e) {
                Problems.write(res, 503, "UPSTREAM_UNAVAILABLE", "Temporarily unavailable",
                        "This part of Sprout is not reachable right now. Try again shortly.", 5L);
                return;
            } catch (HttpTimeoutException e) {
                Problems.write(res, 504, "UPSTREAM_UNAVAILABLE", "Took too long",
                        "The stream did not start in time. Try again.", null);
                return;
            } catch (Throwable e) {
                if (e instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                Problems.write(res, 503, "UPSTREAM_UNAVAILABLE", "Temporarily unavailable",
                        "This part of Sprout is not reachable right now. Try again shortly.", 5L);
                return;
            }
            boolean isStream = reply.statusCode() == 200 && reply.headers().firstValue("content-type")
                    .map(ct -> ct.startsWith("text/event-stream")).orElse(false);
            copyHeaders(reply, res);
            if (!isStream) {
                // the service refused (unknown symbol, bad request, ...): pass its answer on as is
                try (InputStream in = reply.body()) {
                    in.transferTo(res.getOutputStream());
                }
                return;
            }
            res.setHeader("X-Accel-Buffering", "no"); // tell any proxy in front not to buffer
            AsyncContext async = req.startAsync();
            async.setTimeout(0);
            InputStream in = reply.body();
            async.addListener(new AsyncListener() {
                @Override public void onComplete(AsyncEvent e) { }
                @Override public void onTimeout(AsyncEvent e) { closeQuietly(in); }
                @Override public void onError(AsyncEvent e) { closeQuietly(in); }
                @Override public void onStartAsync(AsyncEvent e) { }
            });
            res.flushBuffer();
            meters.counter("gateway.streams.opened", "route", route.name()).increment();
            Thread.ofVirtual().name("gw-stream-" + route.name()).start(() -> relay(in, async, client, route));
            handedOver = true;
        } finally {
            if (!handedOver) {
                slots.close(client);
            }
        }
    }

    /** Copies the stream until either side goes away, then closes both so the service lets go too. */
    private void relay(InputStream in, AsyncContext async, String client, GatewayProperties.Route route) {
        try (in) {
            OutputStream out = async.getResponse().getOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (IOException | IllegalStateException e) {
            // the client or the service hung up: normal for a stream
        } finally {
            slots.close(client);
            meters.counter("gateway.streams.closed", "route", route.name()).increment();
            try {
                async.complete();
            } catch (IllegalStateException ignored) {
                // already completed by the container after a client error
            }
        }
    }

    private static void closeQuietly(InputStream in) {
        try {
            in.close();
        } catch (IOException ignored) {
            // nothing more to do
        }
    }

    private HttpRequest buildUpstream(HttpServletRequest req, GatewayProperties.Route route, String path, String method,
                                      byte[] body, String client, Optional<TokenVerifier.Caller> caller) {
        String query = req.getQueryString();
        URI target = URI.create(route.target() + path + (query == null ? "" : "?" + query));
        HttpRequest.Builder b = HttpRequest.newBuilder(target).timeout(props.requestTimeout())
                .method(method, body.length == 0 ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        for (String name : Collections.list(req.getHeaderNames())) {
            String lower = name.toLowerCase(Locale.ROOT);
            if (HOP_BY_HOP.contains(lower) || SPOOFABLE.contains(lower) || lower.equals(EdgeFilter.REQUEST_ID.toLowerCase(Locale.ROOT))) {
                continue;
            }
            for (String value : Collections.list(req.getHeaders(name))) {
                b.header(name, value);
            }
        }
        b.header(EdgeFilter.REQUEST_ID, (String) req.getAttribute(EdgeFilter.REQUEST_ID));
        b.header("X-Forwarded-For", client);
        b.header("X-Forwarded-Proto", req.getHeader("CF-Visitor") != null ? "https" : req.getScheme());
        caller.ifPresent(c -> {
            b.header("X-User-Id", c.userId());
            b.header("X-Session-Id", c.sessionId());
        });
        // the service's work joins the gateway's trace (the client's was dropped at the edge)
        Tracer t = tracer.getIfAvailable();
        Propagator p = propagator.getIfAvailable();
        Span span = t == null ? null : t.currentSpan();
        if (span != null && p != null) {
            p.inject(span.context(), b, HttpRequest.Builder::setHeader);
        }
        return b.build();
    }

    private static void copyReply(HttpResponse<byte[]> reply, HttpServletResponse res) throws IOException {
        copyHeaders(reply, res);
        res.getOutputStream().write(reply.body());
    }

    private static void copyHeaders(HttpResponse<?> reply, HttpServletResponse res) {
        res.setStatus(reply.statusCode());
        reply.headers().map().forEach((name, values) -> {
            String lower = name.toLowerCase(Locale.ROOT);
            if (!HOP_BY_HOP.contains(lower) && !lower.equals(EdgeFilter.REQUEST_ID.toLowerCase(Locale.ROOT))
                    && !lower.startsWith(":")) {
                values.forEach(v -> res.addHeader(name, v));
            }
        });
    }

    private String clientAddress(HttpServletRequest req) {
        String cf = req.getHeader("CF-Connecting-IP");
        if (props.trustCloudflareIp() && cf != null && !cf.isBlank()) {
            return cf.trim();
        }
        return req.getRemoteAddr();
    }
}
