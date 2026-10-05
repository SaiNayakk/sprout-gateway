package app.sprout.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The gateway against a stub upstream: token checks, header hygiene, rate limits, timeouts,
 * the circuit breaker and request ids.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.config.name=gateway",
        "management.server.port=0",
        "sprout.gateway.request-timeout=1s",
        "sprout.gateway.max-body-bytes=2048",
        "sprout.gateway.rate-limits.auth-per-minute=1000",
        "sprout.gateway.rate-limits.default-per-minute=1000"})
class GatewayTest {

    static final ObjectMapper JSON = new ObjectMapper();
    static final RSAKey KEY = rsa();
    static final RSAKey OTHER_KEY = rsa();
    static final AtomicInteger FLAKY_HITS = new AtomicInteger();
    static final HttpServer UPSTREAM = startUpstream();
    static final int CLOSED_PORT = freePort();

    @DynamicPropertySource
    static void routes(DynamicPropertyRegistry r) {
        String up = "http://127.0.0.1:" + UPSTREAM.getAddress().getPort();
        r.add("sprout.gateway.jwks-url", () -> up + "/.well-known/jwks.json");
        r.add("sprout.gateway.routes[0].name", () -> "identity");
        r.add("sprout.gateway.routes[0].prefix", () -> "/api/identity");
        r.add("sprout.gateway.routes[0].target", () -> up);
        r.add("sprout.gateway.routes[0].public[0]", () -> "POST /v1/sessions");
        r.add("sprout.gateway.routes[0].public[1]", () -> "GET /v1/slow");
        r.add("sprout.gateway.routes[0].auth-limited[0]", () -> "POST /v1/limited");
        r.add("sprout.gateway.routes[0].public[2]", () -> "POST /v1/limited");
        r.add("sprout.gateway.routes[1].name", () -> "down");
        r.add("sprout.gateway.routes[1].prefix", () -> "/api/down");
        r.add("sprout.gateway.routes[1].target", () -> "http://127.0.0.1:" + CLOSED_PORT);
        r.add("sprout.gateway.routes[1].public[0]", () -> "GET /v1/anything");
        r.add("sprout.gateway.routes[2].name", () -> "flaky");
        r.add("sprout.gateway.routes[2].prefix", () -> "/api/flaky");
        r.add("sprout.gateway.routes[2].target", () -> up);
        r.add("sprout.gateway.routes[2].public[0]", () -> "GET /v1/fail");
        // TEST-NET-1: never answers, so connecting times out (like a host that was just killed)
        r.add("sprout.gateway.routes[3].name", () -> "blackhole");
        r.add("sprout.gateway.routes[3].prefix", () -> "/api/blackhole");
        r.add("sprout.gateway.routes[3].target", () -> "http://192.0.2.1:9");
        r.add("sprout.gateway.routes[3].public[0]", () -> "GET /v1/anything");
    }

    @LocalServerPort int port;
    final HttpClient client = HttpClient.newHttpClient();

    // ── routing and tokens ───────────────────────────────────────────────────

    @Test
    void publicEndpointsPassWithoutAToken() throws Exception {
        var res = send("POST", "/api/identity/v1/sessions", "{\"email\":\"a\"}", Map.of());
        assertThat(res.statusCode()).isEqualTo(200);
        JsonNode echo = JSON.readTree(res.body());
        assertThat(echo.path("path").asText()).isEqualTo("/v1/sessions");
        assertThat(echo.path("body").asText()).isEqualTo("{\"email\":\"a\"}");
        assertThat(echo.path("headers").has("x-user-id")).isFalse();
    }

    @Test
    void protectedEndpointsNeedAToken() throws Exception {
        var res = send("GET", "/api/identity/v1/users/me", null, Map.of());
        assertThat(res.statusCode()).isEqualTo(401);
        assertThat(JSON.readTree(res.body()).path("code").asText()).isEqualTo("UNAUTHENTICATED");
        assertThat(res.headers().firstValue("content-type")).hasValue("application/problem+json");
    }

    @Test
    void aValidTokenIsForwardedWithTheCallersIdAndSpoofedHeadersAreDropped() throws Exception {
        String user = UUID.randomUUID().toString();
        var res = send("GET", "/api/identity/v1/users/me?x=1", null, Map.of(
                "Authorization", "Bearer " + token(KEY, user, "sprout", Instant.now().plusSeconds(600)),
                "X-User-Id", "someone-else",
                "X-Forwarded-For", "10.0.0.1"));
        assertThat(res.statusCode()).isEqualTo(200);
        JsonNode headers = JSON.readTree(res.body()).path("headers");
        assertThat(headers.path("x-user-id").asText()).isEqualTo(user);
        assertThat(headers.path("x-session-id").asText()).isNotBlank();
        assertThat(headers.path("x-forwarded-for").asText()).isNotEqualTo("10.0.0.1");
        assertThat(JSON.readTree(res.body()).path("query").asText()).isEqualTo("x=1");
    }

    @Test
    void expiredWrongAudienceForgedAndUnsignedTokensAreRejected() throws Exception {
        String user = UUID.randomUUID().toString();
        String expired = token(KEY, user, "sprout", Instant.now().minusSeconds(120));
        String wrongAudience = token(KEY, user, "someone-else", Instant.now().plusSeconds(600));
        String forged = token(OTHER_KEY, user, "sprout", Instant.now().plusSeconds(600));
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ("{\"sub\":\"" + user + "\",\"sid\":\"s\",\"iss\":\"sprout-identity\",\"aud\":\"sprout\",\"exp\":9999999999,\"iat\":1}").getBytes(StandardCharsets.UTF_8));
        String unsigned = header + "." + payload + ".";
        for (String t : new String[] {expired, wrongAudience, forged, unsigned, "garbage"}) {
            var res = send("GET", "/api/identity/v1/users/me", null, Map.of("Authorization", "Bearer " + t));
            assertThat(res.statusCode()).as(t).isEqualTo(401);
        }
    }

    // ── request ids and headers ──────────────────────────────────────────────

    @Test
    void requestIdsAreCreatedPropagatedAndEchoed() throws Exception {
        var given = send("POST", "/api/identity/v1/sessions", "{}", Map.of("X-Request-Id", "trace-42"));
        assertThat(given.headers().firstValue("x-request-id")).hasValue("trace-42");
        assertThat(JSON.readTree(given.body()).path("headers").path("x-request-id").asText()).isEqualTo("trace-42");

        var created = send("POST", "/api/identity/v1/sessions", "{}", Map.of("X-Request-Id", "bad id with spaces"));
        String id = created.headers().firstValue("x-request-id").orElseThrow();
        assertThat(id).isNotEqualTo("bad id with spaces").matches("[0-9a-f-]{36}");
    }

    @Test
    void aClientsTraceNeverReachesAService() throws Exception {
        var res = send("POST", "/api/identity/v1/sessions", "{}", Map.of(
                "traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
                "tracestate", "evil=1", "baggage", "userId=someone-else", "b3", "0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-1"));
        JsonNode headers = JSON.readTree(res.body()).path("headers");
        assertThat(headers.path("traceparent").asText()).doesNotContain("0af7651916cd43dd8448eb211c80319c");
        assertThat(headers.has("tracestate")).isFalse();
        assertThat(headers.has("baggage")).isFalse();
        assertThat(headers.has("b3")).isFalse();
    }

    @Test
    void responsesCarrySecurityHeaders() throws Exception {
        var res = send("POST", "/api/identity/v1/sessions", "{}", Map.of());
        assertThat(res.headers().firstValue("x-content-type-options")).hasValue("nosniff");
        assertThat(res.headers().firstValue("cache-control")).hasValue("no-store");
        assertThat(res.headers().firstValue("x-frame-options")).hasValue("DENY");
    }

    // ── failures upstream ────────────────────────────────────────────────────

    @Test
    void anUnreachableServiceIs503() throws Exception {
        var res = send("GET", "/api/down/v1/anything", null, Map.of());
        assertThat(res.statusCode()).isEqualTo(503);
        assertThat(JSON.readTree(res.body()).path("code").asText()).isEqualTo("UPSTREAM_UNAVAILABLE");
    }

    @Test
    void aServiceThatNeverAcceptsTheConnectionIs503NotA504() throws Exception {
        long start = System.nanoTime();
        var res = send("GET", "/api/blackhole/v1/anything", null, Map.of());
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertThat(res.statusCode()).as("the request never arrived, so it's safe to retry").isEqualTo(503);
        assertThat(res.headers().firstValue("retry-after")).isPresent();
        assertThat(ms).isLessThan(3000);
    }

    @Test
    void aSlowServiceTimesOutAs504() throws Exception {
        var res = send("GET", "/api/identity/v1/slow", null, Map.of());
        assertThat(res.statusCode()).isEqualTo(504);
    }

    @Test
    void repeatedFailuresOpenTheCircuitAndStopCallingTheService() throws Exception {
        for (int i = 0; i < 10; i++) {
            assertThat(send("GET", "/api/flaky/v1/fail", null, Map.of()).statusCode()).isEqualTo(500);
        }
        int hitsBefore = FLAKY_HITS.get();
        var res = send("GET", "/api/flaky/v1/fail", null, Map.of());
        assertThat(res.statusCode()).isEqualTo(503);
        assertThat(res.headers().firstValue("retry-after")).isPresent();
        assertThat(FLAKY_HITS.get()).as("the open circuit fails fast without calling the service").isEqualTo(hitsBefore);
    }

    // ── bad requests ─────────────────────────────────────────────────────────

    @Test
    void unknownRoutesTraversalAndNonApiPathsAre404() throws Exception {
        assertThat(send("GET", "/api/nope/v1/x", null, Map.of()).statusCode()).isEqualTo(404);
        assertThat(send("GET", "/api/identity/v1/%2e%2e/admin", null, Map.of()).statusCode()).isEqualTo(404);
        assertThat(send("GET", "/api/identity", null, Map.of()).statusCode()).isEqualTo(404);
        var other = send("GET", "/wp-admin", null, Map.of());
        assertThat(other.statusCode()).isEqualTo(404);
        assertThat(JSON.readTree(other.body()).path("code").asText()).isEqualTo("NOT_FOUND");
    }

    @Test
    void oversizedBodiesAreRejected() throws Exception {
        var res = send("POST", "/api/identity/v1/sessions", "x".repeat(3000), Map.of());
        assertThat(res.statusCode()).isEqualTo(413);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    HttpResponse<String> send(String method, String path, String body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        if (body != null) {
            b.header("Content-Type", "application/json");
        }
        headers.forEach(b::header);
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    static String token(RSAKey key, String user, String audience, Instant expires) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer("sprout-identity").audience(audience).subject(user)
                .claim("sid", UUID.randomUUID().toString()).issueTime(new Date())
                .expirationTime(Date.from(expires)).build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    static RSAKey rsa() {
        try {
            return new RSAKeyGenerator(2048).keyUse(KeyUse.SIGNATURE).keyIDFromThumbprint(true).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static int freePort() {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Echoes requests as JSON, serves the JWKS, and has deliberately slow and failing endpoints. */
    static HttpServer startUpstream() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/.well-known/jwks.json", ex ->
                    reply(ex, 200, new JWKSet(KEY.toPublicJWK()).toString()));
            server.createContext("/v1/slow", ex -> {
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
                reply(ex, 200, "{}");
            });
            server.createContext("/v1/fail", ex -> {
                FLAKY_HITS.incrementAndGet();
                reply(ex, 500, "{\"code\":\"BOOM\"}");
            });
            server.createContext("/", ex -> {
                Map<String, Object> echo = new LinkedHashMap<>();
                echo.put("path", ex.getRequestURI().getPath());
                echo.put("query", ex.getRequestURI().getQuery());
                echo.put("body", new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                Map<String, String> hs = new LinkedHashMap<>();
                ex.getRequestHeaders().forEach((k, v) -> hs.put(k.toLowerCase(), String.join(",", v)));
                echo.put("headers", hs);
                reply(ex, 200, JSON.writeValueAsString(echo));
            });
            server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
            server.start();
            return server;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static void reply(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }
}
