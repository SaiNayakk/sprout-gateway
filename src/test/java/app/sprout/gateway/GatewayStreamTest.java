package app.sprout.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.sun.net.httpserver.HttpServer;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Server-Sent Events through the gateway: relayed live, capped, and released when clients leave. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.config.name=gateway",
        "management.server.port=0",
        "sprout.gateway.trust-cloudflare-ip=true",
        "sprout.gateway.streams.per-client=2",
        "sprout.gateway.streams.total=3",
        "sprout.gateway.rate-limits.auth-per-minute=1000",
        "sprout.gateway.rate-limits.default-per-minute=1000"})
class GatewayStreamTest {

    static final ObjectMapper JSON = new ObjectMapper();
    static final RSAKey KEY = GatewayTest.rsa();
    static final AtomicInteger OPEN_UPSTREAM = new AtomicInteger();
    static final HttpServer UPSTREAM = startUpstream();

    @DynamicPropertySource
    static void routes(DynamicPropertyRegistry r) {
        String up = "http://127.0.0.1:" + UPSTREAM.getAddress().getPort();
        r.add("sprout.gateway.jwks-url", () -> up + "/.well-known/jwks.json");
        r.add("sprout.gateway.routes[0].name", () -> "md");
        r.add("sprout.gateway.routes[0].prefix", () -> "/api/md");
        r.add("sprout.gateway.routes[0].target", () -> up);
        r.add("sprout.gateway.routes[0].public[0]", () -> "GET /v1/instruments/{symbol}");
        r.add("sprout.gateway.routes[0].streams[0]", () -> "GET /v1/stream");
    }

    @LocalServerPort int port;
    @Autowired MeterRegistry meters;
    final HttpClient client = HttpClient.newHttpClient();

    HttpResponse<InputStream> open(String query, String ip, boolean withToken) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/md/v1/stream?" + query))
                .header("Accept", "text/event-stream").header("CF-Connecting-IP", ip);
        if (withToken) {
            b.header("Authorization", "Bearer " + GatewayTest.token(KEY, UUID.randomUUID().toString(), "sprout",
                    Instant.now().plusSeconds(600)));
        }
        return client.send(b.build(), HttpResponse.BodyHandlers.ofInputStream());
    }

    @Test
    void eventsArriveAsTheServiceSendsThemNotAtTheEnd() throws Exception {
        long start = System.currentTimeMillis();
        HttpResponse<InputStream> res = open("n=30", "198.18.1.1", true);
        assertThat(res.statusCode()).isEqualTo(200);
        assertThat(res.headers().firstValue("content-type").orElse("")).startsWith("text/event-stream");
        assertThat(res.headers().firstValue("x-request-id")).isPresent();
        List<Long> arrivals = new ArrayList<>();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(res.body(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                if (line.startsWith("data:")) {
                    arrivals.add(System.currentTimeMillis() - start);
                }
            }
        }
        assertThat(arrivals).hasSize(30);
        // the service takes about 3 s to send them all; the first must not wait for the last
        assertThat(arrivals.get(0)).isLessThan(1500);
        assertThat(arrivals.get(29) - arrivals.get(0)).isGreaterThan(2000);
    }

    @Test
    void streamsDontCountAsSlowRequests() throws Exception {
        HttpResponse<InputStream> res = open("n=25", "198.18.1.9", true);
        try (InputStream in = res.body()) {
            in.readAllBytes(); // a 2.5 s stream
        }
        for (Timer t : meters.find("http.server.requests").timers()) {
            assertThat(t.max(TimeUnit.MILLISECONDS)).as(t.getId().toString()).isLessThan(2000);
        }
        assertThat(meters.find("gateway.streams.opened").counter().count()).isPositive();
    }

    @Test
    void aStreamNeedsAToken() throws Exception {
        HttpResponse<InputStream> res = open("n=5", "198.18.1.2", false);
        assertThat(res.statusCode()).isEqualTo(401);
        assertThat(JSON.readTree(res.body()).path("code").asText()).isEqualTo("UNAUTHENTICATED");
    }

    @Test
    void theServicesRefusalIsPassedOnAndFreesTheSlot() throws Exception {
        for (int i = 0; i < 5; i++) {
            HttpResponse<InputStream> res = open("bad=1", "198.18.1.3", true);
            assertThat(res.statusCode()).isEqualTo(404);
            assertThat(JSON.readTree(res.body()).path("code").asText()).isEqualTo("UNKNOWN_INSTRUMENT");
        }
    }

    @Test
    void streamsAreCappedPerClientAndInTotalAndFreedWhenClientsLeave() throws Exception {
        HttpResponse<InputStream> a = open("n=300", "198.18.2.1", true);
        HttpResponse<InputStream> b = open("n=300", "198.18.2.1", true);
        assertThat(a.statusCode()).isEqualTo(200);
        assertThat(b.statusCode()).isEqualTo(200);

        HttpResponse<InputStream> third = open("n=300", "198.18.2.1", true);
        assertThat(third.statusCode()).isEqualTo(429);
        assertThat(third.headers().firstValue("retry-after")).isPresent();

        HttpResponse<InputStream> other = open("n=300", "198.18.2.2", true);
        assertThat(other.statusCode()).as("another client still gets one").isEqualTo(200);
        HttpResponse<InputStream> full = open("n=300", "198.18.2.3", true);
        assertThat(full.statusCode()).as("but the gateway is now full").isEqualTo(503);

        a.body().close(); // the first client goes away
        long deadline = System.currentTimeMillis() + 3000;
        int status = 0;
        while (System.currentTimeMillis() < deadline) {
            HttpResponse<InputStream> again = open("n=300", "198.18.2.3", true);
            status = again.statusCode();
            if (status == 200) {
                again.body().close();
                break;
            }
            again.body().close();
            Thread.sleep(100);
        }
        assertThat(status).as("the slot is released once the gateway notices").isEqualTo(200);
        b.body().close();
        other.body().close();
        Thread.sleep(800);
        assertThat(OPEN_UPSTREAM.get()).as("and the service's connections are closed too").isZero();
    }

    @Test
    void pathPatternsMatchExactlyOneSegment() throws Exception {
        HttpRequest one = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/md/v1/instruments/HARBOR")).build();
        HttpRequest two = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/md/v1/instruments/HARBOR/extra")).build();
        assertThat(client.send(one, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(200);
        assertThat(client.send(two, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(401);
    }

    /** A stub service: JWKS, an instrument lookup, and an event stream of n events 100 ms apart. */
    static HttpServer startUpstream() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/.well-known/jwks.json", ex -> GatewayTest.reply(ex, 200, new JWKSet(KEY.toPublicJWK()).toString()));
            server.createContext("/v1/instruments/", ex -> GatewayTest.reply(ex, 200, "{\"symbol\":\"HARBOR\"}"));
            server.createContext("/v1/stream", ex -> {
                String q = ex.getRequestURI().getQuery() == null ? "" : ex.getRequestURI().getQuery();
                if (q.contains("bad=1")) {
                    GatewayTest.reply(ex, 404, "{\"code\":\"UNKNOWN_INSTRUMENT\"}");
                    return;
                }
                int n = Integer.parseInt(q.replaceAll(".*n=(\\d+).*", "$1"));
                ex.getResponseHeaders().add("Content-Type", "text/event-stream");
                ex.sendResponseHeaders(200, 0);
                OPEN_UPSTREAM.incrementAndGet();
                try (OutputStream out = ex.getResponseBody()) {
                    for (int i = 1; i <= n; i++) {
                        out.write(("event:tick\ndata:{\"seq\":" + i + "}\n\n").getBytes(StandardCharsets.UTF_8));
                        out.flush();
                        Thread.sleep(100);
                    }
                } catch (IOException | InterruptedException e) {
                    // the gateway hung up on us: what should happen when its client leaves
                } finally {
                    OPEN_UPSTREAM.decrementAndGet();
                    ex.close();
                }
            });
            server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
            server.start();
            return server;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
