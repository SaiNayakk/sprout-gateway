package app.sprout.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Sign-in style endpoints get a much lower limit than everything else, to slow password guessing. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.config.name=gateway",
        "management.server.port=0",
        "sprout.gateway.rate-limits.auth-per-minute=3",
        "sprout.gateway.rate-limits.default-per-minute=1000"})
class GatewayRateLimitTest {

    @DynamicPropertySource
    static void routes(DynamicPropertyRegistry r) {
        String up = "http://127.0.0.1:" + GatewayTest.UPSTREAM.getAddress().getPort();
        r.add("sprout.gateway.jwks-url", () -> up + "/.well-known/jwks.json");
        r.add("sprout.gateway.routes[0].name", () -> "identity");
        r.add("sprout.gateway.routes[0].prefix", () -> "/api/identity");
        r.add("sprout.gateway.routes[0].target", () -> up);
        r.add("sprout.gateway.routes[0].public[0]", () -> "POST /v1/sessions");
        r.add("sprout.gateway.routes[0].public[1]", () -> "POST /v1/other");
        r.add("sprout.gateway.routes[0].auth-limited[0]", () -> "POST /v1/sessions");
    }

    @LocalServerPort int port;
    final HttpClient client = HttpClient.newHttpClient();

    @Test
    void theFourthSignInInAMinuteIsRefusedButOtherCallsStillWork() throws Exception {
        for (int i = 0; i < 3; i++) {
            assertThat(post("/api/identity/v1/sessions").statusCode()).isEqualTo(200);
        }
        HttpResponse<String> limited = post("/api/identity/v1/sessions");
        assertThat(limited.statusCode()).isEqualTo(429);
        assertThat(limited.headers().firstValue("retry-after")).isPresent();
        assertThat(new ObjectMapper().readTree(limited.body()).path("code").asText()).isEqualTo("RATE_LIMITED");
        assertThat(post("/api/identity/v1/other").statusCode()).isEqualTo(200);
    }

    HttpResponse<String> post(String path) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{}")).build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
