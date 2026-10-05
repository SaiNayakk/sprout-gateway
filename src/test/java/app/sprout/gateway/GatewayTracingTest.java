package app.sprout.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpServer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** With tracing on, every call a service gets is part of a trace the gateway started, never the client's. */
@AutoConfigureObservability
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.config.name=gateway",
        "management.server.port=0",
        "management.tracing.enabled=true",
        "management.otlp.tracing.endpoint=http://127.0.0.1:9/v1/traces"})
class GatewayTracingTest {

    static final String CLIENTS_TRACE = "0af7651916cd43dd8448eb211c80319c";
    static final HttpServer UPSTREAM = GatewayTest.startUpstream();

    @DynamicPropertySource
    static void routes(DynamicPropertyRegistry r) {
        String up = "http://127.0.0.1:" + UPSTREAM.getAddress().getPort();
        r.add("sprout.gateway.jwks-url", () -> up + "/.well-known/jwks.json");
        r.add("sprout.gateway.routes[0].name", () -> "identity");
        r.add("sprout.gateway.routes[0].prefix", () -> "/api/identity");
        r.add("sprout.gateway.routes[0].target", () -> up);
        r.add("sprout.gateway.routes[0].public[0]", () -> "POST /v1/sessions");
    }

    @LocalServerPort int port;

    @Test
    void theServiceJoinsTheGatewaysTraceNotTheClients() throws Exception {
        HttpResponse<String> res = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/identity/v1/sessions"))
                .header("traceparent", "00-" + CLIENTS_TRACE + "-b7ad6b7169203331-01")
                .POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());
        JsonNode headers = GatewayTest.JSON.readTree(res.body()).path("headers");
        String traceparent = headers.path("traceparent").asText();
        assertThat(traceparent).as("the gateway's own trace goes onward").matches("00-[0-9a-f]{32}-[0-9a-f]{16}-0[01]");
        assertThat(traceparent).doesNotContain(CLIENTS_TRACE);
    }
}
