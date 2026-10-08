package app.sprout.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The gateway as one of two cells (ADR-027): customers' writes are journalled in the other cell before they are
 * forwarded, every write carries an idempotency key, a fenced cell takes no writes, and the other cell's replays
 * and journal entries are accepted only with the cells' key.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.config.name=gateway",
        "management.server.port=0",
        "sprout.gateway.request-timeout=2s",
        "sprout.gateway.rate-limits.auth-per-minute=1000",
        "sprout.gateway.rate-limits.default-per-minute=1000",
        "sprout.gateway.cell.id=a",
        "sprout.gateway.cell.key=cells-shared-key-for-tests",
        "sprout.gateway.cell.journal-timeout=1s"})
class GatewayCellTest {

    static final ObjectMapper JSON = new ObjectMapper();
    static final HttpServer UPSTREAM = upstream();
    /** The other cell: what it was sent, and whether it answers. */
    static final List<JsonNode> PEER_GOT = new CopyOnWriteArrayList<>();
    static final AtomicInteger PEER_STATUS = new AtomicInteger(204);
    static final HttpServer PEER = peer();
    static final Path DIR = tempDir();
    static final Path FENCE = DIR.resolve("fenced");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        String up = "http://127.0.0.1:" + UPSTREAM.getAddress().getPort();
        r.add("sprout.gateway.jwks-url", () -> up + "/.well-known/jwks.json");
        r.add("sprout.gateway.cell.peer-url", () -> "http://127.0.0.1:" + PEER.getAddress().getPort());
        r.add("sprout.gateway.cell.journal-dir", () -> DIR.resolve("journal").toString());
        r.add("sprout.gateway.cell.fence-file", FENCE::toString);
        r.add("sprout.gateway.routes[0].name", () -> "oms");
        r.add("sprout.gateway.routes[0].prefix", () -> "/api/oms");
        r.add("sprout.gateway.routes[0].target", () -> up);
        r.add("sprout.gateway.routes[1].name", () -> "identity");
        r.add("sprout.gateway.routes[1].prefix", () -> "/api/identity");
        r.add("sprout.gateway.routes[1].target", () -> up);
        r.add("sprout.gateway.routes[1].public[0]", () -> "POST /v1/sessions");
    }

    @LocalServerPort int port;
    final HttpClient client = HttpClient.newHttpClient();
    final String user = UUID.randomUUID().toString();

    @BeforeEach
    void reset() throws IOException {
        PEER_GOT.clear();
        PEER_STATUS.set(204);
        Files.deleteIfExists(FENCE);
    }

    @Test
    void aWriteIsJournalledInTheOtherCellBeforeItIsForwarded() throws Exception {
        var res = send("POST", "/api/oms/v1/orders?x=1", "{\"symbol\":\"SUNROOT\"}", Map.of("Authorization", bearer(),
                "Idempotency-Key", "order-key-12345", "Content-Type", "application/json"));
        assertThat(res.statusCode()).isEqualTo(200);
        assertThat(PEER_GOT).hasSize(1);
        JsonNode e = PEER_GOT.get(0);
        assertThat(e.path("cell").asText()).isEqualTo("a");
        assertThat(e.path("userId").asText()).isEqualTo(user);
        assertThat(e.path("method").asText()).isEqualTo("POST");
        assertThat(e.path("uri").asText()).isEqualTo("/api/oms/v1/orders");
        assertThat(e.path("query").asText()).isEqualTo("x=1");
        assertThat(e.path("idempotencyKey").asText()).isEqualTo("order-key-12345");
        assertThat(new String(Base64.getDecoder().decode(e.path("body").asText()), StandardCharsets.UTF_8)).isEqualTo("{\"symbol\":\"SUNROOT\"}");
        assertThat(res.headers().firstValue("X-Sprout-Protection")).isEmpty();
    }

    @Test
    void aWriteTheServiceRefusesIsNotedSoAReplayLeavesItRefused() throws Exception {
        var res = send("POST", "/api/oms/v1/refuse", "{}", Map.of("Authorization", bearer(), "Idempotency-Key", "order-key-refused"));
        assertThat(res.statusCode()).isEqualTo(422);
        String id = PEER_GOT.get(0).path("id").asText();
        for (int i = 0; i < 50 && PEER_GOT.size() < 2; i++) {
            Thread.sleep(50);   // the note is sent without waiting
        }
        assertThat(PEER_GOT.get(1).path("outcomeOf").asText()).isEqualTo(id);
        assertThat(PEER_GOT.get(1).path("status").asInt()).isEqualTo(422);
    }

    @Test
    void aWriteWithoutAKeyIsGivenOneAndToldIt() throws Exception {
        var res = send("POST", "/api/oms/v1/orders", "{}", Map.of("Authorization", bearer(), "Content-Type", "application/json"));
        String key = res.headers().firstValue("Idempotency-Key").orElseThrow();
        assertThat(JSON.readTree(res.body()).path("headers").path("idempotency-key").asText()).as("the service gets it").isEqualTo(key);
        assertThat(PEER_GOT.get(0).path("idempotencyKey").asText()).as("and so does the journal").isEqualTo(key);
    }

    @Test
    void readsAndSignInAreNotJournalled() throws Exception {
        send("GET", "/api/oms/v1/orders", null, Map.of("Authorization", bearer()));
        send("POST", "/api/identity/v1/sessions", "{\"email\":\"a\"}", Map.of("Content-Type", "application/json"));
        assertThat(PEER_GOT).isEmpty();
    }

    @Test
    void ifTheOtherCellIsAwayTheWriteGoesAheadAndSaysItIsUnprotected() throws Exception {
        PEER_STATUS.set(503);
        var res = send("POST", "/api/oms/v1/orders", "{}", Map.of("Authorization", bearer(), "Idempotency-Key", "order-key-67890"));
        assertThat(res.statusCode()).isEqualTo(200);
        assertThat(res.headers().firstValue("X-Sprout-Protection")).hasValue("unprotected");
    }

    @Test
    void aFencedCellTakesNoWritesButStillAnswersReads() throws Exception {
        Files.createFile(FENCE);
        var write = send("POST", "/api/oms/v1/orders", "{}", Map.of("Authorization", bearer(), "Idempotency-Key", "order-key-fenced"));
        assertThat(write.statusCode()).isEqualTo(503);
        assertThat(write.headers().firstValue("Retry-After")).hasValue("60");
        assertThat(send("GET", "/api/oms/v1/orders", null, Map.of("Authorization", bearer())).statusCode()).isEqualTo(200);
        assertThat(PEER_GOT).isEmpty();
    }

    @Test
    void theOtherCellReplaysAWriteForACustomerWithTheCellsKeyAndItIsNotJournalledAgain() throws Exception {
        var res = send("POST", "/api/oms/v1/orders", "{}", Map.of("X-Cell-Replay-Key", "cells-shared-key-for-tests",
                "X-Cell-Replay-User", user, "Idempotency-Key", "order-key-replayed"));
        assertThat(res.statusCode()).isEqualTo(200);
        JsonNode headers = JSON.readTree(res.body()).path("headers");
        assertThat(headers.path("x-user-id").asText()).isEqualTo(user);
        assertThat(headers.path("idempotency-key").asText()).isEqualTo("order-key-replayed");
        assertThat(headers.has("x-cell-replay-key")).as("the key never reaches a service").isFalse();
        assertThat(PEER_GOT).isEmpty();

        var wrong = send("POST", "/api/oms/v1/orders", "{}", Map.of("X-Cell-Replay-Key", "guess", "X-Cell-Replay-User", user));
        assertThat(wrong.statusCode()).isEqualTo(401);
    }

    @Test
    void theOtherCellsJournalEntriesAreKeptOnDiskOnlyWithTheCellsKey() throws Exception {
        String entry = "{\"cell\":\"b\",\"userId\":\"" + user + "\",\"method\":\"POST\",\"uri\":\"/api/oms/v1/orders\","
                + "\"idempotencyKey\":\"k-12345678\",\"body\":\"e30=\"}";
        assertThat(send("POST", "/api/cells/v1/journal", entry, Map.of("Content-Type", "application/json", "X-Cell-Key", "nope")).statusCode())
                .isEqualTo(401);
        assertThat(send("POST", "/api/cells/v1/journal", "{\"cell\":\"b\"}", Map.of("Content-Type", "application/json",
                "X-Cell-Key", "cells-shared-key-for-tests")).statusCode()).isEqualTo(400);
        assertThat(send("POST", "/api/cells/v1/journal", entry, Map.of("Content-Type", "application/json",
                "X-Cell-Key", "cells-shared-key-for-tests")).statusCode()).isEqualTo(204);
        try (Stream<Path> files = Files.list(DIR.resolve("journal"))) {
            Path file = files.filter(f -> f.getFileName().toString().startsWith("b-")).findFirst().orElseThrow();
            JsonNode line = JSON.readTree(Files.readAllLines(file).get(Files.readAllLines(file).size() - 1));
            assertThat(line.path("idempotencyKey").asText()).isEqualTo("k-12345678");
            assertThat(line.path("receivedAt").asText()).isNotBlank();
        }
    }

    @Test
    void theOtherCellCanNameTheRealClientOnlyWithTheCellsKey() throws Exception {
        var trusted = send("GET", "/api/oms/v1/orders", null, Map.of("Authorization", bearer(),
                "X-Cell-Key", "cells-shared-key-for-tests", "X-Sprout-Client-IP", "203.0.113.7"));
        JsonNode h = JSON.readTree(trusted.body()).path("headers");
        assertThat(h.path("x-forwarded-for").asText()).isEqualTo("203.0.113.7");
        assertThat(h.has("x-sprout-client-ip")).as("not passed on").isFalse();
        var untrusted = send("GET", "/api/oms/v1/orders", null, Map.of("Authorization", bearer(), "X-Sprout-Client-IP", "203.0.113.7"));
        assertThat(JSON.readTree(untrusted.body()).path("headers").path("x-forwarded-for").asText()).isNotEqualTo("203.0.113.7");
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    String bearer() throws Exception {
        return "Bearer " + GatewayTest.token(GatewayTest.KEY, user, "sprout", Instant.now().plusSeconds(600));
    }

    HttpResponse<String> send(String method, String path, String body, Map<String, String> headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        headers.forEach(b::header);
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** The gateway test's stub, plus an address that refuses every write (422). */
    static HttpServer upstream() {
        HttpServer s = GatewayTest.startUpstream();
        s.createContext("/v1/refuse", ex -> {
            byte[] b = "{\"code\":\"VALIDATION_FAILED\"}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(422, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        return s;
    }

    static HttpServer peer() {
        try {
            HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            s.createContext("/api/cells/v1/journal", ex -> {
                if ("cells-shared-key-for-tests".equals(ex.getRequestHeaders().getFirst("X-Cell-Key")) && PEER_STATUS.get() == 204) {
                    PEER_GOT.add(JSON.readTree(ex.getRequestBody().readAllBytes()));
                }
                ex.sendResponseHeaders(PEER_STATUS.get(), -1);
                ex.close();
            });
            s.start();
            return s;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static Path tempDir() {
        try {
            return Files.createTempDirectory("cell-test");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
