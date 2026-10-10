package app.sprout.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.micrometer.core.instrument.MeterRegistry;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * This cell's half of the cross-cell write journal (ADR-027). Before a customer's write is forwarded, it is sent to
 * the other cell, which appends it to a file there; if this cell is then lost, the other cell replays the file
 * against its copy of this cell's database, and each write's idempotency key makes a replay of something that had
 * already happened a no-op. Writes are delivered at least once; their keys make them take effect once.
 *
 * <p>The file is one JSON line per write, flushed to disk before the sender is answered, one file per sending cell
 * per hour, kept for two hours (replication lags by seconds; the journal only has to cover that gap).
 */
@Component
public class CellJournal {

    private static final Logger log = LoggerFactory.getLogger(CellJournal.class);
    private static final Set<String> WRITES = Set.of("POST", "PUT", "PATCH", "DELETE");
    private static final DateTimeFormatter HOUR = DateTimeFormatter.ofPattern("yyyyMMddHH").withZone(ZoneOffset.UTC);
    static final Duration KEEP = Duration.ofHours(2);
    /** How long the journal's circuit stays open after the other cell has failed to answer, before it tries again. */
    static final Duration OPEN_FOR = Duration.ofSeconds(15);

    /** One write, as journalled. {@code id} names the entry; {@code body} is the raw request body. */
    public record Entry(String id, String cell, String userId, String method, String uri, String query, String idempotencyKey,
                        String contentType, byte[] body, String requestId) {}

    private final GatewayProperties.Cell cell;
    private final ObjectMapper json;
    private final MeterRegistry meters;
    private final Clock clock;
    private final HttpClient http;
    private final CircuitBreaker breaker;

    public CellJournal(GatewayProperties props, ObjectMapper json, MeterRegistry meters) {
        this.cell = props.cell();
        this.json = json;
        this.meters = meters;
        this.clock = Clock.systemUTC();
        Duration timeout = cell == null || cell.journalTimeout() == null ? Duration.ofSeconds(2) : cell.journalTimeout();
        this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
        this.breaker = CircuitBreaker.of("cell-journal", CircuitBreakerConfig.custom()
                .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
                .slidingWindowSize(10).minimumNumberOfCalls(4).failureRateThreshold(50)
                .waitDurationInOpenState(cell != null && cell.journalCircuitOpen() != null ? cell.journalCircuitOpen() : OPEN_FOR)
                .permittedNumberOfCallsInHalfOpenState(2)
                .automaticTransitionFromOpenToHalfOpenEnabled(true).build());
    }

    public boolean enabled() {
        return cell != null && cell.enabled();
    }

    public String cellId() {
        return enabled() ? cell.id() : null;
    }

    public static boolean isWrite(String method) {
        return WRITES.contains(method);
    }

    /** Whether a write to this address is one the other cell must be able to replay. */
    public boolean covers(String uri) {
        if (!enabled()) {
            return false;
        }
        if (cell.unjournaled() != null) {
            for (String prefix : cell.unjournaled()) {
                if (uri.equals(prefix) || uri.startsWith(prefix + "/")) {
                    return false;
                }
            }
        }
        return true;
    }

    /** While the fence file exists this cell takes no writes: the other cell may be taking its customers over. */
    public boolean fenced() {
        return enabled() && cell.fenceFile() != null && !cell.fenceFile().isBlank() && Files.exists(Path.of(cell.fenceFile()));
    }

    /** Whether {@code key} is the cells' shared key (compared in constant time). */
    public boolean isCellKey(String key) {
        return enabled() && key != null && cell.key() != null && !cell.key().isBlank()
                && MessageDigest.isEqual(key.getBytes(StandardCharsets.UTF_8), cell.key().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Sends a write to the other cell's journal. True once it is on the other cell's disk; false if the other cell
     * couldn't be reached or refused it (the write then goes ahead unprotected, and is counted).
     */
    public boolean send(Entry e) {
        if (cell.peerUrl() == null || cell.peerUrl().isBlank()) {
            meters.counter("gateway.cell.journal", "outcome", "no_peer").increment();
            return false;
        }
        // Every write waits for this call, so a slow or unreachable other cell must not cost every write its timeout (found by
        // an experiment: a frozen peer cut this cell's throughput from 40 to 6 orders a second). After a few failures the circuit
        // opens and writes go ahead unprotected at once; it lets two calls through every OPEN_FOR to see whether the peer is back.
        if (!breaker.tryAcquirePermission()) {
            meters.counter("gateway.cell.journal", "outcome", "skipped").increment();
            unprotected(e, "the journal's circuit is open: the other cell is slow or away");
            return false;
        }
        long start = System.nanoTime();
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(cell.peerUrl() + "/api/cells/v1/journal"))
                    .timeout(cell.journalTimeout() == null ? Duration.ofSeconds(2) : cell.journalTimeout())
                    .header("Content-Type", "application/json").header("X-Cell-Key", cell.key())
                    .POST(HttpRequest.BodyPublishers.ofByteArray(json.writeValueAsBytes(line(e)))).build();
            int status = http.send(req, HttpResponse.BodyHandlers.discarding()).statusCode();
            boolean ok = status == 204;
            long took = System.nanoTime() - start;
            if (ok) {
                breaker.onSuccess(took, TimeUnit.NANOSECONDS);
            } else {
                breaker.onError(took, TimeUnit.NANOSECONDS, new IllegalStateException("status " + status));
            }
            meters.counter("gateway.cell.journal", "outcome", ok ? "journalled" : "refused").increment();
            if (!ok) {
                log.warn("The other cell refused a journal entry ({}): the write goes ahead unprotected", status);
                unprotected(e, "refused with " + status);
            }
            return ok;
        } catch (Exception ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            breaker.onError(System.nanoTime() - start, TimeUnit.NANOSECONDS, ex);
            meters.counter("gateway.cell.journal", "outcome", "unreachable").increment();
            unprotected(e, "unreachable");
            return false;
        }
    }

    /** Forgets the journal's failures: the circuit closes. For tests, and for a peer known to be back. */
    void resetCircuit() {
        breaker.reset();
    }

    boolean circuitOpen() {
        return breaker.getState() != CircuitBreaker.State.CLOSED;
    }

    /**
     * Writes down, on this cell's own disk, a write that went ahead without the other cell having it, so that something can alert
     * on it (the entry itself is not kept: only what and when). Best effort.
     */
    private synchronized void unprotected(Entry e, String why) {
        meters.counter("gateway.cell.unprotected").increment();
        if (cell.journalDir() == null || cell.journalDir().isBlank()) {
            return;
        }
        try {
            Path dir = Path.of(cell.journalDir());
            Files.createDirectories(dir);
            Instant now = clock.instant();
            ObjectNode n = json.createObjectNode();
            n.put("id", e.id());
            n.put("at", now.toString());
            n.put("method", e.method());
            n.put("uri", e.uri());
            n.put("why", why);
            Files.writeString(dir.resolve("unprotected-" + cell.id() + "-" + HOUR.format(now) + ".jsonl"), json.writeValueAsString(n) + "\n",
                    StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // the write has gone ahead; this record is a convenience
        }
    }

    /**
     * Tells the other cell that a journalled write was refused (4xx) and the customer told so, so a replay doesn't make
     * it happen after all. Sent without waiting: if this note is lost, the replay is still safe for keyed writes, and
     * the window is the moment between the answer and this cell being lost.
     */
    public void noteRefused(String entryId, int status) {
        if (cell.peerUrl() == null || cell.peerUrl().isBlank()) {
            return;
        }
        try {
            ObjectNode n = json.createObjectNode();
            n.put("cell", cell.id());
            n.put("outcomeOf", entryId);
            n.put("status", status);
            n.put("at", clock.instant().toString());
            HttpRequest req = HttpRequest.newBuilder(URI.create(cell.peerUrl() + "/api/cells/v1/journal"))
                    .timeout(cell.journalTimeout() == null ? Duration.ofSeconds(2) : cell.journalTimeout())
                    .header("Content-Type", "application/json").header("X-Cell-Key", cell.key())
                    .POST(HttpRequest.BodyPublishers.ofByteArray(json.writeValueAsBytes(n))).build();
            http.sendAsync(req, HttpResponse.BodyHandlers.discarding());
        } catch (Exception ignored) {
            // best effort, as above
        }
    }

    ObjectNode line(Entry e) {
        ObjectNode n = json.createObjectNode();
        n.put("id", e.id());
        n.put("at", clock.instant().toString());
        n.put("cell", e.cell());
        n.put("userId", e.userId());
        n.put("method", e.method());
        n.put("uri", e.uri());
        if (e.query() != null) {
            n.put("query", e.query());
        }
        n.put("idempotencyKey", e.idempotencyKey());
        if (e.contentType() != null) {
            n.put("contentType", e.contentType());
        }
        n.put("body", Base64.getEncoder().encodeToString(e.body() == null ? new byte[0] : e.body()));
        if (e.requestId() != null) {
            n.put("requestId", e.requestId());
        }
        return n;
    }

    /**
     * Appends an entry the other cell sent, and returns once it is on disk. One writer at a time, so lines never
     * interleave.
     */
    public synchronized void append(ObjectNode entry) throws IOException {
        String from = entry.path("cell").asText("unknown").toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9-]", "");
        Path dir = Path.of(cell.journalDir());
        Files.createDirectories(dir);
        Instant now = clock.instant();
        entry.put("receivedAt", now.toString());
        Path file = dir.resolve(from + "-" + HOUR.format(now) + ".jsonl");
        byte[] bytes = (json.writeValueAsString(entry) + "\n").getBytes(StandardCharsets.UTF_8);
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.WRITE)) {
            ByteBuffer buf = ByteBuffer.wrap(bytes);
            while (buf.hasRemaining()) {
                ch.write(buf);
            }
            ch.force(true);
        }
        meters.counter("gateway.cell.journal.received", "from", from).increment();
        prune(dir, now);
    }

    private void prune(Path dir, Instant now) {
        String oldest = HOUR.format(now.minus(KEEP));
        try (Stream<Path> files = Files.list(dir)) {
            files.filter(f -> f.getFileName().toString().endsWith(".jsonl")).forEach(f -> {
                String name = f.getFileName().toString();
                String hour = name.substring(name.lastIndexOf('-') + 1, name.length() - ".jsonl".length());
                if (hour.compareTo(oldest) < 0) {
                    try {
                        Files.deleteIfExists(f);
                    } catch (IOException ignored) {
                        // tried again on the next append
                    }
                }
            });
        } catch (IOException ignored) {
            // nothing to prune
        }
    }
}
