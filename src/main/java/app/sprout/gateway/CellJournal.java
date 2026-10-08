package app.sprout.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
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

    /** One write, as journalled. {@code body} is the raw request body. */
    public record Entry(String cell, String userId, String method, String uri, String query, String idempotencyKey,
                        String contentType, byte[] body, String requestId) {}

    private final GatewayProperties.Cell cell;
    private final ObjectMapper json;
    private final MeterRegistry meters;
    private final Clock clock;
    private final HttpClient http;

    public CellJournal(GatewayProperties props, ObjectMapper json, MeterRegistry meters) {
        this.cell = props.cell();
        this.json = json;
        this.meters = meters;
        this.clock = Clock.systemUTC();
        Duration timeout = cell == null || cell.journalTimeout() == null ? Duration.ofSeconds(2) : cell.journalTimeout();
        this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
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
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(cell.peerUrl() + "/api/cells/v1/journal"))
                    .timeout(cell.journalTimeout() == null ? Duration.ofSeconds(2) : cell.journalTimeout())
                    .header("Content-Type", "application/json").header("X-Cell-Key", cell.key())
                    .POST(HttpRequest.BodyPublishers.ofByteArray(json.writeValueAsBytes(line(e)))).build();
            int status = http.send(req, HttpResponse.BodyHandlers.discarding()).statusCode();
            boolean ok = status == 204;
            meters.counter("gateway.cell.journal", "outcome", ok ? "journalled" : "refused").increment();
            if (!ok) {
                log.warn("The other cell refused a journal entry ({}): the write goes ahead unprotected", status);
            }
            return ok;
        } catch (Exception ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            meters.counter("gateway.cell.journal", "outcome", "unreachable").increment();
            return false;
        }
    }

    ObjectNode line(Entry e) {
        ObjectNode n = json.createObjectNode();
        n.put("id", UUID.randomUUID().toString());
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
