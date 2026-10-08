package app.sprout.gateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Where the other cell sends its writes before forwarding them (ADR-027). Only the cells' shared key is accepted, and
 * only where this gateway is a cell; anywhere else this address doesn't exist.
 */
@RestController
public class CellJournalController {

    private static final int MAX_BYTES = 256 * 1024;   // a write is at most 64 KB; base64 and the envelope add a third

    private final CellJournal journal;
    private final ObjectMapper json;

    public CellJournalController(CellJournal journal, ObjectMapper json) {
        this.journal = journal;
        this.json = json;
    }

    @PostMapping("/api/cells/v1/journal")
    public void receive(HttpServletRequest req, HttpServletResponse res) throws IOException {
        if (!journal.enabled()) {
            Problems.write(res, 404, "NOT_FOUND", "Not found", "There's no API at this address.", null);
            return;
        }
        if (!journal.isCellKey(req.getHeader("X-Cell-Key"))) {
            Problems.write(res, 401, "UNAUTHENTICATED", "Not a cell", "Only the other cell may write here.", null);
            return;
        }
        byte[] body = req.getInputStream().readNBytes(MAX_BYTES + 1);
        JsonNode entry;
        try {
            entry = body.length > MAX_BYTES ? null : json.readTree(body);
        } catch (IOException e) {
            entry = null;
        }
        if (!(entry instanceof ObjectNode o) || !o.hasNonNull("method") || !o.hasNonNull("uri") || !o.hasNonNull("userId")
                || !o.hasNonNull("idempotencyKey") || !o.hasNonNull("cell")) {
            Problems.write(res, 400, "VALIDATION_FAILED", "Invalid entry",
                    "Send a journal entry: cell, userId, method, uri, idempotencyKey and body.", null);
            return;
        }
        journal.append(o);
        res.setStatus(204);
    }
}
