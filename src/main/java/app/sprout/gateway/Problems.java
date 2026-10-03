package app.sprout.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.MDC;

/** Writes RFC 9457 problem responses, in the same shape the services use. */
final class Problems {

    private static final ObjectMapper JSON = new ObjectMapper();

    private Problems() {}

    static void write(HttpServletResponse res, int status, String code, String title, String detail, Long retryAfter)
            throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", "https://sainayakk.github.io/sprout-platform/errors/#" + code.toLowerCase());
        body.put("title", title);
        body.put("status", status);
        body.put("code", code);
        body.put("detail", detail);
        if (retryAfter != null) {
            body.put("retryAfterSeconds", retryAfter);
            res.setHeader("Retry-After", String.valueOf(retryAfter));
        }
        String requestId = MDC.get("requestId");
        if (requestId != null) {
            body.put("requestId", requestId);
        }
        res.setStatus(status);
        res.setContentType("application/problem+json");
        JSON.writeValue(res.getOutputStream(), body);
    }
}
