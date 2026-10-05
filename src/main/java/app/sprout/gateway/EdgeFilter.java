package app.sprout.gateway;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Runs first on every request: assigns the request id that follows it through every service,
 * drops any trace a client sends (so the gateway starts every trace, and no one can attach their
 * requests to someone else's trace or force sampling), and adds the security headers every
 * response should carry.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class EdgeFilter extends OncePerRequestFilter {

    public static final String REQUEST_ID = "X-Request-Id";

    /** Trace propagation headers (W3C, B3, Jaeger): only the gateway starts a trace. */
    static final Set<String> TRACE_HEADERS = Set.of("traceparent", "tracestate", "baggage", "b3", "x-b3-traceid",
            "x-b3-spanid", "x-b3-parentspanid", "x-b3-sampled", "x-b3-flags", "uber-trace-id");

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String id = req.getHeader(REQUEST_ID);
        if (id == null || id.isBlank() || id.length() > 100 || !id.matches("[A-Za-z0-9._-]+")) {
            id = UUID.randomUUID().toString();
        }
        MDC.put("requestId", id);
        req.setAttribute(REQUEST_ID, id);
        res.setHeader(REQUEST_ID, id);
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("Referrer-Policy", "no-referrer");
        res.setHeader("X-Frame-Options", "DENY");
        if (req.getRequestURI().startsWith("/api/")) {
            res.setHeader("Cache-Control", "no-store");
        }
        try {
            chain.doFilter(new WithoutTrace(req), res);
        } finally {
            MDC.remove("requestId");
        }
    }

    /** The request as the rest of the gateway sees it: without the client's trace headers. */
    static final class WithoutTrace extends HttpServletRequestWrapper {

        WithoutTrace(HttpServletRequest req) {
            super(req);
        }

        private static boolean hidden(String name) {
            return name != null && TRACE_HEADERS.contains(name.toLowerCase(Locale.ROOT));
        }

        @Override
        public String getHeader(String name) {
            return hidden(name) ? null : super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            return hidden(name) ? Collections.emptyEnumeration() : super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            return Collections.enumeration(Collections.list(super.getHeaderNames()).stream().filter(n -> !hidden(n)).toList());
        }
    }
}
