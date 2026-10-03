package app.sprout.gateway;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Runs first on every request: assigns the request id that follows it through every service,
 * and adds the security headers every response should carry.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class EdgeFilter extends OncePerRequestFilter {

    public static final String REQUEST_ID = "X-Request-Id";

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
            chain.doFilter(req, res);
        } finally {
            MDC.remove("requestId");
        }
    }
}
