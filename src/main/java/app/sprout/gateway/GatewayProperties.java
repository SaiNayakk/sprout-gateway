package app.sprout.gateway;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.Name;

/** Settings under {@code sprout.gateway} in gateway.yml. */
@ConfigurationProperties("sprout.gateway")
public record GatewayProperties(
        String issuer,
        String audience,
        String jwksUrl,
        Duration connectTimeout,
        Duration requestTimeout,
        long maxBodyBytes,
        boolean trustCloudflareIp,
        RateLimits rateLimits,
        List<Route> routes) {

    public record RateLimits(int authPerMinute, int defaultPerMinute) {}

    /**
     * Requests under {@code prefix} go to {@code target} with the prefix removed. Endpoints are
     * written as {@code "METHOD /path"}.
     */
    public record Route(
            String name,
            String prefix,
            String target,
            @Name("public") List<String> publicEndpoints,
            List<String> authLimited) {

        public boolean isPublic(String method, String path) {
            return matches(publicEndpoints, method, path);
        }

        public boolean isAuthLimited(String method, String path) {
            return matches(authLimited, method, path);
        }

        private static boolean matches(List<String> endpoints, String method, String path) {
            return endpoints != null && endpoints.contains(method + " " + path);
        }
    }
}
