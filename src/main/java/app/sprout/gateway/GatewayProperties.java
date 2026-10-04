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
        Streams streams,
        List<Route> routes) {

    public record RateLimits(int authPerMinute, int defaultPerMinute) {}

    /** Long-lived Server-Sent Events streams: how many one client, and everyone, may hold open. */
    public record Streams(int perClient, int total) {}

    /**
     * Requests under {@code prefix} go to {@code target} with the prefix removed. Endpoints are
     * written as {@code "METHOD /path"}; a path segment written as {@code {name}} matches any one
     * segment, e.g. {@code "GET /v1/instruments/{symbol}"}.
     */
    public record Route(
            String name,
            String prefix,
            String target,
            @Name("public") List<String> publicEndpoints,
            List<String> authLimited,
            List<String> streams) {

        public boolean isPublic(String method, String path) {
            return matches(publicEndpoints, method, path);
        }

        public boolean isAuthLimited(String method, String path) {
            return matches(authLimited, method, path);
        }

        public boolean isStream(String method, String path) {
            return matches(streams, method, path);
        }

        static boolean matches(List<String> endpoints, String method, String path) {
            if (endpoints == null) {
                return false;
            }
            for (String endpoint : endpoints) {
                int space = endpoint.indexOf(' ');
                if (space > 0 && endpoint.substring(0, space).equals(method)
                        && pathMatches(endpoint.substring(space + 1), path)) {
                    return true;
                }
            }
            return false;
        }

        private static boolean pathMatches(String pattern, String path) {
            String[] want = pattern.split("/", -1);
            String[] got = path.split("/", -1);
            if (want.length != got.length) {
                return false;
            }
            for (int i = 0; i < want.length; i++) {
                boolean variable = want[i].startsWith("{") && want[i].endsWith("}");
                if (variable ? got[i].isEmpty() : !want[i].equals(got[i])) {
                    return false;
                }
            }
            return true;
        }
    }
}
