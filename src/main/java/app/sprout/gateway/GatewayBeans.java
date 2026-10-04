package app.sprout.gateway;

import io.micrometer.observation.ObservationPredicate;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Locale;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.observation.ServerRequestObservationContext;

@Configuration(proxyBeanMethods = false)
public class GatewayBeans {

    @Bean
    RateLimiter rateLimiter() {
        return new RateLimiter();
    }

    /**
     * Leaves price streams out of the request metrics. A stream is one request that stays open for
     * minutes, so counting it as a request would push every latency percentile to the length of the
     * longest stream (seen in pre-prod as a p50 of 30 s). Streams have their own gateway.streams.*
     * metrics instead.
     */
    @Bean
    ObservationPredicate streamsAreNotRequests(GatewayProperties props) {
        return (name, context) -> {
            if (!(context instanceof ServerRequestObservationContext server) || server.getCarrier() == null) {
                return true;
            }
            HttpServletRequest req = server.getCarrier();
            String uri = req.getRequestURI();
            String method = req.getMethod().toUpperCase(Locale.ROOT);
            for (GatewayProperties.Route route : props.routes()) {
                if (uri.startsWith(route.prefix() + "/") && route.isStream(method, uri.substring(route.prefix().length()))) {
                    return false;
                }
            }
            return true;
        };
    }
}
