package app.sprout.gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
public class GatewayBeans {

    @Bean
    RateLimiter rateLimiter() {
        return new RateLimiter();
    }
}
