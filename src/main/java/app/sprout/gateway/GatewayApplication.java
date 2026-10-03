package app.sprout.gateway;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * The single entry point for clients. Verifies access tokens, limits request rates, routes to the
 * owning service and stamps every request with an id. Reads {@code gateway.yml}.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class GatewayApplication {

    public static final String CONFIG_NAME = "gateway";

    public static void main(String[] args) {
        builder().run(args);
    }

    public static SpringApplicationBuilder builder() {
        return new SpringApplicationBuilder(GatewayApplication.class)
                .properties("spring.config.name=" + CONFIG_NAME);
    }
}
