package app.sprout.gateway;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.MalformedURLException;
import java.net.URI;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Verifies access tokens locally with identity's published keys (JWKS), so the gateway doesn't
 * call identity on every request. Keys are cached and refreshed when an unknown key id appears,
 * which is how key rotation works without downtime.
 */
@Component
public class TokenVerifier {

    public record Caller(String userId, String sessionId) {}

    private final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();

    public TokenVerifier(GatewayProperties props) throws MalformedURLException {
        JWKSource<SecurityContext> keys = JWKSourceBuilder.create(URI.create(props.jwksUrl()).toURL())
                .retrying(true)
                .build();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keys));
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                props.audience(),
                new JWTClaimsSet.Builder().issuer(props.issuer()).build(),
                Set.of("sub", "sid", "exp", "iat")));
    }

    /** The caller, or empty if the token is missing, malformed, forged, expired or for someone else. */
    public Optional<Caller> verify(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return Optional.empty();
        }
        try {
            JWTClaimsSet claims = processor.process(authorizationHeader.substring(7).trim(), null);
            return Optional.of(new Caller(claims.getSubject(), claims.getStringClaim("sid")));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
