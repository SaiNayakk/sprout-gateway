package app.sprout.gateway;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.RateLimitReachedException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.MalformedURLException;
import java.net.URI;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Verifies access tokens locally with identity's published keys (JWKS), so the gateway doesn't
 * call identity on every request. Keys are cached and refreshed when an unknown key id appears,
 * which is how key rotation works without downtime.
 *
 * <p>Fetching the keys must not decide whether a customer is signed in. The library's defaults give
 * identity 500 ms to answer and then refuse to ask again for 30 s; a busy identity therefore made
 * every token look invalid for up to half a minute, and customers were told to sign in again
 * (seen in the deployment shapes experiment). So the keys are fetched with patient timeouts, refreshed
 * in the background before they expire, kept when identity can't be reached, and a token that can't
 * be checked at all is {@link KeysUnavailable}, not invalid.
 */
@Component
public class TokenVerifier {

    private static final Logger log = LoggerFactory.getLogger(TokenVerifier.class);
    private static final int FETCH_TIMEOUT_MS = 3_000;

    public record Caller(String userId, String sessionId) {}

    /** Identity's keys couldn't be fetched and none are cached: the token was neither accepted nor refused. */
    public static final class KeysUnavailable extends RuntimeException {
        KeysUnavailable(Throwable cause) {
            super("identity's signing keys are unavailable", cause);
        }
    }

    private final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();

    public TokenVerifier(GatewayProperties props) throws MalformedURLException {
        JWKSource<SecurityContext> keys = JWKSourceBuilder.create(URI.create(props.jwksUrl()).toURL(),
                        new DefaultResourceRetriever(FETCH_TIMEOUT_MS, FETCH_TIMEOUT_MS, JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT))
                .cache(TimeUnit.MINUTES.toMillis(5), FETCH_TIMEOUT_MS * 2L)
                .refreshAheadCache(TimeUnit.SECONDS.toMillis(60), true)   // refreshed in the background, before they expire
                .outageTolerant(TimeUnit.HOURS.toMillis(1))               // the last keys stay good while identity is away
                .retrying(true)
                .build();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keys));
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                props.audience(),
                new JWTClaimsSet.Builder().issuer(props.issuer()).build(),
                Set.of("sub", "sid", "exp", "iat")));
    }

    /**
     * The caller, or empty if the token is missing, malformed, forged, expired or for someone else.
     *
     * @throws KeysUnavailable if identity's keys can't be had, so the token can't be checked either way
     */
    public Optional<Caller> verify(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return Optional.empty();
        }
        try {
            JWTClaimsSet claims = processor.process(authorizationHeader.substring(7).trim(), null);
            return Optional.of(new Caller(claims.getSubject(), claims.getStringClaim("sid")));
        } catch (RateLimitReachedException e) {
            // an unknown key id asked for a refetch too soon after the last one: a token signed by no key of ours
            return Optional.empty();
        } catch (KeySourceException e) {
            log.warn("Couldn't fetch identity's signing keys: {}", e.toString());
            throw new KeysUnavailable(e);
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
