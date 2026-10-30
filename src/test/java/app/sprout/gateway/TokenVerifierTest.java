package app.sprout.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Fetching identity's keys never decides whether a customer is signed in. */
class TokenVerifierTest {

    static final RSAKey KEY = GatewayTest.rsa();
    static final RSAKey OTHER_KEY = GatewayTest.rsa();

    final AtomicLong delayMs = new AtomicLong();
    final AtomicInteger status = new AtomicInteger(200);
    final AtomicInteger fetches = new AtomicInteger();
    final HttpServer identity = identity();

    @AfterEach
    void stop() {
        identity.stop(0);
    }

    @Test
    void aSlowIdentityStillHasItsTokensAccepted() throws Exception {
        delayMs.set(1_200);   // the library's default gave identity 500 ms, then refused every token for 30 s
        TokenVerifier tokens = verifier();
        String user = UUID.randomUUID().toString();
        assertThat(tokens.verify("Bearer " + GatewayTest.token(KEY, user, "sprout", Instant.now().plusSeconds(600))))
                .hasValueSatisfying(c -> assertThat(c.userId()).isEqualTo(user));
    }

    @Test
    void whenTheKeysCantBeFetchedATokenIsNeitherAcceptedNorRefused() throws Exception {
        status.set(503);
        TokenVerifier tokens = verifier();
        String good = "Bearer " + GatewayTest.token(KEY, UUID.randomUUID().toString(), "sprout", Instant.now().plusSeconds(600));
        assertThatThrownBy(() -> tokens.verify(good)).isInstanceOf(TokenVerifier.KeysUnavailable.class);
    }

    @Test
    void keysAlreadyFetchedKeepWorkingWhileIdentityIsAway() throws Exception {
        TokenVerifier tokens = verifier();
        String good = "Bearer " + GatewayTest.token(KEY, UUID.randomUUID().toString(), "sprout", Instant.now().plusSeconds(600));
        assertThat(tokens.verify(good)).isPresent();
        status.set(503);
        assertThat(tokens.verify(good)).isPresent();
    }

    @Test
    void tokensSignedByAKeyThatIsntOursAreRefusedNotRetried() throws Exception {
        TokenVerifier tokens = verifier();
        String forged = "Bearer " + GatewayTest.token(OTHER_KEY, UUID.randomUUID().toString(), "sprout", Instant.now().plusSeconds(600));
        for (int i = 0; i < 5; i++) {
            assertThat(tokens.verify(forged)).isEmpty();   // never "unavailable", however often an unknown key id asks for a refetch
        }
        assertThat(fetches.get()).isLessThanOrEqualTo(3);
    }

    TokenVerifier verifier() throws Exception {
        String url = "http://127.0.0.1:" + identity.getAddress().getPort() + "/.well-known/jwks.json";
        return new TokenVerifier(new GatewayProperties("sprout-identity", "sprout", url, null, null, 0, false, null, null, null, null));
    }

    HttpServer identity() {
        try {
            HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            s.createContext("/.well-known/jwks.json", ex -> {
                fetches.incrementAndGet();
                try {
                    Thread.sleep(delayMs.get());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                byte[] body = status.get() == 200
                        ? new JWKSet(KEY.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8)
                        : "{}".getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().add("Content-Type", "application/json");
                ex.sendResponseHeaders(status.get(), body.length);
                ex.getResponseBody().write(body);
                ex.close();
            });
            s.start();
            return s;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
