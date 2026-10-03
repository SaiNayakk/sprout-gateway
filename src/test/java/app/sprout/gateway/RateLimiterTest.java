package app.sprout.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class RateLimiterTest {

    final AtomicLong nanos = new AtomicLong();
    final RateLimiter limiter = new RateLimiter(nanos::get);

    @Test
    void allowsABurstUpToTheLimitThenAsksToWait() {
        for (int i = 0; i < 10; i++) {
            assertThat(limiter.tryAcquire("1.2.3.4|auth", 10)).isZero();
        }
        assertThat(limiter.tryAcquire("1.2.3.4|auth", 10)).isEqualTo(6); // one token per 6 s
    }

    @Test
    void refillsOverTime() {
        for (int i = 0; i < 10; i++) {
            limiter.tryAcquire("k", 10);
        }
        assertThat(limiter.tryAcquire("k", 10)).isPositive();
        nanos.addAndGet(6_000_000_000L);
        assertThat(limiter.tryAcquire("k", 10)).isZero();
        assertThat(limiter.tryAcquire("k", 10)).isPositive();
    }

    @Test
    void keysAreIndependent() {
        for (int i = 0; i < 10; i++) {
            limiter.tryAcquire("a", 10);
        }
        assertThat(limiter.tryAcquire("a", 10)).isPositive();
        assertThat(limiter.tryAcquire("b", 10)).isZero();
    }

    @Test
    void neverHoldsMoreThanOneMinutesWorth() {
        limiter.tryAcquire("k", 10);
        nanos.addAndGet(3_600_000_000_000L); // an hour idle
        int allowed = 0;
        while (limiter.tryAcquire("k", 10) == 0) {
            allowed++;
        }
        assertThat(allowed).isEqualTo(10);
    }
}
