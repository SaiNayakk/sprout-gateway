package app.sprout.gateway;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Token buckets per key (client address + limit class). A bucket holds up to {@code perMinute}
 * tokens and refills continuously, so bursts are allowed but the average rate is capped.
 */
public class RateLimiter {

    private static final long IDLE_NANOS = 10L * 60 * 1_000_000_000L;
    private static final int SWEEP_ABOVE = 10_000;

    private final LongSupplier nanoTime;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimiter() {
        this(System::nanoTime);
    }

    RateLimiter(LongSupplier nanoTime) {
        this.nanoTime = nanoTime;
    }

    /** 0 if the request may proceed, otherwise the seconds to wait before retrying. */
    public long tryAcquire(String key, int perMinute) {
        long now = nanoTime.getAsLong();
        if (buckets.size() > SWEEP_ABOVE) {
            buckets.values().removeIf(b -> now - b.lastNanos > IDLE_NANOS);
        }
        Bucket bucket = buckets.computeIfAbsent(key, k -> new Bucket(perMinute, now));
        synchronized (bucket) {
            double perNano = perMinute / 60e9;
            bucket.tokens = Math.min(perMinute, bucket.tokens + (now - bucket.lastNanos) * perNano);
            bucket.lastNanos = now;
            if (bucket.tokens >= 1) {
                bucket.tokens -= 1;
                return 0;
            }
            return Math.max(1, (long) Math.ceil((1 - bucket.tokens) / perNano / 1e9));
        }
    }

    int trackedKeys() {
        return buckets.size();
    }

    private static final class Bucket {
        double tokens;
        long lastNanos;

        Bucket(int capacity, long now) {
            this.tokens = capacity;
            this.lastNanos = now;
        }
    }
}
