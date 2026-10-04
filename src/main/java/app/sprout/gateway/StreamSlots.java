package app.sprout.gateway;

import io.micrometer.core.instrument.MeterRegistry;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Counts open streams per client and in total. A stream holds a connection to a service for as long
 * as the client keeps it open, so both are capped: one client can't hold hundreds, and the gateway
 * never holds more than the services behind it can serve.
 */
final class StreamSlots {

    enum Result { OPENED, CLIENT_FULL, GATEWAY_FULL }

    private final int perClient;
    private final int total;
    private final Map<String, AtomicInteger> byClient = new ConcurrentHashMap<>();
    private final AtomicInteger open = new AtomicInteger();

    StreamSlots(int perClient, int total, MeterRegistry meters) {
        this.perClient = perClient;
        this.total = total;
        meters.gauge("gateway.streams.open", open);
    }

    synchronized Result tryOpen(String client) {
        if (open.get() >= total) {
            return Result.GATEWAY_FULL;
        }
        AtomicInteger mine = byClient.computeIfAbsent(client, k -> new AtomicInteger());
        if (mine.get() >= perClient) {
            return Result.CLIENT_FULL;
        }
        mine.incrementAndGet();
        open.incrementAndGet();
        return Result.OPENED;
    }

    synchronized void close(String client) {
        AtomicInteger mine = byClient.get(client);
        if (mine != null && mine.decrementAndGet() <= 0) {
            byClient.remove(client);
        }
        open.decrementAndGet();
    }

    int open() {
        return open.get();
    }
}
