# sprout-gateway

The single entry point for **Sprout**, a simulated end-to-end brokerage. Every client request comes through here; no service is reachable from outside on its own. Architecture, environments and test evidence live in [sprout-platform](https://github.com/SaiNayakk/sprout-platform).

## What it does, in order

1. **Request id.** Assigns an `X-Request-Id` (or keeps a well-formed one from the client), puts it on every log line and passes it to the service, so one request can be followed everywhere.
2. **Route.** `/api/<service>/...` goes to the owning service with the prefix removed. The longest prefix wins. Paths with `..`, `//` or encoded slashes and dots are refused.
3. **Rate limit.** Token buckets per client address. Sign-in, sign-up, two-factor and refresh share a strict limit (10 a minute) to slow password guessing; everything else gets 120 a minute. Over the limit: `429` with `Retry-After`.
4. **Token check.** Verifies RS256 access tokens locally against identity's published keys (cached; refetched when a new key id appears, so keys can rotate without downtime). Checks issuer, audience and expiry. Only endpoints listed as public skip this.
5. **Header hygiene.** Drops headers a client must never set (`X-User-Id`, `X-Session-Id`, `X-Forwarded-*`, `Forwarded`), then sets the real caller and client address itself. Services can trust these headers because only the gateway can reach them.
6. **Forward** with a 2 s connect and 5 s total timeout, through a **circuit breaker** per service: when half of the last 20 calls fail, it stops calling for 10 s and answers `503` immediately instead of piling up waiting requests.
7. **Security headers** on every response: `nosniff`, `no-referrer`, `DENY` framing, `no-store` on the API.

### Streams

Endpoints a route lists under `streams` (live prices) are Server-Sent Events. The gateway checks the token as usual, then relays the service's events as they arrive, for as long as both ends stay connected:

- relayed chunk by chunk on a virtual thread, so an open stream holds no request thread and nothing is buffered;
- **capped**: 5 open streams per client (`429` beyond that) and 500 in total (`503`), because each holds a connection to the service;
- when the client leaves, the gateway closes its connection to the service too, so the service stops sending at once;
- if the service refuses (unknown symbol, bad request), its problem response is passed on unchanged.

Errors are RFC 9457 problem details with the same stable codes the services use (`UNAUTHENTICATED`, `RATE_LIMITED`, `UPSTREAM_UNAVAILABLE`, `NOT_FOUND`).

| Upstream failure | Answer |
|---|---|
| Can't connect | `503`, `Retry-After: 5` |
| Took over 5 s | `504`. The action may still have happened, so clients check before retrying |
| Circuit open | `503`, `Retry-After: 10`, without calling the service |

## Configuration

Routes live in `gateway.yml`:

```yaml
sprout:
  gateway:
    routes:
      - name: identity
        prefix: /api/identity
        target: http://127.0.0.1:8101
        public: [POST /v1/users, POST /v1/sessions, ...]
        auth-limited: [POST /v1/sessions, ...]
      - name: marketdata
        prefix: /api/marketdata
        target: http://127.0.0.1:8103
        public: [GET /v1/market, GET /v1/instruments, GET /v1/instruments/{symbol}]
        streams: [GET /v1/stream]
```

A path segment written `{name}` matches exactly one segment: `GET /v1/instruments/{symbol}` matches `/v1/instruments/HARBOR` but not `/v1/instruments/HARBOR/history`.

| Variable | Default | Meaning |
|---|---|---|
| `GATEWAY_PORT` / `GATEWAY_BIND` | `8100` / `0.0.0.0` | Public listen address |
| `GATEWAY_MANAGEMENT_PORT` | `8190` (localhost only) | Health and metrics, never public |
| `GATEWAY_JWKS_URL` | identity's `/.well-known/jwks.json` | Where verification keys come from |
| `GATEWAY_IDENTITY_URL` | `http://127.0.0.1:8101` | The identity service |
| `GATEWAY_MARKETDATA_URL` | `http://127.0.0.1:8103` | The market-data service |
| `GATEWAY_TRUST_CF_IP` | `false` | Use `CF-Connecting-IP` as the client address (only behind Cloudflare) |

In production it runs in the **edge host** JVM together with identity (see sprout-platform).

## Tests

`mvn verify` runs the gateway against a stub service that serves keys, echoes requests, and has deliberately slow and failing endpoints. It covers:

- public and protected routes
- expired, wrong-audience, forged and unsigned (`alg: none`) tokens
- spoofed identity headers being dropped
- request ids
- security headers
- an unreachable service, a timeout, and the circuit breaker opening and failing fast without calling the service
- path traversal, oversized bodies, and the sign-in rate limit
- streams: events arriving live rather than at the end, the per-client and total caps, slots and service connections released when a client leaves, and path patterns matching exactly one segment

## License

MIT
