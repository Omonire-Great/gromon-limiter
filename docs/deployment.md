# Deployment

## Choosing a storage backend

| Deployment | Backend | Why |
| --- | --- | --- |
| One process, one worker, dev/tests | `memory` | no dependencies, no network hop |
| Gunicorn/uWSGI with N workers | `redis` | otherwise each worker enforces `limit x N` |
| Several services or hosts | `redis` | one shared budget |
| Serverless (per-container memory) | `redis` | containers are recreated constantly |
| Kubernetes replicas | `redis` | same, plus a real cluster behind it |

Memory storage is not a scaled-down Redis; it is a different guarantee. With
four workers and `limit="5/minute"`, a naive deployment lets an attacker make
20 attempts a minute. If you run more than one process, use Redis.

## Environment

```console
export OMONIRE_LIMITER_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export REDIS_URL="rediss://user:password@redis.internal:6379/0"
```

- `OMONIRE_LIMITER_SECRET` must be **identical on every instance** of the
  application. A different salt per instance means a different key space per
  instance, which silently disables shared limiting.
- Generate it once and store it in a secret manager. Rotating it resets all
  counters.
- `REDIS_URL` belongs in the environment or a secret manager, never in source.
  Use `rediss://` whenever the network is not private.

## Minimal production setup

```python
import os
from flask import Flask
from omonire_limiter import AuthLimiter

app = Flask(__name__)

limiter = AuthLimiter(
    app,
    limit="5/minute",
    storage="redis",                          # shared state
    identifier=("ip", "account"),
    account_limit_multiplier=3,
    cooldown=300,
    trusted_proxies=os.environ["TRUSTED_PROXIES"].split(","),   # your LB only
    fail_open=False,                          # auth must fail closed
    namespace="auth",                         # distinct from other limiters
)

@app.post("/login")
@limiter.limit("5/minute")
def login():
    ...
```

## Behind a reverse proxy

The limiter trusts `X-Forwarded-For` only from `trusted_proxies`. Two
conditions must both hold:

1. The proxy appends the real client address to `X-Forwarded-For` (nginx
   `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`).
2. The application is reachable **only** through that proxy. If the app is also
   exposed directly, a direct client can set the header itself.

Verify from inside the container:

```console
$ curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:5000/login \
    -H 'X-Forwarded-For: 9.9.9.9' -d 'email=a@b.com&password=x'
```

If requests from one real user ever produce different `429`s depending on their
IP, the proxy list is wrong. If every user shares one budget, the list is missing
the proxy.

## Reverse proxy (nginx)

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

location = /login {
    limit_req zone=login burst=5 nodelay;
    proxy_pass http://app;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Layering is deliberate: the proxy sheds gross floods cheaply, and the
application limiter enforces the policy that depends on *both* IP and account.
The proxy alone cannot stop password spraying; the application limiter alone
cannot absorb a volumetric flood.

Do not let the proxy cache or retry 429 responses, and make sure it passes
`Retry-After` through untouched.

## Health and failure behaviour

`fail_open=False` (the default) means a Redis outage returns 429 on auth
endpoints. Consequences to plan for:

- Clients see "try again shortly" instead of a 500, so they retry rather than
  reporting a broken service.
- Alert on any 429 with `rule="storage"`; that is the signal that the limiter
  itself is degraded.
- Size the Redis connection pool for your worker count:
  `socket_connect_timeout=2`, `socket_timeout=2` so a hung connection fails fast
  instead of tying up a worker.
- For endpoints where an outage is worse than an unmetered request, use a
  separate limiter instance with `fail_open=True` and a different `namespace`.

```python
AuthLimiter(
    app,
    limit="60/minute",
    identifier=("ip",),
    fail_open=True,
    namespace="api",
)
```

## Observability

The package logs to the `omonire_limiter` logger and only emits operational
metadata: namespace, rule name, fail-open/fail-closed transitions. No
identifiers, no bodies, no secrets. Everything else is exposed on the response,
so metrics can be derived from it:

- 429 rate per route (from access logs)
- `X-RateLimit-Remaining` distribution (a client never getting near zero is
  suspicious; a client always at zero is a misconfigured client)
- share of 429s with `X-RateLimit-Policy: cooldown:*` (attacks versus noise)
- count of `rule="storage"` responses (limiter degraded)

Worth alerting on: a sudden 429 spike, any sustained `rule="storage"`, and Redis
memory growth (sliding-window logs hold one entry per hit per window).

## Sizing

- Storage keys per active rule: one counter (or one log) plus one cooldown
  marker. A 5/minute sliding window over one hour keeps ~300 entries per active
  rule.
- `MemoryStorage(max_keys=100_000)` bounds a single process. Below that it drops
  expired keys; above it, the oldest half. Watch for a steady climb to the
  ceiling, which means the identifier space is larger than expected (for example
  a proxy pool that is not listed in `trusted_proxies`, so every request looks
  like a new client).
- `sliding_window` costs one `ZADD` + `ZCOUNT` per rule per request;
  `fixed_window` costs one `INCR`. On a busy endpoint, that difference is real
  but rarely the bottleneck — Redis round trips and the request itself dominate.

## Checklist

- [ ] `OMONIRE_LIMITER_SECRET` set from a secret manager, identical everywhere
- [ ] `storage="redis"` with more than one worker or replica
- [ ] TLS to Redis, credentials from the environment
- [ ] `trusted_proxies` lists exactly the proxies in front of the app
- [ ] App not directly reachable from the internet
- [ ] `fail_open` decided per endpoint; `False` for authentication
- [ ] `limiter.reset(...)` on successful authentication
- [ ] Alerts on 429 spikes and on `rule="storage"`
- [ ] `Retry-After` passed through by the proxy, 429s not cached or retried
- [ ] Layer proxy-level `limit_req` in front of the application limiter

## Upgrading

1. Read the release notes; this project follows the milestone roadmap in
   [roadmap.md](roadmap.md).
2. `V1.x` changes are additive: new optional settings, new algorithms. Existing
   constructor calls keep working.
3. Changing `OMONIRE_LIMITER_SECRET`, `namespace` or `algorithm` changes storage
   keys and therefore resets counters for the affected keys. Do it deliberately,
   during a quiet period, and expect a one-off burst of effectively unthrottled
   attempts.
