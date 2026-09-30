# Architecture

`omonire-limiter` is built as five layers. Each one only knows about the layer
below it, which is what keeps the SDK usable on its own and makes a future
framework adapter a small file instead of a rewrite.

```
   application
        |  @limiter.limit("5/minute")
        v
+-----------------------------------+
| omonire_limiter.flask               |  identity extraction, 429 rendering,
| omonire_limiter.decorators          |  response headers
+-----------------+-----------------+
                  |  Decision
                  v
+-----------------------------------+
| omonire_limiter.core.LimiterCore    |  rules, cooldowns, scoping,
|                                   |  fail-open / fail-closed
+---------+-------------+-----------+
          |             |
          v             v
+-----------------+  +---------------------+
| algorithms      |  | identifiers          |  IP normalisation,
| fixed_window    |  | Identity, client_ip, |  trusted proxies,
| sliding_window  |  | HMAC fingerprints    |  account normalisation
+--------+--------+  +---------------------+
         |  (Storage contract: increment / log_add / log_count / mark)
         v
+-----------------------------------+
| storage                           |  MemoryStorage (threads) |
|                                   |  RedisStorage  (Lua,     |
|                                   |   many processes)        |
+-----------------------------------+
```

## Why this shape

- **The core does not import Flask.** `omonire_limiter.core` knows about limits,
  identities, algorithms and storage, and nothing about HTTP. A Django, FastAPI
  or ASGI adapter is a request-parsing and response-rendering concern only.
- **The core has no required dependencies.** `pip install omonire-limiter` pulls
  nothing in. Flask and redis-py are optional extras, imported lazily inside
  the functions that need them, so an application without Redis never imports
  `redis`.
- **Algorithms talk to storage through four atomic primitives.** Anything that
  can implement `increment`, `log_add`, `log_count` and `mark` can back the
  engine. That is why a third backend (DynamoDB, memcached, SQL) is a single
  class, not a change to the engine.
- **Everything that changes behaviour is a `Settings` field.** No globals, no
  module-level state (the only exception is the algorithm registry, which is
  immutable in practice), so two limiters with different policies can coexist in
  one process and tests never leak configuration into each other.

## Request flow

`LimiterCore._evaluate` is the whole decision procedure, and it is deliberately
short:

1. **Cooldown pass.** For every rule whose identity material is present, ask
   storage whether a cooldown marker is active. If one is, return a blocked
   `Decision` immediately — *without* recording another hit.
2. **Counting pass.** For every applicable rule, record the hit and compare
   against that rule's limit.
3. **First breach wins.** The rule that goes over its limit arms its own
   cooldown and the request is blocked. Rules evaluated after it are left
   untouched, so a blocked request never inflates an unrelated budget.
4. **Otherwise** report the tightest rule (the one with the least headroom), so
   `X-RateLimit-Remaining` describes the limit the caller will hit first.

Two details in that flow are load-bearing:

- **A blocked request must not extend its own cooldown.** Charging hits during a
  cooldown would mean a client that keeps retrying is punished forever, and it
  turns "wait 60 seconds" into "stop trying for 60 seconds".
- **Only the breached rule is armed.** An IP breach should not start a cooldown
  against the account, otherwise a botnet could deliberately trigger the
  account cooldown to lock a real user out — the denial-of-service the whole
  two-budget design exists to prevent.

## Identities and keys

A rule is a triple of (identifier, scope, limit). The storage key is:

```
omonire_limiter:<namespace>:<algorithm>:<scope>:<hmac>
```

- `namespace` isolates one limiter from another, so several limiters (or
  several environments) can share one Redis database.
- `algorithm` keeps `fixed_window` and `sliding_window` data apart; switching
  algorithms mid-flight cannot corrupt the other one's keys.
- `scope` is `METHOD /path` by default, so `/login` and `/recover` never share a
  budget. `scope="global"` gives one budget for the whole application.
- `hmac` is a truncated HMAC-SHA256 over the identity material and a secret salt.
  The address, account or document number is not in the key, not in the logs and
  not in the response. See [security.md](security.md).

The prefix is composed by `storage_key_for` (see
`omonire_limiter/algorithms/__init__.py`) and prefixed again by the storage
backend's own `prefix`, which exists so one Redis database can host unrelated
installations of unrelated applications.

## Algorithms

| | `fixed_window` | `sliding_window` (default) |
| --- | --- | --- |
| Data structure | one counter with a TTL | sorted set (Redis) / list (memory) of hit timestamps |
| Storage ops per request | 1 `INCR` | 1 `ZADD` + `ZCOUNT` inside one Lua script |
| Worst-case burst at the boundary | up to `2 x limit` in one second | bounded by `limit` |
| `Retry-After` accuracy | window end (can be pessimistic) | exact: when the oldest hit leaves the window |
| Cost | cheapest | one extra key per rule |

Both are implemented against the same `Algorithm` protocol, and `get_algorithm`
resolves names through a small registry, so a third algorithm is a class plus
one registry entry. The per-route override (`@limiter.limit(..., algorithm=...)`)
exists because the right choice is per endpoint: a cheap, low-stakes endpoint
rarely needs the accuracy, an expensive or abusable one usually does.

Sliding-window members must be unique: the log is a Redis sorted set, and two
entries with the same score *and* member collapse into one, silently letting a
request through. Timestamps alone are not unique (concurrent requests do land in
the same microsecond), so each member is `timestamp-random-prefix-counter`.

## Storage contract

`Storage` (see `omonire_limiter/storage/base.py`) is six methods:

| Method | Contract |
| --- | --- |
| `increment(key, amount, window_seconds)` | Atomic add; expiry set on creation only (that is what makes a fixed window fixed) |
| `current(key)` | Read without mutating |
| `clear(key)` | Full delete — counter, log or marker, the caller cannot tell from the key |
| `log_add(key, member, timestamp, window_seconds)` | Atomic append + prune, returns `(count, oldest)` |
| `log_count(key, since, until)` | Count entries in a time range |
| `mark` / `marked_until` | Cooldown marker with an absolute expiry |
| `clear_prefix(prefix)` | Maintenance; must not use `KEYS` on Redis |

Implementations **must** be atomic per method. That single requirement is why
the Redis backend uses Lua: `INCR` followed by `EXPIRE`, or `ZREMRANGEBYSCORE`
followed by `ZCARD`, are read-modify-write sequences that interleave across web
workers and would lose hits.

`MemoryStorage` is a dict behind an `RLock` with a `max_keys` ceiling: expired
keys are dropped first, and if the store is still oversized the oldest half is
sacrificed. Deliberately trading a temporarily looser limit for not running out
of memory.

`RedisStorage` registers five scripts (`INCR`+`EXPIRE`, `GET`+`PTTL`, sliding
`ZADD`+prune+`ZCARD`, `ZCOUNT`, plain `GET`) and never uses `KEYS`; maintenance
is `SCAN` based. Cooldown markers store an *absolute* expiry as the value and a
relative TTL for Redis to expire on. The absolute value is what the engine
compares against its (injectable) clock; the TTL is only how Redis cleans up.
Without that split, a test with a fake clock and a real Redis would disagree
about whether a cooldown is active.

## Cooldowns

A cooldown is a marker key derived from the counter key
(`<counter>:cooldown`), set with the rule's TTL, and read before every count.
Deriving it from the counter key guarantees a marker and its counter can never
drift apart, and `reset()` can clear both together.

There is no permanent lock anywhere in this design. `cooldown=0` disables
cooldowns entirely; otherwise the marker expires on its own and the caller is
limited by the normal budget again.

## Failure behaviour

`fail_open` is an explicit setting with a secure default:

| | `fail_open=False` (default) | `fail_open=True` |
| --- | --- | --- |
| Storage unreachable | 429 with a clear message, `rule="storage"` | request allowed, warning logged |
| Suitable for | authentication endpoints | endpoints where an outage is worse than an unmetered request |

The core re-raises `StorageError` when failing closed; the Flask layer catches
it and renders a 429 rather than a 500, because "try again shortly" is a more
honest answer to a client than an unhandled error. Logs contain the namespace
and nothing else.

## Time

`LimiterCore(..., clock=...)` takes a callable returning a unix timestamp. Every
test injects `FakeClock` instead of sleeping, which is why the suite covers
window rollover, cooldown expiry and boundary behaviour deterministically and
in under a second.

## Extending

| Goal | Where it goes |
| --- | --- |
| New framework | new `omonire_limiter/<framework>.py` beside `flask.py`, reusing `LimiterCore` |
| New storage backend | subclass `Storage`, implement six methods |
| New algorithm | implement the `Algorithm` protocol, add to `ALGORITHMS` |
| Different key scheme | override `LimiterCore.rule_key` / `storage_key` |
| Central policy (V3) | a `Storage` whose backend is the Omonire backend service |
