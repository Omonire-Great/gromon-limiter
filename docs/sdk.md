# SDK guide

In V1 the "SDK" is the Python package itself. The hosted Gromon backend client
(`GromonClient`) arrives in V3; see [roadmap.md](roadmap.md). Nothing in this
document requires an account or a network call — the library is fully usable on
its own, which is the point of splitting the SDK from the service.

## Install

```console
pip install gromon-limiter
pip install gromon-limiter[flask]   # Flask integration
pip install gromon-limiter[redis]   # Redis storage
```

Python 3.10+. The core has no runtime dependencies.

## Three integration levels

### 1. Decorator (Flask)

The shortest path. The limiter runs before the view, so a blocked request never
reaches the password check.

```python
from gromon_limiter import AuthLimiter

limiter = AuthLimiter(app, limit="10/minute", storage="redis")

@app.post("/login")
@limiter.limit("5/minute")
def login(): ...
```

### 2. Imperative check

Useful for endpoints that are not simple views, for background jobs, or for
applying the same policy in a non-HTTP code path.

```python
from gromon_limiter import Identity
from gromon_limiter.flask import current_limiter, current_decision

limiter = current_limiter()
identity = Identity(ip=resolve_client_ip(request), account=payload["email"])

if not limiter.check(identity, path="/login", method="POST").allowed:
    return jsonify(error="rate_limit_exceeded"), 429
```

`current_decision()` returns the `Decision` recorded for the current request when
the decorator already ran, so an audit log can include `rule` and `remaining`
without re-deriving them.

### 3. The engine directly

No Flask at all — for CLI tools, workers, or a future framework adapter.

```python
from gromon_limiter import LimiterCore, MemoryStorage, Identity
from gromon_limiter.config import Settings, resolve_key_salt

core = LimiterCore(
    Settings(
        key_salt=resolve_key_salt(None, storage_name="memory"),
        default_limit="5/minute",
    ),
    MemoryStorage(),
)

decision = core.check(Identity(ip="1.2.3.4"), path="/login", method="POST")
if not decision.allowed:
    raise RuntimeError(f"retry in {decision.retry_after}s")
```

## Reusable engine instance

Build the engine once and share it. Construction validates configuration and
compiles the proxy list, so doing it per request wastes work:

```python
# limits.py
from gromon_limiter import LimiterCore, MemoryStorage
from gromon_limiter.config import Settings, resolve_key_salt

core = LimiterCore(
    Settings(key_salt=resolve_key_salt(None, storage_name="memory"), default_limit="5/minute"),
    MemoryStorage(),
)
```

```python
# views.py
from limits import core
from gromon_limiter import Identity

def guard(request) -> None:
    if not core.check(Identity(ip=request.remote_addr), path=request.path, method=request.method).allowed:
        abort(429)
```

## Adapting another framework

Three small pieces, all of them thin:

1. **Resolve the identity** into `Identity(ip=..., account=...)`. Use
   `gromon_limiter.identifiers.client_ip` so proxy handling stays correct.
2. **Call `core.check(...)`** with the request's path and method.
3. **Render the outcome**: return your framework's 429 response with
   `build_body(decision)` and `build_headers(decision)`.

```python
from gromon_limiter import build_body, build_headers

if not decision.allowed:
    return JsonResponse(
        build_body(decision),
        status=429,
        headers=build_headers(decision),
    )
```

Nothing else in the package needs to know which framework is in use.

## Writing a storage backend

Implement six methods (see [architecture.md](architecture.md#storage-contract)).
`increment` and `log_add` must be atomic per caller; everything else is a plain
read or write.

```python
from gromon_limiter.storage.base import CounterState, Storage

class MyStorage(Storage):
    name = "mine"
    shared = True

    def increment(self, key, *, amount=1, window_seconds): ...
    def current(self, key): ...
    def clear(self, key): ...
    def log_add(self, key, *, member, timestamp, window_seconds): ...
    def log_count(self, key, *, since, until): ...
    def mark(self, key, *, ttl_seconds, now): ...
    def marked_until(self, key, *, now): ...
    def clear_prefix(self, prefix): ...
```

Backends with `shared = True` are required by `resolve_key_salt` to have an
explicit `GROMON_LIMITER_SECRET`, since per-process salts would break them.

Pass an instance straight through:

```python
AuthLimiter(app, storage=MyStorage(...), key_salt=os.environ["GROMON_LIMITER_SECRET"])
```

## Writing an algorithm

```python
from gromon_limiter.algorithms import ALGORITHMS, get_algorithm, storage_key_for
from gromon_limiter.errors import ConfigurationError

class TokenBucket:
    name = "token_bucket"

    def check(self, storage, *, key, limit, now):
        state = storage.increment(key, window_seconds=limit.window_seconds)
        return state.value, state.reset_at

    def reset(self, storage, *, key):
        storage.clear(key)

ALGORITHMS[TokenBucket.name] = TokenBucket()
```

Then add `"token_bucket"` to `ALGORITHM_NAMES` in `gromon_limiter/config.py` so
configuration validation accepts it, and use
`@limiter.limit(..., algorithm="token_bucket")`.

`check` must record the hit and return `(count, next_available_at)`, where
`count` includes the hit just recorded and `next_available_at` is an absolute
unix timestamp or `None`.

## Testing against the limiter

`LimiterCore` accepts an injectable clock, so time-dependent behaviour can be
tested without sleeping:

```python
from gromon_limiter import LimiterCore, MemoryStorage, Identity
from gromon_limiter.config import Settings

now = [1_700_000_000.0]
core = LimiterCore(
    Settings(key_salt="test-salt-not-for-production", default_limit="1/minute"),
    MemoryStorage(clock=lambda: now[0]),
    clock=lambda: now[0],
)

identity = Identity(ip="1.2.3.4")
assert core.check(identity, path="/login", method="POST").allowed
assert not core.check(identity, path="/login", method="POST").allowed
now[0] += 61
assert core.check(identity, path="/login", method="POST").allowed
```

For a full suite, copy the pattern in `tests/conftest.py`: a `FakeClock`, a
`make_settings` factory and a `make_core` factory, so each test gets a fresh
engine and never leaks state.

## Using the same policy from another service

V1 has no hosted service, so there is no cross-service SDK. Until V3, two
services can only share a budget by sharing the Redis database and the key
salt — the same requirements as two instances of one application. That is enough
for a monolith split into an API and a worker; anything wider needs the V3
control plane.

## Versioning

`1.0.x` is the current line; `0.1.x` was V1 under the retired `g3-limiter`
name. Public names in `gromon_limiter.__all__` are stable within a milestone, and
the installed version is readable as `gromon_limiter.__version__`. Settings are
keyword-only and additive: new options appear with defaults that preserve current
behaviour.
