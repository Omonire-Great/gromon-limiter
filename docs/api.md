# API reference (V1)

Everything public is importable from the package root:

```python
from great_limiter import (
    AuthLimiter,          # Flask limiter for authentication endpoints
    Limiter,              # V2 general-purpose alias (see roadmap)
    GreatShield,          # V3 stub: raises NotImplementedError
    LimiterCore,          # framework-agnostic engine
    Decision,             # the result of one evaluation
    RateLimit,            # an immutable "<amount> per <window>" value
    Identity,             # resolved identity of one request
    Storage, CounterState, MemoryStorage, RedisStorage,
    build_headers, build_payload, build_body,
    client_ip, TrustedProxies,
    GreatLimiterError, ConfigurationError, InvalidLimitError,
    RateLimitExceeded, StorageError,
)
```

---

## `AuthLimiter`

```python
AuthLimiter(app=None, **settings)      # AuthLimiter(app, limit="5/minute")
limiter = AuthLimiter(limit="5/minute") # deferred: bind later
limiter.init_app(app)
```

Keyword arguments are stored when `app` is omitted and applied by `init_app`, so
both forms are equivalent. The full keyword list is in
[configuration.md](configuration.md).

### Methods and properties

| Member | Returns | Notes |
| --- | --- | --- |
| `init_app(app=None, **settings)` | `AuthLimiter` | Idempotent for the same app; raises `ConfigurationError` if a *different* limiter is already registered |
| `core` | `LimiterCore` | Raises `RuntimeError` before initialisation |
| `core_or_none()` | `LimiterCore \| None` | Safe before initialisation |
| `settings` | `Settings` | |
| `storage` | `Storage` | |
| `limit(spec=None, **options)` | decorator | `@limiter.limit("5/minute")` |
| `check(**kwargs)` | `Decision` | Delegates to `LimiterCore.check` |
| `reset(**kwargs)` | `int` | Clears one identity's counters and cooldowns |
| `clear_all()` | `int` | Clears this namespace (tests, admin tooling) |

---

## `LimiterCore`

The engine, with no Flask dependency.

```python
LimiterCore(settings: Settings, storage: Storage, *, clock: Callable[[], float] | None = None)
```

### `check(identity, *, path="/", method="GET", limit=None, algorithm=None, enforce=False) -> Decision`

| Argument | Meaning |
| --- | --- |
| `identity` | `Identity(ip=..., account=..., extras={...})` |
| `path`, `method` | build the scope; distinct routes get distinct budgets |
| `limit` | `str` or `RateLimit`, overrides `settings.default_limit` |
| `algorithm` | overrides `settings.algorithm` |
| `enforce` | `True` raises `RateLimitExceeded` instead of returning a blocked `Decision` |

Raises `StorageError` when storage fails and `fail_open` is `False`.

### `check_or_raise(identity, **kwargs) -> Decision`

`check(..., enforce=True)`.

### `reset(identity, *, path="/", method="GET", algorithm=None) -> int`

Clears the counters and cooldown markers belonging to `identity`. Returns the
number of rules touched (normally the number of applicable identifiers).

### `clear_all() -> int`

Removes every key in this limiter's namespace. Other namespaces sharing the same
storage are untouched.

### Properties

`settings`, `storage`, `trusted_proxies`, plus `scope_for(path, method)` and
`rule_key(components, identity, suffix)` for tooling.

---

## `Decision`

Frozen result of one evaluation.

| Field | Type | Meaning |
| --- | --- | --- |
| `allowed` | `bool` | Whether the request may proceed |
| `blocked` | `bool` | `not allowed` |
| `limit` | `int \| None` | The limit of the decisive rule |
| `remaining` | `int \| None` | Requests left in the current window |
| `reset_at` | `float \| None` | Absolute unix timestamp when a slot frees up |
| `retry_after` | `float \| None` | Seconds to wait |
| `bucket` | `str \| None` | Fingerprint of the rule that decided (never the raw identifier) |
| `policy` | `str \| None` | `"5/60s"` or `"cooldown:60s"` |
| `message` | `str` | Human-readable reason |
| `rule` | `str \| None` | `"ip"`, `"account"`, `"storage"`, ... |

### Response helpers

```python
build_headers(decision) -> dict[str, str]
build_payload(decision) -> dict[str, Any]
build_body(decision) -> str            # compact JSON
```

Headers emitted:

```
X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset,
X-RateLimit-Policy, X-RateLimit-Bucket, Retry-After
```

Body on a 429:

```json
{
  "error": "rate_limit_exceeded",
  "message": "Too many attempts. Please wait before retrying.",
  "limit": 5,
  "remaining": 0,
  "reset_at": 1700000060,
  "retry_after": 60,
  "bucket": "6f1a2c9d4e5f60718293a4b5c6d7e8f9"
}
```

---

## `RateLimit`

```python
RateLimit(limit=5, window_seconds=60.0, raw="5/minute")
RateLimit.parse("100/5 minutes")
```

Immutable, hashable, validated on construction (`InvalidLimitError`). Properties:
`window` (seconds rounded up, used for TTLs), `raw` (the original text when
parsed from a string).

---

## `Identity` and IP resolution

```python
Identity(ip="1.2.3.4", account="v@example.com", extras={"api_key": "..."})
identity.get("api_key")                # extras lookup
identity.material_for(("ip", "account"))
```

```python
client_ip(remote_addr=..., forwarded_for=..., real_ip=..., trusted_proxies=TrustedProxies([...]))
TrustedProxies(["10.0.0.0/8"]).contains("10.1.2.3")   # True
normalize_ip("::ffff:127.0.0.1")                     # "127.0.0.1"
normalize_account(" V@Example.com ")                # "v@example.com"
fingerprint(salt, "default:ip", "ip=1.2.3.4")        # 32 hex chars
```

---

## `Settings`

Frozen, validated, constructible directly for non-Flask use.

```python
Settings(
    key_salt=...,
    namespace="auth",
    identifier=("ip", "account"),
    default_limit="10/minute",     # strings accepted
    algorithm="sliding_window",
    account_limit_multiplier=3.0,
    cooldown_seconds=60.0,
    account_cooldown_seconds=None,
    trusted_proxies=(),
    account_fields=DEFAULT_ACCOUNT_FIELDS,
    scope="endpoint",
    fail_open=False,
    enabled=True,
    skip_methods=("OPTIONS",),
    headers=True,
    status_code=429,
    extra_identifier_fields=frozenset(),
)
settings.with_overrides(default_limit="20/minute")   # copy with changes
```

Helpers: `resolve_key_salt(explicit, *, storage_name)` and
`normalise_proxies(entries)`.

---

## Storage

```python
storage = MemoryStorage(max_keys=100_000, clock=None)
storage = RedisStorage(url=..., client=..., prefix="great_limiter", **client_kwargs)
storage = build_storage("redis", url=..., client=...)
```

`Storage` contract: `increment`, `current`, `clear`, `log_add`, `log_count`,
`mark`, `marked_until`, `clear_prefix`, `close`. `increment` and `log_add` must be
atomic per caller.

`CounterState(value: int, reset_at: float | None)`.

`Storage` is a context manager, so `with RedisStorage(url=...) as storage:`
closes a client it created on exit.

---

## Decorator

```python
@limiter.limit(
    limit_spec=None,          # str | RateLimit | None -> the configured default
    algorithm=None,           # per-route algorithm override
    scope_path=None,          # str or callable, overrides the scope
    raise_on_limit=False,     # raise RateLimitExceeded instead of returning 429
)
```

`@app.route` must be **above** `@limiter.limit`. A malformed `limit_spec` raises
at decoration time, not on the first request.

Introspection helpers: `view_limit(view)` and `view_algorithm(view)` from
`great_limiter.decorators`.

---

## Flask helpers (`great_limiter.flask`)

| Helper | Purpose |
| --- | --- |
| `init_auth_limiter(limiter, app, **settings)` | what `AuthLimiter(app, ...)` calls |
| `current_limiter()` | the limiter bound to the current app |
| `resolve_limiter(app)` | the limiter registered on an app, or `ConfigurationError` |
| `build_identity(account_fields, *, trusted_proxies=None, headers=None)` | build an `Identity` from the current request |
| `current_decision()` | the `Decision` recorded for this request, if any |
| `EXTENSION_KEY` | `"great_limiter"`, the `app.extensions` key |

---

## Errors

```
GreatLimiterError
├── ConfigurationError (also a ValueError)
│   └── InvalidLimitError
├── StorageError
└── RateLimitExceeded      .decision -> Decision
```

`ConfigurationError` is raised at start-up. `StorageError` is raised at request
time and translated into a 429 by the Flask layer when `fail_open=False`.
`RateLimitExceeded` carries the `Decision` so an error handler does not have to
re-derive the status, the `Retry-After` value or the payload.
