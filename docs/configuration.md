# Configuration

Everything that changes behaviour is an explicit argument to `AuthLimiter`,
`init_auth_limiter` or `Settings`. Nothing is read from a global, so two limiters
with different policies can coexist in one process.

Configuration is validated eagerly: bad values raise `ConfigurationError` (or
`InvalidLimitError`) at start-up, never on the first login attempt.

## Quick reference

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `limit` | `str \| RateLimit` | `"10/minute"` | Default budget for protected routes |
| `storage` | `str \| Storage` | `"memory"` | `"memory"`, `"redis"`, or a built backend |
| `storage_url` | `str \| None` | `None` | Redis URL when `storage="redis"` |
| `redis_client` | `Any` | `None` | Existing `redis.Redis`, takes precedence over the URL |
| `key_salt` | `str \| None` | `$OMONIRE_LIMITER_SECRET` | HMAC salt for identifier fingerprints |
| `namespace` | `str` | `"auth"` | Key namespace; isolates limiters sharing one Redis |
| `identifier` | `Iterable[str]` | `("ip", "account")` | Which independent budgets to keep |
| `algorithm` | `str` | `"sliding_window"` | `"sliding_window"` or `"fixed_window"` |
| `account_limit_multiplier` | `float` | `3.0` | Account budget = IP budget x this |
| `cooldown` | `float` | `60` | Seconds blocked after a breach |
| `account_cooldown` | `float \| None` | `None` | Overrides `cooldown` for the account rule |
| `trusted_proxies` | `Iterable[str] \| str` | `()` | Addresses/CIDRs allowed to set forwarding headers |
| `account_fields` | `Iterable[str]` | see below | Request fields inspected for the account |
| `scope` | `str` | `"endpoint"` | `endpoint`, `path`, `method`, `global` |
| `fail_open` | `bool` | `False` | Storage outage allows the request |
| `enabled` | `bool` | `True` | Kill switch |
| `skip_methods` | `Iterable[str]` | `("OPTIONS",)` | Methods that are never limited |
| `headers` | `bool` | `True` | Publish `X-RateLimit-*` on responses |
| `status_code` | `int` | `429` | `429` (recommended) or `403` |
| `clock` | `Callable[[], float]` | `time.time` | Injectable time source |

## Limit strings

`"<amount> per <window>"`, with the amount a whole number:

```python
RateLimit.parse("10/minute")     # 10 per 60s
RateLimit.parse("100/5 minutes") # 100 per 300s
RateLimit.parse("1/hour")
RateLimit.parse("30/second")
RateLimit.parse("2/day")
RateLimit.parse("1/week")
RateLimit.parse("5/1.5m")        # 5 per 90s
RateLimit.parse(5, window_seconds=60)
```

Accepted units: `second(s)`, `sec`, `s`, `minute(s)`, `min`, `m`, `hour(s)`,
`hr`, `h`, `day(s)`, `d`, `week(s)`, `w`. Underscores and thousands separators
are allowed in the amount (`"1_000/hour"`).

Rejected at start-up: a non-numeric amount, an unknown unit, a window below one
second, a limit above 1,000,000,000, a window above 366 days, and a zero or
negative amount.

## Identifiers

`identifier` names the independent budgets to keep. Each entry is a separate
rule with its own counter, cooldown and limit.

| Value | Where it comes from |
| --- | --- |
| `"ip"` | the resolved client IP (see trusted proxies) |
| `"account"` | the first matching field in `account_fields` |
| anything else | looked up in `Identity.extras`; must be declared in `extra_identifier_fields` |

Rules for a missing component are skipped, not merged: a JSON-less request on a
route configured for `("ip", "account")` is limited by IP alone. A request with
neither an IP nor an account is allowed, and deliberately *not* bucketed
together with other such requests — a shared "anonymous" bucket would let one
attacker exhaust everyone's budget.

`account_fields` defaults to `email`, `username`, `user`, `account`, `login`,
`identifier`, `phone`, `document`, `cpf`, checked in the JSON body first, then
the form body, then the query string.

### The account multiplier

```python
AuthLimiter(app, limit="5/minute", account_limit_multiplier=3)
# IP: 5/minute      account: 15/minute
```

Set it to `1` only when a route genuinely should not distinguish a human from a
botnet — for example an internal service-to-service endpoint. On a public login
form, matching limits hand an attacker a lockout button.

## Scope

| `scope` | Key segment | Use when |
| --- | --- | --- |
| `"endpoint"` (default) | `POST /login` | one budget per route and method |
| `"path"` | `/login` | the same budget for every method on a path |
| `"method"` | `POST` | one budget per HTTP method |
| `"global"` | `global` | one budget for the whole application |

Scoping by `request.path` means blueprints sharing a path prefix share a budget.
If two routes need independent budgets, set `namespace` differently per limiter
rather than relying on paths.

## Algorithms

| `algorithm` | Cost | Boundary burst | `Retry-After` |
| --- | --- | --- | --- |
| `"sliding_window"` (default) | one `ZADD`+`ZCARD` in Lua | none beyond `limit` | exact |
| `"fixed_window"` | one `INCR` | up to `2 x limit` | window end (may be pessimistic) |

Override per route with `@limiter.limit("3/hour", algorithm="fixed_window")`.

## Storage

### memory

```python
AuthLimiter(app, storage="memory")                    # default
```

In-process, thread-safe, no dependencies. Correct for a single worker and for
tests. **Not** correct for multiple workers: each process counts separately, so
the effective limit is `limit x workers`.

`MemoryStorage(max_keys=100_000)` bounds memory; expired keys are dropped first,
then the oldest half if the store is still oversized.

### redis

```python
AuthLimiter(app, storage="redis", storage_url=os.environ["REDIS_URL"])
AuthLimiter(app, storage="redis", redis_client=existing_pool)
```

Resolution order: `redis_client` → `storage_url` → `REDIS_URL` from the
environment. Missing all three is a `ConfigurationError`. `OMONIRE_LIMITER_SECRET`
must be set and identical everywhere.

Extra keyword arguments are forwarded to `Redis.from_url`:

```python
RedisStorage(
    url=url,
    prefix="myapp",                     # extra isolation inside one Redis DB
    socket_connect_timeout=2,
    socket_timeout=2,
    ssl_cert_reqs="required",
    health_check_interval=30,
)
```

A `redis_client` passed in is *not* closed by `close()`: it usually belongs to a
shared pool that other components still need.

## Proxies

```python
AuthLimiter(app, trusted_proxies=["10.0.0.0/8", "192.168.1.7", "::1/128"])
```

Entries may be single addresses or CIDR blocks; a comma-separated string works
too. Unparseable entries are ignored rather than fatal, and can never widen
trust. With an empty list (the default) forwarding headers are ignored entirely.

Behind a proxy, remember the application must actually receive the client
address in the socket peer position: run the app behind the proxy, and do not
expose it directly to the internet, or every request will appear to come from
the proxy.

## Failure behaviour

| Setting | Storage unreachable |
| --- | --- |
| `fail_open=False` (default) | 429, `rule="storage"`, "try again shortly" |
| `fail_open=True` | request allowed, warning logged |

`fail_open=True` is a per-endpoint decision about which failure is worse. Keep it
`False` for authentication.

## Environment variables

| Variable | Used for |
| --- | --- |
| `OMONIRE_LIMITER_SECRET` | HMAC salt (required for Redis; at least 16 characters) |
| `REDIS_URL` | default Redis connection for `storage="redis"` |

```console
$ python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Examples

Tight protection on a public login form:

```python
AuthLimiter(
    app,
    limit="5/minute",
    storage="redis",
    identifier=("ip", "account"),
    account_limit_multiplier=4,
    cooldown=300,
    trusted_proxies=["10.0.0.0/8"],
    account_fields=("email",),
)
```

Lax protection on a read-only endpoint where availability wins:

```python
AuthLimiter(
    app,
    limit="60/minute",
    identifier=("ip",),
    fail_open=True,
    cooldown=0,
    headers=False,
    scope="path",
)
```

Per-route overrides on one limiter:

```python
limiter = AuthLimiter(app, limit="30/minute", storage="redis")

@app.post("/login")
@limiter.limit("5/minute")
def login(): ...

@app.post("/recover")
@limiter.limit("3/hour", algorithm="fixed_window")
def recover(): ...

@app.post("/sms")
@limiter.limit(raise_on_limit=True)      # render the 429 yourself
def sms(): ...
```

## Validation errors

| Message | Fix |
| --- | --- |
| `key salt must be at least 16 characters` | generate a longer `OMONIRE_LIMITER_SECRET` |
| `OMONIRE_LIMITER_SECRET must be set when using redis storage` | set it, identically on every instance |
| `namespace must not contain whitespace` | use `"auth"` or `"auth-v2"` |
| `unknown identifier(s): session` | use `ip`/`account`, or declare `extra_identifier_fields` |
| `account_limit_multiplier must be >= 1` | a multiplier below 1 makes the account budget tighter than the IP budget |
| `limit must be a whole number` | `"5/minute"`, not `"five/minute"` |
| `window must be at least 1 second` | use a larger window |
| `scope must be one of ...` | `endpoint`, `path`, `method` or `global` |
| `algorithm must be one of ...` | `sliding_window` or `fixed_window` |
| `status_code must be 429 (recommended) or 403` | 429 is what clients expect |
