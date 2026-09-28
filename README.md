# great-limiter

Rate limiting for authentication endpoints, built for the
[Great Shield](https://github.com/CyberExpert-ZT) project.

[![CI](https://github.com/CyberExpert-ZT/great-limiter/actions/workflows/ci.yml/badge.svg)](https://github.com/CyberExpert-ZT/great-limiter/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

`great-limiter` answers one question on every request: *has this caller already
spent too many attempts, and if so, when may they try again?* It is deliberately
small, framework-agnostic at the core, and explicit about the security
decisions it makes.

```python
from flask import Flask, jsonify, request
from great_limiter import AuthLimiter

app = Flask(__name__)
limiter = AuthLimiter(
    app,
    limit="5/minute",
    storage="redis",                      # shared across workers/instances
    trusted_proxies=["10.0.0.0/8"],       # only trust X-Forwarded-For from these
)


@app.post("/login")
@limiter.limit("5/minute")
def login():
    ...
```

```console
$ curl -i -X POST localhost:5000/login -d 'email=victim@example.com&password=guess'
HTTP/1.1 429 TOO MANY REQUESTS
Retry-After: 60
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1700000060
X-RateLimit-Policy: cooldown:60s
X-RateLimit-Bucket: 6f1a...

{"error":"rate_limit_exceeded","message":"Too many attempts. Please wait before retrying.",
 "limit":5,"remaining":0,"reset_at":1700000060,"retry_after":60,"bucket":"6f1a..."}
```

## Why it exists

Brute-force protection on a login endpoint is not "one counter per IP". A single
IP limit is defeated by a botnet, and a single account limit is an attack
against honest users: guessing hard against `victim@example.com` from many
addresses would otherwise lock the real account out. This library therefore
keeps **two independent budgets** at once:

- a tight **per-IP** budget, which is cheap for an attacker to burn through;
- a looser **per-account** budget (3x by default), which survives a distributed
  attack and stops mass password spraying;
- a **temporary cooldown** after a breach, so a run of guesses costs the
  attacker time rather than only costing them quota.

There is no way to permanently lock an account. A cooldown always expires.

## Install

```console
pip install great-limiter            # core engine, no dependencies
pip install great-limiter[flask]     # Flask integration
pip install great-limiter[redis]     # Redis storage
```

From a clone, `pip install -e ".[dev]"` gives you the editable install plus the
test and lint tooling.

Set a stable key salt whenever more than one process (or more than one restart)
matters. Without it, memory storage generates a random one and warns; Redis
refuses to start, because a per-process salt would split the key space and
silently defeat every limit.

```console
$ python -c "import secrets; print(secrets.token_urlsafe(32))"
export GREAT_LIMITER_KEY_SALT="the-value-you-generated"
```

## Using it

### Flask (V1)

```python
from great_limiter import AuthLimiter

# Immediately, or later with AuthLimiter(limit=...).init_app(app).
limiter = AuthLimiter(app, limit="10/minute", storage="redis")

@app.post("/login")
@limiter.limit("5/minute")            # or omit the argument for the default
def login(): ...

@app.post("/recover")
@limiter.limit("3/hour", algorithm="fixed_window")
def recover(): ...
```

Decorator order matters: `@app.post` goes **above** `@limiter.limit`, so Flask
registers the wrapper as the view.

To render the error yourself instead of returning the built-in 429:

```python
from great_limiter import RateLimitExceeded

@app.post("/login")
@limiter.limit("5/minute", raise_on_limit=True)
def login(): ...

@app.errorhandler(RateLimitExceeded)
def too_many(error):
    return {"try_again_in": error.decision.retry_after}, 429
```

After a *successful* login, clear the caller's counters so their own typos (or
someone else on the same NAT) do not accumulate:

```python
from great_limiter import Identity
from great_limiter.flask import current_limiter

limiter.reset(Identity(ip=..., account=...), path="/login", method="POST")
```

### Without Flask

The engine has no web-framework dependency, so any stack can use it:

```python
from great_limiter import LimiterCore, MemoryStorage
from great_limiter.config import Settings, resolve_key_salt
from great_limiter.identifiers import Identity

core = LimiterCore(
    Settings(
        key_salt=resolve_key_salt(None, storage_name="memory"),
        default_limit="5/minute",        # strings are accepted and validated
    ),
    MemoryStorage(),
)

decision = core.check(Identity(ip="1.2.3.4", account="v@example.com"), path="/login", method="POST")
if not decision.allowed:
    ...  # decision.retry_after, decision.reset_at, decision.rule
```

`enforce=True` (or `core.check_or_raise(...)`) raises `RateLimitExceeded`
carrying the same `Decision`, for callers that prefer exceptions.

## Behaviour worth knowing

| Situation | Result |
| --- | --- |
| Within limit | Allowed, `X-RateLimit-Remaining` published |
| Limit exceeded | 429 JSON + `Retry-After` (RFC 9110) |
| Request during cooldown | Blocked immediately, **without** consuming another hit |
| Only one rule's cooldown armed | The rule that actually broke |
| No IP and no account in the request | Allowed, not lumped into a shared "anonymous" bucket |
| `OPTIONS` | Skipped by default (`skip_methods`) |
| Storage unreachable | 429 by default (`fail_open=False`) |
| Limit string is nonsense | `InvalidLimitError` at start-up, not on the first request |

`Retry-After` is computed from the moment a slot actually frees up, so with the
default `sliding_window` algorithm a client that waits exactly that long
succeeds.

## Configuration

Every knob is an explicit argument; nothing is read from a global.

| Argument | Default | Notes |
| --- | --- | --- |
| `limit` | `"10/minute"` | Accepts `10/minute`, `100/5 minutes`, `1/hour`, `5/1.5m` |
| `storage` | `"memory"` | `"redis"` needs `storage_url`, `redis_client`, or `REDIS_URL` |
| `identifier` | `("ip", "account")` | Which independent budgets to keep |
| `algorithm` | `"sliding_window"` | or `"fixed_window"` |
| `account_limit_multiplier` | `3.0` | Account budget = IP budget x this |
| `cooldown` | `60` seconds | Applied per breached rule |
| `account_cooldown` | falls back to `cooldown` | |
| `trusted_proxies` | `()` | Addresses or CIDRs allowed to set forwarding headers |
| `account_fields` | email, username, user, account, login, identifier, phone, document, cpf | Request fields inspected for the account |
| `scope` | `"endpoint"` | `endpoint`, `path`, `method`, `global` |
| `fail_open` | `False` | Storage outage allows the request instead of 429 |
| `enabled` | `True` | Kill switch |
| `headers` | `True` | Publish `X-RateLimit-*` (429 always keeps `Retry-After`) |
| `status_code` | `429` | `403` also allowed |
| `namespace` | `"auth"` | Key namespace; one Redis can host several limiters |

Full reference: [`docs/configuration.md`](docs/configuration.md).

## Storage

- **`memory`** — in-process, thread-safe, no dependencies. Correct for a single
  process and for tests; **not** correct for multiple workers.
- **`redis`** — atomic Lua scripts, so several web workers and several instances
  share one budget. Use this in production.

`MemoryStorage` and `RedisStorage` are interchangeable, and the tests run the
real Lua scripts through `fakeredis` so the Redis path is covered even without a
Redis server.

## Security

The design decisions and their reasoning are in
[`docs/security.md`](docs/security.md). The short version:

- Forwarding headers are ignored unless the socket peer is a configured trusted
  proxy, so `X-Forwarded-For` cannot be used to evade a limit.
- Identifiers are HMAC-fingerprinted; an email address or IP never appears in a
  Redis key, a log line, or a response body.
- Request bodies are read through Flask's cache, so the limiter never consumes
  the form the view is about to parse.
- Nothing is logged except operational metadata (namespace, rule name). No
  credentials, no bodies, no identifier values.

## Development

```console
pip install -e ".[dev]"
python -m pytest -q          # full suite
python -m pytest -q -m redis # storage tests (live Redis if REDIS_URL is set)
python -m ruff check great_limiter tests
python -m mypy
```

To exercise a real Redis, set `REDIS_URL=redis://localhost:6379/0`. Without it
the suite falls back to `fakeredis`, which runs the same Lua scripts in-process.

## Roadmap

Deliberately incremental; each milestone is usable on its own.

| Milestone | Scope | Status |
| --- | --- | --- |
| V1 | Auth endpoint limiting, IP + account, cooldowns, memory/Redis, Flask | **done** |
| V2 | General-purpose API limiter (`Limiter`), key builders, per-route policies | next |
| V3 | Great Shield service client: shared policy across services | planned |
| V4 | Control plane: dashboard, metrics, rule management | planned |
| V5 | Multi-region edge enforcement, SDKs, billing | planned |

`Limiter` and `GreatShield` are exported for forward compatibility. `Limiter` is
currently a thin general-purpose alias of `AuthLimiter`; `GreatShield` raises
`NotImplementedError` until V3. Neither pretends to work.

## Licence

MIT. See [LICENSE](LICENSE). Changes are recorded in
[CHANGELOG.md](CHANGELOG.md).
