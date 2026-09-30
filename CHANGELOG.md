# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-09-30

First release under the Omonire Limiter name, and a major version because the
rename broke three things a caller can observe. V1 shipped as 0.1.0; this
release adds V2 and the rebrand.

### Added

- `PolicyEvaluator`, which evaluates a `Policy` through `LimiterCore`. Each rule
  gets a narrow engine view keyed on a synthetic identifier, so unrelated budgets
  never merge and the V1 engine stays the single place limits are enforced.
- `PolicyVerdict`: `allowed`, `denied_by()`, the full list of rule evaluations,
  and `storage_failed` so a fail-open "allowed" is distinguishable from a real
  pass.
- Weighted request costs end to end. `LimiterCore.check` takes `cost`, both
  algorithms charge it, and `Storage.log_add` takes an `amount` so the whole
  charge lands in one atomic operation. Cost applies to every rule in a policy,
  not only the one that declared it.
- Per-rule `cooldown_seconds`, including `0` for "block without arming a marker".
  A refused attempt inside a cooldown does not extend the wait.
- `KeyBuilder.materials_or_none()`, used by the evaluator to skip a rule whose
  components are absent rather than raising on an unauthenticated request.
- `LimiterCore.clock`, so a derived engine evaluates on the same time source as
  the one it was derived from.
- `Decision.storage_failed`, so a fail-open decision is self-describing.

### Fixed

- `RedisStorage.increment` accepted an `amount` and adjusted the TTL for it, but
  the Lua script always issued `INCR` and added 1. A weighted charge was silently
  dropped on Redis while working in memory. The script now uses `INCRBY`.
- `RedisStorage` sliding-window log: a weighted hit added several entries sharing
  one score, and the script passed them to `ZADD` without score/member pairing,
  which Redis rejects. Entries are now added one at a time with distinct members.

### Changed

- **Renamed to Omonire Limiter.** The distribution is `omonire-limiter` (was
  `g3-limiter`) and the import is `omonire_limiter` (was `g3_limiter`). No
  behaviour changed: rate limiting, policy evaluation, storage, adapters and the
  public API are otherwise identical. `pip install g3-limiter` keeps resolving to
  the old 0.1.0 release; it will not pick up this rename.
- Four names that are *stored or configured* rather than cosmetic also moved, so
  an upgrade is not invisible:
  - The key-salt environment variable is now `OMONIRE_LIMITER_SECRET` (was
    `OMONIRE_LIMITER_KEY_SALT`). Redis-backed deployments **fail to start** until
    the secret is renamed. There is no fallback to the previous name.
  - The Redis key prefix is now `omonire_limiter:`, so every live counter is
    orphaned. Pass `prefix="g3_limiter"` to `RedisStorage`/`build_storage` to
    keep reading the old keyspace during a transition, and avoid running old and
    new versions against one Redis at the same time: they count against disjoint
    keys, which doubles the effective limit mid-deploy.
  - The logger is now `omonire_limiter`, so log filters and alerts keyed on
    `g3_limiter` stop matching until they are updated.
  - The Flask `app.extensions` key is now `omonire_limiter` (`EXTENSION_KEY`).
- `G3Client` is now `OmonireClient`; the old name remains as an alias.
- `0.1.0` was published to PyPI as `g3-limiter`. `omonire-limiter` has not been
  published yet.
- A `Rule` with a static `cost` below 1 is now rejected at construction. A zero
  cost made the rule unenforceable while still looking configured.
- The README no longer says the package is unpublished; 0.1.0 is on PyPI.

### Removed

- `G3LimiterError`, the former base class of every exception in the package.
  `ConfigurationError` is now a `ValueError`; `StorageError` and
  `RateLimitExceeded` are now plain `Exception` subclasses. There is no longer a
  single class that catches the whole family, so `except G3LimiterError:` must
  become `except (ConfigurationError, StorageError, RateLimitExceeded):`.
  **This is a breaking change** and the main reason the next release should be a
  major version.

## [0.1.0] - 2026-09-28

First release, published as `g3-limiter`: V1, auth-endpoint rate limiting.

### Added

- Framework-agnostic `LimiterCore`: independent per-IP and per-account budgets,
  the account budget looser by `account_limit_multiplier` so a distributed
  attack cannot lock a real user out.
- Temporary cooldowns per breached rule. Hits are not counted while a cooldown
  is active, so retrying cannot extend a punishment indefinitely, and only the
  rule that actually breached is armed.
- `fixed_window` and `sliding_window` algorithms. Sliding window gives an exact
  `Retry-After`; its log members are unique per process so concurrent hits
  cannot collapse in a Redis sorted set.
- `MemoryStorage` (thread-safe, bounded by `max_keys`) and `RedisStorage`
  (atomic Lua scripts, `SCAN`-based maintenance, never `KEYS`).
- Flask integration: `AuthLimiter`, `@limiter.limit(...)`, JSON 429 with
  `Retry-After`, and `X-RateLimit-*` headers on allowed responses.
- Identifiers are HMAC-fingerprinted, so no email address or IP ever appears in
  a storage key, a log line or a response body.
- Forwarding headers are honoured only when the socket peer is a configured
  trusted proxy, closing the `X-Forwarded-For` spoofing hole.
- Fail-open and fail-closed modes, defaulting to fail-closed for auth.
- Eager configuration validation: bad limits, namespaces, identifiers and salts
  raise at start-up instead of on the first login attempt.
- `Limiter` (general-purpose alias) and `G3Client` (V3 stub) exported for
  forward compatibility. Neither fakes functionality.

[Unreleased]: https://github.com/Omonire/Omonire-Limiter/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Omonire/Omonire-Limiter/releases/tag/v1.0.0
[0.1.0]: https://github.com/Omonire/g3-limiter/releases/tag/v0.1.0
