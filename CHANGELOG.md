# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-09-30

First release under the Gromon Limiter name, and the first release of this
distribution on PyPI at all. A major version because the rename broke three
things a caller can observe. V1 shipped as 0.1.0 under the retired `g3-limiter`
name; this release adds V2 and the rebrand.

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
- Flask binding for V2. `Limiter.for_policy(policy, app, ...)` configures a
  limiter in one call, `@limiter.limit(policy=...)` applies a policy to a single
  route, and `extras_provider=` supplies authenticated material (`user`, `tenant`,
  `api_key`) per request so `by_user()` and friends are enforced instead of
  skipped. A rule whose material is absent is skipped, so an anonymous caller is
  not pooled into a shared user bucket. `decorator.view_policy()` reads a route's
  policy back off the view.
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

- **Renamed to Gromon Limiter.** The distribution is `gromon-limiter` (was
  `omonire-limiter`, itself renamed from `g3-limiter`) and the import is
  `gromon_limiter` (was `omonire_limiter`, previously `g3_limiter`). No
  behaviour changed: rate limiting, policy evaluation, storage, adapters and the
  public API are otherwise identical.
- Four names that are *stored or configured* rather than cosmetic also moved, so
  an upgrade is not invisible:
  - The key-salt environment variable is now `GROMON_LIMITER_SECRET` (was
    `OMONIRE_LIMITER_SECRET`, before that `G3_LIMITER_KEY_SALT`).
    Redis-backed deployments **fail to start** until the secret is renamed.
    There is no fallback to any previous name.
  - The Redis key prefix is now `gromon_limiter:`, so every live counter is
    orphaned. Pass `prefix="omonire_limiter"` to `RedisStorage`/`build_storage`
    to keep reading an older keyspace during a transition, and avoid running
    old and new versions against one Redis at the same time: they count against
    disjoint keys, which doubles the effective limit mid-deploy.
  - The logger is now `gromon_limiter`, so log filters and alerts keyed on
    `omonire_limiter` stop matching until they are updated.
  - The Flask `app.extensions` key is now `gromon_limiter` (`EXTENSION_KEY`).
- `OmonireClient` is now `GromonClient`, and the earlier `G3Client` alias has
  been **removed** rather than carried forward. There are no back-compat aliases
  for any previous brand: no release was ever published under `gromon-limiter`,
  `omonire-limiter` or `g3-limiter`, so there is no installed base to stay
  compatible with.
- `GROMON_LIMITER_SECRET` is the only supported salt variable name going forward.
- `1.0.0` is the first release under the `gromon-limiter` name, and the first
  release of this distribution on PyPI at all.
- A `Rule` with a static `cost` below 1 is now rejected at construction. A zero
  cost made the rule unenforceable while still looking configured.
- The README no longer says the package is unpublished; 0.1.0 is on PyPI.

### Fixed

- A `Policy` attached to a Flask limiter was accepted, reported by
  `Limiter.policy_for()`, and then ignored: every request took the V1 path and was
  limited by `default_limit`. The policy model was fully implemented and fully
  tested at the `PolicyEvaluator` level while nothing in the Flask layer called it,
  so a configured policy silently enforced the wrong number. The Flask layer now
  routes policy-bound requests through `PolicyEvaluator`.
- `Limiter.for_policy(policy, app)` raised `TypeError`; the parameter had to be
  passed by keyword even though `AuthLimiter(app)` takes it positionally. `app` is
  now accepted positionally.
- `Limiter.reset()` only cleared V1 counters, so resetting a caller on a
  policy-backed limiter reported success while removing nothing and the caller
  stayed blocked. It now routes through `PolicyEvaluator.reset`.

### Removed

- `G3LimiterError`, the former base class of every exception in the package.
  `ConfigurationError` is now a `ValueError`; `StorageError` and
  `RateLimitExceeded` are now plain `Exception` subclasses. There is no longer a
  single class that catches the whole family, so `except G3LimiterError:` must
  become `except (ConfigurationError, StorageError, RateLimitExceeded):`.
  **This is a breaking change** and the main reason the next release should be a
  major version.

## [0.1.0] - 2026-09-28

First release, under the now-retired `g3-limiter` name: V1, auth-endpoint rate
limiting. That distribution was never published to PyPI under that name, so
`gromon-limiter` 1.0.0 is the first installable release of this codebase.

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

[Unreleased]: https://github.com/omonire-great/gromon-limiter/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/omonire-great/gromon-limiter/releases/tag/v1.0.0
[0.1.0]: https://github.com/omonire-great/gromon-limiter/releases/tag/v0.1.0
