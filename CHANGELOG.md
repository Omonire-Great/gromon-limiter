# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-09-28

First release: V1, auth-endpoint rate limiting.

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
- `Limiter` (general-purpose alias) and `GreatShield` (V3 stub) exported for
  forward compatibility. Neither fakes functionality.

[Unreleased]: https://github.com/Omonire/great-limiter/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Omonire/great-limiter/releases/tag/v0.1.0
