# Security

This document records the security decisions taken in V1 and the reasoning
behind them. Every one of them is enforced by a test; the test name is given so
the guarantee can be verified rather than trusted.

## Threat model

`omonire-limiter` defends authentication endpoints (login, password reset, MFA
codes, signup) against:

| Attack | Mitigation |
| --- | --- |
| Brute force from one host | per-IP budget |
| Distributed / low-and-slow password guessing | per-account budget, looser than the IP budget |
| Password spraying across many accounts | per-IP budget still applies to every attempt |
| Permanent denial of service against a victim | account budget is looser; **no permanent lock exists** |
| Header spoofing to reset one's own bucket | forwarding headers are ignored unless the peer is a trusted proxy |
| Identifier disclosure through Redis keys or logs | HMAC fingerprinting of all identity material |
| Unbounded memory growth from an attacker | `MemoryStorage` key ceiling; `MAX_MATERIAL_LENGTH` cap on key material |
| Lockout amplification by retrying during a cooldown | hits are not counted while a cooldown is active |

Out of scope for V1: DDoS absorption at the network layer, credential
verification, MFA, and bot detection. Rate limiting raises the cost of an
attack; it does not end it.

## 1. Forwarding headers are never trusted by default

`X-Forwarded-For` and `X-Real-IP` are attacker-controlled. If they were used
unconditionally, one extra header would grant an unlimited supply of identities
and defeat every IP-based limit.

`client_ip()` (see `omonire_limiter/identifiers.py`) therefore:

1. takes the socket peer (`request.remote_addr`) as the only value the server
   observed itself;
2. consults the forwarding headers **only if that peer is inside
   `trusted_proxies`**;
3. walks the `X-Forwarded-For` chain right-to-left and takes the first hop that
   is not itself a trusted proxy.

With `trusted_proxies=()` — the default — the headers are ignored completely.

*Failure mode of a wrong configuration:* listing a proxy you do not control
(for example the entire internet) hands identity selection back to the attacker.
Listing too few is safe: you fall back to the proxy's own address and limits
become coarser, not absent.

*Tests:* `test_flask_auth.py::test_forwarded_header_is_ignored_without_trusted_proxies`,
`::test_spoofed_forwarded_header_cannot_evade`,
`::test_forwarded_header_is_used_for_a_trusted_proxy`.

## 2. Identity material is fingerprinted, never stored

An email address or IP address in a Redis key is a disclosure waiting to happen:
`KEYS *`, a slow-query log, a backup, a dashboard, or a support engineer with
`redis-cli` all reveal who was rate limited and why. A key that also survives in
a snapshot outlives the incident review that justified it.

`LimiterCore.rule_key` normalises the identity material, joins it with a unit
separator, and takes a truncated HMAC-SHA256 keyed by `OMONIRE_LIMITER_SECRET`:

```python
fingerprint(salt, "default:account", "account=victim@example.com")
# -> "6f1a2c9d4e5f60718293a4b5c6d7e8f9"  (32 hex chars, one-way)
```

Properties that matter:

- **Stable** for the same salt, so limits work across processes and restarts.
- **One-way**, so keys disclose nothing.
- **Domain-separated** by the rule name, so an account fingerprint cannot be
  replayed as an IP fingerprint.
- **Bounded**: at most `MAX_MATERIAL_LENGTH` (512) characters reach the HMAC, so
  a hostile 10 MB "email" cannot inflate every key.
- Account values are lowercased and truncated first, so `V@Example.com` and
  `v@example.com ` share one budget rather than two.

*Tests:* `test_identifiers.py` (fingerprint stability, case folding,
one-wayness, material cap), `test_core.py::test_account_is_case_insensitive`.

### The salt

`OMONIRE_LIMITER_SECRET` is a secret. It is not logged, and it is required (at
least 16 characters) for shared storage:

- **Memory storage** with no salt generates a random one and logs a warning.
  Acceptable for one process; counters reset on restart and are not shared.
- **Redis storage** with no salt is a hard `ConfigurationError`. A per-process
  salt would give each instance a different key space, so every limit would be
  silently per-instance — the exact failure a distributed limiter must not have.

Rotating the salt invalidates existing counters (limits reset once). Plan it as
an explicit event, not a routine change.

*Tests:* `test_core.py::test_redis_requires_explicit_stable_salt`,
`::test_short_salt_is_rejected`,
`::test_memory_storage_gets_a_ephemeral_salt_with_warning`.

## 3. Request bodies are read, never consumed

The account identifier lives in the request body, so the limiter has to look at
it. Reading the raw WSGI stream would leave the view with an empty form — a
subtle, production-only bug where login starts failing with "missing password"
under load.

`omonire_limiter/flask.py` uses `request.get_json(silent=True)`, `request.form` and
`request.args`, all of which Werkzeug caches. Order is body → form → query: a
query parameter is more likely to be an ambient or shared value, so a real body
field wins.

Malformed JSON is treated as "no account", not as an error: the request is
limited by IP alone and the view still sees the original body.

*Tests:* `test_flask_auth.py::test_malformed_json_does_not_break_the_limiter`,
`::test_account_identifier_is_read_from_form`, `::test_form_body_is_still_readable_by_the_view`.

## 4. Nothing sensitive is logged

The package logs to the `omonire_limiter` logger, and only ever operational
metadata: the namespace, the rule name, whether a decision was fail-open or
fail-closed. No identifier values, no account names, no IPs, no credentials, no
request bodies, no headers.

The `X-RateLimit-Bucket` header and the `bucket` field in the 429 body expose
only the fingerprint, which is what lets a support engineer correlate a user's
complaint with the limiter's state without the key being meaningful on its own.

## 5. No permanent account lock

`cooldown_seconds` (60 by default) bounds every punishment. When the marker
expires the caller is back on the normal budget; there is no flag, no
"lockout_until" column, and no code path that extends a lock without a new
breach.

Two further rules keep the cooldown from becoming a denial-of-service primitive:

- **Only the breached rule is armed.** An IP breach arms the IP cooldown. It does
  not touch the account cooldown, so an attacker cannot lock a victim out by
  deliberately exceeding the IP budget against their address.
- **The account budget is looser than the IP budget**
  (`account_limit_multiplier`, 3.0 by default). If the two were equal, spraying
  `victim@example.com` from a handful of addresses would exhaust the account's
  budget exactly as if the attacker sat on one IP.

Call `reset()` (or `limiter.reset(...)`) after a *successful* authentication so
that failures from before the success — a typo, or a shared NAT — do not count
against the user's new session.

*Tests:* `test_core.py::test_only_the_breached_rule_is_armed`,
`::test_account_rule_catches_distributed_attack`,
`::test_account_limit_is_looser_than_ip_limit_by_default`,
`::test_cooldown_blocks_repeatedly_without_consuming_hits`,
`test_flask_auth.py::test_success_resets_counters`.

## 6. Failing closed by default

If storage is unreachable, an authentication endpoint that silently stops
limiting is an authentication endpoint with no brute-force protection. The
default `fail_open=False` returns 429 instead. `fail_open=True` is available for
endpoints where an outage is worse than an unmetered request, and it is never
the default.

A cooldown decision reports `rule="storage"` and a plain "try again shortly"
message, so a client is not told its password was wrong.

*Tests:* `test_core.py::test_fail_closed_by_default`,
`::test_fail_open_allows_when_storage_is_down`,
`test_flask_auth.py::test_storage_outage_fails_closed`.

## 7. Bounded work per request

- Identifier material is truncated (`MAX_ACCOUNT_LENGTH` 256,
  `MAX_MATERIAL_LENGTH` 512), so key building is O(1) in the size of the attack.
- `MemoryStorage` has a `max_keys` ceiling and evicts expired keys first, then
  the oldest half. Growing without bound is not an option: a flood of distinct
  identifiers would otherwise take the process down, which is a worse outcome
  than a temporarily looser limit.
- Sliding-window logs are pruned on every write, so a log never grows past its
  window's worth of hits.
- `clear_prefix` uses Redis `SCAN`, never `KEYS`, so maintenance does not block
  the server.

*Tests:* `test_storage_memory.py::test_eviction_bounds_memory`,
`test_core.py::test_extra_identifiers_must_be_declared`.

## 8. Atomicity across processes

A limit that can be raced is not a limit. `MemoryStorage` serialises every
mutation with an `RLock`; `RedisStorage` performs each read-modify-write inside
a Lua script, so `INCR`+`EXPIRE` and `ZADD`+prune+`ZCARD` cannot interleave
between workers.

Sliding-window members are unique per process (random prefix + monotonic
counter). With a timestamp-only member, two concurrent requests in the same
microsecond would collapse into one sorted-set entry and one of them would go
uncounted — a rate limit that silently under-counts exactly when traffic
spikes.

*Tests:* `test_integration_redis.py::test_concurrent_log_adds_are_not_lost`,
`test_algorithms.py::test_sliding_window_members_are_unique`,
`::test_sliding_window_members_differ_across_instances`.

## 9. Misconfiguration fails at start-up

Every setting is validated in `Settings.__post_init__` and limit strings are
parsed when the decorator is defined, not on the first request. An empty
namespace, an unknown identifier, a cooldown of `-1`, a nonsense limit such as
`"5/fortnight"` and a short salt all raise immediately, with a message that says
what to do.

This matters operationally: a limiter that starts unconfigured and fails on the
first login attempt has failed at the worst possible moment.

*Tests:* `test_limits.py`, `test_core.py::test_settings_reject_bad_configuration`,
`::test_extra_identifiers_must_be_declared`.

## Deployment checklist

- [ ] `OMONIRE_LIMITER_SECRET` set from a secret manager, identical on every
      instance, at least 16 characters.
- [ ] `storage="redis"` whenever more than one worker or instance serves the
      endpoint.
- [ ] `trusted_proxies` lists exactly the proxies in front of the app, and
      nothing else.
- [ ] Redis credentials from the environment or a secret manager, never in
      source; TLS (`rediss://`) if the network is not private.
- [ ] `fail_open` chosen deliberately per endpoint; left `False` for auth.
- [ ] `limiter.reset(...)` called after successful authentication.
- [ ] Rate limit headers treated as advisory by clients, `Retry-After` obeyed.
- [ ] Metrics on the `omonire_limiter` logger, alerting on 429 spikes and on
      `rule="storage"` responses.
