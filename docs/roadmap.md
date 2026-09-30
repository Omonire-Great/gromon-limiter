# Roadmap

The project is built in five milestones. Each one is independently useful and
independently tested; nothing waits for the milestone after it. Work proceeds in
order, and a milestone is only "done" when its tests, documentation and security
review are done.

## V1 — Auth endpoint limiting (shipped as 0.1.0)

**Goal:** protect login, password reset, MFA and signup endpoints well enough
to deploy.

| Item | Status |
| --- | --- |
| Framework-agnostic engine (`LimiterCore`) | done |
| Fixed and sliding window algorithms | done |
| Memory and Redis storage, atomic Lua scripts | done |
| Independent per-IP and per-account budgets | done |
| Temporary cooldowns, never a permanent lock | done |
| HMAC-fingerprinted identifiers | done |
| Trusted-proxy handling, no header spoofing | done |
| Flask integration, decorator, JSON 429, `Retry-After` | done |
| Eager configuration validation | done |
| 429, 502, 200, cache, proxy, salt, scope and race tests | done |
| Architecture, security, configuration, API, SDK, deployment docs | done |

Deliberately excluded: permanent lockout, CAPTCHA, geo rules, risk scoring,
dashboards, hosted API.

## V2 — General-purpose API limiter (current)

**Goal:** rate limit any endpoint, not just authentication.

| Item | Status |
| --- | --- |
| `Limiter` as the documented public entry point | done (`Limiter.for_policy`, `policy_for`) |
| Key builders: route, user, tenant, API key, arbitrary callables | done (`omonire_limiter.policies`) |
| Per-route and per-blueprint policies declared as data | done (`Policy` / `Rule` data model) |
| Weighted limits (cost per request) | done (`Rule.cost`, `fixed_cost`; atomic in both backends) |
| Policy evaluation over the V1 engine | done (`PolicyEvaluator`, `PolicyVerdict`) |
| Flask enforcement of a bound policy | done (`for_policy`, `@limiter.limit(policy=)`, `extras_provider`) |
| Per-rule cooldowns and fail-open/fail-closed per policy | done |
| Global (`scope="global"`) limits | partial (scope already in V1 config, no V2 sugar) |
| Blueprint-level policy defaults | partial (per-route via `policy=`; no `app.blueprint` hook) |
| `Retry-After`-aware client helpers | next |
| Django and FastAPI adapters on the existing engine | next |
| Response hooks (custom status, body, headers) | next |

Design constraint: V2 reuses `LimiterCore`. `AuthLimiter` keeps working through
inheritance, so no V1 application has to change. The engine gained two additive
parameters for this milestone, `cost` on `check` and a public `clock`, plus a
`storage_failed` flag on `Decision`. Every one of them defaults to the V1
behaviour, so existing callers are unaffected.

## V3 — Omonire backend service

**Goal:** one policy, enforced everywhere, including by services that are not
Python.

| Item | Status |
| --- | --- |
| `OmonireClient` client replacing the `NotImplementedError` stub | planned |
| Central rule store with local caching and fail-safe defaults | planned |
| Signed configuration so a compromised client cannot raise its own limit | planned |
| Sync/async Python clients, TypeScript client | planned |
| Idempotent counters so a retry never double-charges | planned |
| PII-free telemetry: bucket fingerprints only, never raw identifiers | planned |
| Self-hosted and hosted deployment | planned |

Design constraint: the service is a *better* source of policy, never a hard
dependency at request time. A local cache plus a safe default keeps latency at
memory-read speed and keeps the service outage from becoming an outage.

## V4 — Control plane

**Goal:** operators manage policy without a deploy.

| Item | Status |
| --- | --- |
| Dashboard: limits, cooldowns, active buckets, per-rule overrides | planned |
| Audit log of every policy change, with actor and reason | planned |
| Prometheus metrics and OpenTelemetry spans | planned |
| Alerts: 429 spikes, `rule="storage"`, salt mismatches | planned |
| Tenants, roles, per-environment configuration | planned |
| Emergency kill switch that does not require a restart | planned |

## V5 — Platform

**Goal:** enforcement close to the traffic, at scale.

| Item | Status |
| --- | --- |
| Regional/edge enforcement with central policy | planned |
| Protocol support beyond HTTP (WebSocket, gRPC, queue consumers) | planned |
| Automatic tiering (per-IP, per-account, per-tenant, per-ASN) | planned |
| Anomaly detection: credential stuffing vs spray vs single-target | planned |
| Billing and plan enforcement | planned |
| Compliance: data residency, retention, right-to-erasure for fingerprints | planned |

## Principles across milestones

1. **No permanent lock.** Every punishment is time-boxed. This is a product
   decision, not a limitation, and it is not going to change.
2. **Deploy-safe defaults.** A missing dependency or an outage must never turn
   into an unprotected endpoint or an unusable one.
3. **No identifier disclosure.** Fingerprints in storage, telemetry and logs.
4. **Boring, explicit configuration.** No magic, no globals, no reflection.
5. **Test each milestone before starting the next.** A milestone that is not
   green is not done.
6. **Failures must be legible.** Every error message says what was wrong and
   what to do about it.

## What is explicitly not planned

- CAPTCHA or challenge-response integration (V1 leaves room for it as a
  `Decision` extension; the design does not commit to a vendor).
- Permanent bans, IP reputation databases, third-party threat feeds.
- Replacing the application's own authentication. This library limits; it does
  not authenticate.
