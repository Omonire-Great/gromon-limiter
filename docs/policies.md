# V2 policies

V2 replaces V1's "one limit per route, keyed by IP and account" with a
declarative model: a **policy** is data, a **rule** is one budget inside it, and
a **key builder** decides who a rule counts.

The engine (`LimiterCore`) is unchanged in structure. Everything here is the
layer above it, plus two additions to the engine itself: per-request **cost** and
the clock needed to evaluate rules on the same time source.

## Policy and rule

```python
from great_limiter import Limiter, Policy, Rule, by_ip, by_user, fixed_cost

policy = Policy(
    name="admin",
    rules=(
        Rule(key=by_ip(), limit="20/minute", name="ip"),
        Rule(key=by_user(), limit="200/minute", name="user"),
    ),
)

limiter = Limiter.for_policy(policy, key_salt=os.environ["GREAT_LIMITER_KEY_SALT"])
```

A request is allowed only when **every** rule allows it. That is what makes V1's
"IP rule and account rule, both enforced" a property of the model rather than a
special case in the engine.

Rules are independent budgets. Two rules on the same key builder with different
limits are *not* merged, because sharing a counter would let one rule's traffic
consume the other's allowance. The rule label is folded into the key material to
guarantee that.

## Key builders

| Builder | Counts per |
| --- | --- |
| `by_ip()` | client address |
| `by_account()` | email / username from the body |
| `by_user()` | authenticated user (`Identity.extras["user"]`) |
| `by_tenant()` | tenant or plan |
| `by_api_key()` | API key |
| `by_route()` | the route itself, shared across all callers |

`by_ip()` is the safe default for pre-auth endpoints, because an unauthenticated
request has nothing else to key on. `by_user()` is right for everything
post-auth, and matters more than it looks: an office behind one NAT shares an IP
across every employee, so an IP limit there blocks the whole company.

Components are normalised before fingerprinting. Accounts are case-folded, IPs are
canonicalised (`::ffff:1.2.3.4` collapses to `1.2.3.4`), so no caller can occupy
two budgets with a spelling change.

## Composite and independent keys

```python
KeyBuilder(components=("tenant", "user"))                    # both together
KeyBuilder(components=("tenant", "user"), independent=True)  # one bucket each
```

The composite form is "this tenant's this user". The independent form produces
two counters, so breaching either dimension blocks the request. Use it for
fairness: a noisy tenant cannot spend another tenant's allowance.

## Evaluating a policy

`PolicyEvaluator` is the entry point. It holds one `LimiterCore` and derives a
narrow engine view per rule.

```python
from great_limiter.engine import PolicyEvaluator

evaluator = PolicyEvaluator(limiter.core)
verdict = evaluator.check(policy, identity, path="/admin/refunds", method="POST")

if not verdict.allowed:
    return error(429, headers=build_headers(verdict.decision))
```

- `verdict.allowed` is the answer. `PolicyVerdict` is falsy when blocked, so
  `if not verdict:` works.
- `verdict.denied_by()` is the label of the rule that blocked, or `None`.
- `verdict.decision.rule` carries the same label, so `build_headers` and log
  lines never show the internal synthetic identifier.
- `verdict.storage_failed` is `True` when a storage error was absorbed by a
  fail-open policy. `allowed` then means "allowed because we could not tell", and
  a caller that cares should log it rather than treat it as a pass.
- `verdict.evaluations` is every rule that ran, in policy order.

For an unauthenticated endpoint, pass the request identity and the resolved
session separately:

```python
verdict = evaluator.check(policy, request_identity, path="/api", extras=session)
```

`extras` wins on conflict. A user id established by authentication is more
trustworthy than anything the body claimed under the same key, so a caller cannot
dodge a limit by rotating a claimed user id.

### The reported rule

When several rules allow, the verdict reports the **tightest** one, meaning the
rule with the least headroom left. That is what makes `X-RateLimit-Remaining`
honest: reporting the first rule evaluated would describe a budget the client is
not actually closest to.

`short_circuit` (the default) stops at the first breach, so later rules are not
charged. Set it to `False` to charge every rule regardless, which is what you
want when all budgets must reflect the traffic even though the request is denied.

## Unresolvable identities

If a rule needs `user` and the request has no authenticated user, the **evaluator
skips that rule** for that request. It is not counted against anything, and the
request is judged on the rules that do apply.

The alternative would be a shared bucket every anonymous caller lands in, which
lets one attacker exhaust everybody's allowance at once.

`KeyBuilder.materials()` still raises in that situation, so code that needs an
identity can insist on one. The evaluator deliberately uses the non-raising
`materials_or_none()`, because "this rule does not apply" is a routine outcome on
an unauthenticated request rather than a misconfiguration.

When absence is legitimate and should share a budget, name it:

```python
KeyBuilder(components=("user",), fallback="anonymous")
```

## Weighted limits

A counter counts requests. A weighted limit counts work:

```python
Rule(key=by_tenant(), limit="1000/hour", cost=fixed_cost(20))
```

A $500 refund costs 20 units, a $1 charge costs 1. Pass a callable instead of
`fixed_cost` when the cost depends on the request.

The cost is charged against **every** rule in the policy, not only the one that
declared it. Otherwise a caller could pick the expensive operation to avoid the
cheap rule, which is the opposite of the intent.

The whole charge is one atomic storage operation. Splitting a cost-5 request into
five calls would let concurrent callers each pass a check that only the sum would
fail, so a limit of 30 with cost 3 admits exactly 10, not 15.

A cost function that returns nonsense is treated as costing the rule's whole
limit, which denies rather than making an expensive operation free. One that
raises propagates: hiding that behind a wrong number would be worse, and a 429
that reads as ordinary rate limiting would hide the bug.

`Retry-After` for a weighted rule points at the oldest entry leaving the window,
which frees one slot rather than the whole cost. A client that follows it exactly
may be refused once more. That is deliberate: an honest extra 429 beats a
`Retry-After` that says "retry now" and means it.

## Per-rule cooldowns

```python
Rule(key=by_ip(), limit="5/minute", cooldown_seconds=300, name="login")
```

`cooldown_seconds` overrides the engine-wide default for that rule, and `0` is
meaningful: it means "block on breach without arming a marker", which suits a
cheap public endpoint that should not carry a five-minute lockout.

A refused attempt inside an active cooldown does **not** extend the wait. If it
did, a client that kept retrying would never be served again, which is the
permanent lockout this library refuses to implement.

`reset()` clears the marker along with the counter, so a correct password lifts
the block immediately.

## No permanent punishment

A rule blocks for a bounded window. Nothing in the policy model can lock an
account permanently, and `reset()` remains available to clear a counter after a
successful login. This is a product decision, not a missing feature.

`reset()` must be given the same `path` and `method` used at check time, because
the scope is part of the storage key. A mismatched reset silently clears nothing,
which is the safe failure: the caller stays limited rather than a counter being
half-cleared.

## Limits and cost per policy

`MAX_RULES_PER_POLICY` is 32. Each rule costs at least one storage round trip on
the hot path, so a policy with hundreds of rules is a configuration mistake and
is rejected at check time rather than quietly becoming a slow endpoint. An
`independent` builder costs one round trip per dimension, so a two-component
independent rule counts as two.

Rule views are built once and cached, so the per-request cost is storage calls
only, not settings construction.

## Security notes

- Every key is HMAC-fingerprinted before it reaches storage. A user id, tenant
  name or email never appears in a Redis key, a log line or a header.
- `Policy` and `Rule` validate in `__post_init__`, so a bad limit, cost, name or
  builder raises at start-up rather than on the first request.
- `fail_closed` is a per-policy decision, which is the point: an auth or payment
  endpoint wants to deny when storage misbehaves, a public read endpoint does
  not.
- A zero cost is rejected at construction. It would make a rule unenforceable
  while still looking configured.
- The policy evaluator shares the parent engine's clock, so tests that inject a
  fake time source exercise rules on that same timeline rather than the wall
  clock.
