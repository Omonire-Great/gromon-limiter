# V2 policies

V2 replaces V1's "one limit per route, keyed by IP and account" with a
declarative model: a **policy** is data, a **rule** is one budget inside it, and
a **key builder** decides who a rule counts.

The engine (`LimiterCore`) is unchanged. Everything here is the layer above it.

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

## Unresolvable identities

If a rule needs `user` and the request has no authenticated user, the builder
**raises** rather than falling back. Silently substituting a shared bucket would
put every anonymous caller into one limit and hand an attacker a way to lock out
everybody at once.

When absence is legitimate, name it:

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

A cost function that returns nonsense is treated as costing the rule's whole
limit, which denies rather than making an expensive operation free. One that
raises propagates: hiding that behind a wrong number would be worse.

## No permanent punishment

A rule blocks for a bounded window. Nothing in the policy model can lock an
account permanently, and `reset()` remains available to clear a counter after a
successful login. This is a product decision, not a missing feature.

## Security notes

- Every key is HMAC-fingerprinted before it reaches storage. A user id, tenant
  name or email never appears in a Redis key, a log line or a header.
- `Policy` and `Rule` validate in `__post_init__`, so a bad limit, cost, name or
  builder raises at start-up rather than on the first request.
- `fail_closed` is a per-policy decision, which is the point: an auth or payment
  endpoint wants to deny when storage misbehaves, a public read endpoint does
  not.
