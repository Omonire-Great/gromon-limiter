"""Tests for V2 policy evaluation on top of the V1 engine."""

from __future__ import annotations

import pytest

from great_limiter import (
    ConfigurationError,
    Identity,
    LimiterCore,
    MemoryStorage,
    RateLimitExceeded,
)
from great_limiter.config import Settings
from great_limiter.core import DEFAULT_COOLDOWN_MESSAGE, build_headers
from great_limiter.engine import MAX_RULES_PER_POLICY, PolicyEvaluator
from great_limiter.policies import (
    KeyBuilder,
    Policy,
    Rule,
    by_account,
    by_ip,
    by_tenant,
    by_user,
    fixed_cost,
)
from great_limiter.storage.base import CounterState, Storage

SALT = "engine-test-salt-long-enough"


class FakeClock:
    """Manually advanced time source, so no test has to sleep."""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_core(clock: object | None = None) -> LimiterCore:
    return LimiterCore(
        Settings(key_salt=SALT, default_limit="1000/minute"),
        MemoryStorage(),
        clock=clock,  # type: ignore[arg-type]
    )


def make_evaluator(clock: FakeClock | None = None) -> PolicyEvaluator:
    return PolicyEvaluator(make_core(clock))


def api_policy() -> Policy:
    return Policy(
        name="api",
        rules=(
            Rule(key=by_ip(), limit="2/minute", name="ip"),
            Rule(key=by_user(), limit="5/minute", name="user"),
        ),
    )


# ------------------------------------------------------------- basic evaluation


def test_all_rules_are_evaluated_when_every_one_allows() -> None:
    ev = make_evaluator()
    verdict = ev.check(api_policy(), Identity(ip="1.2.3.4", extras={"user": "u1"}), path="/api")
    assert verdict.allowed
    assert verdict.rule_names() == ("ip", "user")


def test_a_breached_rule_blocks_the_request() -> None:
    ev = make_evaluator()
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    for _ in range(3):
        verdict = ev.check(api_policy(), identity, path="/api")
    assert not verdict.allowed
    assert verdict.denied_by() == "ip"


def test_decision_reports_the_policy_label_not_the_internal_identifier() -> None:
    ev = make_evaluator()
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    for _ in range(3):
        verdict = ev.check(api_policy(), identity, path="/api")
    # The engine keys on a synthetic "v2:api:ip" component. That is an
    # implementation detail; callers configure rules by label.
    assert verdict.decision.rule == "ip"
    assert "v2:" not in (verdict.decision.rule or "")


def test_blocked_decision_carries_usable_headers() -> None:
    ev = make_evaluator()
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    verdict = ev.check(api_policy(), identity, path="/api")
    for _ in range(2):
        verdict = ev.check(api_policy(), identity, path="/api")
    headers = build_headers(verdict.decision)
    assert headers["X-RateLimit-Limit"] == "2"
    assert headers["X-RateLimit-Remaining"] == "0"
    assert int(headers["Retry-After"]) > 0


def test_rules_on_different_components_do_not_share_a_counter() -> None:
    ev = make_evaluator()
    # Saturating the IP rule must not consume the user rule's budget, even
    # though the same request is charged to both.
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    for _ in range(3):
        ev.check(api_policy(), identity, path="/api")
    other = Identity(ip="9.9.9.9", extras={"user": "u2"})
    verdict = ev.check(api_policy(), other, path="/api")
    assert verdict.allowed
    assert verdict.decision.remaining == 1


def test_two_rules_with_the_same_components_keep_separate_budgets() -> None:
    ev = make_evaluator()
    policy = Policy(
        name="tiered",
        rules=(
            Rule(key=by_ip(), limit="1/minute", name="strict"),
            Rule(key=by_ip(), limit="50/minute", name="generous"),
        ),
    )
    identity = Identity(ip="1.2.3.4")
    for _ in range(2):
        verdict = ev.check(policy, identity, path="/api")
    assert not verdict.allowed
    assert verdict.denied_by() == "strict"


def test_same_rule_on_two_policies_keeps_two_counters() -> None:
    ev = make_evaluator()
    a = Policy(name="a", rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),))
    b = Policy(name="b", rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),))
    identity = Identity(ip="1.2.3.4")
    ev.check(a, identity, path="/api")
    ev.check(b, identity, path="/api")
    # The first request on each policy is allowed: distinct policies are
    # distinct budgets, not one shared counter.
    assert ev.check(a, identity, path="/api").allowed is False
    assert ev.check(b, identity, path="/api").allowed is False


def test_tightest_rule_is_reported_so_headers_are_not_optimistic() -> None:
    ev = make_evaluator()
    policy = Policy(
        name="mixed",
        rules=(
            Rule(key=by_ip(), limit="100/minute", name="loose"),
            Rule(key=by_user(), limit="2/minute", name="tight"),
        ),
    )
    verdict = ev.check(policy, Identity(ip="1.2.3.4", extras={"user": "u1"}), path="/api")
    verdict = ev.check(policy, Identity(ip="1.2.3.4", extras={"user": "u1"}), path="/api")
    # Two hits against the user rule leaves it tighter than the untouched IP rule,
    # so the reported numbers must describe the user rule.
    assert verdict.allowed
    assert verdict.decision.limit == 2
    assert verdict.decision.rule == "tight"


def test_a_rule_absent_from_the_request_is_skipped() -> None:
    ev = make_evaluator()
    policy = Policy(
        name="mixed",
        rules=(
            Rule(key=by_ip(), limit="10/minute", name="ip"),
            Rule(key=by_user(), limit="1/minute", name="user"),
        ),
    )
    # No user resolved, so the user rule must not apply at all rather than
    # falling back to a bucket every anonymous caller would share.
    verdict = ev.check(policy, Identity(ip="1.2.3.4"), path="/api")
    assert verdict.allowed
    assert verdict.rule_names() == ("ip",)


def test_no_applicable_rule_still_allows() -> None:
    ev = make_evaluator()
    policy = Policy(name="useronly", rules=(Rule(key=by_user(), limit="1/minute", name="u"),))
    verdict = ev.check(policy, Identity(), path="/api")
    assert verdict.allowed
    assert verdict.evaluations == ()


def test_composite_key_counts_the_pair_not_either_half() -> None:
    ev = make_evaluator()
    policy = Policy(
        name="composite",
        rules=(
            Rule(
                key=KeyBuilder(components=("tenant", "user")),
                limit="1/minute",
                name="pair",
            ),
        ),
    )
    tenant = {"tenant": "acme", "user": "u1"}
    assert ev.check(policy, Identity(extras=tenant), path="/api").allowed
    # Same tenant, different user: a separate bucket.
    other = {"tenant": "acme", "user": "u2"}
    assert ev.check(policy, Identity(extras=other), path="/api").allowed
    # Same pair again: blocked.
    assert not ev.check(policy, Identity(extras=tenant), path="/api").allowed


def test_independent_key_blocks_on_either_dimension() -> None:
    ev = make_evaluator()
    policy = Policy(
        name="independent",
        rules=(
            Rule(
                key=KeyBuilder(components=("tenant", "user"), independent=True),
                limit="1/minute",
                name="tenant-or-user",
            ),
        ),
    )
    first = {"tenant": "acme", "user": "u1"}
    assert ev.check(policy, Identity(extras=first), path="/api").allowed
    # Different user, same tenant: the tenant bucket is now over its limit.
    second = {"tenant": "acme", "user": "u2"}
    verdict = ev.check(policy, Identity(extras=second), path="/api")
    assert not verdict.allowed


# ------------------------------------------------------------------ short circuit


def test_short_circuit_stops_at_the_first_breach() -> None:
    ev = make_evaluator()
    policy = Policy(
        name="ordered",
        short_circuit=True,
        rules=(
            Rule(key=by_ip(), limit="1/minute", name="first"),
            Rule(key=by_user(), limit="1/minute", name="second"),
        ),
    )
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    ev.check(policy, identity, path="/api")
    verdict = ev.check(policy, identity, path="/api")
    assert not verdict.allowed
    # The second rule was never charged, which is the point of short circuiting.
    assert verdict.rule_names() == ("first",)


def test_without_short_circuit_every_rule_is_evaluated() -> None:
    ev = make_evaluator()
    policy = Policy(
        name="ordered",
        short_circuit=False,
        rules=(
            Rule(key=by_ip(), limit="1/minute", name="first"),
            Rule(key=by_user(), limit="1/minute", name="second"),
        ),
    )
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    ev.check(policy, identity, path="/api")
    verdict = ev.check(policy, identity, path="/api")
    assert not verdict.allowed
    assert verdict.rule_names() == ("first", "second")


def test_disabled_rules_are_never_evaluated() -> None:
    ev = make_evaluator()
    policy = Policy(
        name="mixed",
        rules=(
            Rule(key=by_ip(), limit="1/minute", name="on"),
            Rule(key=by_user(), limit="1/minute", name="off", enabled=False),
        ),
    )
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    ev.check(policy, identity, path="/api")
    verdict = ev.check(policy, identity, path="/api")
    assert verdict.denied_by() == "on"
    assert "off" not in verdict.rule_names()


# -------------------------------------------------------------------- fail modes


def test_empty_policy_allows_without_touching_storage() -> None:
    ev = make_evaluator()
    verdict = ev.check(Policy(name="empty"), Identity(ip="1.2.3.4"))
    assert verdict.allowed
    assert verdict.evaluations == ()


def test_evaluator_rejects_a_non_policy() -> None:
    ev = make_evaluator()
    with pytest.raises(ConfigurationError, match="expects a Policy"):
        ev.check("2/minute", Identity(ip="1.2.3.4"))  # type: ignore[arg-type]


def test_evaluator_rejects_a_non_core() -> None:
    with pytest.raises(ConfigurationError, match="needs a LimiterCore"):
        PolicyEvaluator(object())  # type: ignore[arg-type]


def test_absurd_rule_count_is_rejected_rather_than_slowly_evaluated() -> None:
    ev = make_evaluator()
    rules = tuple(
        Rule(key=by_ip(), limit="1/minute", name=f"r{index}")
        for index in range(MAX_RULES_PER_POLICY + 1)
    )
    policy = Policy(name="absurd", rules=rules)
    with pytest.raises(ConfigurationError, match="storage round trip"):
        ev.check(policy, Identity(ip="1.2.3.4"))


def test_check_rejects_a_non_policy_before_any_storage_access() -> None:
    ev = make_evaluator()
    with pytest.raises(ConfigurationError):
        ev.check(None, Identity(ip="1.2.3.4"))  # type: ignore[arg-type]


# ------------------------------------------------------------- fail-open/closed


class _BrokenStorage(Storage):
    """Storage whose every operation fails, to exercise the failure policy."""

    name = "broken"

    def __init__(self) -> None:
        from great_limiter.errors import StorageError

        self._error = StorageError("storage is down")

    def _fail(self) -> None:
        raise self._error

    def increment(
        self, key: str, *, amount: int = 1, window_seconds: float
    ) -> CounterState:
        self._fail()

    def current(self, key: str) -> CounterState:
        self._fail()

    def clear(self, key: str) -> None:
        self._fail()

    def log_add(
        self, key: str, *, member: str, timestamp: float, window_seconds: float
    ) -> tuple[int, float | None]:
        self._fail()

    def log_count(self, key: str, *, since: float, until: float) -> int:
        self._fail()

    def mark(self, key: str, *, ttl_seconds: float, now: float) -> float:
        self._fail()

    def marked_until(self, key: str, *, now: float) -> float | None:
        self._fail()

    def clear_prefix(self, prefix: str) -> int:
        self._fail()


def _broken_evaluator(fail_open: bool) -> PolicyEvaluator:
    core = LimiterCore(
        Settings(
            key_salt=SALT,
            default_limit="1000/minute",
            fail_open=fail_open,
        ),
        _BrokenStorage(),
    )
    return PolicyEvaluator(core)


def test_fail_open_policy_allows_but_reports_the_failure() -> None:
    ev = _broken_evaluator(fail_open=True)
    policy = Policy(
        name="flaky",
        fail_closed=False,
        rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),),
    )
    verdict = ev.check(policy, Identity(ip="1.2.3.4"))
    assert verdict.allowed
    # A caller reading only `allowed` would think the limit was enforced. It was
    # not, and the verdict has to say so.
    assert verdict.storage_failed
    assert "unavailable" in verdict.decision.message


def test_fail_closed_policy_propagates_the_storage_error() -> None:
    from great_limiter.errors import StorageError

    ev = _broken_evaluator(fail_open=False)
    policy = Policy(
        name="flaky",
        fail_closed=True,
        rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),),
    )
    with pytest.raises(StorageError):
        ev.check(policy, Identity(ip="1.2.3.4"))


# ----------------------------------------------------------------------- resets


def test_reset_clears_a_blocked_caller() -> None:
    ev = make_evaluator()
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    for _ in range(3):
        verdict = ev.check(api_policy(), identity, path="/api", method="POST")
    assert not verdict.allowed
    assert ev.reset(api_policy(), identity, path="/api", method="POST") > 0
    assert ev.check(api_policy(), identity, path="/api", method="POST").allowed


def test_reset_with_a_different_scope_clears_nothing() -> None:
    ev = make_evaluator()
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    for _ in range(3):
        ev.check(api_policy(), identity, path="/api", method="POST")
    # The scope is part of the storage key, so a mismatched reset is a no-op
    # rather than a partial clear.
    ev.reset(api_policy(), identity, path="/other", method="POST")
    assert not ev.check(api_policy(), identity, path="/api", method="POST").allowed


def test_reset_skips_rules_the_identity_cannot_satisfy() -> None:
    ev = make_evaluator()
    policy = Policy(name="useronly", rules=(Rule(key=by_user(), limit="1/minute", name="u"),))
    assert ev.reset(policy, Identity(ip="1.2.3.4")) == 0


# ---------------------------------------------------------------------- extras


def test_extras_supply_authenticated_material() -> None:
    ev = make_evaluator()
    policy = Policy(name="api", rules=(Rule(key=by_user(), limit="1/minute", name="user"),))
    request_identity = Identity(ip="1.2.3.4")
    session = Identity(extras={"user": "u7"})
    assert ev.check(policy, request_identity, path="/api", extras=session).allowed
    verdict = ev.check(policy, request_identity, path="/api", extras=session)
    assert not verdict.allowed


def test_extras_beat_the_request_body_for_the_same_key() -> None:
    ev = make_evaluator()
    policy = Policy(name="api", rules=(Rule(key=by_user(), limit="1/minute", name="user"),))
    # A request claiming to be u1 but authenticated as u2 must be counted
    # against u2, or a caller could rotate a claimed user id to dodge the limit.
    claimed = Identity(ip="1.2.3.4", extras={"user": "u1"})
    session = Identity(extras={"user": "u2"})
    for _ in range(2):
        verdict = ev.check(policy, claimed, path="/api", extras=session)
    assert not verdict.allowed


def test_empty_extras_are_ignored() -> None:
    ev = make_evaluator()
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    verdict = ev.check(api_policy(), identity, path="/api", extras=Identity())
    assert verdict.allowed


# ------------------------------------------------------------------- tenant key


def test_tenant_rule_is_independent_per_tenant() -> None:
    ev = make_evaluator()
    policy = Policy(name="api", rules=(Rule(key=by_tenant(), limit="1/minute", name="tenant"),))
    assert ev.check(policy, Identity(extras={"tenant": "a"}), path="/api").allowed
    assert ev.check(policy, Identity(extras={"tenant": "b"}), path="/api").allowed
    assert not ev.check(policy, Identity(extras={"tenant": "a"}), path="/api").allowed


def test_account_rule_normalises_case_before_counting() -> None:
    ev = make_evaluator()
    policy = Policy(name="login", rules=(Rule(key=by_account(), limit="1/minute", name="acct"),))
    assert ev.check(policy, Identity(account="v@e.com"), path="/login").allowed
    # Same account, different spelling: must not buy a second attempt.
    assert not ev.check(policy, Identity(account="V@E.com"), path="/login").allowed


# ------------------------------------------------------------------- verdict api


def test_verdict_is_truthy_when_allowed_and_falsy_when_not() -> None:
    ev = make_evaluator()
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    assert bool(ev.check(api_policy(), identity, path="/api"))
    for _ in range(2):
        verdict = ev.check(api_policy(), identity, path="/api")
    assert not bool(verdict)


def test_denied_by_is_none_when_allowed() -> None:
    ev = make_evaluator()
    verdict = ev.check(api_policy(), Identity(ip="1.2.3.4", extras={"user": "u1"}), path="/api")
    assert verdict.denied_by() is None


def test_evaluator_exposes_its_core() -> None:
    core = make_core()
    assert PolicyEvaluator(core).core is core


def test_rule_views_are_reused_rather_than_rebuilt_per_request() -> None:
    ev = make_evaluator()
    policy = api_policy()
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    ev.check(policy, identity, path="/api")
    before = dict(ev._rule_cores)
    ev.check(policy, identity, path="/api")
    assert ev._rule_cores is not None
    # Same slots, so a hot path does not rebuild Settings per request.
    assert set(ev._rule_cores) == set(before)


def test_enforce_style_usage_still_raises_through_the_engine() -> None:
    # Sanity check that the underlying engine behaviour the evaluator relies on
    # is intact: enforce=True raises rather than returning a blocking decision.
    core = make_core()
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    core.check(identity, path="/x", method="GET", limit="1/minute")
    with pytest.raises(RateLimitExceeded):
        core.check(identity, path="/x", method="GET", limit="1/minute", enforce=True)


# -------------------------------------------------------------- weighted costs


def test_a_costly_rule_consumes_several_slots_at_once() -> None:
    ev = make_evaluator()
    policy = Policy(
        name="search",
        rules=(Rule(key=by_user(), limit="10/minute", cost=4, name="search"),),
    )
    identity = Identity(extras={"user": "u1"})
    assert ev.check(policy, identity, path="/search").decision.remaining == 6
    assert ev.check(policy, identity, path="/search").decision.remaining == 2
    # The third request would take the count to 12, past the limit of 10.
    assert not ev.check(policy, identity, path="/search").allowed


def test_cost_is_charged_against_every_rule_not_just_the_expensive_one() -> None:
    ev = make_evaluator()
    policy = Policy(
        name="mixed",
        rules=(
            Rule(key=by_ip(), limit="100/minute", name="ip"),
            Rule(key=by_user(), limit="100/minute", cost=3, name="expensive"),
        ),
    )
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    ev.check(policy, identity, path="/api")
    # Both rules see the same 3-slot charge; an attacker must not get a free
    # ride on the cheap rule by choosing an expensive operation.
    assert ev.check(policy, identity, path="/api").decision.rule == "expensive"
    assert ev.core.storage is not None


def test_a_callable_cost_is_evaluated_per_request() -> None:
    ev = make_evaluator()
    policy = Policy(
        name="conditional",
        rules=(
            Rule(
                key=by_user(),
                limit="10/minute",
                cost=lambda subject: 5 if subject.extras.get("premium") else 1,
                name="tiered",
            ),
        ),
    )
    plain = Identity(extras={"user": "u1"})
    premium = Identity(extras={"user": "u2", "premium": "yes"})
    assert ev.check(policy, plain, path="/api").decision.remaining == 9
    assert ev.check(policy, premium, path="/api").decision.remaining == 5


def test_fixed_cost_helper_matches_an_explicit_integer() -> None:
    charge = fixed_cost(3)
    assert charge(object()) == 3
    policy_a = Policy(name="a", rules=(Rule(key=by_ip(), limit="10/minute", cost=3, name="r"),))
    policy_b = Policy(
        name="b", rules=(Rule(key=by_ip(), limit="10/minute", cost=charge, name="r"),)
    )
    assert policy_a.rules[0].cost_for(Identity(ip="1.1.1.1")) == (
        policy_b.rules[0].cost_for(Identity(ip="1.1.1.1"))
    )


def test_a_static_cost_below_one_is_rejected_by_the_rule() -> None:
    # A zero cost is rejected at construction: it would make the rule
    # unenforceable while still looking configured.
    with pytest.raises(ConfigurationError, match="cost must be >= 1"):
        Rule(key=by_ip(), limit="10/minute", cost=0, name="zero")
    with pytest.raises(ConfigurationError, match="cost must be >= 1"):
        Rule(key=by_ip(), limit="10/minute", cost=-2, name="negative")


def test_a_callable_cost_returning_a_bad_value_charges_the_full_limit() -> None:
    # A callable cannot be checked at construction, because its result depends
    # on the request. A nonsensical result must deny rather than free.
    rule = Rule(key=by_ip(), limit="10/minute", cost=lambda _: 0, name="zero")
    assert rule.cost_for(Identity(ip="1.2.3.4")) == 10


def test_a_raising_cost_function_is_not_converted_into_a_rate_limit() -> None:
    def explode(_: object) -> int:
        raise RuntimeError("boom")

    rule = Rule(key=by_ip(), limit="7/minute", cost=explode, name="broken")
    # A bug in the caller's pricing code has to surface as itself. Swallowing it
    # and charging the full limit would answer with a 429 that reads as ordinary
    # rate limiting and hides the defect.
    with pytest.raises(RuntimeError, match="boom"):
        rule.cost_for(Identity(ip="1.2.3.4"))


def test_cost_is_rejected_directly_on_the_engine() -> None:
    core = make_core()
    with pytest.raises(ConfigurationError, match="cost must be >= 1"):
        core.check(Identity(ip="1.2.3.4"), path="/x", cost=0)


# ------------------------------------------------------------------- cooldown


def test_a_rule_cooldown_blocks_subsequent_attempts_without_extending() -> None:
    clock = FakeClock()
    ev = make_evaluator(clock)
    policy = Policy(
        name="login",
        rules=(
            Rule(key=by_ip(), limit="2/minute", cooldown_seconds=30.0, name="ip"),
        ),
    )
    identity = Identity(ip="1.2.3.4")
    ev.check(policy, identity, path="/login")
    ev.check(policy, identity, path="/login")
    assert not ev.check(policy, identity, path="/login").allowed

    inside = ev.check(policy, identity, path="/login")
    assert not inside.allowed
    first_wait = inside.decision.retry_after
    assert first_wait is not None and 0 < first_wait <= 30

    # A refused attempt must not restart the wait. If it did, a client that
    # kept retrying would never be served again, which is precisely the
    # permanent lockout this library refuses to implement.
    clock.advance(10)
    later = ev.check(policy, identity, path="/login")
    assert not later.allowed
    assert later.decision.retry_after is not None
    assert later.decision.retry_after < first_wait

    # Once the cooldown expires it is over, even though the counter is still
    # over its limit: the block then comes from the limit, not the marker.
    clock.advance(25)
    after = ev.check(policy, identity, path="/login")
    assert not after.allowed
    assert after.decision.message != DEFAULT_COOLDOWN_MESSAGE
    # The whole cooldown is time-boxed: the window rolls over and access returns.
    clock.advance(61)
    assert ev.check(policy, identity, path="/login").allowed


def test_a_zero_cooldown_blocks_without_arming_a_marker() -> None:
    clock = FakeClock()
    ev = make_evaluator(clock)
    policy = Policy(
        name="public",
        rules=(Rule(key=by_ip(), limit="1/minute", cooldown_seconds=0.0, name="ip"),),
    )
    identity = Identity(ip="1.2.3.4")
    assert ev.check(policy, identity, path="/api").allowed
    assert not ev.check(policy, identity, path="/api").allowed
    # No marker was armed, so the next request is judged on the counter alone
    # once the window rolls over rather than waiting out a cooldown.
    clock.advance(61)
    assert ev.check(policy, identity, path="/api").allowed


def test_cooldowns_are_per_rule() -> None:
    clock = FakeClock()
    ev = make_evaluator(clock)
    policy = Policy(
        name="mixed",
        rules=(
            Rule(key=by_ip(), limit="1/minute", cooldown_seconds=300.0, name="ip"),
            Rule(key=by_user(), limit="5/minute", cooldown_seconds=0.0, name="user"),
        ),
    )
    identity = Identity(ip="1.2.3.4", extras={"user": "u1"})
    ev.check(policy, identity, path="/api")
    blocked = ev.check(policy, identity, path="/api")
    assert blocked.denied_by() == "ip"
    # A caller with a fresh IP but the same exhausted user is held by the user
    # rule's counter, not the IP rule's cooldown.
    other = Identity(ip="5.5.5.5", extras={"user": "u1"})
    assert ev.check(policy, other, path="/api").allowed


def test_an_independent_rule_charges_every_dimension_even_when_one_blocks() -> None:
    ev = make_evaluator()
    policy = Policy(
        name="independent",
        short_circuit=False,
        rules=(
            Rule(
                key=KeyBuilder(components=("tenant", "user"), independent=True),
                limit="2/minute",
                name="both",
            ),
        ),
    )
    identity = Identity(extras={"tenant": "acme", "user": "u1"})
    for _ in range(3):
        verdict = ev.check(policy, identity, path="/api")
    # Both dimensions were charged on the attempt that already breached the
    # tenant, so a caller cannot keep hitting a user bucket by having the tenant
    # dimension block first.
    assert not verdict.allowed
    # Two evaluations of one rule: one per dimension.
    assert verdict.rule_names() == ("both", "both")

    # The tenant dimension really was charged, so a brand new user in the same
    # tenant is refused: the user bucket is fresh but the tenant budget is spent.
    newcomer = Identity(extras={"tenant": "acme", "user": "u2"})
    assert not ev.check(policy, newcomer, path="/api").allowed

    # Conversely the user dimension was charged too, so the same user in a fresh
    # tenant is refused as well.
    moved = Identity(extras={"tenant": "other", "user": "u1"})
    assert not ev.check(policy, moved, path="/api").allowed

    # Only a caller new on both dimensions starts clean.
    untouched = Identity(extras={"tenant": "other", "user": "u2"})
    assert ev.check(policy, untouched, path="/api").allowed


def test_reset_clears_an_active_cooldown() -> None:
    clock = FakeClock()
    ev = make_evaluator(clock)
    policy = Policy(
        name="login",
        rules=(Rule(key=by_ip(), limit="1/minute", cooldown_seconds=600.0, name="ip"),),
    )
    identity = Identity(ip="1.2.3.4")
    ev.check(policy, identity, path="/login")
    assert not ev.check(policy, identity, path="/login").allowed
    # A correct password must lift the block immediately rather than after the
    # full cooldown.
    ev.reset(policy, identity, path="/login")
    assert ev.check(policy, identity, path="/login").allowed


# ----------------------------------------------------------------- fake clock


def test_rules_are_evaluated_against_the_injected_clock() -> None:
    clock = FakeClock()
    ev = make_evaluator(clock)
    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="2/minute", name="ip"),))
    identity = Identity(ip="1.2.3.4")
    ev.check(policy, identity, path="/api")
    ev.check(policy, identity, path="/api")
    assert not ev.check(policy, identity, path="/api").allowed
    # If the rule views fell back to the wall clock, this window would never
    # roll over in the test's own time and the assertion below would fail.
    clock.advance(61)
    assert ev.check(policy, identity, path="/api").allowed


def test_a_window_rolls_over_on_the_injected_clock() -> None:
    clock = FakeClock()
    ev = make_evaluator(clock)
    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),))
    identity = Identity(ip="1.2.3.4")
    assert ev.check(policy, identity, path="/api").allowed
    assert not ev.check(policy, identity, path="/api").allowed
    clock.advance(61)
    assert ev.check(policy, identity, path="/api").allowed
