"""Tests for the V2 policy-aware Limiter entry point."""

from __future__ import annotations

import pytest

from g3_limiter import (
    AuthLimiter,
    ConfigurationError,
    Identity,
    Limiter,
    Policy,
    Rule,
    by_ip,
    by_user,
)


def _policy() -> Policy:
    return Policy(
        name="api",
        rules=(
            Rule(key=by_ip(), limit="100/minute", name="ip"),
            Rule(key=by_user(), limit="20/minute", name="user"),
        ),
    )


def test_for_policy_attaches_the_policy() -> None:
    limiter = Limiter.for_policy(_policy())
    assert limiter.default_policy is not None
    assert limiter.default_policy.name == "api"


def test_policy_for_returns_the_default_when_no_override() -> None:
    limiter = Limiter.for_policy(_policy())
    assert limiter.policy_for().name == "api"


def test_per_route_policy_overrides_the_default() -> None:
    limiter = Limiter.for_policy(_policy())
    override = Policy(name="payments", rules=(Rule(key=by_user(), limit="5/hour", name="u"),))
    assert limiter.policy_for(override).name == "payments"


def test_unbound_limiter_has_no_policy_and_skips_evaluation() -> None:
    # A V1 application that never declares a policy must not gain one, and must
    # not have to construct an empty Policy to say "no limits here".
    assert Limiter().policy_for() is None


def test_empty_policy_is_skipped_rather_than_evaluated() -> None:
    empty = Policy(name="all-rules-disabled", rules=())
    assert Limiter.for_policy(empty).policy_for() is None


def test_policy_with_only_disabled_rules_is_skipped() -> None:
    policy = Policy(
        name="observability-only",
        rules=(Rule(key=by_ip(), limit="1/minute", name="off", enabled=False),),
    )
    assert Limiter.for_policy(policy).policy_for() is None


def test_for_policy_rejects_a_non_policy() -> None:
    with pytest.raises(ConfigurationError, match="expects a Policy"):
        Limiter.for_policy("100/minute")  # type: ignore[arg-type]


def test_auth_limiter_carries_a_none_policy_default() -> None:
    # V1 gains no behaviour. The attribute exists with a None default so an
    # adapter can read it off any limiter without a getattr dance, but V1
    # deliberately has no policy_for(): with no policies to resolve, the method
    # would be dead weight on the entry point most V1 users touch.
    limiter = AuthLimiter()
    assert limiter.default_policy is None
    assert not hasattr(limiter, "policy_for")


def test_policy_keys_resolve_per_rule_for_a_real_identity() -> None:
    identity = Identity(ip="1.2.3.4", extras={"user": "u-9"})
    keys = _policy().all_keys("a-salt-long-enough-for-tests", identity)
    assert set(keys) == {"ip", "user"}
    assert all(len(key) == 1 for key in keys.values())
