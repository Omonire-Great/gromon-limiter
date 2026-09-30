"""Tests for the V2 key builder and policy data model."""

from __future__ import annotations

import pytest

from omonire_limiter import ConfigurationError
from omonire_limiter.identifiers import Identity
from omonire_limiter.limits import RateLimit
from omonire_limiter.policies import (
    KeyBuilder,
    Policy,
    Rule,
    by_account,
    by_api_key,
    by_ip,
    by_route,
    by_tenant,
    by_user,
    compose_key,
    constant_time_equals,
    fixed_cost,
    rules_for,
)

SALT = "test-salt-value-long-enough"


def test_by_ip_builds_one_bucket() -> None:
    identity = Identity(ip="203.0.113.5")
    assert by_ip().materials(identity) == (("ip=203.0.113.5",),)


def test_account_is_case_folded_so_case_cannot_double_a_budget() -> None:
    lower = Identity(account="victim@example.com")
    upper = Identity(account="Victim@Example.COM")
    assert by_account().materials(lower) == by_account().materials(upper)


def test_ip_is_canonicalised_so_ipv4_mapped_cannot_bypass() -> None:
    plain = Identity(ip="1.2.3.4")
    mapped = Identity(ip="::ffff:1.2.3.4")
    assert by_ip().materials(plain) == by_ip().materials(mapped)


def test_unresolvable_identity_raises_rather_than_collapsing_anonymity() -> None:
    with pytest.raises(ConfigurationError, match="cannot resolve an identity"):
        by_user().materials(Identity(ip="1.2.3.4"))


def test_fallback_names_what_is_used_when_identity_is_absent() -> None:
    builder = KeyBuilder(components=("user",), fallback="anonymous")
    assert builder.materials(Identity()) == (("fallback=anonymous",),)


def test_independent_builder_yields_one_bucket_per_component() -> None:
    builder = KeyBuilder(components=("tenant", "user"), independent=True)
    identity = Identity(extras={"tenant": "acme", "user": "u-7"})
    assert builder.materials(identity) == (("tenant=acme",), ("user=u-7",))


def test_independent_builder_skips_absent_components() -> None:
    builder = KeyBuilder(components=("tenant", "user"), independent=True)
    assert builder.materials(Identity(extras={"user": "u-7"})) == (("user=u-7",),)


def test_composite_builder_is_all_of_the_components_together() -> None:
    builder = KeyBuilder(components=("tenant", "user"))
    identity = Identity(extras={"tenant": "acme", "user": "u-7"})
    assert builder.materials(identity) == (("tenant=acme", "user=u-7"),)


def test_partial_identity_degrades_to_what_was_present() -> None:
    builder = KeyBuilder(components=("tenant", "user"))
    assert builder.materials(Identity(extras={"user": "u-7"})) == (("user=u-7",),)


def test_two_caller_sharing_a_tenant_do_not_share_a_bucket() -> None:
    builder = KeyBuilder(components=("tenant", "user"))
    one = builder.materials(Identity(extras={"tenant": "acme", "user": "u-1"}))
    two = builder.materials(Identity(extras={"tenant": "acme", "user": "u-2"}))
    assert one != two


def test_compose_key_cannot_be_forged_into_a_collision() -> None:
    # Without escaping, a value containing the separator could be crafted to
    # produce the same joined key as a different component split.
    forged = compose_key("user=a", "b")
    honest = compose_key("user=ab", "")
    assert forged != honest


def test_compose_key_drops_empty_components() -> None:
    assert compose_key("a", None, "b", "") == "a\x1fb"


def test_fingerprint_is_stable_and_never_reveals_input() -> None:
    builder = by_account()
    identity = Identity(account="victim@example.com")
    first = builder.fingerprint(SALT, identity)
    assert first == builder.fingerprint(SALT, identity)
    assert "victim" not in first[0] and "example" not in first[0]


def test_a_different_salt_yields_a_different_key_space() -> None:
    identity = Identity(ip="1.2.3.4")
    assert by_ip().fingerprint(SALT, identity) != by_ip().fingerprint(
        "a-completely-different-salt", identity
    )


def test_prefix_separates_two_rules_with_identical_components() -> None:
    identity = Identity(ip="1.2.3.4")
    plain = by_ip().fingerprint(SALT, identity)
    prefixed = KeyBuilder(components=("ip",), prefix="login").fingerprint(SALT, identity)
    assert plain != prefixed


def test_route_builder_needs_route_material_supplied() -> None:
    with pytest.raises(ConfigurationError):
        by_route().materials(Identity(ip="1.2.3.4"))


def test_key_builder_rejects_empty_components() -> None:
    with pytest.raises(ConfigurationError, match="at least one component"):
        KeyBuilder(components=())


def test_key_builder_rejects_duplicate_components() -> None:
    with pytest.raises(ConfigurationError, match="unique"):
        KeyBuilder(components=("ip", "ip"))


def test_key_builder_rejects_blank_component_names() -> None:
    with pytest.raises(ConfigurationError, match="non-empty"):
        KeyBuilder(components=("ip", "  "))


def test_key_builder_rejects_newline_in_prefix() -> None:
    with pytest.raises(ConfigurationError, match="newlines"):
        KeyBuilder(components=("ip",), prefix="a\nb")


def test_named_builders_use_the_expected_component() -> None:
    identity = Identity(extras={"user": "u-1", "tenant": "acme", "api_key": "key-9"})
    assert by_user().materials(identity) == (("user=u-1",),)
    assert by_tenant().materials(identity) == (("tenant=acme",),)
    assert by_api_key().materials(identity) == (("api_key=key-9",),)


def test_rule_accepts_a_limit_string() -> None:
    rule = Rule(key=by_ip(), limit="5/minute")
    assert isinstance(rule.limit, RateLimit)
    assert rule.limit.limit == 5


def test_rule_rejects_an_unusable_limit() -> None:
    with pytest.raises(ConfigurationError, match="limit string"):
        Rule(key=by_ip(), limit=object())  # type: ignore[arg-type]


def test_rule_rejects_a_bool_cost() -> None:
    with pytest.raises(ConfigurationError, match="cost"):
        Rule(key=by_ip(), limit="1/minute", cost=True)


def test_rule_rejects_negative_cost() -> None:
    with pytest.raises(ConfigurationError, match="cost"):
        Rule(key=by_ip(), limit="1/minute", cost=-1)


def test_fixed_cost_helper() -> None:
    cost = fixed_cost(20)
    assert cost(object()) == 20


def test_fixed_cost_rejects_a_negative_value() -> None:
    with pytest.raises(ConfigurationError, match="cost"):
        fixed_cost(-5)


def test_weighted_rule_charges_the_configured_cost() -> None:
    rule = Rule(key=by_ip(), limit="1000/hour", cost=fixed_cost(20))
    assert rule.cost_for(object()) == 20


def test_broken_cost_function_denies_rather_than_charging_nothing() -> None:
    def bad(_: object) -> int:
        return -99  # type: ignore[return-value]

    rule = Rule(key=by_ip(), limit="10/minute", cost=bad)
    # Falling back to the whole limit is the safe reading: a mis-priced
    # operation must not become free.
    assert rule.cost_for(object()) == 10


def test_raising_cost_function_is_not_swallowed_silently() -> None:
    def bad(_: object) -> int:
        raise RuntimeError("boom")

    rule = Rule(key=by_ip(), limit="10/minute", cost=bad)
    with pytest.raises(RuntimeError, match="boom"):
        rule.cost_for(object())


def test_rule_label_falls_back_to_its_components() -> None:
    assert Rule(key=by_ip(), limit="1/minute").label == "ip"
    assert Rule(key=by_ip(), limit="1/minute", name="login").label == "login"


def test_policy_keeps_every_rule_rather_than_merging_shared_keys() -> None:
    policy = Policy(
        name="login",
        rules=(
            Rule(key=by_ip(), limit="10/minute", name="ip"),
            Rule(key=by_ip(), limit="3/minute", name="ip-strict"),
        ),
    )
    keys = policy.all_keys(SALT, Identity(ip="1.2.3.4"))
    assert set(keys) == {"ip", "ip-strict"}
    # Separate budgets: a hit on one must not consume the other.
    assert keys["ip"] != keys["ip-strict"]


def test_policy_excludes_disabled_rules_from_evaluation() -> None:
    policy = Policy(
        name="api",
        rules=(
            Rule(key=by_ip(), limit="10/minute", name="on"),
            Rule(key=by_user(), limit="1/minute", name="off", enabled=False),
        ),
    )
    assert policy.labels() == ("on",)
    assert "off" not in policy.all_keys(SALT, Identity(ip="1.2.3.4"))


def test_disabled_only_policy_is_empty_and_skippable() -> None:
    policy = Policy(
        name="api",
        rules=(Rule(key=by_user(), limit="1/minute", name="off", enabled=False),),
    )
    assert policy.is_empty()


def test_policy_rejects_a_non_rule() -> None:
    with pytest.raises(ConfigurationError, match="expected Rule"):
        Policy(name="api", rules=("1/minute",))  # type: ignore[arg-type]


def test_policy_rejects_a_blank_name() -> None:
    with pytest.raises(ConfigurationError, match="non-empty"):
        Policy(name="  ")


def test_policy_rejects_a_newline_in_the_name() -> None:
    with pytest.raises(ConfigurationError, match="newlines"):
        Policy(name="api\nv2")


def test_policy_with_rules_returns_a_new_object() -> None:
    base = Policy(name="api", rules=(Rule(key=by_ip(), limit="1/minute", name="a"),))
    extended = base.with_rules(Rule(key=by_user(), limit="1/minute", name="b"))
    assert len(base.rules) == 1
    assert len(extended.rules) == 2


def test_policy_rule_lookup_by_label() -> None:
    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="1/minute", name="a"),))
    assert policy.rule_named("a") is not None
    assert policy.rule_named("missing") is None


def test_rules_for_freezes_and_validates_decorator_input() -> None:
    rule = Rule(key=by_ip(), limit="1/minute")
    assert rules_for([rule]) == (rule,)


def test_rules_for_rejects_a_raw_limit_string() -> None:
    with pytest.raises(ConfigurationError, match="expected Rule"):
        rules_for(["1/minute"])  # type: ignore[list-item]


def test_constant_time_equals_matches_only_identical_strings() -> None:
    assert constant_time_equals("abc", "abc")
    assert not constant_time_equals("abc", "abd")
