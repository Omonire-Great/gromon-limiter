"""V2 policy evaluation on top of :class:`~great_limiter.core.LimiterCore`.

V1's engine knows about two rules, ``ip`` and ``account``, because that is all an
authentication endpoint needs. V2 needs an arbitrary number of rules, each with
its own key, limit, cost and cooldown, declared as data
(:mod:`great_limiter.policies`).

Rather than fork the algorithm code, this module **reuses** ``LimiterCore`` as the
counter: each V2 rule is evaluated by calling ``core.check`` with an
:class:`~great_limiter.identifiers.Identity` pre-seeded to match exactly the
components that rule cares about, and a per-rule scope. The engine's
cooldown handling, storage atomicity and header building then apply unchanged.

The trade-off is deliberate and worth stating plainly: one Redis round trip per
rule, versus one for a V1 request. For the endpoints this targets — login, MFA,
payments, admin — the request count is low and the correctness matters more than
the round trip. A caller with fifty rules should not have fifty.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import replace
from typing import Any

from great_limiter.core import Decision, LimiterCore
from great_limiter.errors import ConfigurationError, StorageError
from great_limiter.identifiers import Identity
from great_limiter.policies import Policy, Rule

__all__ = [
    "PolicyDecision",
    "PolicyEvaluator",
    "PolicyVerdict",
]

logger = logging.getLogger("great_limiter")

#: Safety valve. A policy with more rules than this is almost certainly a
#: configuration mistake, and evaluating it literally would issue one storage
#: round trip per rule on every request.
MAX_RULES_PER_POLICY = 32


class PolicyVerdict:
    """Aggregate outcome of evaluating a whole policy.

    Not a dataclass because ``Decision`` is compared in tests by value and this
    wraps a *list* of them, which would need a custom ``__eq__`` to stay useful.
    A small class with explicit attributes reads better at the call site.
    """

    __slots__ = ("allowed", "decision", "evaluations", "storage_failed")

    def __init__(
        self,
        allowed: bool,
        decision: Decision,
        evaluations: Sequence[tuple[Rule, Decision]],
        storage_failed: bool = False,
    ) -> None:
        self.allowed = allowed
        #: The decision that denied the request, or the tightest allowing one.
        self.decision = decision
        #: Every rule that was evaluated, in policy order.
        self.evaluations = tuple(evaluations)
        #: True when a storage error was absorbed by fail-open behaviour, so
        #: ``allowed`` is "allowed because we could not tell", not "allowed".
        self.storage_failed = storage_failed

    def __bool__(self) -> bool:
        return self.allowed

    def rule_names(self) -> tuple[str, ...]:
        return tuple(rule.label for rule, _ in self.evaluations)

    def denied_by(self) -> str | None:
        """Label of the rule that blocked, or ``None`` when allowed."""
        if self.allowed:
            return None
        return self.decision.rule

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        state = "allowed" if self.allowed else f"blocked by {self.denied_by()}"
        return f"PolicyVerdict({state}, rules={list(self.rule_names())})"


#: Backwards-friendly alias. ``PolicyDecision`` reads better in type hints where
#: the reader expects a noun, ``PolicyVerdict`` where they expect a judgement.
PolicyDecision = PolicyVerdict


class PolicyEvaluator:
    """Evaluates a :class:`~great_limiter.policies.Policy` through the engine."""

    __slots__ = ("_core", "_rule_cores")

    def __init__(self, core: LimiterCore) -> None:
        if not isinstance(core, LimiterCore):
            raise ConfigurationError(
                f"PolicyEvaluator needs a LimiterCore, got {type(core).__name__}"
            )
        self._core = core
        # One engine view per (policy, rule), each restricted to a single
        # synthetic identifier. Built once and reused: constructing a Settings
        # per request would be visible in the hot path.
        self._rule_cores: dict[tuple[str, str], LimiterCore] = {}

    @property
    def core(self) -> LimiterCore:
        return self._core

    def _core_for(self, policy: Policy, rule: Rule) -> tuple[LimiterCore, str]:
        """Return the engine view keyed on exactly this rule's material.

        ``LimiterCore`` derives its key from the identifiers named in
        ``Settings.identifier``. Restricting a copy of the settings to one
        synthetic identifier is what makes a V2 rule evaluate through the V1
        engine: the engine sees a single component and treats it as the whole
        identity, so unrelated budgets never merge.

        The view is cached per rule rather than per caller. That works because
        the view keys on a synthetic *name*, and the caller's material is passed
        in as that name's value, so one view serves every caller while each
        caller still gets its own counter.
        """
        slot = (policy.name, rule.label)
        existing = self._rule_cores.get(slot)
        component = _component_name(policy, rule)
        if existing is not None:
            return existing, component
        overrides: dict[str, Any] = {
            "identifier": (component,),
            # The synthetic identifier is not "account", so the account
            # multiplier cannot apply: a V2 rule's limit is exactly what the
            # policy says, with no hidden scaling.
            "extra_identifier_fields": frozenset({component}),
            "account_limit_multiplier": 1.0,
        }
        if rule.cooldown_seconds is not None:
            # A per-rule cooldown overrides the engine-wide default, and
            # zero is meaningful here: it means "block on breach without arming a
            # marker", which is what a cheap public endpoint usually wants.
            overrides["cooldown_seconds"] = rule.cooldown_seconds
        scoped = LimiterCore(
            self._core.settings.with_overrides(**overrides),
            self._core.storage,
            # Share the engine's clock, otherwise a test that injects a fake time
            # source would silently evaluate V2 rules against the wall clock.
            clock=self._core.clock,
        )
        self._rule_cores[slot] = scoped
        return scoped, component

    def check(
        self,
        policy: Policy,
        identity: Identity,
        *,
        path: str = "/",
        method: str = "GET",
        extras: Identity | None = None,
    ) -> PolicyVerdict:
        """Evaluate every enabled rule in ``policy`` against ``identity``.

        ``extras`` carries authenticated material (``user``, ``tenant``,
        ``api_key``) that is not on the request itself, so a caller can pass the
        unauthenticated request identity and the resolved session separately.
        """
        if not isinstance(policy, Policy):
            raise ConfigurationError(
                f"check expects a Policy, got {type(policy).__name__}"
            )
        rules = policy.enabled_rules
        if not rules:
            return PolicyVerdict(True, Decision(allowed=True, message="policy has no rules"), ())
        if len(rules) > MAX_RULES_PER_POLICY:
            raise ConfigurationError(
                f"policy {policy.name!r} has {len(rules)} rules, the limit is "
                f"{MAX_RULES_PER_POLICY}; each rule costs a storage round trip"
            )

        merged = _merge(identity, extras)
        evaluations: list[tuple[Rule, Decision]] = []
        blocked: list[Decision] = []
        storage_failed = False

        for rule in rules:
            materials = _materials_for(rule, merged)
            if not materials:
                # The rule's components are not present on this request, so there
                # is nothing to count. Skipping is correct: the alternative is a
                # shared fallback bucket that one caller could exhaust on
                # everyone's behalf.
                continue
            rule_core, component = self._core_for(policy, rule)
            cost = rule.cost_for(merged)
            for material in materials:
                try:
                    decision = rule_core.check(
                        Identity(extras={component: material}),
                        path=_rule_scope(rule, path, policy),
                        method=method,
                        limit=rule.limit,
                        cost=cost,
                    )
                except StorageError:
                    if policy.fail_closed:
                        raise
                    # Fail open, but say so. A caller reading only `allowed` would
                    # otherwise believe the limit was enforced when nothing was
                    # counted.
                    storage_failed = True
                    logger.warning(
                        "great_limiter: storage unavailable, allowing request under "
                        "policy %r (fail-open)",
                        policy.name,
                    )
                    evaluations.append(
                        (rule, Decision(allowed=True, message="storage unavailable"))
                    )
                    continue

                if decision.storage_failed:
                    # The engine failed open internally; carry the signal up so
                    # `storage_failed` is true regardless of which layer swallowed
                    # the error.
                    storage_failed = True

                evaluations.append((rule, decision))
                if not decision.allowed:
                    blocked.append(_relabel(decision, rule))
                    if policy.short_circuit:
                        return PolicyVerdict(False, blocked[-1], evaluations)
                    # Without short circuiting, keep charging the remaining
                    # rules so every budget reflects this request. They still all
                    # have to pass for the request to be allowed.
                    continue

        if blocked:
            # Reached only when short_circuit is off: at least one rule denied.
            return PolicyVerdict(False, blocked[0], evaluations)
        if not evaluations:
            return PolicyVerdict(
                True, Decision(allowed=True, message="no rule applied to this request"), ()
            )
        if storage_failed:
            return PolicyVerdict(
                True,
                Decision(
                    allowed=True,
                    message="storage unavailable (fail-open)",
                    storage_failed=True,
                ),
                evaluations,
                storage_failed=True,
            )
        tightest_rule, tightest_decision = _tightest(evaluations)
        return PolicyVerdict(True, _relabel(tightest_decision, tightest_rule), evaluations)

    def reset(
        self,
        policy: Policy,
        identity: Identity,
        *,
        path: str = "/",
        method: str = "GET",
        extras: Identity | None = None,
    ) -> int:
        """Clear every counter this policy would charge for ``identity``.

        ``path`` and ``method`` must match the values used when the limit was
        charged, because the scope is part of the storage key. Call this after a
        successful authentication so a legitimate user is not left blocked by
        their own earlier typos.
        """
        merged = _merge(identity, extras)
        total = 0
        for rule in policy.enabled_rules:
            materials = _materials_for(rule, merged)
            if not materials:
                continue
            rule_core, component = self._core_for(policy, rule)
            for material in materials:
                # The scope has to match the one used at check time or the
                # counters cleared here are not the ones the next request will
                # read. A successful login must actually lift the limit.
                total += rule_core.reset(
                    Identity(extras={component: material}),
                    path=_rule_scope(rule, path, policy),
                    method=method,
                )
        return total


def _merge(identity: Identity, extras: Identity | None) -> Identity:
    """Combine the request identity with authenticated extras.

    Explicit extras win on conflict: a user id established by authentication is
    more trustworthy than anything the request body claimed under the same key.
    """
    if extras is None:
        return identity
    if not extras.extras and not extras.account and not extras.ip:
        return identity
    combined = dict(identity.extras)
    combined.update(extras.extras)
    return Identity(
        ip=extras.ip or identity.ip,
        account=extras.account or identity.account,
        extras=combined,
    )


def _component_name(policy: Policy, rule: Rule) -> str:
    """Synthetic identifier name for one rule.

    It carries the policy and rule labels so two policies, or two rules, can
    never be reduced to the same engine view. The separators are stripped from
    the labels because a newline in an identifier name would end up in a
    Redis key.
    """
    safe_policy = policy.name.replace("\r", " ").replace("\n", " ")
    safe_rule = rule.label.replace("\r", " ").replace("\n", " ")
    return f"v2:{safe_policy}:{safe_rule}"


def _materials_for(rule: Rule, identity: Identity) -> tuple[str, ...]:
    """Reduce ``identity`` to the opaque values one rule counts against.

    The projection is what lets the V1 engine evaluate an arbitrary rule. The
    engine derives key material from the identity it is handed, so handing it one
    component makes that component the whole key; passing the full identity would
    fold every identifier into every rule's key and merge unrelated budgets.

    A builder with several components but ``independent=False`` describes a
    single bucket keyed on the composite, so it yields one value. An
    ``independent=True`` builder describes several buckets, and every one of them
    has to be charged: a tenant-wide cap means a request is limited by the
    tenant's budget and by the user's, not by either alone.
    """
    material = rule.key.materials_or_none(identity)
    if not material:
        return ()
    # The unit separator keeps the pieces unambiguously joined, so a component
    # value containing the separator cannot forge another composite.
    return tuple("␟".join(bucket) for bucket in material)


def _rule_scope(rule: Rule, path: str, policy: Policy) -> str:
    """Build a per-rule scope so two rules on one route keep separate counters.

    Without the rule label in the scope, a policy with a 10/min and a 100/min
    rule on the same endpoint would share one counter and the tighter rule would
    appear to be the looser one.
    """
    return f"{path}#policy={policy.name}#rule={rule.label}"


def _relabel(decision: Decision, rule: Rule | None) -> Decision:
    """Replace the engine's synthetic rule name with the policy's own label.

    The engine reports the identifier it keyed on, which here is an internal
    ``v2:<policy>:<rule>`` string. Callers configure rules by their label and
    logs and audit trails should show that, not the implementation detail.
    """
    if rule is None or decision.rule == rule.label:
        return decision
    return replace(decision, rule=rule.label)


def _tightest(evaluations: Sequence[tuple[Rule, Decision]]) -> tuple[Rule | None, Decision]:
    """Return the rule and decision with the least headroom left.

    The headers a client sees should describe the rule closest to its limit, not
    whichever rule happened to be evaluated first.
    """
    best: tuple[Rule | None, Decision] | None = None
    best_ratio = 2.0
    for rule, decision in evaluations:
        if decision.limit is None or decision.limit <= 0:
            continue
        remaining = decision.remaining if decision.remaining is not None else 0
        ratio = remaining / decision.limit
        if ratio < best_ratio:
            best_ratio = ratio
            best = (rule, decision)
    if best is None:
        return None, Decision(allowed=True)
    return best
