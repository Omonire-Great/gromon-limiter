"""V2: turning a request into one or more independent limiter rules.

A rule answers three questions and nothing else:

* **who** is being limited (the key),
* **how much** they get (the limit),
* **what happens** when they run out (the response).

Keeping those separate is what lets V1's auth case and V2's general API case
share one engine. An auth endpoint limits *one* rule per identifier with a
cooldown; a payments endpoint needs *several* rules at different costs, and an
admin panel needs *asymmetric* limits by role.

Two design rules from V1 are preserved deliberately:

1. **No raw input in a key.** Every key is HMAC-fingerprinted before it reaches
   storage, so a user id or tenant name never lands in a Redis key.
2. **No permanent punishment.** A rule may be temporarily blocked; nothing here
   can lock an account forever.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from great_limiter.errors import ConfigurationError
from great_limiter.identifiers import (
    Identity,
    fingerprint,
    normalize_account,
    normalize_ip,
)
from great_limiter.limits import RateLimit

__all__ = [
    "KeyBuilder",
    "Policy",
    "Rule",
    "by_account",
    "by_api_key",
    "by_ip",
    "by_route",
    "by_tenant",
    "by_user",
    "compose_key",
    "fixed_cost",
]

#: Character used to join key components. A unit separator can appear in a user
#: supplied value, so component boundaries are still escaped below: a value that
#: literally contains the separator is percent-escaped rather than dropped.
_SEP = "\x1f"


def _escape(value: str) -> str:
    """Escape the separator and backslash so components cannot merge.

    Without this, ``user="a\\x1fb"`` and ``tenant="a"`` + ``user="b"`` could
    produce the same joined string and share a bucket. A limiter that can be
    made to collide is a limiter that can be bypassed.
    """
    if _SEP not in value and "\\" not in value:
        return value
    out = []
    for char in value:
        if char == _SEP:
            out.append("%1f")
        elif char == "\\":
            out.append("%5c")
        else:
            out.append(char)
    return "".join(out)


def compose_key(*parts: str | None) -> str:
    """Join non-empty components into one unambiguous key string.

    Empty and ``None`` components are dropped, so a rule keyed on
    ``(tenant, user)`` still produces a distinct-but-valid key when the caller
    is anonymous and no tenant was supplied.
    """
    return _SEP.join(_escape(part) for part in parts if part)


@dataclass(frozen=True, slots=True)
class KeyBuilder:
    """Builds the *material* a rule is keyed on, before fingerprinting.

    The builder deliberately returns readable material rather than a finished
    Redis key. Fingerprinting happens in :meth:`fingerprint`, which needs the
    salt, and keeping that separate means a builder is trivially testable and
    safe to log.
    """

    #: Ordered identifier names, e.g. ``("ip",)`` or ``("tenant", "user")``.
    components: tuple[str, ...] = ("ip",)
    #: Optional fallback used when none of ``components`` resolve. Without one,
    #: an unresolvable identity raises rather than silently collapsing every
    #: anonymous caller into a single shared bucket.
    fallback: str | None = None
    #: Prefix, so two rules with identical components still get separate
    #: counters even when applied to the same endpoint.
    prefix: str = ""
    #: When true, components are combined as separate buckets rather than one.
    #: ``False`` (default) means "all of these together identify the caller".
    independent: bool = False

    def __post_init__(self) -> None:
        if not self.components:
            raise ConfigurationError("KeyBuilder needs at least one component")
        if any(not name or not name.strip() for name in self.components):
            raise ConfigurationError("KeyBuilder component names must be non-empty")
        if len(set(self.components)) != len(self.components):
            raise ConfigurationError("KeyBuilder component names must be unique")
        if any(char in self.prefix for char in "\r\n"):
            raise ConfigurationError("KeyBuilder prefix must not contain newlines")

    def materials(self, identity: Identity) -> tuple[tuple[str, ...], ...]:
        """Return one tuple of components per bucket this rule should count.

        For an ``independent=False`` builder that is always a single tuple. For
        ``independent=True`` it is one tuple per component, so each dimension
        gets its own counter and breaching any of them blocks the request.
        """
        if self.independent:
            buckets: list[tuple[str, ...]] = []
            for name in self.components:
                value = _component_value(name, identity)
                if value:
                    buckets.append((f"{name}={value}",))
            return tuple(buckets) or _fallback_buckets(self.fallback)

        resolved = tuple(
            f"{name}={value}"
            for name in self.components
            if (value := _component_value(name, identity))
        )
        return (resolved,) if resolved else _fallback_buckets(self.fallback)

    def materials_or_none(self, identity: Identity) -> tuple[tuple[str, ...], ...] | None:
        """Like :meth:`materials`, but ``None`` when nothing resolved.

        Callers that must treat an unresolvable identity as "this rule does not
        apply" use this instead of catching the configuration error: a rule that
        cannot be keyed is a routine outcome on an unauthenticated request, not
        a misconfiguration.
        """
        if self.independent:
            buckets = [
                bucket
                for name in self.components
                if (value := _component_value(name, identity))
                for bucket in ((f"{name}={value}",),)
            ]
            if buckets:
                return tuple(buckets)
        else:
            resolved = tuple(
                f"{name}={value}"
                for name in self.components
                if (value := _component_value(name, identity))
            )
            if resolved:
                return (resolved,)
        if self.fallback is None:
            return None
        return _fallback_buckets(self.fallback)

    def fingerprint(self, salt: str, identity: Identity) -> tuple[str, ...]:
        """Return the storage keys for this rule, one per bucket."""
        return tuple(fingerprint(salt, self.prefix, *parts) for parts in self.materials(identity))


def _component_value(name: str, identity: Identity) -> str | None:
    """Read one named component off an :class:`Identity`, normalising it.

    ``ip`` is canonicalised as an address and ``account`` as a case-insensitive
    string so that ``Bob@Example.com`` and ``bob@example.com`` cannot occupy two
    buckets, and so ``::ffff:1.2.3.4`` does not bypass an IPv4 rule.
    """
    if name == "ip":
        return normalize_ip(identity.ip)
    if name == "account":
        return normalize_account(identity.account)
    value = identity.get(name)
    if value is None:
        return None
    return normalize_account(value)


def _fallback_buckets(fallback: str | None) -> tuple[tuple[str, ...], ...]:
    if fallback is None:
        raise ConfigurationError(
            "cannot resolve an identity for this rule; supply the component on the "
            "Identity, or set KeyBuilder(fallback=...) to name what to use when it is absent"
        )
    return ((f"fallback={normalize_account(fallback) or fallback}",),)


def by_ip(**options: Any) -> KeyBuilder:
    """Limit per client address. The safe default for pre-auth endpoints."""
    return KeyBuilder(components=("ip",), **options)


def by_account(**options: Any) -> KeyBuilder:
    """Limit per account identifier. Requires a body or header to supply one."""
    return KeyBuilder(components=("account",), **options)


def by_user(**options: Any) -> KeyBuilder:
    """Limit per authenticated user, read from ``Identity.extras['user']``."""
    return KeyBuilder(components=("user",), **options)


def by_tenant(**options: Any) -> KeyBuilder:
    """Limit per tenant, typically on a subscription or plan."""
    return KeyBuilder(components=("tenant",), **options)


def by_api_key(**options: Any) -> KeyBuilder:
    """Limit per API key, from ``Identity.extras['api_key']``."""
    return KeyBuilder(components=("api_key",), **options)


def by_route(**options: Any) -> KeyBuilder:
    """Limit per (method, path) rather than per caller.

    Use for a global ceiling: "this endpoint may take 1000 requests a minute
    from everyone combined". Pair it with a caller rule for fairness.
    """
    return KeyBuilder(components=("route",), **options)


def fixed_cost(cost: int) -> Callable[[Any], int]:
    """Return a cost function that always charges ``cost``.

    Weighted limits are how a V2 limiter stops being a request counter: a
    $500 refund can cost 20 units while a $1 charge costs 1.
    """

    if cost < 0:
        raise ConfigurationError("cost must be >= 0")

    def _cost(_: Any) -> int:
        return cost

    return _cost


@dataclass(frozen=True, slots=True)
class Rule:
    """One limit, one key, one outcome.

    A policy is a collection of rules; a request is allowed only when *every*
    rule allows it. That is what makes the V1 "IP rule and account rule, both
    enforced" behaviour a property of the model rather than a special case.
    """

    key: KeyBuilder
    limit: RateLimit
    #: Units consumed per request. A plain counter uses 1; weighted limits use
    #: a callable derived from the request.
    cost: int | Callable[[Any], int] = 1
    #: Independent cool-down. When false the rule inherits the limiter default.
    cooldown_seconds: float | None = None
    #: Human label used in logs, headers and the audit trail.
    name: str = ""
    #: When false the rule is evaluated but never blocks, so it can be observed
    #: before being enforced.
    enabled: bool = True

    def __post_init__(self) -> None:
        # Both fields are annotated narrowly but configuration routinely arrives
        # from strings, so each is inspected as a plain object. A bad value must
        # be a ConfigurationError at construction, never an AttributeError on
        # the first request that hits this rule.
        given_limit: object = self.limit
        if isinstance(given_limit, str):
            given_limit = RateLimit.parse(given_limit)
            object.__setattr__(self, "limit", given_limit)
        if not isinstance(given_limit, RateLimit):
            found = type(given_limit).__name__
            raise ConfigurationError(
                f"Rule limit must be a RateLimit or a limit string, got {found}"
            )
        given_cost: object = self.cost
        if not callable(given_cost):
            # bool is an int subclass; `cost=True` is a configuration mistake,
            # not a request that costs one unit.
            if not isinstance(given_cost, int) or isinstance(given_cost, bool):
                raise ConfigurationError("Rule cost must be a positive int or a callable")
            # Zero is rejected rather than allowed: a request that costs nothing
            # is never counted, so it would be a way to bypass the rule entirely
            # while still looking configured.
            if given_cost < 1:
                raise ConfigurationError("Rule cost must be >= 1")
        if self.cooldown_seconds is not None and self.cooldown_seconds < 0:
            raise ConfigurationError("Rule cooldown_seconds must be >= 0")
        if any(char in self.name for char in "\r\n"):
            raise ConfigurationError("Rule name must not contain newlines")

    @property
    def label(self) -> str:
        """A stable identifier for this rule, for headers and logs."""
        if self.name:
            return self.name
        return "+".join(self.key.components)

    def cost_for(self, subject: Any) -> int:
        """Resolve the units this request consumes.

        A wrong *return value* is resolved defensively: the rule's own limit is
        charged, which denies rather than letting an expensive operation through
        for free.

        A cost function that *raises* is deliberately not caught. A bug in the
        caller's pricing code should surface as itself, not be laundered into a
        429 that looks like ordinary rate limiting and hides the defect.
        """
        # The result of a user supplied cost function is `Any` as far as the
        # annotation goes, but it is checked as a plain object because a wrong
        # return type must not become a free pass.
        value: object = self.cost(subject) if callable(self.cost) else self.cost
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            return self.limit.limit
        return value

    def fingerprint_keys(self, salt: str, identity: Identity) -> tuple[str, ...]:
        """Return the storage keys this rule would count against.

        The rule label is folded into the key material. Two rules with identical
        components are two separate budgets, so they must not share a counter,
        otherwise one rule's traffic would silently consume the other's
        allowance.
        """
        return tuple(
            fingerprint(salt, f"rule={self.label}", key)
            for key in self.key.fingerprint(salt, identity)
        )


@dataclass(frozen=True, slots=True)
class Policy:
    """A named, ordered set of rules applied to one endpoint or blueprint.

    Policies are data, not code, so the same object can be written as a literal,
    loaded from a config file, or produced per-tenant. ``default_policy`` is the
    one used when a route has no explicit policy of its own.
    """

    name: str
    rules: tuple[Rule, ...] = ()
    #: When true a request that would breach *any* rule is rejected, even if
    #: later rules have not been evaluated yet. Short-circuiting is the default
    #: because it avoids spending Redis round trips on a request already denied.
    short_circuit: bool = True
    #: When true a storage failure denies the request. Authentication and
    #: payment endpoints want this; a public read endpoint usually does not.
    fail_closed: bool = False
    #: Optional per-rule overrides, e.g. an admin allowance that raises the
    #: limit rather than replacing the policy.
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ConfigurationError("Policy name must be a non-empty string")
        if any(char in self.name for char in "\r\n"):
            raise ConfigurationError("Policy name must not contain newlines")
        normalised: list[Rule] = []
        for rule in self.rules:
            if not isinstance(rule, Rule):
                raise ConfigurationError(
                    f"Policy {self.name!r} contains a {type(rule).__name__}, expected Rule"
                )
            normalised.append(rule)
        object.__setattr__(self, "rules", tuple(normalised))

    @property
    def enabled_rules(self) -> tuple[Rule, ...]:
        """Rules that are actually enforced."""
        return tuple(rule for rule in self.rules if rule.enabled)

    def labels(self) -> tuple[str, ...]:
        """Names of the enforced rules, for diagnostics."""
        return tuple(rule.label for rule in self.enabled_rules)

    def is_empty(self) -> bool:
        """True when nothing would be checked, so the call can be skipped."""
        return not self.enabled_rules

    def rule_named(self, name: str) -> Rule | None:
        """Look up a rule by label."""
        for rule in self.rules:
            if rule.label == name:
                return rule
        return None

    def with_rules(self, *rules: Rule) -> Policy:
        """Return a copy with ``rules`` appended."""
        return Policy(
            name=self.name,
            rules=(*self.rules, *rules),
            short_circuit=self.short_circuit,
            fail_closed=self.fail_closed,
            metadata=dict(self.metadata),
        )

    def all_keys(
        self, salt: str, identity: Identity
    ) -> Mapping[str, tuple[str, ...]]:
        """Map each enabled rule label to the keys it would count against.

        Two rules that resolve to the same key are intentionally *not*
        collapsed: they are separate budgets, and sharing a key would let one
        rule's traffic consume another's allowance.
        """
        return {
            rule.label: rule.fingerprint_keys(salt, identity) for rule in self.enabled_rules
        }


def _validate_rules(rules: Sequence[Rule], owner: str) -> None:
    """Shared rule validation for adapters that build policies at runtime."""
    for rule in rules:
        if not isinstance(rule, Rule):
            raise ConfigurationError(
                f"{owner} received a {type(rule).__name__}, expected Rule"
            )


def rules_for(rules: Iterable[Rule], owner: str = "policy") -> tuple[Rule, ...]:
    """Validate and freeze an iterable of rules.

    Adapters (Flask, Django, FastAPI) accept ``*rules`` from a decorator, so
    this keeps that input path as strict as a :class:`Policy` built directly.
    """
    collected = tuple(rules)
    _validate_rules(collected, owner)
    return collected


def constant_time_equals(left: str, right: str) -> bool:
    """Compare two strings without leaking their contents through timing.

    Only used for comparing user supplied secrets against stored material; not
    a general purpose equality helper.
    """
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
