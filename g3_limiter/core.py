"""Framework-agnostic rate limiting engine.

The core of the library. It knows about rate limits, identities, algorithms and
storage, and nothing about HTTP, Flask, or any particular web framework. That
separation is what keeps the SDK usable on its own, and it is why a future
Django/FastAPI integration is a small adapter rather than a rewrite.

Evaluation order for one request:

1. If a **cooldown** marker is active for the identity, block immediately
   without counting another hit. Counting here would extend the punishment for
   every attempt made during the cooldown, which is both unfair and a cheap way
   to keep a legitimate user locked out.
2. Otherwise **count** the hit against every configured rule (by default one
   per identifier: ``ip`` and ``account``).
3. If any rule is now over its limit, set the cooldown marker and block.

A cooldown is always time-boxed. Nothing in this library can lock an account
permanently: once ``cooldown_seconds`` elapses the marker expires on its own.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from g3_limiter.algorithms import NAMESPACE as KEY_NAMESPACE
from g3_limiter.algorithms import get_algorithm, storage_key_for
from g3_limiter.config import Settings
from g3_limiter.errors import ConfigurationError, RateLimitExceeded, StorageError
from g3_limiter.identifiers import Identity, TrustedProxies, fingerprint
from g3_limiter.limits import RateLimit
from g3_limiter.storage.base import Storage

__all__ = [
    "Decision",
    "LimiterCore",
    "build_headers",
    "build_payload",
    "cooldown_key",
]

#: Cap on the identifier material fed into the key fingerprint, so a hostile
#: caller cannot inflate every Redis key with a megabyte of "email".
MAX_MATERIAL_LENGTH = 512

DEFAULT_BLOCK_MESSAGE = "Rate limit exceeded. Please slow down."
DEFAULT_COOLDOWN_MESSAGE = "Too many attempts. Please wait before retrying."


def cooldown_key(counter_key: str) -> str:
    """Key of the cooldown marker that belongs to ``counter_key``.

    Deriving it from the counter key (instead of an unrelated namespace) is what
    guarantees a marker and its counter can never drift apart.
    """
    return f"{counter_key}:cooldown"


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome of evaluating one request.

    ``reset_at`` and ``retry_after`` are absolute unix timestamps / relative
    seconds respectively, matching what the ``RateLimit-*`` headers and the JSON
    error body publish.
    """

    allowed: bool = True
    limit: int | None = None
    remaining: int | None = None
    reset_at: float | None = None
    retry_after: float | None = None
    bucket: str | None = None
    policy: str | None = None
    message: str = DEFAULT_BLOCK_MESSAGE
    rule: str | None = None
    #: True when this decision was produced by failing open on a storage error,
    #: so ``allowed`` reflects a skipped check rather than a passing one.
    storage_failed: bool = False

    @property
    def blocked(self) -> bool:
        return not self.allowed


def build_headers(decision: Decision) -> dict[str, str]:
    """Standard rate limit response headers for ``decision``.

    Both the ``X-RateLimit-*`` convention and ``Retry-After`` (RFC 9110) are
    emitted, so generic HTTP clients can react without a bespoke parser.
    """
    headers: dict[str, str] = {}
    if decision.limit is not None:
        headers["X-RateLimit-Limit"] = str(decision.limit)
    if decision.remaining is not None:
        headers["X-RateLimit-Remaining"] = str(max(0, decision.remaining))
    if decision.reset_at is not None:
        headers["X-RateLimit-Reset"] = str(int(decision.reset_at))
    if decision.policy:
        headers["X-RateLimit-Policy"] = decision.policy
    if decision.bucket:
        headers["X-RateLimit-Bucket"] = decision.bucket
    if decision.retry_after is not None:
        headers["Retry-After"] = str(max(0, int(decision.retry_after)))
    return headers


def build_payload(decision: Decision) -> dict[str, Any]:
    """JSON-ready error body for a blocked request."""
    payload: dict[str, Any] = {
        "error": "rate_limit_exceeded",
        "message": decision.message,
    }
    if decision.limit is not None:
        payload["limit"] = decision.limit
    if decision.remaining is not None:
        payload["remaining"] = max(0, decision.remaining)
    if decision.reset_at is not None:
        payload["reset_at"] = int(decision.reset_at)
    if decision.retry_after is not None:
        payload["retry_after"] = max(0, int(decision.retry_after))
    if decision.bucket:
        payload["bucket"] = decision.bucket
    return payload


def build_body(decision: Decision) -> str:
    """Serialise :func:`build_payload` to a compact JSON string."""
    return json.dumps(build_payload(decision), separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class _RuleResult:
    """Per-rule bookkeeping, kept internal."""

    name: str
    count: int
    limit: RateLimit
    reset_at: float | None
    bucket: str


class LimiterCore:
    """The rate limiting engine.

    Parameters
    ----------
    settings:
        Validated configuration (namespace, identifiers, cooldowns, ...).
    storage:
        A :class:`~g3_limiter.storage.base.Storage` backend.
    clock:
        Time source, injectable so tests can advance time deterministically
        instead of sleeping.
    """

    __slots__ = ("_clock", "_settings", "_storage", "_trusted")

    def __init__(
        self,
        settings: Settings,
        storage: Storage,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._settings = settings.validated()
        self._storage = storage
        self._clock = clock or time.time
        # Compiled once: the proxy list is consulted on every request.
        self._trusted = self._settings.trusted

    # ------------------------------------------------------------- properties

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def storage(self) -> Storage:
        return self._storage

    @property
    def clock(self) -> Callable[[], float]:
        """The time source in use.

        Exposed so that derived engines (the V2 policy evaluator builds one view
        per rule) stay on the same clock instead of falling back to the wall
        clock and disagreeing with the engine they were derived from.
        """
        return self._clock

    @property
    def trusted_proxies(self) -> TrustedProxies:
        return self._trusted

    def _now(self) -> float:
        return self._clock()

    # ------------------------------------------------------------ key building

    def scope_for(self, path: str, method: str) -> str:
        """Return the scope segment for a route.

        ``endpoint`` (the default) keys on ``METHOD path``: a login route and an
        API route never share a budget. ``path``/``method`` narrow that, and
        ``global`` gives one budget for the whole process.
        """
        mode = self._settings.scope
        normalised_path = path or "/"
        if mode == "global":
            return "global"
        if mode == "method":
            return method.upper()
        if mode == "path":
            return normalised_path
        return f"{method.upper()} {normalised_path}"

    def rule_key(self, components: Sequence[str], identity: Identity, suffix: str) -> str:
        """Fingerprint one rule's identity material.

        The result is a truncated HMAC: stable across processes and restarts
        (given the same salt), and one-way, so a Redis keyspace scan or a
        ``KEYS`` dump reveals neither email addresses nor IP addresses.
        """
        material = identity.material_for(components)
        if not material:
            return ""
        payload = "\x1f".join(material)
        if len(payload) > MAX_MATERIAL_LENGTH:
            payload = payload[:MAX_MATERIAL_LENGTH]
        return fingerprint(self._settings.key_salt, suffix, payload)

    def storage_key(self, algorithm: str, scope: str, rule_key: str) -> str:
        return storage_key_for(self._settings.namespace, algorithm, scope, rule_key)

    def rules_for(self, limit: RateLimit | None) -> list[tuple[str, RateLimit, tuple[str, ...]]]:
        """Expand a limit into the per-identifier rules to evaluate.

        For the default ``("ip", "account")`` identifiers this yields an IP rule
        and an account rule. The account limit is deliberately looser
        (``account_limit_multiplier``): if it matched the IP limit exactly, one
        attacker could lock a victim out simply by guessing their password.
        """
        base = limit or self._settings.default_limit
        rules: list[tuple[str, RateLimit, tuple[str, ...]]] = []
        for component in self._settings.identifier:
            component_limit = base
            if component == "account" and self._settings.account_limit_multiplier != 1.0:
                scaled = int(base.limit * self._settings.account_limit_multiplier)
                if scaled != base.limit:
                    component_limit = RateLimit(
                        limit=scaled,
                        window_seconds=base.window_seconds,
                        raw=f"{scaled}/{int(base.window)}s",
                    )
            rules.append((component, component_limit, (component,)))
        return rules

    # ----------------------------------------------------------------- checks

    def _cooldown_for(
        self, name: str, counter: str, now: float
    ) -> float | None:
        """Absolute expiry of an active cooldown for ``counter``, if any."""
        return self._storage.marked_until(cooldown_key(counter), now=now)

    def _activate_cooldown(self, name: str, counter: str, now: float) -> None:
        ttl = (
            self._settings.account_cooldown
            if name == "account"
            else self._settings.cooldown_seconds
        )
        if ttl > 0:
            self._storage.mark(cooldown_key(counter), ttl_seconds=ttl, now=now)

    def check(
        self,
        identity: Identity,
        *,
        path: str = "/",
        method: str = "GET",
        limit: RateLimit | str | None = None,
        algorithm: str | None = None,
        cost: int = 1,
        enforce: bool = False,
    ) -> Decision:
        """Evaluate ``identity`` against every configured rule.

        Parameters
        ----------
        identity:
            The resolved request identity (IP, account, extras).
        path, method:
            Used to build the scope, so distinct routes get distinct budgets.
        limit:
            Optional per-call limit overriding ``settings.default_limit``.
        algorithm:
            Overrides ``settings``' algorithm; defaults to ``sliding_window``.
        cost:
            How many slots this request consumes. The default 1 charges one hit.
            A larger value charges more in a single atomic storage operation,
            so an expensive operation cannot be repeated within an otherwise
            ordinary request budget.
        enforce:
            When ``True``, raise :class:`RateLimitExceeded` instead of returning
            a blocking :class:`Decision`. Frameworks that want to customise the
            error response use ``enforce=False`` and inspect the result.
        """
        if not self._settings.enabled:
            return Decision(allowed=True)
        if cost < 1:
            raise ConfigurationError("cost must be >= 1")

        if isinstance(limit, str):
            parsed_limit = RateLimit.parse(limit)
        else:
            parsed_limit = limit or self._settings.default_limit
        algo = get_algorithm(algorithm or self._settings.algorithm)
        now = self._now()
        method_u = (method or "GET").upper()
        if method_u in self._settings.skip_methods:
            return Decision(allowed=True)
        scope = self.scope_for(path, method_u)

        try:
            decision = self._evaluate(
                identity=identity,
                scope=scope,
                method=method_u,
                limit=parsed_limit,
                algo=algo,
                now=now,
                cost=cost,
            )
        except StorageError:
            if self._settings.fail_open:
                return Decision(
                    allowed=True,
                    message="storage unavailable (fail-open)",
                    storage_failed=True,
                )
            raise

        if enforce and not decision.allowed:
            raise RateLimitExceeded(decision)
        return decision

    def _evaluate(
        self,
        *,
        identity: Identity,
        scope: str,
        method: str,
        limit: RateLimit,
        algo: Any,
        now: float,
        cost: int = 1,
    ) -> Decision:
        # Phase 1: an active cooldown blocks without consuming a hit.
        for name, component_limit, components in self.rules_for(limit):
            key = self.rule_key(components, identity, f"default:{name}")
            if not key:
                # The identity did not carry this component (for example a
                # request with no body on a JSON-only login form). Nothing to
                # count, so the rule simply does not apply to this request.
                continue
            counter = self.storage_key(algo.name, scope, key)
            expires_at = self._cooldown_for(name, counter, now)
            if expires_at is not None:
                return Decision(
                    allowed=False,
                    limit=component_limit.limit,
                    remaining=0,
                    reset_at=expires_at,
                    retry_after=max(0.0, expires_at - now),
                    bucket=key,
                    policy=f"cooldown:{int(component_limit.window)}s",
                    message=DEFAULT_COOLDOWN_MESSAGE,
                    rule=name,
                )

        # Phase 2: count the hit against every rule, then report the tightest.
        results: list[_RuleResult] = []
        for name, component_limit, components in self.rules_for(limit):
            key = self.rule_key(components, identity, f"default:{name}")
            if not key:
                continue
            counter = self.storage_key(algo.name, scope, key)
            count, next_available = algo.check(
                self._storage, key=counter, limit=component_limit, now=now, cost=cost
            )
            results.append(
                _RuleResult(
                    name=name,
                    count=count,
                    limit=component_limit,
                    reset_at=next_available,
                    bucket=key,
                )
            )
            if count > component_limit.limit:
                # Breached: arm the cooldown for this rule, and stop here so a
                # blocked request never inflates the *other* rule's counter.
                self._activate_cooldown(name, counter, now)
                breached = _RuleResult(name, count, component_limit, next_available, key)
                return self._blocked_decision(breached, now)

        if not results:
            # No applicable rule (no IP resolvable and no account supplied).
            # Allow, and do not invent a shared "anonymous" bucket: lumping every
            # such caller together would let one attacker exhaust everyone's
            # budget.
            return Decision(allowed=True, message="no identifier available")

        tightest = min(results, key=lambda result: result.limit.limit - result.count)
        return Decision(
            allowed=True,
            limit=tightest.limit.limit,
            remaining=max(0, tightest.limit.limit - tightest.count),
            reset_at=tightest.reset_at,
            bucket=tightest.bucket,
            policy=f"{tightest.limit.limit}/{tightest.limit.window}s",
            rule=tightest.name,
        )

    def _blocked_decision(self, result: _RuleResult, now: float) -> Decision:
        retry_after = None
        if result.reset_at is not None:
            retry_after = max(0.0, result.reset_at - now)
        return Decision(
            allowed=False,
            limit=result.limit.limit,
            remaining=0,
            reset_at=result.reset_at,
            retry_after=retry_after,
            bucket=result.bucket,
            policy=f"{result.limit.limit}/{result.limit.window}s",
            message=DEFAULT_BLOCK_MESSAGE,
            rule=result.name,
        )

    def check_or_raise(self, identity: Identity, **kwargs: Any) -> Decision:
        """Convenience wrapper: ``check(..., enforce=True)``."""
        kwargs.setdefault("enforce", True)
        return self.check(identity, **kwargs)

    # ----------------------------------------------------------------- resets

    def reset(
        self,
        identity: Identity,
        *,
        path: str = "/",
        method: str = "GET",
        algorithm: str | None = None,
    ) -> int:
        """Clear the counters and cooldowns for ``identity``.

        Returns the number of keys removed. Call this after a *successful*
        authentication so that failed attempts (from the user's own typos or from
        someone sharing their IP) do not accumulate against a legitimate session.
        """
        algo = get_algorithm(algorithm or self._settings.algorithm)
        scope = self.scope_for(path, (method or "GET").upper())
        removed = 0
        for name, _component_limit, components in self.rules_for(None):
            key = self.rule_key(components, identity, f"default:{name}")
            if not key:
                continue
            counter = self.storage_key(algo.name, scope, key)
            algo.reset(self._storage, key=counter)
            self._storage.clear(cooldown_key(counter))
            removed += 1
        return removed

    def clear_all(self) -> int:
        """Remove every key owned by this limiter's namespace.

        Intended for tests and for an administrative "reset all limits" action.
        The prefix is the one every key of this limiter starts with, so keys
        belonging to another limiter sharing the same storage are untouched. The
        Redis implementation is ``SCAN`` based and never uses ``KEYS``.
        """
        namespace_prefix = f"{KEY_NAMESPACE}:{self._settings.namespace}:"
        return self._storage.clear_prefix(namespace_prefix)
