"""Public API surface.

The package exposes a small, explicit API: :class:`AuthLimiter` is the entry
point for authentication endpoints (V1), :class:`Limiter` is general purpose
(V2), and :class:`GromonClient` is the SaaS client stub (present but not yet
implemented in full, to keep the scope to V1). Every symbol here is considered
stable within its milestone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from gromon_limiter.core import (
    Decision,
    LimiterCore,
    build_body,
    build_headers,
    build_payload,
)
from gromon_limiter.engine import (
    MAX_RULES_PER_POLICY,
    PolicyEvaluator,
    PolicyVerdict,
)
from gromon_limiter.errors import (
    ConfigurationError,
    InvalidLimitError,
    RateLimitExceeded,
    StorageError,
)
from gromon_limiter.identifiers import Identity, TrustedProxies, client_ip
from gromon_limiter.limits import RateLimit
from gromon_limiter.policies import (
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
    fixed_cost,
)
from gromon_limiter.storage.base import CounterState, Storage
from gromon_limiter.storage.memory import MemoryStorage
from gromon_limiter.storage.redis import RedisStorage

if TYPE_CHECKING:  # pragma: no cover - only needed by type checkers
    from flask import Flask

    from gromon_limiter.config import Settings

__all__ = [
    "MAX_RULES_PER_POLICY",
    "AuthLimiter",
    "ConfigurationError",
    "CounterState",
    "Decision",
    "GromonClient",
    "Identity",
    "InvalidLimitError",
    "KeyBuilder",
    "Limiter",
    "LimiterCore",
    "MemoryStorage",
    "Policy",
    "PolicyEvaluator",
    "PolicyVerdict",
    "RateLimit",
    "RateLimitExceeded",
    "RedisStorage",
    "Rule",
    "Storage",
    "StorageError",
    "TrustedProxies",
    "build_body",
    "build_headers",
    "build_payload",
    "by_account",
    "by_api_key",
    "by_ip",
    "by_route",
    "by_tenant",
    "by_user",
    "client_ip",
    "compose_key",
    "fixed_cost",
]


# ---------------------------------------------------------------- V1 entry points


class AuthLimiter:
    """Flask-aware authentication limiter (V1).

    This class wires :class:`LimiterCore` to Flask's request/response cycle. It
    is intentionally thin: all policy lives in the core and in configuration.
    The constructor accepts either an existing Flask app (to initialise
    immediately) or ``None`` (to use ``init_app`` later).
    """

    _core: LimiterCore | None
    _settings: Settings | None
    _storage: Storage | None
    _app: Flask | None
    _kwargs: dict[str, Any]
    #: V2 policy default. Declared here rather than only on ``Limiter`` so that
    #: the attribute exists on every instance and ``policy_for`` never raises
    #: AttributeError on a V1 object.
    default_policy: Policy | None = None
    #: Supplies authenticated material (user, tenant, api_key) for V2 rules. Set
    #: by ``init_auth_limiter``; ``None`` on a V1 limiter means no rule needs it.
    extras_provider: Any = None
    #: Cached policy evaluator, built on first use by the Flask layer. The cache
    #: holds one engine view per (policy, rule), so it must outlive a request.
    _evaluator: PolicyEvaluator | None = None

    def __init__(self, app: Flask | None = None, **kwargs: Any) -> None:
        # Keyword arguments are held so that the deferred form
        # ``AuthLimiter(limit=...).init_app(app)`` behaves exactly like
        # ``AuthLimiter(app, limit=...)``.
        self._core = None
        self._settings = None
        self._storage = None
        self._app = None
        self._kwargs = dict(kwargs)
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask | None = None, **kwargs: Any) -> AuthLimiter:
        """Bind the limiter to a Flask app.

        Called without ``app`` the arguments are only stored, for a later
        ``init_app(app)`` call.
        """
        from gromon_limiter.flask import init_auth_limiter

        if app is None:
            self._kwargs.update(kwargs)
            return self
        init_auth_limiter(self, app, **{**self._kwargs, **kwargs})
        return self

    @property
    def core(self) -> LimiterCore:
        if self._core is None:
            raise RuntimeError("AuthLimiter not initialised; call init_app first")
        return self._core

    def core_or_none(self) -> LimiterCore | None:
        """Return the engine, or ``None`` when the limiter is not bound yet."""
        return self._core

    @property
    def settings(self) -> Settings:
        if self._settings is None:
            raise RuntimeError("AuthLimiter not initialised; call init_app first")
        return self._settings

    @property
    def storage(self) -> Storage:
        if self._storage is None:
            raise RuntimeError("AuthLimiter not initialised; call init_app first")
        return self._storage

    def limit(self, limit: str | RateLimit | None = None, **options: Any) -> Any:
        """Decorate a view with a per-route limit.

        Called without an argument the limiter's configured default applies;
        pass a string such as ``"5/minute"`` to override it for one route.
        """
        from gromon_limiter.decorators import limit as _limit

        return _limit(self, limit, **options)

    def check(self, **kwargs: Any) -> Decision:
        """Evaluate a limit outside a request cycle (see ``LimiterCore.check``)."""
        return self.core.check(**kwargs)

    def reset(self, identity: Identity, **kwargs: Any) -> int:
        """Drop stored counters for a caller, e.g. after a successful login.

        ``identity`` is positional-or-keyword, matching
        :meth:`LimiterCore.reset`, so ``reset(identity=...)`` also works.
        """
        return self.core.reset(identity, **kwargs)

    def clear_all(self) -> int:
        """Remove every counter this limiter owns. Mainly for tests and tooling."""
        return self.core.clear_all()


# ---------------------------------------------------------------- V2 entry point (scaffold)


class Limiter(AuthLimiter):
    """General-purpose API limiter (V2).

    Shares the same engine as :class:`AuthLimiter` but is named explicitly for
    non-auth endpoints. Backward compatibility with V1 is preserved by
    inheritance: existing code using ``AuthLimiter`` continues to work.

    V2 adds the declarative model in :mod:`gromon_limiter.policies`: a
    :class:`Policy` of :class:`Rule` objects, each with its own
    :class:`KeyBuilder`, limit and optional cost. Adapters bind a policy to a
    route and evaluate every rule, allowing a request only when all of them do.
    """

    @classmethod
    def for_policy(cls, policy: Policy, app: Flask | None = None, **kwargs: Any) -> Limiter:
        """Build a limiter whose routes share one policy.

        The small factory exists so the policy is validated once, at start-up,
        rather than on the first request that reaches a decorated route.

        ``app`` may be passed positionally, matching ``AuthLimiter(app, ...)``, so
        the whole limiter is configured in one call.
        """
        if not isinstance(policy, Policy):
            raise ConfigurationError(
                f"for_policy expects a Policy, got {type(policy).__name__}"
            )
        # The policy travels as a kwarg rather than being assigned afterwards, so
        # that `for_policy(p, app)` and `for_policy(p, app=app)` build the same
        # object and the Flask layer sees the policy during init_app.
        limiter = cls(app, policy=policy, **kwargs)
        limiter.default_policy = policy
        return limiter

    def policy_for(self, override: Policy | None = None) -> Policy | None:
        """Return the policy that applies to a route, or ``None`` to skip."""
        chosen = override if override is not None else self.default_policy
        if chosen is None or chosen.is_empty():
            return None
        return chosen

    def reset(
        self,
        identity: Identity,
        *,
        policy: Policy | None = None,
        **kwargs: Any,
    ) -> int:
        """Drop stored counters for a caller, e.g. after a successful login.

        Takes the same ``identity``/``path``/``method`` arguments as
        :meth:`LimiterCore.reset`, so an existing V1 call site needs no change.

        When a policy applies the counters are cleared through
        :meth:`PolicyEvaluator.reset`, because those live under per-rule keys the
        V1 engine does not know about. Clearing the V1 core instead would report
        success while removing nothing, and the caller would stay blocked by their
        own earlier failed attempts. ``policy`` is keyword-only so it cannot
        collide with the positional ``identity``.
        """
        chosen = self.policy_for(policy)
        if chosen is None:
            return super().reset(identity, **kwargs)
        from gromon_limiter.flask import evaluator_for

        return evaluator_for(self).reset(chosen, identity, **kwargs)


# ---------------------------------------------------------------- V3/V5 stub


class GromonClient:
    """Client stub for the hosted Gromon backend (V3+).

    The full central service client is out of scope for V1. This placeholder is
    exported so the public API surface matches the final product vision without
    faking behaviour.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover - stub
        raise NotImplementedError(
            "GromonClient is not implemented in V1. It will be introduced in V3 "
            "(gromon-backend: centralised rate limiting service)."
        )
