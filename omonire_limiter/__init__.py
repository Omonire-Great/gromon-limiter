"""Public API surface.

The package exposes a small, explicit API: :class:`AuthLimiter` is the entry
point for authentication endpoints (V1), :class:`Limiter` is general purpose
(V2), and :class:`OmonireClient` is the SaaS client stub (present but not yet
implemented in full, to keep the scope to V1). Every symbol here is considered
stable within its milestone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from omonire_limiter.core import (
    Decision,
    LimiterCore,
    build_body,
    build_headers,
    build_payload,
)
from omonire_limiter.engine import (
    MAX_RULES_PER_POLICY,
    PolicyEvaluator,
    PolicyVerdict,
)
from omonire_limiter.errors import (
    ConfigurationError,
    InvalidLimitError,
    RateLimitExceeded,
    StorageError,
)
from omonire_limiter.identifiers import Identity, TrustedProxies, client_ip
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
    fixed_cost,
)
from omonire_limiter.storage.base import CounterState, Storage
from omonire_limiter.storage.memory import MemoryStorage
from omonire_limiter.storage.redis import RedisStorage

if TYPE_CHECKING:  # pragma: no cover - only needed by type checkers
    from flask import Flask

    from omonire_limiter.config import Settings

__all__ = [
    "MAX_RULES_PER_POLICY",
    "AuthLimiter",
    "ConfigurationError",
    "CounterState",
    "Decision",
    "Identity",
    "InvalidLimitError",
    "KeyBuilder",
    "Limiter",
    "LimiterCore",
    "MemoryStorage",
    "OmonireClient",
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
        from omonire_limiter.flask import init_auth_limiter

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
        from omonire_limiter.decorators import limit as _limit

        return _limit(self, limit, **options)

    def check(self, **kwargs: Any) -> Decision:
        """Evaluate a limit outside a request cycle (see ``LimiterCore.check``)."""
        return self.core.check(**kwargs)

    def reset(self, **kwargs: Any) -> int:
        """Drop stored counters for a caller, e.g. after a successful login."""
        return self.core.reset(**kwargs)

    def clear_all(self) -> int:
        """Remove every counter this limiter owns. Mainly for tests and tooling."""
        return self.core.clear_all()


# ---------------------------------------------------------------- V2 entry point (scaffold)


class Limiter(AuthLimiter):
    """General-purpose API limiter (V2).

    Shares the same engine as :class:`AuthLimiter` but is named explicitly for
    non-auth endpoints. Backward compatibility with V1 is preserved by
    inheritance: existing code using ``AuthLimiter`` continues to work.

    V2 adds the declarative model in :mod:`omonire_limiter.policies`: a
    :class:`Policy` of :class:`Rule` objects, each with its own
    :class:`KeyBuilder`, limit and optional cost. Adapters bind a policy to a
    route and evaluate every rule, allowing a request only when all of them do.
    """

    @classmethod
    def for_policy(cls, policy: Policy, **kwargs: Any) -> Limiter:
        """Build a limiter whose routes share one policy.

        The small factory exists so the policy is validated once, at start-up,
        rather than on the first request that reaches a decorated route.
        """
        if not isinstance(policy, Policy):
            raise ConfigurationError(
                f"for_policy expects a Policy, got {type(policy).__name__}"
            )
        limiter = cls(**kwargs)
        limiter.default_policy = policy
        return limiter

    def policy_for(self, override: Policy | None = None) -> Policy | None:
        """Return the policy that applies to a route, or ``None`` to skip."""
        chosen = override if override is not None else self.default_policy
        if chosen is None or chosen.is_empty():
            return None
        return chosen


# ---------------------------------------------------------------- V3/V5 stub


class OmonireClient:
    """Client stub for the hosted Omonire backend (V3+).

    The full central service client is out of scope for V1. This placeholder is
    exported so the public API surface matches the final product vision without
    faking behaviour.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover - stub
        raise NotImplementedError(
            "OmonireClient is not implemented in V1. It will be introduced in V3 "
            "(omonire-backend: centralised rate limiting service)."
        )


#: Pre-rebrand name of :class:`OmonireClient`, kept so existing imports keep
#: working. The class only ever raised ``NotImplementedError``, so nothing that
#: runs today depends on which of the two names it is bound to.
G3Client = OmonireClient
