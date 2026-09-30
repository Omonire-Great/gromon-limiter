"""The ``@limiter.limit(...)`` decorator.

The decorator resolves identity, asks the engine for a decision, and either
calls the view or returns 429. It works with :class:`~omonire_limiter.AuthLimiter`
(V1) and with the general :class:`~omonire_limiter.Limiter` (V2), so the two
milestones share one implementation.

Ordering matters and is a common source of confusion:

.. code-block:: python

    @app.post("/login")      # app.route first: it registers the URL rule
    @limiter.limit("5/minute")
    def login(): ...

The decorator is applied first (bottom-up), so ``limiter.limit`` receives the
raw view function and Flask registers the wrapper.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

from omonire_limiter.errors import ConfigurationError, RateLimitExceeded
from omonire_limiter.limits import RateLimit
from omonire_limiter.policies import Policy

__all__ = ["limit", "view_algorithm", "view_limit", "view_policy"]

F = TypeVar("F", bound=Callable[..., Any])


def limit(
    limiter: Any,
    limit_spec: str | RateLimit | None = None,
    *,
    algorithm: str | None = None,
    scope_path: str | Callable[..., str] | None = None,
    raise_on_limit: bool = False,
    policy: Policy | None = None,
) -> Callable[[F], F]:
    """Limit requests to a view.

    Parameters
    ----------
    limiter:
        An initialised :class:`~omonire_limiter.AuthLimiter` (or ``Limiter``).
    limit_spec:
        Overrides the limiter's default limit for this route only, e.g.
        ``"5/minute"``. Omit it to use the configured default.
    algorithm:
        Per-route algorithm override, e.g. ``"fixed_window"``.
    scope_path:
        Override the scope string (usually ``request.path``). Accepts a callable
        evaluated inside the request context. Rarely needed; the limiter's
        ``scope`` setting is the normal control.
    raise_on_limit:
        Raise :class:`~omonire_limiter.RateLimitExceeded` instead of returning a
        429 response, so a project can centralise error handling in one
        ``@app.errorhandler``.
    policy:
        A V2 :class:`~omonire_limiter.Policy` governing this route. When given it
        takes precedence over ``limit_spec`` and ``algorithm``: a policy declares
        its own per-rule limits, and layering the V1 limit on top would enforce
        something the policy never said.
    """
    if limit_spec is not None and not isinstance(limit_spec, RateLimit):
        # Fail at import/definition time, not on the first request.
        RateLimit.parse(limit_spec)
    if policy is not None and not isinstance(policy, Policy):
        raise ConfigurationError(
            f"policy= expects a Policy, got {type(policy).__name__}"
        )

    def decorator(view: F) -> F:
        @wraps(view)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from omonire_limiter import flask as gl

            if limiter.core_or_none() is None:
                raise ConfigurationError(
                    "this limiter was never bound to a Flask app; construct it as "
                    "AuthLimiter(app) or call limiter.init_app(app) first"
                )

            path = None
            if scope_path is not None:
                path = scope_path(*args, **kwargs) if callable(scope_path) else scope_path

            decision = gl.evaluate(
                limiter,
                limit=limit_spec,
                algorithm=algorithm,
                path=path,
                policy=policy,
            )

            if not decision.allowed:
                if raise_on_limit:
                    raise RateLimitExceeded(decision)
                return gl.render_blocked(decision)

            return view(*args, **kwargs)

        # Recorded for introspection: tooling can read the effective limit off a
        # view without having to re-parse the decorator.
        setattr(wrapper, _ROUTE_LIMIT_ATTR, limit_spec)
        setattr(wrapper, _ROUTE_ALGORITHM_ATTR, algorithm)
        setattr(wrapper, _ROUTE_POLICY_ATTR, policy)
        return wrapper  # type: ignore[return-value]

    return decorator


#: Attributes used to introspect a view's configuration.
_ROUTE_LIMIT_ATTR = "_omonire_limiter_limit"
_ROUTE_ALGORITHM_ATTR = "_omonire_limiter_algorithm"
_ROUTE_POLICY_ATTR = "_omonire_limiter_policy"


def view_limit(view: Any) -> str | RateLimit | None:
    """Return the limit configured on a view, for introspection and tooling."""
    return getattr(view, _ROUTE_LIMIT_ATTR, None)


def view_algorithm(view: Any) -> str | None:
    """Return the per-route algorithm override, if one was set."""
    return getattr(view, _ROUTE_ALGORITHM_ATTR, None)


def view_policy(view: Any) -> Policy | None:
    """Return the policy set explicitly on this view, or ``None``.

    ``None`` means the route was decorated without ``policy=``, so it inherits
    whatever the limiter's default is. To resolve the policy that would actually
    govern the request, combine the two::

        limiter.policy_for(view_policy(view))

    Note that ``@app.route`` returns the wrapped view, so read this off the name
    bound below ``@app.route``, not off the undecorated function.
    """
    return getattr(view, _ROUTE_POLICY_ATTR, None)
