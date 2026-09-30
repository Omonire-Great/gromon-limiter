"""Flask integration for :mod:`omonire_limiter`.

This is the only module in the package that imports Flask. It does three things
and delegates everything else to :class:`~omonire_limiter.core.LimiterCore`:

* build a validated :class:`~omonire_limiter.config.Settings` and attach the
  engine to ``app.extensions``;
* resolve the request identity from Flask's cached request object;
* convert a blocking :class:`~omonire_limiter.core.Decision` into a 429 JSON
  response and publish rate limit headers on allowed responses.

The identity is read through ``request.get_json(silent=True)`` /
``request.form`` on purpose: Werkzeug caches both, so the limiter can look for an
account identifier without consuming the body the view is about to read. Reading
the raw WSGI stream here would leave the view with an empty form.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import replace
from typing import Any

from omonire_limiter.config import (
    ALGORITHM_NAMES,
    DEFAULT_ACCOUNT_FIELDS,
    Settings,
    normalise_proxies,
    resolve_key_salt,
)
from omonire_limiter.core import Decision, LimiterCore, build_body, build_headers
from omonire_limiter.engine import PolicyEvaluator
from omonire_limiter.errors import ConfigurationError, RateLimitExceeded, StorageError
from omonire_limiter.identifiers import Identity, client_ip, normalize_account
from omonire_limiter.limits import RateLimit
from omonire_limiter.policies import Policy
from omonire_limiter.storage import build_storage
from omonire_limiter.storage.base import Storage

try:  # pragma: no cover - exercised implicitly by every Flask test
    from flask import current_app, g, has_request_context, request
except ImportError as exc:  # pragma: no cover - depends on environment
    raise ImportError(
        "Flask is required for the Flask integration; install it with "
        "`pip install omonire-limiter[flask]`"
    ) from exc

__all__ = [
    "ExtrasProvider",
    "build_identity",
    "current_limiter",
    "init_auth_limiter",
    "resolve_limiter",
]

logger = logging.getLogger("omonire_limiter")

#: Key under which the engine is stored in ``app.extensions``.
EXTENSION_KEY = "omonire_limiter"

#: Where the decorator stashes the decision so ``after_request`` can publish it.
_DECISION_ATTR = "_omonire_limiter_decision"

#: Where the decorator stashes the Flask config on first use, for introspection.
_ROUTE_ATTR = "_omonire_limiter_limit"

#: Supplies authenticated identity material (user, tenant, api_key) for V2 rules.
#: Called once per request, inside the request context, so it can read the
#: session or a verified token. Returning ``None`` means "nothing extra", and a
#: rule keyed on material that is absent is skipped rather than counted against a
#: shared bucket.
ExtrasProvider = Callable[[], "Identity | Mapping[str, str] | None"]


def _limiter_from(app: Any) -> Any:
    return app.extensions.get(EXTENSION_KEY)


def resolve_limiter(app: Any) -> Any:
    """Return the limiter registered on ``app`` or raise."""
    limiter = _limiter_from(app)
    if limiter is None:
        raise ConfigurationError(
            "omonire_limiter is not initialised on this app; call AuthLimiter(app) "
            "or limiter.init_app(app) before using the decorator"
        )
    return limiter


def current_limiter() -> Any:
    """Return the limiter bound to the current Flask app."""
    if not has_request_context():
        raise RuntimeError("current_limiter() requires a request context")
    return resolve_limiter(current_app)


def build_identity(
    account_fields: Iterable[str] = DEFAULT_ACCOUNT_FIELDS,
    *,
    trusted_proxies: Any = None,
    headers: Any = None,
) -> Identity:
    """Resolve the :class:`~omonire_limiter.identifiers.Identity` of this request.

    ``headers`` defaults to ``request.headers``. It is a parameter so tests (and
    a future non-Flask adapter) can supply a plain mapping.
    """
    fields = tuple(account_fields)
    header_map = request.headers if headers is None else headers
    ip = client_ip(
        remote_addr=request.remote_addr,
        forwarded_for=header_map.get("X-Forwarded-For"),
        real_ip=header_map.get("X-Real-IP"),
        trusted_proxies=trusted_proxies,
    )
    account = _account_from_request(fields)
    return Identity(ip=ip, account=account)


def _account_from_request(fields: tuple[str, ...]) -> str | None:
    """Look for an account identifier in the JSON body, form body, then query.

    Order is deliberate: an explicit body field beats a query parameter, because
    a query parameter is far more likely to be a shared/ambient value.
    """
    payload = request.get_json(silent=True)
    if isinstance(payload, dict):
        value = _first_field(payload, fields)
        if value:
            return value
    for container in (request.form, request.args):
        value = _first_field(container, fields)
        if value:
            return value
    return None


def _first_field(container: Any, fields: tuple[str, ...]) -> str | None:
    for name in fields:
        if name in container:
            normalised = normalize_account(container[name])
            if normalised:
                return normalised
    return None


def _make_identity(limiter: Any) -> Identity:
    settings: Settings = limiter.settings
    return build_identity(
        settings.account_fields,
        trusted_proxies=limiter.core.trusted_proxies,
    )


def _extras_for(limiter: Any) -> Identity | None:
    """Resolve authenticated material for V2 rules keyed on user/tenant/api_key.

    A provider that raises must not turn into a 500 on every request, so the
    failure is logged and treated as "no extras". A rule that needed the material
    is then *skipped* by the evaluator rather than counted against a shared
    bucket, which is the safe direction: the rule stops applying instead of every
    anonymous caller landing in one bucket an attacker could exhaust.
    """
    provider: ExtrasProvider | None = getattr(limiter, "extras_provider", None)
    if provider is None:
        return None
    try:
        supplied = provider()
    except Exception:
        # A provider that raises must not turn into a 500 on every request.
        logger.exception(
            "omonire_limiter: extras provider raised; rules keyed on it are skipped "
            "(namespace=%s)",
            getattr(limiter.settings, "namespace", "?"),
        )
        return None
    if supplied is None:
        return None
    if isinstance(supplied, Identity):
        return supplied
    return Identity(extras=dict(supplied))


def evaluator_for(limiter: Any) -> PolicyEvaluator:
    """Return the limiter's policy evaluator, building it once.

    The evaluator caches one engine view per (policy, rule), so constructing a new
    one per request would throw that cache away and rebuild settings on the hot
    path. Public because :meth:`Limiter.reset` needs it outside a request cycle.
    """
    existing: PolicyEvaluator | None = getattr(limiter, "_evaluator", None)
    if existing is None:
        existing = PolicyEvaluator(limiter.core)
        limiter._evaluator = existing
    return existing


def _policy_decision(
    limiter: Any,
    policy: Policy,
    identity: Identity,
    *,
    path: str,
    method: str,
) -> Decision:
    """Evaluate a V2 policy and reduce the verdict to a single ``Decision``.

    The verdict is collapsed here so the rest of the Flask layer — the 429
    renderer, the header publisher, ``raise_on_limit`` — keeps working unchanged
    whether a V1 limit or a V2 policy produced the decision.
    """
    verdict = evaluator_for(limiter).check(
        policy,
        identity,
        path=path,
        method=method,
        extras=_extras_for(limiter),
    )
    decision = verdict.decision
    if not verdict.allowed:
        return decision
    # The verdict may have absorbed a storage error under a fail-open policy, in
    # which case `decision.allowed` is "allowed because we could not tell". That
    # has to reach the caller, so the flag is carried on the decision the rest of
    # the layer can see.
    if verdict.storage_failed and not decision.storage_failed:
        decision = replace(decision, storage_failed=True)
    return decision


def _blocked_response(decision: Decision, status_code: int, *, include_info: bool) -> Any:
    """Render a blocking decision as a Flask JSON response.

    ``Retry-After`` is always sent: RFC 9110 requires it on a 429, and a client
    that cannot tell when to retry will simply keep hammering. The remaining
    ``X-RateLimit-*`` fields follow the ``headers`` setting; when they are off
    the same values are still available in the JSON body.
    """
    response = current_app.response_class(
        build_body(decision),
        status=status_code,
        mimetype="application/json",
    )
    headers = build_headers(decision)
    for header, value in headers.items():
        if header == "Retry-After" or include_info:
            response.headers[header] = value
    return response


def render_blocked(decision: Decision) -> Any:
    """Return the 429 (or configured status) response for a blocked request.

    Called by the decorator. Kept here so the status code, the body and the
    headers always come from the same configuration.
    """
    limiter = _limiter_from(current_app)
    settings = limiter.settings if limiter is not None else None
    return _blocked_response(
        decision,
        settings.status_code if settings else 429,
        include_info=settings.headers if settings else True,
    )


def init_auth_limiter(
    limiter: Any,
    app: Any,
    *,
    limit: str | RateLimit = "10/minute",
    storage: str | Storage = "memory",
    storage_url: str | None = None,
    redis_client: Any = None,
    key_salt: str | None = None,
    namespace: str = "auth",
    identifier: Iterable[str] = ("ip", "account"),
    algorithm: str = "sliding_window",
    account_limit_multiplier: float = 3.0,
    cooldown: float = 60.0,
    account_cooldown: float | None = None,
    trusted_proxies: Iterable[str] | str = (),
    account_fields: Iterable[str] = DEFAULT_ACCOUNT_FIELDS,
    scope: str = "endpoint",
    fail_open: bool = False,
    enabled: bool = True,
    skip_methods: Iterable[str] = ("OPTIONS",),
    headers: bool = True,
    status_code: int = 429,
    clock: Callable[[], float] | None = None,
    policy: Policy | None = None,
    extras_provider: ExtrasProvider | None = None,
) -> Any:
    """Build the engine and attach it to ``app``.

    Every knob is explicit; nothing is read from a global. The first argument is
    the :class:`~omonire_limiter.AuthLimiter` instance being initialised, so
    ``AuthLimiter(app)`` and ``AuthLimiter().init_app(app)`` behave identically.
    """
    if EXTENSION_KEY in app.extensions:
        existing = app.extensions[EXTENSION_KEY]
        if existing is limiter:
            return app
        raise ConfigurationError(
            "omonire_limiter is already initialised on this app. Constructing two "
            "limiters would count every request twice; reuse the existing one."
        )

    backend: Storage = storage if isinstance(storage, Storage) else build_storage(
        storage, url=storage_url, client=redis_client
    )

    settings = Settings(
        key_salt=resolve_key_salt(key_salt, storage_name=backend.name),
        namespace=namespace,
        identifier=tuple(identifier),
        default_limit=RateLimit.parse(limit),
        algorithm=algorithm,
        account_limit_multiplier=account_limit_multiplier,
        cooldown_seconds=cooldown,
        account_cooldown_seconds=account_cooldown,
        trusted_proxies=normalise_proxies(trusted_proxies),
        account_fields=tuple(account_fields),
        scope=scope,
        fail_open=fail_open,
        enabled=enabled,
        skip_methods=tuple(method.upper() for method in skip_methods),
        headers=headers,
        status_code=status_code,
    )

    core = LimiterCore(settings, backend, clock=clock)

    limiter._core = core
    limiter._settings = settings
    limiter._storage = backend
    limiter._app = app
    # Set unconditionally so the attribute always exists: a V1 limiter must read
    # as "no provider" rather than raising AttributeError deep in a request.
    limiter.extras_provider = extras_provider
    if policy is not None:
        # A policy supplied here becomes the limiter's default, so
        # `Limiter.for_policy(p, app=app)` and `init_app(app, policy=p)` agree.
        limiter.default_policy = policy

    app.extensions[EXTENSION_KEY] = limiter

    if settings.headers:
        app.after_request(_publish_headers)

    return app


def _publish_headers(response: Any) -> Any:
    """Attach rate limit headers to allowed responses.

    Clients need ``X-RateLimit-Remaining`` on *successful* responses too,
    otherwise they cannot pace themselves and only discover the limit by being
    rejected.
    """
    decision: Decision | None = getattr(g, _DECISION_ATTR, None)
    if decision is None:
        return response
    for header, value in build_headers(decision).items():
        response.headers.setdefault(header, value)
    return response


def evaluate(
    limiter: Any,
    *,
    limit: str | RateLimit | None = None,
    algorithm: str | None = None,
    path: str | None = None,
    method: str | None = None,
    policy: Policy | None = None,
) -> Decision:
    """Run one check and record the decision on ``flask.g``.

    The recorded decision is what ``_publish_headers`` turns into response
    headers, and what the decorator uses to decide between returning normally
    and returning 429.

    A V2 ``policy`` on the route (or the limiter's default) is evaluated through
    :class:`~omonire_limiter.engine.PolicyEvaluator` and takes precedence over the
    V1 ``limit``/``algorithm`` arguments. The two models are alternatives, not a
    merge: a policy owns its own per-rule limits, so quietly applying ``limit`` on
    top of it would enforce something the policy never declared.
    """
    settings: Settings = limiter.settings
    if not settings.enabled:
        decision = Decision(allowed=True)
        setattr(g, _DECISION_ATTR, decision)
        return decision

    method_u = (method or request.method).upper()
    if method_u in settings.skip_methods:
        decision = Decision(allowed=True)
        setattr(g, _DECISION_ATTR, decision)
        return decision

    effective_policy = _policy_for(limiter, policy)
    identity = _make_identity(limiter)
    resolved_path = path if path is not None else request.path
    try:
        if effective_policy is not None:
            decision = _policy_decision(
                limiter, effective_policy, identity, path=resolved_path, method=method_u
            )
        else:
            decision = limiter.core.check(
                identity,
                path=resolved_path,
                method=method_u,
                limit=limit,
                algorithm=algorithm,
                enforce=False,
            )
    except StorageError:
        if not settings.fail_open:
            logger.exception(
                "omonire_limiter: storage unavailable, failing closed (namespace=%s)",
                settings.namespace,
            )
            decision = Decision(
                allowed=False,
                limit=settings.default_limit.limit,
                remaining=0,
                retry_after=int(settings.cooldown_seconds) or 1,
                message="Rate limiting is temporarily unavailable. Please retry shortly.",
                rule="storage",
            )
        else:
            logger.warning(
                "omonire_limiter: storage unavailable, allowing request "
                "(fail_open=True, namespace=%s)",
                settings.namespace,
            )
            decision = Decision(allowed=True)

    setattr(g, _DECISION_ATTR, decision)
    return decision


def _policy_for(limiter: Any, override: Policy | None) -> Policy | None:
    """Return the policy that applies to this request, or ``None`` for the V1 path.

    ``policy_for`` is looked up dynamically because it only exists on ``Limiter``
    (V2); a V1 ``AuthLimiter`` must fall through to the engine untouched.
    """
    resolver: Callable[[Policy | None], Policy | None] | None = getattr(
        limiter, "policy_for", None
    )
    if resolver is None:
        return None
    return resolver(override)


def current_decision() -> Decision | None:
    """Return the decision recorded for the current request, if any."""
    if not has_request_context():
        return None
    return getattr(g, _DECISION_ATTR, None)


__all__ += [
    "ALGORITHM_NAMES",
    "EXTENSION_KEY",
    "RateLimitExceeded",
    "StorageError",
    "current_decision",
    "evaluate",
]
