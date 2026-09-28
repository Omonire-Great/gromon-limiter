"""Flask integration for :mod:`g3_limiter`.

This is the only module in the package that imports Flask. It does three things
and delegates everything else to :class:`~g3_limiter.core.LimiterCore`:

* build a validated :class:`~g3_limiter.config.Settings` and attach the
  engine to ``app.extensions``;
* resolve the request identity from Flask's cached request object;
* convert a blocking :class:`~g3_limiter.core.Decision` into a 429 JSON
  response and publish rate limit headers on allowed responses.

The identity is read through ``request.get_json(silent=True)`` /
``request.form`` on purpose: Werkzeug caches both, so the limiter can look for an
account identifier without consuming the body the view is about to read. Reading
the raw WSGI stream here would leave the view with an empty form.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from typing import Any

from g3_limiter.config import (
    ALGORITHM_NAMES,
    DEFAULT_ACCOUNT_FIELDS,
    Settings,
    normalise_proxies,
    resolve_key_salt,
)
from g3_limiter.core import Decision, LimiterCore, build_body, build_headers
from g3_limiter.errors import ConfigurationError, RateLimitExceeded, StorageError
from g3_limiter.identifiers import Identity, client_ip, normalize_account
from g3_limiter.limits import RateLimit
from g3_limiter.storage import build_storage
from g3_limiter.storage.base import Storage

try:  # pragma: no cover - exercised implicitly by every Flask test
    from flask import current_app, g, has_request_context, request
except ImportError as exc:  # pragma: no cover - depends on environment
    raise ImportError(
        "Flask is required for the Flask integration; install it with "
        "`pip install g3-limiter[flask]`"
    ) from exc

__all__ = [
    "build_identity",
    "current_limiter",
    "init_auth_limiter",
    "resolve_limiter",
]

logger = logging.getLogger("g3_limiter")

#: Key under which the engine is stored in ``app.extensions``.
EXTENSION_KEY = "g3_limiter"

#: Where the decorator stashes the decision so ``after_request`` can publish it.
_DECISION_ATTR = "_g3_limiter_decision"

#: Where the decorator stashes the Flask config on first use, for introspection.
_ROUTE_ATTR = "_g3_limiter_limit"


def _limiter_from(app: Any) -> Any:
    return app.extensions.get(EXTENSION_KEY)


def resolve_limiter(app: Any) -> Any:
    """Return the limiter registered on ``app`` or raise."""
    limiter = _limiter_from(app)
    if limiter is None:
        raise ConfigurationError(
            "g3_limiter is not initialised on this app; call AuthLimiter(app) "
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
    """Resolve the :class:`~g3_limiter.identifiers.Identity` of this request.

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
) -> Any:
    """Build the engine and attach it to ``app``.

    Every knob is explicit; nothing is read from a global. The first argument is
    the :class:`~g3_limiter.AuthLimiter` instance being initialised, so
    ``AuthLimiter(app)`` and ``AuthLimiter().init_app(app)`` behave identically.
    """
    if EXTENSION_KEY in app.extensions:
        existing = app.extensions[EXTENSION_KEY]
        if existing is limiter:
            return app
        raise ConfigurationError(
            "g3_limiter is already initialised on this app. Constructing two "
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
) -> Decision:
    """Run one check and record the decision on ``flask.g``.

    The recorded decision is what ``_publish_headers`` turns into response
    headers, and what the decorator uses to decide between returning normally
    and returning 429.
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

    identity = _make_identity(limiter)
    try:
        decision = limiter.core.check(
            identity,
            path=path if path is not None else request.path,
            method=method_u,
            limit=limit,
            algorithm=algorithm,
            enforce=False,
        )
    except StorageError:
        if not settings.fail_open:
            logger.exception(
                "g3_limiter: storage unavailable, failing closed (namespace=%s)",
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
                "g3_limiter: storage unavailable, allowing request "
                "(fail_open=True, namespace=%s)",
                settings.namespace,
            )
            decision = Decision(allowed=True)

    setattr(g, _DECISION_ATTR, decision)
    return decision


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
