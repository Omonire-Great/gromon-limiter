"""Explicit, validated configuration for the limiter.

Everything that changes behaviour lives on :class:`Settings` and nothing reads a
global. Configuration is validated in ``__post_init__`` so that a bad value
raises at start-up rather than on the first login attempt.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass, field, replace

from omonire_limiter.errors import ConfigurationError
from omonire_limiter.identifiers import SALT_ENV_VAR, TrustedProxies, new_salt
from omonire_limiter.limits import RateLimit

#: Algorithm names are the keys of the registry in ``omonire_limiter.algorithms``.
#: The list is duplicated here (instead of importing the registry) to keep
#: configuration validation free of import cycles.
ALGORITHM_NAMES: frozenset[str] = frozenset({"fixed_window", "sliding_window"})

__all__ = [
    "ALGORITHM_NAMES",
    "DEFAULT_ACCOUNT_FIELDS",
    "KNOWN_IDENTIFIERS",
    "SCOPE_MODES",
    "Settings",
    "normalise_proxies",
    "resolve_key_salt",
]

logger = logging.getLogger("omonire_limiter")

#: Request fields inspected, in order, when looking for an account identifier.
DEFAULT_ACCOUNT_FIELDS: tuple[str, ...] = (
    "email",
    "username",
    "user",
    "account",
    "login",
    "identifier",
    "phone",
    "document",
    "cpf",
)

#: Identifier names with built-in meaning on :class:`~omonire_limiter.identifiers.Identity`.
#: Any other name is looked up in ``Identity.extras`` and simply yields no rule
#: material when the application did not supply it.
KNOWN_IDENTIFIERS: frozenset[str] = frozenset({"ip", "account"})

#: How a rule is scoped beyond the identifier itself.
SCOPE_MODES: frozenset[str] = frozenset({"endpoint", "path", "method", "global"})

#: Backends that need a stable, shared salt (multiple processes, shared storage).
_SHARED_STORAGE = frozenset({"redis"})

#: Default ceiling for an authentication endpoint: 10 attempts per minute. Module
#: level so the dataclass default is a shared instance rather than a call.
DEFAULT_LIMIT = RateLimit(limit=10, window_seconds=60.0, raw="10/minute")


def resolve_key_salt(explicit: str | None, *, storage_name: str) -> str:
    """Resolve the HMAC salt used to fingerprint identifiers.

    Precedence: explicit argument, then the ``OMONIRE_LIMITER_SECRET``
    environment variable, then a fresh random salt.

    A random fallback is only acceptable for single-process, in-memory
    deployments: it changes on every restart (counters reset) and differs per
    process. For shared storage that would silently break limits, so it is a
    hard configuration error there.
    """
    candidate = (explicit or os.environ.get(SALT_ENV_VAR) or "").strip()
    if candidate:
        if len(candidate) < 16:
            raise ConfigurationError(
                f"key salt must be at least 16 characters (use {SALT_ENV_VAR}); "
                "generate one with `python -c \"import secrets;print(secrets.token_urlsafe(32))\"`"
            )
        return candidate

    if storage_name in _SHARED_STORAGE:
        raise ConfigurationError(
            f"{SALT_ENV_VAR} must be set when using {storage_name} storage; a per-process "
            "salt would give every instance a different key space and defeat the limit"
        )
    salt = new_salt()
    logger.warning(
        "omonire_limiter: no key salt configured, generated an ephemeral one. "
        "Counters reset on restart and are not shared. Set %s for stable behaviour.",
        SALT_ENV_VAR,
    )
    return salt


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated limiter configuration.

    Defaults are the ones recommended for authentication endpoints: a tight
    per-IP limit, a looser per-account limit (so an attacker cannot lock a real
    user out by guessing), a short cooldown, and ``fail_open=False`` because an
    authentication endpoint should not silently become unlimited when a
    dependency misbehaves.
    """

    key_salt: str
    namespace: str = "auth"
    identifier: tuple[str, ...] = ("ip", "account")
    default_limit: RateLimit = DEFAULT_LIMIT
    algorithm: str = "sliding_window"
    account_limit_multiplier: float = 3.0
    cooldown_seconds: float = 60.0
    account_cooldown_seconds: float | None = None
    trusted_proxies: tuple[str, ...] = ()
    account_fields: tuple[str, ...] = DEFAULT_ACCOUNT_FIELDS
    scope: str = "endpoint"
    fail_open: bool = False
    enabled: bool = True
    skip_methods: tuple[str, ...] = ("OPTIONS",)
    headers: bool = True
    status_code: int = 429
    extra_identifier_fields: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        # Coerce the string form so every downstream consumer can rely on
        # ``default_limit`` being a RateLimit. A string reaching the engine
        # unchecked would surface as an AttributeError on the first request.
        # The field is annotated as RateLimit, but configuration commonly comes
        # from strings, so the value is inspected as a plain object.
        given_limit: object = self.default_limit
        if isinstance(given_limit, str):
            given_limit = RateLimit.parse(given_limit)
            object.__setattr__(self, "default_limit", given_limit)
        if not isinstance(given_limit, RateLimit):
            raise ConfigurationError(
                "default_limit must be a RateLimit or a limit string, got "
                f"{type(given_limit).__name__}"
            )
        if not self.namespace or not self.namespace.strip():
            raise ConfigurationError("namespace must be a non-empty string")
        if any(char in self.namespace for char in "\r\n\t "):
            raise ConfigurationError("namespace must not contain whitespace")
        if not self.identifier:
            raise ConfigurationError(
                "identifier must name at least one of " + ", ".join(sorted(KNOWN_IDENTIFIERS))
            )
        unknown = set(self.identifier) - (KNOWN_IDENTIFIERS | self.extra_identifier_fields)
        if unknown:
            raise ConfigurationError(
                "unknown identifier(s): "
                + ", ".join(sorted(unknown))
                + "; use one of "
                + ", ".join(sorted(KNOWN_IDENTIFIERS))
                + " or declare them in extra_identifier_fields"
            )
        if len(set(self.identifier)) != len(self.identifier):
            raise ConfigurationError("identifier entries must be unique")
        if self.account_limit_multiplier < 1:
            raise ConfigurationError("account_limit_multiplier must be >= 1")
        if self.cooldown_seconds < 0:
            raise ConfigurationError("cooldown_seconds must be >= 0")
        if self.account_cooldown_seconds is not None and self.account_cooldown_seconds < 0:
            raise ConfigurationError("account_cooldown_seconds must be >= 0")
        if self.scope not in SCOPE_MODES:
            raise ConfigurationError(
                f"scope must be one of {', '.join(sorted(SCOPE_MODES))}, got {self.scope!r}"
            )
        if self.algorithm not in ALGORITHM_NAMES:
            raise ConfigurationError(
                f"algorithm must be one of {', '.join(sorted(ALGORITHM_NAMES))}, "
                f"got {self.algorithm!r}"
            )
        if self.status_code not in (403, 429):
            raise ConfigurationError("status_code must be 429 (recommended) or 403")
        if not self.account_fields:
            raise ConfigurationError("account_fields must not be empty")

    @property
    def trusted(self) -> TrustedProxies:
        """Compiled proxy allow-list, built once per settings object."""
        return TrustedProxies(self.trusted_proxies)

    @property
    def account_cooldown(self) -> float:
        """Cooldown applied to the account rule (falls back to the shared one)."""
        if self.account_cooldown_seconds is None:
            return self.cooldown_seconds
        return self.account_cooldown_seconds

    def with_overrides(self, **changes: object) -> Settings:
        """Return a copy with ``changes`` applied (used by decorators)."""
        return replace(self, **changes)  # type: ignore[arg-type]

    def validated(self) -> Settings:
        """Force validation; useful when settings are built dynamically."""
        self.__post_init__()
        return self


def normalise_proxies(entries: Iterable[str] | None) -> tuple[str, ...]:
    """Normalise a proxy configuration into a tuple of strings."""
    if entries is None:
        return ()
    if isinstance(entries, str):
        entries = [part for part in entries.split(",")]
    return tuple(str(entry).strip() for entry in entries if str(entry).strip())
