"""Exception hierarchy for :mod:`great_limiter`.

Every error raised by this package derives from :class:`GreatLimiterError` so an
application can catch the whole family with a single ``except`` clause, while
still being able to distinguish configuration mistakes from runtime problems.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from great_limiter.core import Decision

__all__ = [
    "ConfigurationError",
    "GreatLimiterError",
    "InvalidLimitError",
    "RateLimitExceeded",
    "StorageError",
]


class GreatLimiterError(Exception):
    """Base class for all errors raised by great_limiter."""


class ConfigurationError(GreatLimiterError, ValueError):
    """The limiter was configured with values that cannot work.

    Raised eagerly at construction time (never on the first request) so a
    misconfiguration fails during start-up instead of in production traffic.
    """


class InvalidLimitError(ConfigurationError):
    """A rate limit string such as ``"5/minute"`` could not be parsed."""


class StorageError(GreatLimiterError):
    """The backing store could not be reached or returned an unusable result."""


class RateLimitExceeded(GreatLimiterError):
    """Raised when a caller exceeds a limit and the limiter is in raising mode.

    The full :class:`~great_limiter.core.Decision` is available on the exception
    so a custom error handler can render the correct status, ``Retry-After``
    value and payload without re-deriving anything.
    """

    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.message)
        self.decision = decision
