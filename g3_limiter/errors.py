"""Exception hierarchy for :mod:`g3_limiter`.

Every error raised by this package derives from :class:`G3LimiterError` so an
application can catch the whole family with a single ``except`` clause, while
still being able to distinguish configuration mistakes from runtime problems.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from g3_limiter.core import Decision

__all__ = [
    "ConfigurationError",
    "G3LimiterError",
    "InvalidLimitError",
    "RateLimitExceeded",
    "StorageError",
]


class G3LimiterError(Exception):
    """Base class for all errors raised by g3_limiter."""


class ConfigurationError(G3LimiterError, ValueError):
    """The limiter was configured with values that cannot work.

    Raised eagerly at construction time (never on the first request) so a
    misconfiguration fails during start-up instead of in production traffic.
    """


class InvalidLimitError(ConfigurationError):
    """A rate limit string such as ``"5/minute"`` could not be parsed."""


class StorageError(G3LimiterError):
    """The backing store could not be reached or returned an unusable result."""


class RateLimitExceeded(G3LimiterError):
    """Raised when a caller exceeds a limit and the limiter is in raising mode.

    The full :class:`~g3_limiter.core.Decision` is available on the exception
    so a custom error handler can render the correct status, ``Retry-After``
    value and payload without re-deriving anything.
    """

    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.message)
        self.decision = decision
