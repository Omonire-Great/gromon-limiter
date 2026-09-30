"""Exception hierarchy for :mod:`gromon_limiter`.

The classes are siblings rather than a single family: a configuration mistake
(:class:`ConfigurationError`) is also a :class:`ValueError`, while a storage
outage (:class:`StorageError`) and a refused request
(:class:`RateLimitExceeded`) are independent runtime errors. Catch the specific
class you can act on.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from gromon_limiter.core import Decision

__all__ = [
    "ConfigurationError",
    "InvalidLimitError",
    "RateLimitExceeded",
    "StorageError",
]


class ConfigurationError(ValueError):
    """The limiter was configured with values that cannot work.

    Raised eagerly at construction time (never on the first request) so a
    misconfiguration fails during start-up instead of in production traffic.
    """


class InvalidLimitError(ConfigurationError):
    """A rate limit string such as ``"5/minute"`` could not be parsed."""


class StorageError(Exception):
    """The backing store could not be reached or returned an unusable result."""


class RateLimitExceeded(Exception):
    """Raised when a caller exceeds a limit and the limiter is in raising mode.

    The full :class:`~gromon_limiter.core.Decision` is available on the exception
    so a custom error handler can render the correct status, ``Retry-After``
    value and payload without re-deriving anything.
    """

    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.message)
        self.decision = decision
