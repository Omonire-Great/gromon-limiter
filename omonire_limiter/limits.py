"""Parsing and validation of human readable rate limits.

The canonical input is a short string such as ``"5/minute"``. Everything the
limiter does afterwards works with :class:`RateLimit` instances, so parsing is
kept in one place and validated strictly: a nonsensical limit must fail at
configuration time, never halfway through a login flow.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from omonire_limiter.errors import InvalidLimitError

__all__ = ["RateLimit"]

#: Seconds per supported time unit. The long forms are preferred for readability.
_UNIT_SECONDS: dict[str, float] = {
    "second": 1.0,
    "minute": 60.0,
    "hour": 3600.0,
    "day": 86400.0,
    "week": 604800.0,
    "month": 2592000.0,  # 30 days, deliberately not a calendar month
    "year": 31536000.0,  # 365 days
}

#: Accepted abbreviations, mapped onto the long-form keys above.
_UNIT_ALIASES: dict[str, str] = {
    "s": "second",
    "sec": "second",
    "secs": "second",
    "m": "minute",
    "min": "minute",
    "mins": "minute",
    "h": "hour",
    "hr": "hour",
    "hrs": "hour",
    "d": "day",
    "days": "day",
    "w": "week",
    "wk": "week",
    "wks": "week",
    "mo": "month",
    "mos": "month",
    "y": "year",
    "yr": "year",
}

#: Upper bound on a window. Anything longer is almost certainly a typo and would
#: create storage keys that effectively never expire.
MAX_WINDOW_SECONDS = 366 * 86400.0

#: Upper bound on a single window's request count (1e9), guarding against typos
#: such as ``"5000000000/day"`` silently disabling protection.
MAX_LIMIT = 1_000_000_000

# "5/minute", "5 per minute", "10,000/day", "100/2h", "10 per 2 minutes"
_PATTERN = re.compile(
    r"^\s*(?P<amount>[\d][\d,_]*)\s*(?:/|\bper\b)\s*"
    r"(?:(?P<multiple>\d+(?:\.\d+)?)\s*)?"
    r"(?P<unit>[a-z]+)\s*$",
    re.IGNORECASE,
)


def _parse_amount(raw: str) -> int:
    digits = raw.replace(",", "").replace("_", "")
    if not digits.isdigit():
        raise InvalidLimitError(f"limit amount must be a whole number, got {raw!r}")
    return int(digits)


@dataclass(frozen=True, slots=True)
class RateLimit:
    """An immutable ``<amount> per <window>`` limit.

    ``window_seconds`` is kept as a float because inputs such as ``"0.5/min"``
    are meaningful (30 seconds). :attr:`window` is the rounded-up integer used
    for storage expiry, so sub-second windows still get a sane TTL.
    """

    limit: int
    window_seconds: float
    raw: str = ""

    def __post_init__(self) -> None:
        # Limits are frequently built from configuration or request data that is
        # not statically typed, so the annotations above are not trustworthy at
        # runtime. The values are re-read as `object` to keep these checks
        # meaningful instead of being optimised away as always-true.
        given_limit: object = self.limit
        given_window: object = self.window_seconds
        if not isinstance(given_limit, int) or isinstance(given_limit, bool):
            raise InvalidLimitError(f"limit must be an int, got {self.limit!r}")
        if given_limit < 1:
            raise InvalidLimitError("limit must be at least 1 request")
        if given_limit > MAX_LIMIT:
            raise InvalidLimitError(f"limit must not exceed {MAX_LIMIT:,} requests")
        if not isinstance(given_window, (int, float)) or isinstance(given_window, bool):
            raise InvalidLimitError(
                f"window must be a number of seconds, got {self.window_seconds!r}"
            )
        if given_window < 1:
            raise InvalidLimitError("window must be at least 1 second")
        if given_window > MAX_WINDOW_SECONDS:
            raise InvalidLimitError(
                "window must not exceed 366 days "
                f"({MAX_WINDOW_SECONDS / 86400:.0f} days), got {self.window_seconds}s"
            )

    @property
    def window(self) -> int:
        """The window rounded up to whole seconds (used for storage TTLs)."""
        return max(1, math.ceil(self.window_seconds))

    @property
    def description(self) -> str:
        """A compact human readable form, e.g. ``5/60s``."""
        return f"{self.limit}/{self.window}s"

    @classmethod
    def parse(cls, value: str | RateLimit) -> RateLimit:
        """Parse ``value`` into a :class:`RateLimit`.

        Accepts ``"5/minute"``, ``"5 per minute"``, ``"100/2h"``,
        ``"10,000/day"`` and the long/short form of every supported unit.
        Already-parsed limits pass through unchanged so decorators can accept
        both without the caller caring.
        """
        if isinstance(value, RateLimit):
            return value
        if not isinstance(value, str):
            raise InvalidLimitError(f"limit must be a string, got {type(value).__name__}")

        match = _PATTERN.match(value)
        if match is None:
            raise InvalidLimitError(
                f"cannot parse limit {value!r}; expected '<amount>/<unit>', "
                "for example '5/minute', '100/2 hours' or '10,000/day'"
            )

        amount = _parse_amount(match.group("amount"))
        unit_token = match.group("unit").lower()
        if unit_token.endswith("s") and unit_token[:-1] in _UNIT_SECONDS:
            unit_token = unit_token[:-1]
        unit = _UNIT_ALIASES.get(unit_token, unit_token)
        if unit not in _UNIT_SECONDS:
            supported = ", ".join(sorted(_UNIT_SECONDS))
            raise InvalidLimitError(
                f"unknown time unit {match.group('unit')!r} in {value!r}; supported: {supported}"
            )

        multiple = match.group("multiple")
        multiplier = float(multiple) if multiple is not None else 1.0
        return cls(limit=amount, window_seconds=multiplier * _UNIT_SECONDS[unit], raw=value)

    def __str__(self) -> str:
        return self.raw or self.description
