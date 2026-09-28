"""Limit string parsing and validation.

A malformed limit must be a start-up error, never a request-time surprise.
"""

from __future__ import annotations

import pytest

from great_limiter.errors import InvalidLimitError
from great_limiter.limits import RateLimit


@pytest.mark.parametrize(
    ("text", "limit", "window"),
    [
        ("5/minute", 5, 60),
        ("5/m", 5, 60),
        ("5/min", 5, 60),
        ("5 per minute", 5, 60),
        ("100/hour", 100, 3600),
        ("100/h", 100, 3600),
        ("10,000/day", 10_000, 86400),
        ("10000/day", 10_000, 86400),
        ("1/second", 1, 1),
        ("1/s", 1, 1),
        ("100/2h", 100, 7200),
        ("10 per 2 minutes", 10, 120),
        ("7/week", 7, 604800),
        ("1/month", 1, 2592000),
        ("5/minutes", 5, 60),
        ("  5 / minute  ", 5, 60),
        ("30/30s", 30, 30),
    ],
)
def test_parses_valid_limits(text: str, limit: int, window: float) -> None:
    parsed = RateLimit.parse(text)
    assert parsed.limit == limit
    assert parsed.window_seconds == pytest.approx(window)
    assert parsed.raw == text


def test_fractional_multiplier_is_allowed() -> None:
    assert RateLimit.parse("6/0.5minute").window_seconds == pytest.approx(30)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "5",
        "5/",
        "/minute",
        "abc",
        "-5/minute",
        "0/minute",
        "5/fortnight",
        "5 per",
        "per minute",
        "5/minute extra",
        "1.5/minute",
        "5/0minutes",
        "5/0.1seconds",
        "5/0.5seconds",
    ],
)
def test_rejects_invalid_limits(text: str) -> None:
    with pytest.raises(InvalidLimitError):
        RateLimit.parse(text)


def test_rejects_non_string_input() -> None:
    with pytest.raises(InvalidLimitError):
        RateLimit.parse(5)  # type: ignore[arg-type]


def test_rejects_negative_and_zero_limit() -> None:
    with pytest.raises(InvalidLimitError):
        RateLimit(limit=0, window_seconds=60)
    with pytest.raises(InvalidLimitError):
        RateLimit(limit=-1, window_seconds=60)


def test_rejects_absurd_window() -> None:
    with pytest.raises(InvalidLimitError):
        RateLimit(limit=5, window_seconds=400 * 86400)


def test_rejects_absurd_limit() -> None:
    with pytest.raises(InvalidLimitError):
        RateLimit(limit=5_000_000_000, window_seconds=60)


def test_window_rounds_up_for_ttl() -> None:
    # A fractional but sub-minute window such as "10/1.5 minutes" is legal; the
    # TTL used for expiry is rounded up so a 90.0s window never gets a 90s TTL
    # that expires early.
    assert RateLimit(limit=10, window_seconds=90.0).window == 90
    assert RateLimit.parse("10/1.5minutes").window == 90


def test_sub_second_windows_are_rejected() -> None:
    # Below one second a network rate limit is meaningless, and a 0s TTL would
    # mean "no expiry".
    with pytest.raises(InvalidLimitError):
        RateLimit.parse("5/0.5seconds")


def test_passthrough_of_parsed_limit() -> None:
    limit = RateLimit.parse("5/minute")
    assert RateLimit.parse(limit) is limit


def test_description_and_str() -> None:
    assert RateLimit(limit=5, window_seconds=60).description == "5/60s"
    assert str(RateLimit.parse("7/hour")) == "7/hour"
    assert str(RateLimit(limit=5, window_seconds=60)) == "5/60s"


def test_is_hashable_and_immutable() -> None:
    limit = RateLimit.parse("5/minute")
    assert {limit, limit} == {limit}
    # frozen=True: reassignment must fail, so a limit cannot be mutated after
    # it has been shared between threads.
    with pytest.raises(AttributeError):
        limit.limit = 10  # type: ignore[misc]
