"""Algorithm behaviour: what each one counts and when it frees a slot."""

from __future__ import annotations

import pytest

from g3_limiter.algorithms import (
    ALGORITHMS,
    FixedWindow,
    SlidingWindow,
    get_algorithm,
    storage_key_for,
)
from g3_limiter.errors import ConfigurationError
from g3_limiter.limits import RateLimit
from g3_limiter.storage.memory import MemoryStorage
from tests.conftest import FakeClock


@pytest.fixture
def backend(clock: FakeClock) -> MemoryStorage:
    return MemoryStorage(clock=clock)


def test_registry_contains_both_algorithms() -> None:
    assert set(ALGORITHMS) == {"fixed_window", "sliding_window"}


def test_get_algorithm_by_name_and_instance() -> None:
    assert isinstance(get_algorithm("fixed_window"), FixedWindow)
    custom = SlidingWindow()
    assert get_algorithm(custom) is custom


def test_get_algorithm_rejects_unknown_name() -> None:
    with pytest.raises(ConfigurationError):
        get_algorithm("magic")


def test_storage_key_is_namespaced_and_distinct_per_algorithm() -> None:
    fixed = storage_key_for("auth", "fixed_window", "POST /login", "abc")
    sliding = storage_key_for("auth", "sliding_window", "POST /login", "abc")
    assert fixed == "g3_limiter:auth:fixed_window:POST /login:abc"
    assert fixed != sliding


# ------------------------------------------------------------------- fixed window


def test_fixed_window_counts_within_window(clock: FakeClock, backend: MemoryStorage) -> None:
    algo = FixedWindow()
    limit = RateLimit.parse("3/minute")
    key = storage_key_for("t", "fixed_window", "s", "r")

    counts = [algo.check(backend, key=key, limit=limit, now=clock.now)[0] for _ in range(4)]
    assert counts == [1, 2, 3, 4]

    # Still inside the window: the count keeps climbing, it does not reset.
    clock.advance(59)
    assert algo.check(backend, key=key, limit=limit, now=clock.now)[0] == 5

    # The window is fixed to its original end, so at t+61 it starts over.
    clock.advance(2)
    assert algo.check(backend, key=key, limit=limit, now=clock.now)[0] == 1


def test_fixed_window_reset_at_is_window_end(clock: FakeClock, backend: MemoryStorage) -> None:
    algo = FixedWindow()
    limit = RateLimit.parse("5/minute")
    count, reset_at = algo.check(
        backend, key="k", limit=limit, now=clock.now
    )
    assert count == 1
    assert reset_at == pytest.approx(clock.now + 60)


def test_fixed_window_reset(clock: FakeClock, backend: MemoryStorage) -> None:
    algo = FixedWindow()
    limit = RateLimit.parse("5/minute")
    algo.check(backend, key="k", limit=limit, now=clock.now)
    algo.reset(backend, key="k")
    assert algo.check(backend, key="k", limit=limit, now=clock.now)[0] == 1


def test_fixed_window_charges_a_weighted_cost(clock: FakeClock, backend: MemoryStorage) -> None:
    algo = FixedWindow()
    limit = RateLimit.parse("10/minute")
    key = storage_key_for("t", "fixed_window", "s", "r")
    # One weighted request consumes several slots, so a caller cannot spend the
    # whole budget in fewer requests by picking the expensive operation.
    assert algo.check(backend, key=key, limit=limit, now=clock.now, cost=4)[0] == 4
    assert algo.check(backend, key=key, limit=limit, now=clock.now, cost=4)[0] == 8
    # Past the limit after one more weighted hit: 12 > 10.
    assert algo.check(backend, key=key, limit=limit, now=clock.now, cost=4)[0] == 12


def test_fixed_window_rejects_a_cost_below_one(
    clock: FakeClock, backend: MemoryStorage
) -> None:
    algo = FixedWindow()
    with pytest.raises(ValueError, match="amount must be >= 1"):
        algo.check(backend, key="k", limit=RateLimit.parse("5/minute"), now=clock.now, cost=0)


# ----------------------------------------------------------------- sliding window


def test_sliding_window_members_are_unique(
    clock: FakeClock, backend: MemoryStorage
) -> None:
    """Members must not collide, or entries would silently merge.

    The Redis backend stores the log as a sorted set, where an identical
    score *and* member overwrites rather than adding. Concurrent requests
    really do land on the same timestamp, so a timestamp-only member would
    let extra requests through.
    """
    algo = SlidingWindow()
    limit = RateLimit.parse("100/minute")
    for _ in range(50):
        # Same clock value on every call: the worst case for collisions.
        assert algo.check(backend, key="k", limit=limit, now=clock.now)[0] < 100
    assert backend.log_count("k", since=clock.now - 1, until=clock.now + 1) == 50


def test_sliding_window_members_differ_across_instances(
    clock: FakeClock, backend: MemoryStorage
) -> None:
    """Two processes must not share member values for the same key."""
    first = SlidingWindow()
    second = SlidingWindow()
    limit = RateLimit.parse("100/minute")
    first.check(backend, key="k", limit=limit, now=clock.now)
    second.check(backend, key="k", limit=limit, now=clock.now)
    assert backend.log_count("k", since=clock.now - 1, until=clock.now + 1) == 2


def test_sliding_window_forgets_as_the_window_slides(
    clock: FakeClock, backend: MemoryStorage
) -> None:
    algo = SlidingWindow()
    limit = RateLimit.parse("3/minute")
    key = storage_key_for("t", "sliding_window", "s", "r")

    for _ in range(3):
        algo.check(backend, key=key, limit=limit, now=clock.now)

    # 30s later the burst is still inside the rolling 60s window.
    clock.advance(30)
    assert algo.check(backend, key=key, limit=limit, now=clock.now)[0] == 4

    # 31s after the first burst, it has slid out.
    clock.advance(31)
    assert algo.check(backend, key=key, limit=limit, now=clock.now)[0] == 2


def test_sliding_window_charges_a_weighted_cost(
    clock: FakeClock, backend: MemoryStorage
) -> None:
    algo = SlidingWindow()
    limit = RateLimit.parse("10/minute")
    key = storage_key_for("t", "sliding_window", "s", "r")
    # Each weighted hit occupies several log entries, so the running count
    # reflects slots consumed rather than requests seen.
    assert algo.check(backend, key=key, limit=limit, now=clock.now, cost=4)[0] == 4
    assert algo.check(backend, key=key, limit=limit, now=clock.now, cost=4)[0] == 8
    assert algo.check(backend, key=key, limit=limit, now=clock.now, cost=4)[0] == 12


def test_sliding_window_weighted_entries_are_all_counted(
    clock: FakeClock, backend: MemoryStorage
) -> None:
    """A weighted hit must not collapse into a single log entry.

    On Redis the log is a sorted set, so entries sharing both score and member
    overwrite one another. A weighted hit that reused one member would be
    counted once no matter how much it was supposed to cost.
    """
    algo = SlidingWindow()
    limit = RateLimit.parse("100/minute")
    for _ in range(10):
        algo.check(backend, key="k", limit=limit, now=clock.now, cost=3)
    assert backend.log_count("k", since=clock.now - 1, until=clock.now + 1) == 30


def test_sliding_window_weighted_entries_roll_out_with_the_window(
    clock: FakeClock, backend: MemoryStorage
) -> None:
    algo = SlidingWindow()
    limit = RateLimit.parse("100/minute")
    key = "k"
    algo.check(backend, key=key, limit=limit, now=clock.now, cost=5)
    assert algo.check(backend, key=key, limit=limit, now=clock.now, cost=5)[0] == 10
    # Both hits were recorded at the same instant, so 61s later the whole burst
    # has slid out at once and the next request starts from a clean log.
    clock.advance(61)
    assert algo.check(backend, key=key, limit=limit, now=clock.now, cost=5)[0] == 5


def test_sliding_window_rejects_a_cost_below_one(
    clock: FakeClock, backend: MemoryStorage
) -> None:
    algo = SlidingWindow()
    with pytest.raises(ValueError, match="amount must be >= 1"):
        algo.check(backend, key="k", limit=RateLimit.parse("5/minute"), now=clock.now, cost=0)


def test_sliding_window_retry_after_points_at_oldest_hit(
    clock: FakeClock, backend: MemoryStorage
) -> None:
    algo = SlidingWindow()
    limit = RateLimit.parse("2/minute")
    key = "k"

    first_at = clock.now
    algo.check(backend, key=key, limit=limit, now=clock.now)
    clock.advance(20)
    _count, next_available = algo.check(backend, key=key, limit=limit, now=clock.now)

    # The first hit leaves the window 60s after it happened, i.e. 40s from now:
    # far more accurate than "wait for the end of the current window".
    assert next_available == pytest.approx(first_at + 60)
    assert next_available - clock.now == pytest.approx(40)


def test_sliding_window_reset(clock: FakeClock, backend: MemoryStorage) -> None:
    algo = SlidingWindow()
    limit = RateLimit.parse("5/minute")
    algo.check(backend, key="k", limit=limit, now=clock.now)
    algo.reset(backend, key="k")
    assert algo.check(backend, key="k", limit=limit, now=clock.now)[0] == 1


def test_fixed_window_allows_boundary_burst(clock: FakeClock, backend: MemoryStorage) -> None:
    """Documents the trade-off of the fixed window, which the sliding window avoids.

    A fixed window hands out a full fresh budget the instant the window rolls
    over, so a caller blocked 0.2s ago gets a whole new allowance 0.2s later.
    This is why ``sliding_window`` is the default.
    """
    algo = FixedWindow()
    limit = RateLimit.parse("5/minute")
    key = "k"

    for _ in range(5):
        algo.check(backend, key=key, limit=limit, now=clock.now)

    clock.advance(59.9)
    blocked_count, _ = algo.check(backend, key=key, limit=limit, now=clock.now)
    assert blocked_count == 6

    clock.advance(0.2)  # the window has just rolled over
    fresh_count, _ = algo.check(backend, key=key, limit=limit, now=clock.now)
    assert fresh_count == 1  # full budget again, 0.2s after being blocked


def test_sliding_window_does_not_burst_at_the_boundary(
    clock: FakeClock, backend: MemoryStorage
) -> None:
    algo = SlidingWindow()
    limit = RateLimit.parse("5/minute")
    key = "k"

    for _ in range(5):
        algo.check(backend, key=key, limit=limit, now=clock.now)

    clock.advance(59.9)
    blocked_count, _ = algo.check(backend, key=key, limit=limit, now=clock.now)
    assert blocked_count == 6

    # The fixed window would have rolled over by now and granted a full new
    # budget. The sliding window still remembers the recent burst, so only a
    # couple of requests fit before the caller is limited again.
    clock.advance(0.2)
    counts = [algo.check(backend, key=key, limit=limit, now=clock.now)[0] for _ in range(5)]
    assert counts == [2, 3, 4, 5, 6]
    assert counts[-1] > limit.limit
