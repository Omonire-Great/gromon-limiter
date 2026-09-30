"""Memory storage semantics and thread safety."""

from __future__ import annotations

import threading

import pytest

from gromon_limiter.storage.memory import MemoryStorage
from tests.conftest import FakeClock


def test_increment_counts_and_sets_expiry(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock)
    first = storage.increment("k", window_seconds=60)
    assert first.value == 1
    assert first.reset_at == pytest.approx(clock.now + 60)

    second = storage.increment("k", window_seconds=60)
    assert second.value == 2
    # The window does not slide on increment, otherwise this would be a
    # sliding window and the algorithm choice would be meaningless.
    assert second.reset_at == pytest.approx(clock.now + 60)


def test_increment_resets_after_expiry(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock)
    storage.increment("k", window_seconds=60)
    clock.advance(59)
    assert storage.increment("k", window_seconds=60).value == 2
    clock.advance(2)
    assert storage.increment("k", window_seconds=60).value == 1


def test_current_does_not_mutate(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock)
    assert storage.current("missing").value == 0
    assert storage.current("missing").reset_at is None

    storage.increment("k", window_seconds=60)
    assert storage.current("k").value == 1
    assert storage.current("k").value == 1  # reading is not a hit


def test_clear_removes_counter(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock)
    storage.increment("k", window_seconds=60)
    storage.clear("k")
    assert storage.current("k").value == 0
    storage.clear("k")  # idempotent


def test_increment_rejects_zero_amount(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock)
    with pytest.raises(ValueError):
        storage.increment("k", amount=0, window_seconds=60)


# --------------------------------------------------------------- sliding window log


def test_log_add_prunes_expired_entries(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock)
    for _ in range(3):
        storage.log_add("log", member="m", timestamp=clock.now, window_seconds=60)
    count, oldest = storage.log_add("log", member="m", timestamp=clock.now, window_seconds=60)
    assert count == 4
    assert oldest == pytest.approx(clock.now)

    clock.advance(30)
    count, oldest = storage.log_add("log", member="m", timestamp=clock.now, window_seconds=60)
    assert count == 5
    assert oldest == pytest.approx(clock.now)

    clock.advance(31)
    # Now at t+61: the four entries from the first burst (t) are older than the
    # 60s window, so only the t+30 entry and the new one survive.
    count, oldest = storage.log_add("log", member="m", timestamp=clock.now, window_seconds=60)
    assert count == 2
    assert oldest == pytest.approx(clock.now - 31)


def test_log_count_filters_by_range(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock)
    start = clock.now
    for offset in (0, 10, 20, 30):
        storage.log_add("log", member=str(offset), timestamp=start + offset, window_seconds=60)
    assert storage.log_count("log", since=start + 5, until=start + 25) == 2
    assert storage.log_count("log", since=start, until=start + 100) == 4
    assert storage.log_count("log", since=start + 100, until=start + 200) == 0
    assert storage.log_count("missing", since=start, until=start + 10) == 0


# ------------------------------------------------------------------------ markers


def test_mark_and_marked_until(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock)
    assert storage.marked_until("cd", now=clock.now) is None

    expires = storage.mark("cd", ttl_seconds=30, now=clock.now)
    assert expires == pytest.approx(clock.now + 30)
    assert storage.marked_until("cd", now=clock.now) == pytest.approx(clock.now + 30)

    clock.advance(31)
    assert storage.marked_until("cd", now=clock.now) is None


def test_clear_prefix(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock)
    storage.increment("ns:a:1", window_seconds=60)
    storage.increment("ns:a:2", window_seconds=60)
    storage.increment("other:1", window_seconds=60)
    storage.mark("ns:a:cd", ttl_seconds=60, now=clock.now)
    assert storage.clear_prefix("ns:a:") == 3
    assert storage.current("other:1").value == 1


# ------------------------------------------------------------------- concurrency


def test_concurrent_increments_are_not_lost(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock)
    threads = 8
    per_thread = 250
    barrier = threading.Barrier(threads)

    def worker() -> None:
        barrier.wait()
        for _ in range(per_thread):
            storage.increment("hot", window_seconds=600)

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()

    assert storage.current("hot").value == threads * per_thread


def test_concurrent_log_adds_are_not_lost(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock)
    threads = 8
    per_thread = 100
    barrier = threading.Barrier(threads)

    def worker() -> None:
        barrier.wait()
        for _ in range(per_thread):
            storage.log_add("log", member="m", timestamp=clock.now, window_seconds=600)

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()

    assert storage.log_count("log", since=clock.now - 1, until=clock.now + 1) == (
        threads * per_thread
    )


# ------------------------------------------------------------------------ eviction


def test_eviction_bounds_memory(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock, max_keys=50)
    for index in range(500):
        storage.increment(f"key:{index}", window_seconds=600)
    assert len(storage._counters) <= 50


def test_expired_keys_are_reclaimed_before_live_ones(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock, max_keys=20)
    for index in range(15):
        storage.increment(f"short:{index}", window_seconds=1)
    clock.advance(5)  # all of the above have expired
    for index in range(40):
        storage.increment(f"long:{index}", window_seconds=600)

    surviving_short = [key for key in storage._counters if key.startswith("short:")]
    assert surviving_short == []


def test_eviction_bounds_live_keys(clock: FakeClock) -> None:
    storage = MemoryStorage(clock=clock, max_keys=20)
    for index in range(200):
        storage.increment(f"live:{index}", window_seconds=600)
    assert len(storage._counters) <= 20


def test_max_keys_must_be_positive(clock: FakeClock) -> None:
    with pytest.raises(ValueError):
        MemoryStorage(max_keys=0, clock=clock)


def test_storage_context_manager(clock: FakeClock) -> None:
    with MemoryStorage(clock=clock) as storage:
        storage.increment("k", window_seconds=60)
