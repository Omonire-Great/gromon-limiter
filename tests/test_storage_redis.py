"""Redis backend tests.

These require a live Redis server and are skipped without one::

    docker run -d -p 6379:6379 redis:7
    REDIS_URL=redis://localhost:6379/15 pytest -m redis

The tests exercise the same contract as the memory backend, so a limit behaves
identically on both. The Lua scripts are what make the shared backend safe for
multiple application instances; ``test_concurrent_log_add_is_atomic`` is the
regression guard for that.
"""

from __future__ import annotations

import os
import threading
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
import redis

from great_limiter.errors import ConfigurationError, StorageError
from great_limiter.storage.redis import RedisStorage

pytestmark = pytest.mark.redis


def _live_redis_client() -> Any:
    """Return a client for a real Redis server, or ``None`` if there is none.

    A real server is preferred because the Lua scripts are the part of the
    backend most worth testing. ``fakeredis`` is used as a fallback so the
    contract is still covered in environments without one; it executes Lua
    through ``lupa``, so the scripts are genuinely exercised rather than mocked.
    """
    url = os.environ.get("REDIS_URL")
    if url:
        try:
            client = redis.Redis.from_url(url, decode_responses=True)
            client.ping()
            return client
        except Exception:
            pass
    if os.environ.get("GREAT_LIMITER_FAKE_REDIS", "1") == "0":
        return None
    try:
        import fakeredis
    except ImportError:
        return None
    return fakeredis.FakeStrictRedis(decode_responses=True)


@pytest.fixture
def redis_backend() -> Iterator[RedisStorage]:
    client = _live_redis_client()
    if client is None:
        pytest.skip(
            "no Redis available: set REDIS_URL, or `pip install fakeredis` for "
            "script-level coverage without a server"
        )
    prefix = f"great_limiter_test:{uuid.uuid4().hex[:8]}"
    backend = RedisStorage(client=client, prefix=prefix)
    yield backend
    backend.clear_prefix("")
    backend.close()


def test_requires_url_or_client() -> None:
    with pytest.raises(ConfigurationError):
        RedisStorage()


def test_declares_itself_as_shared() -> None:
    assert RedisStorage.shared is True


def test_increment_and_current(redis_backend: RedisStorage) -> None:
    state = redis_backend.increment("k", window_seconds=60)
    assert state.value == 1
    assert state.reset_at is not None

    current = redis_backend.current("k")
    assert current.value == 1
    assert current.reset_at is not None


def test_current_of_missing_key(redis_backend: RedisStorage) -> None:
    assert redis_backend.current("missing") == redis_backend.current("missing")
    assert redis_backend.current("missing").value == 0


def test_increment_does_not_extend_the_window(redis_backend: RedisStorage) -> None:
    first = redis_backend.increment("k", window_seconds=60)
    second = redis_backend.increment("k", window_seconds=60)
    assert second.value == 2
    assert second.reset_at == pytest.approx(first.reset_at, abs=1.0)


def test_clear_removes_key(redis_backend: RedisStorage) -> None:
    redis_backend.increment("k", window_seconds=60)
    redis_backend.clear("k")
    assert redis_backend.current("k").value == 0


def test_log_add_prunes_and_reports_oldest(redis_backend: RedisStorage) -> None:
    now = 1_000.0
    count, oldest = redis_backend.log_add(
        "log", member="a", timestamp=now, window_seconds=60
    )
    assert count == 1
    assert oldest == pytest.approx(now)

    count, oldest = redis_backend.log_add(
        "log", member="b", timestamp=now + 30, window_seconds=60
    )
    assert count == 2
    assert oldest == pytest.approx(now)

    # At now+61 the first entry is 61s old, so it has left the 60s window, while
    # the entry at now+30 is only 31s old and survives. Count is taken after the
    # new member is added, so it includes the hit just recorded.
    count, oldest = redis_backend.log_add(
        "log", member="c", timestamp=now + 61, window_seconds=60
    )
    assert count == 2
    assert oldest == pytest.approx(now + 30)

    # By now+91 the second entry has also aged out, leaving only the newest.
    count, oldest = redis_backend.log_add(
        "log", member="d", timestamp=now + 91, window_seconds=60
    )
    assert count == 2
    assert oldest == pytest.approx(now + 61)


def test_log_add_charges_a_weighted_amount(redis_backend: RedisStorage) -> None:
    """A weighted hit must add several members, not one.

    The log is a sorted set, so members sharing both score and member would
    overwrite each other and the extra cost would silently vanish. This is the
    regression guard for the member suffixing in the Lua script.
    """
    now = 1_000.0
    count, oldest = redis_backend.log_add(
        "weighted", member="a", timestamp=now, window_seconds=60, amount=3
    )
    assert count == 3
    assert oldest == pytest.approx(now)

    count, _oldest = redis_backend.log_add(
        "weighted", member="b", timestamp=now, window_seconds=60, amount=3
    )
    # A second weighted hit accumulates on top of the first.
    assert count == 6

    # Pruning still works on a weighted log: after 61s the whole burst is gone.
    count, _oldest = redis_backend.log_add(
        "weighted", member="b", timestamp=now + 61, window_seconds=60, amount=3
    )
    assert count == 3


def test_log_add_rejects_a_non_positive_amount(redis_backend: RedisStorage) -> None:
    with pytest.raises(ValueError, match="amount must be >= 1"):
        redis_backend.log_add(
            "log", member="a", timestamp=1_000.0, window_seconds=60, amount=0
        )


def test_increment_charges_a_weighted_amount(redis_backend: RedisStorage) -> None:
    state = redis_backend.increment("counter", amount=5, window_seconds=60)
    assert state.value == 5
    assert redis_backend.current("counter").value == 5
    with pytest.raises(ValueError, match="amount must be >= 1"):
        redis_backend.increment("counter", amount=0, window_seconds=60)


def test_log_count(redis_backend: RedisStorage) -> None:
    now = 1_000.0
    for offset, member in ((0, "a"), (10, "b"), (20, "c")):
        redis_backend.log_add("log", member=member, timestamp=now + offset, window_seconds=60)
    assert redis_backend.log_count("log", since=now + 5, until=now + 15) == 1
    assert redis_backend.log_count("log", since=now, until=now + 30) == 3
    assert redis_backend.log_count("missing", since=now, until=now + 30) == 0


def test_mark_and_marked_until(redis_backend: RedisStorage) -> None:
    now = 1_000.0
    assert redis_backend.marked_until("cd", now=now) is None
    expires = redis_backend.mark("cd", ttl_seconds=30, now=now)
    assert expires == pytest.approx(now + 30)
    assert redis_backend.marked_until("cd", now=now) == pytest.approx(now + 30)
    assert redis_backend.marked_until("cd", now=now + 31) is None


def test_clear_prefix(redis_backend: RedisStorage) -> None:
    redis_backend.increment("ns:1", window_seconds=60)
    redis_backend.increment("ns:2", window_seconds=60)
    redis_backend.increment("other:1", window_seconds=60)
    assert redis_backend.clear_prefix("ns:") == 2
    assert redis_backend.current("other:1").value == 1


def test_concurrent_increment_is_atomic(redis_backend: RedisStorage) -> None:
    """The Lua script is what makes this safe across threads and processes."""
    threads = 8
    per_thread = 40
    barrier = threading.Barrier(threads)

    def worker() -> None:
        barrier.wait()
        for _ in range(per_thread):
            redis_backend.increment("hot", window_seconds=600)

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()

    assert redis_backend.current("hot").value == threads * per_thread


def test_concurrent_log_add_is_atomic(redis_backend: RedisStorage) -> None:
    threads = 6
    per_thread = 30
    base = 2_000.0
    barrier = threading.Barrier(threads)

    def worker(index: int) -> None:
        barrier.wait()
        for step in range(per_thread):
            redis_backend.log_add(
                "log", member=f"{index}:{step}", timestamp=base, window_seconds=600
            )

    workers = [threading.Thread(target=worker, args=(index,)) for index in range(threads)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()

    assert redis_backend.log_count("log", since=base, until=base + 1) == threads * per_thread


def test_storage_errors_are_wrapped() -> None:
    """Connection failures surface as StorageError, not a raw redis exception."""
    backend = RedisStorage(
        url="redis://127.0.0.1:1/0", prefix="test", socket_connect_timeout=0.2
    )
    with pytest.raises(StorageError):
        backend.increment("k", window_seconds=60)
    backend.close()
