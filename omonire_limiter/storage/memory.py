"""In-process, thread-safe storage.

The default backend: no external dependency, no network hop, good enough for a
single application process and for tests. It is **not** suitable for multiple
workers, because each process gets its own copy of the counters.
"""

from __future__ import annotations

import threading
import time
from bisect import bisect_left, bisect_right
from collections.abc import Callable

from omonire_limiter.storage.base import CounterState, Storage

__all__ = ["MemoryStorage"]

#: Keys are dropped when the store exceeds this many live keys, so a flood of
#: distinct identifiers cannot grow the process without bound.
DEFAULT_MAX_KEYS = 100_000


class MemoryStorage(Storage):
    """Dict-backed storage guarded by a re-entrant lock.

    All mutations happen while holding ``_lock``, so concurrent requests in the
    same process see a consistent count.
    """

    name = "memory"
    shared = False

    __slots__ = ("_clock", "_counters", "_lock", "_logs", "_marks", "_max_keys")

    def __init__(
        self,
        *,
        max_keys: int = DEFAULT_MAX_KEYS,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if max_keys < 1:
            raise ValueError("max_keys must be >= 1")
        self._counters: dict[str, tuple[int, float]] = {}
        self._logs: dict[str, list[float]] = {}
        self._marks: dict[str, float] = {}
        self._lock = threading.RLock()
        self._max_keys = max_keys
        self._clock = clock

    # ---------------------------------------------------------------- helpers

    def _now(self) -> float:
        return self._clock() if self._clock is not None else time.time()

    def _live_key_count(self) -> int:
        return len(self._counters) + len(self._logs) + len(self._marks)

    def _evict_locked(self, now: float) -> None:
        """Drop expired keys, and if still oversized, the oldest half."""
        if self._live_key_count() <= self._max_keys:
            return
        for key, (_value, expires_at) in list(self._counters.items()):
            if expires_at <= now:
                del self._counters[key]
        for key, expires_at in list(self._marks.items()):
            if expires_at <= now:
                del self._marks[key]
        for key, entries in list(self._logs.items()):
            if not entries:
                del self._logs[key]
        if self._live_key_count() <= self._max_keys:
            return
        # Still oversized (a genuine flood of live keys). Sacrifice the oldest
        # half of each map. Evicting live counters temporarily raises the limit
        # for those identifiers, which is the right trade-off: exhausting memory
        # would take the whole application down.
        for store in (self._counters, self._marks):
            if len(store) > self._max_keys // 2:
                for key in list(store.keys())[: len(store) // 2]:
                    del store[key]
        if len(self._logs) > self._max_keys // 2:
            for key in list(self._logs.keys())[: len(self._logs) // 2]:
                del self._logs[key]

    # --------------------------------------------------------------- counters

    def increment(
        self, key: str, *, amount: int = 1, window_seconds: float
    ) -> CounterState:
        if amount < 1:
            raise ValueError("amount must be >= 1")
        with self._lock:
            now = self._now()
            value, expires_at = self._counters.get(key, (0, 0.0))
            if expires_at <= now:
                value, expires_at = 0, now + window_seconds
            value += amount
            self._counters[key] = (value, expires_at)
            self._evict_locked(now)
            return CounterState(value=value, reset_at=expires_at)

    def current(self, key: str) -> CounterState:
        with self._lock:
            now = self._now()
            value, expires_at = self._counters.get(key, (0, 0.0))
            if expires_at <= now:
                return CounterState(value=0, reset_at=None)
            return CounterState(value=value, reset_at=expires_at)

    def clear(self, key: str) -> None:
        """Delete ``key`` from every map.

        ``key`` may be a counter, a sliding-window log, or a cooldown marker, and
        a caller cannot tell which from the key alone. All three maps are
        checked, mirroring the single ``DEL`` the Redis backend performs.
        """
        with self._lock:
            self._counters.pop(key, None)
            self._logs.pop(key, None)
            self._marks.pop(key, None)

    # ---------------------------------------------------------- sliding window

    def log_add(
        self, key: str, *, member: str, timestamp: float, window_seconds: float, amount: int = 1
    ) -> tuple[int, float | None]:
        if amount < 1:
            raise ValueError("amount must be >= 1")
        with self._lock:
            entries = self._logs.get(key)
            if entries is None:
                entries = []
                self._logs[key] = entries
            cutoff = timestamp - window_seconds
            index = bisect_left(entries, cutoff)
            if index:
                del entries[:index]
            # A weighted hit occupies `amount` consecutive slots. They share a
            # timestamp, so the log stays sorted and the memory backend can keep
            # using bisect.
            entries.extend([timestamp] * amount)
            self._evict_locked(self._now())
            return len(entries), entries[0]

    def log_count(self, key: str, *, since: float, until: float) -> int:
        with self._lock:
            entries = self._logs.get(key)
            if not entries:
                return 0
            return bisect_right(entries, until) - bisect_left(entries, since)

    # ---------------------------------------------------------------- marks

    def mark(self, key: str, *, ttl_seconds: float, now: float) -> float:
        expires_at = now + ttl_seconds
        with self._lock:
            self._marks[key] = expires_at
            self._evict_locked(now)
        return expires_at

    def marked_until(self, key: str, *, now: float) -> float | None:
        with self._lock:
            expires_at = self._marks.get(key)
            if expires_at is None:
                return None
            if expires_at <= now:
                del self._marks[key]
                return None
            return expires_at

    # ------------------------------------------------------------ maintenance

    def clear_prefix(self, prefix: str) -> int:
        with self._lock:
            removed = 0
            for store in (self._counters, self._logs, self._marks):
                for key in [key for key in store if key.startswith(prefix)]:
                    del store[key]
                    removed += 1
            return removed
