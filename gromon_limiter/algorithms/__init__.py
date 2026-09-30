"""Rate limiting algorithms.

An *algorithm* decides how a request is counted and when the caller may retry
again. It is intentionally small: given a storage backend it performs one
atomic operation and returns ``(count, next_available_at)``.

Two algorithms ship with the library:

``fixed_window``
    A single counter per key with a TTL. One storage operation, no data
    structure to grow. The trade-off is a burst at the window boundary (up to
    ``2 x limit`` in the worst second) and a slightly late ``Retry-After``.

``sliding_window``
    A log of hit timestamps, pruned on every write. Smooth rate, and
    ``Retry-After`` is exact: it points at the moment the oldest hit in the
    window expires, so a client that waits that long is guaranteed to succeed.

The log is stored in a Redis sorted set, which is why ``sliding_window`` costs
one ``ZADD`` plus a ``ZCARD`` server-side; both happen inside a Lua script, so
concurrent instances cannot interleave.
"""

from __future__ import annotations

import itertools
import secrets
from typing import ClassVar, Protocol

from gromon_limiter.errors import ConfigurationError
from gromon_limiter.limits import RateLimit
from gromon_limiter.storage.base import Storage

__all__ = [
    "ALGORITHMS",
    "Algorithm",
    "FixedWindow",
    "SlidingWindow",
    "get_algorithm",
    "storage_key_for",
]

#: Key namespace. Prefixed on every key so a shared Redis database stays legible.
NAMESPACE = "gromon_limiter"


class Algorithm(Protocol):
    """Strategy interface implemented by every algorithm."""

    name: ClassVar[str]

    def check(
        self, storage: Storage, *, key: str, limit: RateLimit, now: float, cost: int = 1
    ) -> tuple[int, float | None]:
        """Record a hit and return ``(count, next_available_at)``.

        ``count`` includes the hit just recorded, so it is 1 on the first
        request. ``next_available_at`` is the absolute unix timestamp at which
        one slot frees up, or ``None`` if the store cannot say.

        ``cost`` is the number of slots this request consumes. It is 1 for
        ordinary traffic and larger for an operation that is genuinely more
        expensive, so a fixed request budget cannot be spent quickly by a caller
        that keeps choosing the costly variant. The whole charge has to be
        applied in one storage operation, otherwise concurrent callers could
        each pass a limit that only the sum of their costs would breach.
        """
        ...

    def reset(self, storage: Storage, *, key: str) -> None:
        """Discard all recorded state for ``key``."""
        ...


def storage_key_for(namespace: str, algorithm: str, scope: str, rule: str) -> str:
    """Compose a namespaced storage key.

    ``namespace`` isolates one limiter from another; ``algorithm`` keeps the two
    algorithms' data apart; ``scope`` and ``rule`` are already non-identifying
    strings supplied by the caller.
    """
    parts = [NAMESPACE, namespace, algorithm, scope, rule]
    return ":".join(parts)


class FixedWindow:
    """Counter-per-window. Cheap, with an accepted edge burst."""

    name: ClassVar[str] = "fixed_window"

    def check(
        self, storage: Storage, *, key: str, limit: RateLimit, now: float, cost: int = 1
    ) -> tuple[int, float | None]:
        state = storage.increment(
            key, amount=cost, window_seconds=limit.window_seconds
        )
        return state.value, state.reset_at

    def reset(self, storage: Storage, *, key: str) -> None:
        storage.clear(key)


class SlidingWindow:
    """Timestamp log over a rolling interval. Smooth, accurate ``Retry-After``."""

    name: ClassVar[str] = "sliding_window"

    def __init__(self) -> None:
        # Each entry in the log must be a *distinct* member, because the Redis
        # backend stores the log as a sorted set: two entries with the same score
        # and member collapse into one, and the request would go uncounted.
        # Deriving the member from the clock alone is therefore not enough -
        # concurrent requests genuinely do land in the same microsecond. A random
        # per-instance prefix plus a monotonic counter gives uniqueness without a
        # lock or a UUID round trip per request.
        self._prefix = secrets.token_hex(6)
        self._counter = itertools.count()

    def _member(self, now: float) -> str:
        # Unique per instance *and* per call. The suffix matters for weighted
        # hits, where one call adds several entries that share a score: on Redis
        # those entries live in a sorted set, and two entries with the same score
        # and member would collapse into one and undercount the cost.
        return f"{now:.6f}-{self._prefix}-{next(self._counter)}"

    def check(
        self, storage: Storage, *, key: str, limit: RateLimit, now: float, cost: int = 1
    ) -> tuple[int, float | None]:
        count, oldest = storage.log_add(
            key,
            member=self._member(now),
            timestamp=now,
            window_seconds=limit.window_seconds,
            amount=cost,
        )
        if oldest is None:  # pragma: no cover - log_add always returns an entry
            return count, now + limit.window_seconds
        # The retry hint points at the oldest entry, which frees one slot. With
        # cost > 1 a client following it exactly may still be blocked and have to
        # come back. That errs towards an honest 429 rather than a false "you may
        # retry now", which would be worse: the client would loop.
        return count, oldest + limit.window_seconds

    def reset(self, storage: Storage, *, key: str) -> None:
        storage.clear(key)


#: Registry consumed by :func:`get_algorithm`.
ALGORITHMS: dict[str, Algorithm] = {
    FixedWindow.name: FixedWindow(),
    SlidingWindow.name: SlidingWindow(),
}


def get_algorithm(name: str | Algorithm) -> Algorithm:
    """Return the algorithm registered under ``name`` (or pass an instance through)."""
    if not isinstance(name, str):
        return name
    try:
        return ALGORITHMS[name]
    except KeyError as exc:
        raise ConfigurationError(
            f"unknown algorithm {name!r}; supported: {', '.join(sorted(ALGORITHMS))}"
        ) from exc
