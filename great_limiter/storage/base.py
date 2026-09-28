"""Storage interface for counters, sliding-window logs and cooldown markers.

The interface is intentionally tiny and expressed in terms of atomic
primitives. Everything above it (algorithms, engine, HTTP layer) is written
against this contract only, which is what allows the same engine to run on
in-process memory for tests and on Redis for production, single node or many.

Implementations **must** make each method atomic with respect to concurrent
callers. ``increment`` and ``log_add`` in particular are read-modify-write
operations and are the reason the Redis backend uses Lua scripts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

__all__ = ["CounterState", "Storage"]


@dataclass(frozen=True, slots=True)
class CounterState:
    """A counter reading together with the moment it resets.

    ``reset_at`` is an absolute unix timestamp in seconds, or ``None`` when the
    key does not exist. Callers convert it to a delta for ``Retry-After``.
    """

    value: int
    reset_at: float | None

    @property
    def empty(self) -> bool:
        return self.value == 0


class Storage(ABC):
    """Abstract backend for limiter state."""

    #: Short backend name, used in configuration and diagnostics.
    name: ClassVar[str] = "abstract"

    #: True when several processes share this backend. Such backends require a
    #: stable key salt, because a per-process salt would split the key space.
    shared: ClassVar[bool] = False

    # ---------------------------------------------------------------- counters

    @abstractmethod
    def increment(
        self, key: str, *, amount: int = 1, window_seconds: float
    ) -> CounterState:
        """Atomically add ``amount`` to ``key`` and return the new state.

        The expiry is (re)set when the key is created and left untouched on
        subsequent increments, which is what makes this a fixed window.
        """

    @abstractmethod
    def current(self, key: str) -> CounterState:
        """Read ``key`` without modifying it."""

    @abstractmethod
    def clear(self, key: str) -> None:
        """Delete ``key``, whatever kind of key it is (counter, log, marker).

        Used to reset a caller's counters after a successful authentication, so
        it must be a full delete rather than a counter-only decrement.
        """

    # --------------------------------------------------------- sliding window

    @abstractmethod
    def log_add(
        self, key: str, *, member: str, timestamp: float, window_seconds: float
    ) -> tuple[int, float | None]:
        """Atomically append a hit and return ``(count, oldest_timestamp)``.

        Entries older than the window are pruned in the same operation. The
        oldest surviving entry determines when a slot frees up, which gives a
        far more accurate ``Retry-After`` than the window end.
        """

    @abstractmethod
    def log_count(self, key: str, *, since: float, until: float) -> int:
        """Count entries in ``key`` with ``since <= timestamp <= until``."""

    # ---------------------------------------------------------- cooldown mark

    @abstractmethod
    def mark(self, key: str, *, ttl_seconds: float, now: float) -> float:
        """Store an absolute expiry for ``key`` and return it."""

    @abstractmethod
    def marked_until(self, key: str, *, now: float) -> float | None:
        """Return the absolute expiry stored for ``key``, or ``None`` if unset/expired."""

    # ------------------------------------------------------------- maintenance

    @abstractmethod
    def clear_prefix(self, prefix: str) -> int:
        """Delete every key under ``prefix``. Returns the number removed."""

    # Not abstract: closing is optional, and a backend that owns no resources
    # should not be forced to implement a no-op.
    def close(self) -> None:  # noqa: B027
        """Release resources. No-op for backends that hold none."""

    def __enter__(self) -> Storage:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
