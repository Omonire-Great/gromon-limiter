from __future__ import annotations

from gromon_limiter.algorithms import SlidingWindow as _SlidingWindow

__all__ = ["SlidingWindow"]

# Re-export from the canonical module to keep a single implementation.
SlidingWindow = _SlidingWindow  # pragma: no cover - re-export
