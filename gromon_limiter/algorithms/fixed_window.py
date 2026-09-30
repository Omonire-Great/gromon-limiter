from __future__ import annotations

from gromon_limiter.algorithms import FixedWindow as _FixedWindow

__all__ = ["FixedWindow"]

# Re-export from the canonical module to keep a single implementation.
FixedWindow = _FixedWindow  # pragma: no cover - re-export
