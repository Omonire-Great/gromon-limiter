"""Storage backends and the factory to build one.

The factory keeps storage selection declarative: an application can pass
``storage="redis"`` with a ``REDIS_URL`` environment variable instead of
constructing a client by hand.
"""

from __future__ import annotations

import os
from typing import Any, Literal

from great_limiter.errors import ConfigurationError
from great_limiter.storage.base import CounterState, Storage
from great_limiter.storage.memory import MemoryStorage
from great_limiter.storage.redis import RedisStorage

__all__ = [
    "CounterState",
    "MemoryStorage",
    "RedisStorage",
    "Storage",
    "build_storage",
]

StorageName = Literal["memory", "redis"]


def build_storage(
    name: str | Storage = "memory",
    *,
    url: str | None = None,
    client: Any = None,
    prefix: str = "great_limiter",
) -> Storage:
    """Build a storage backend by name.

    ``memory`` keeps everything in-process. ``redis`` requires either ``url`` or
    an existing ``client``; if neither is given, ``REDIS_URL`` from the
    environment is used. Credentials must come from the environment or a secret
    manager, never from source code. Passing an already built :class:`Storage`
    returns it unchanged, so callers can accept either form.
    """
    if isinstance(name, Storage):
        return name
    if name == "memory":
        return MemoryStorage()
    if name == "redis":
        redis_url = url or os.environ.get("REDIS_URL")
        if client is None and not redis_url:
            raise ConfigurationError(
                "redis storage requires url= or a client=, or REDIS_URL in the environment"
            )
        return RedisStorage(url=redis_url, client=client, prefix=prefix)
    raise ConfigurationError(f"unknown storage {name!r}; supported: memory, redis")
