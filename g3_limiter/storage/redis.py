"""Redis storage, the backend to use in production.

Every state transition that must not race is performed inside a Lua script,
because ``WATCH``/``MULTI`` retries are awkward and a plain pipeline does not
make a read-modify-write atomic. Redis executes each script as a single
operation, so concurrent application instances can share one limiter safely.

The ``redis`` package is imported lazily: the core of this library has no
third-party dependencies, and only this module needs Redis.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from g3_limiter.errors import ConfigurationError, StorageError
from g3_limiter.storage.base import CounterState, Storage

if TYPE_CHECKING:  # pragma: no cover - typing only
    from redis.client import Redis

__all__ = ["RedisStorage"]

# INCRBY + conditional EXPIRE, and return the remaining TTL so the caller can
# build Retry-After without a second round trip. INCRBY rather than INCR because
# a weighted operation has to charge several slots in this same atomic step.
_INCREMENT_LUA = """
local value = redis.call('INCRBY', KEYS[1], ARGV[2])
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {value, ttl}
"""

# Read a counter without touching its TTL.
_CURRENT_LUA = """
local value = tonumber(redis.call('GET', KEYS[1]))
if value == nil then
  return {0, -2}
end
local ttl = redis.call('PTTL', KEYS[1])
return {value, ttl}
"""

# Sliding window log: prune the window, then add and count, atomically.
# Returns {count, oldest_score} where count already includes the new member.
_LOG_ADD_LUA = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', tonumber(ARGV[1]) - tonumber(ARGV[2]))
-- A weighted hit adds `amount` members sharing one score. They must be
-- distinct: in a sorted set, two entries with the same score *and* member
-- collapse into one, so reusing the member would silently charge less than the
-- caller asked for.
local score = tonumber(ARGV[1])
for i = 1, tonumber(ARGV[5]) do
  redis.call('ZADD', KEYS[1], score, ARGV[3] .. '#' .. i)
end
redis.call('PEXPIRE', KEYS[1], ARGV[4])
local count = redis.call('ZCARD', KEYS[1])
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
if #oldest == 0 then
  return {count, ''}
end
return {count, oldest[2]}
"""

_LOG_COUNT_LUA = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', tonumber(ARGV[1]) - tonumber(ARGV[2]))
return redis.call('ZCOUNT', KEYS[1], tonumber(ARGV[1]), tonumber(ARGV[3]))
"""

_GET_LUA = """
return redis.call('GET', KEYS[1])
"""


class RedisStorage(Storage):
    """Counter and log storage backed by Redis.

    Parameters
    ----------
    url:
        ``redis://`` / ``rediss://`` connection string. Never hard-code
        credentials; read this from the environment or a secret manager.
    client:
        An already configured ``redis.Redis`` (connection pool, sentinel, ...).
        Takes precedence over ``url`` and is the usual choice in applications
        that already talk to Redis.
    prefix:
        Prepended to every key, so one Redis database can host several
        independent limiters.
    **client_kwargs:
        Forwarded to ``Redis.from_url`` (e.g. ``socket_connect_timeout``,
        ``ssl_cert_reqs``). Ignored when ``client`` is supplied, since the
        caller then owns connection configuration.
    """

    name = "redis"
    shared = True

    # Declared for type checkers only; __slots__ keeps these off the class dict.
    _client: Redis
    _owns_client: bool

    __slots__ = (
        "_client",
        "_clock",
        "_current",
        "_get",
        "_increment",
        "_log_add",
        "_log_count",
        "_owns_client",
        "_prefix",
    )

    def __init__(
        self,
        *,
        url: str | None = None,
        client: Redis | None = None,
        prefix: str = "g3_limiter",
        clock: Callable[[], float] | None = None,
        **client_kwargs: Any,
    ) -> None:
        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            if not url:
                raise ConfigurationError("RedisStorage requires either url= or client=")
            try:
                import redis
            except ImportError as exc:  # pragma: no cover - depends on env
                raise ConfigurationError(
                    "the redis package is required for RedisStorage; "
                    "install it with `pip install g3-limiter[redis]`"
                ) from exc
            # Extra keyword arguments (TLS, timeouts, socket options) are
            # forwarded verbatim, because a production Redis connection usually
            # needs them and there is nothing useful to wrap.
            # redis-py 5.0 annotates from_url as returning None, which is simply
            # wrong: it returns a configured client. Later versions corrected the
            # stub, so a cast is used rather than a `type: ignore`: the ignore
            # would become an error of its own (unused-ignore) on a newer redis.
            from_url = cast("Any", redis.Redis.from_url)
            self._client = cast("Redis", from_url(url, decode_responses=True, **client_kwargs))
            self._owns_client = True
        self._prefix = prefix.strip(":")
        self._clock = clock
        self._increment = self._client.register_script(_INCREMENT_LUA)
        self._current = self._client.register_script(_CURRENT_LUA)
        self._log_add = self._client.register_script(_LOG_ADD_LUA)
        self._log_count = self._client.register_script(_LOG_COUNT_LUA)
        self._get = self._client.register_script(_GET_LUA)

    # ---------------------------------------------------------------- helpers

    def _now(self) -> float:
        return self._clock() if self._clock is not None else time.time()

    def _key(self, key: str) -> str:
        return f"{self._prefix}:{key}"

    def _run(self, script: Any, key: str, args: list[Any]) -> Any:
        try:
            return script(keys=[self._key(key)], args=args)
        except Exception as exc:
            raise StorageError(f"redis operation failed for {key!r}: {exc}") from exc

    # --------------------------------------------------------------- counters

    def increment(
        self, key: str, *, amount: int = 1, window_seconds: float
    ) -> CounterState:
        if amount < 1:
            raise ValueError("amount must be >= 1")
        now = self._now()
        # The counter is charged by the amount in the same script that sets the
        # expiry, so a weighted hit cannot be seen by another caller as a
        # partial charge. The expiry is only (re)set when the key is new, which
        # keeps the window fixed rather than sliding with the traffic.
        ttl_ms = max(1, int(window_seconds * 1000))
        value, ttl = self._run(self._increment, key, [ttl_ms, amount])
        return CounterState(value=int(value), reset_at=now + (int(ttl) / 1000.0))

    def current(self, key: str) -> CounterState:
        value, ttl = self._run(self._current, key, [])
        if int(value) == 0:
            return CounterState(value=0, reset_at=None)
        if int(ttl) < 0:
            return CounterState(value=int(value), reset_at=None)
        return CounterState(value=int(value), reset_at=self._now() + (int(ttl) / 1000.0))

    def clear(self, key: str) -> None:
        try:
            self._client.delete(self._key(key))
        except Exception as exc:
            raise StorageError(f"redis delete failed for {key!r}: {exc}") from exc

    # ---------------------------------------------------------- sliding window

    def log_add(
        self, key: str, *, member: str, timestamp: float, window_seconds: float, amount: int = 1
    ) -> tuple[int, float | None]:
        if amount < 1:
            raise ValueError("amount must be >= 1")
        count, oldest = self._run(
            self._log_add,
            key,
            [
                int(timestamp * 1000),
                int(window_seconds * 1000),
                member,
                int(window_seconds * 1000),
                amount,
            ],
        )
        return int(count), (float(oldest) / 1000.0 if oldest not in (None, "", b"") else None)

    def log_count(self, key: str, *, since: float, until: float) -> int:
        count = self._run(
            self._log_count,
            key,
            [int(since * 1000), int(until * 1000), int(until * 1000)],
        )
        return int(count)

    # ---------------------------------------------------------------- marks

    def mark(self, key: str, *, ttl_seconds: float, now: float) -> float:
        """Store an absolute expiry with a relative TTL.

        The value is an absolute timestamp so that :meth:`marked_until` can be
        evaluated against an injected clock; the TTL is set as a relative
        duration because that is the only form Redis can expire on.
        """
        expires_at = now + ttl_seconds
        try:
            self._client.set(
                self._key(key), repr(expires_at), px=max(1, int(ttl_seconds * 1000))
            )
        except Exception as exc:
            raise StorageError(f"redis set failed for {key!r}: {exc}") from exc
        return expires_at

    def marked_until(self, key: str, *, now: float) -> float | None:
        """Absolute expiry of ``key``, judged against ``now``.

        The TTL Redis reports is relative to *the server's* clock, so when ``now``
        comes from an injected clock the two can disagree. The stored value is an
        absolute timestamp, so it is compared directly with ``now`` and the
        server's TTL is only used to detect a missing key. That keeps the result
        consistent with the injected clock the rest of the engine uses.
        """
        raw = self._run(self._get, key, [])
        if raw is None or raw == "":
            return None
        try:
            expires_at = float(raw)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return None
        return expires_at if expires_at > now else None

    # ------------------------------------------------------------ maintenance

    def clear_prefix(self, prefix: str) -> int:
        pattern = self._key(prefix) + "*"
        removed = 0
        try:
            batch: list[str] = []
            for key in self._client.scan_iter(match=pattern, count=500):
                batch.append(key)
                if len(batch) >= 500:
                    removed += self._delete_batch(batch)
                    batch = []
            if batch:
                removed += self._delete_batch(batch)
        except Exception as exc:
            raise StorageError(f"redis scan/delete failed for {pattern!r}: {exc}") from exc
        return removed

    def _delete_batch(self, keys: list[str]) -> int:
        # redis-py's stubs model the sync and async clients in one union, so the
        # return type needs narrowing even though the sync client is guaranteed
        # here (this package never constructs an asyncio.Redis). Going through
        # `Any` keeps this working across redis-py versions instead of relying
        # on a `type: ignore` that goes stale as soon as the stubs are fixed.
        return int(cast("Any", self._client.delete)(*keys))

    def close(self) -> None:
        # Only close a client this object created. A client handed in by the
        # application is usually a shared connection pool that other components
        # still need, so closing it would break them.
        if not self._owns_client:
            return
        with contextlib.suppress(Exception):
            # redis-py does not annotate close() in every supported version.
            cast("Any", self._client).close()
