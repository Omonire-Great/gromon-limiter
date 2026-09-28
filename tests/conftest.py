"""Shared fixtures.

Time is faked everywhere. A rate limiter is a time-dependent state machine, and
tests that sleep for 60 seconds to observe a window rolling over are slow and
flaky; injecting the clock makes the same assertions deterministic.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator

import pytest
from flask import Flask

from g3_limiter import AuthLimiter
from g3_limiter.config import Settings, resolve_key_salt
from g3_limiter.core import LimiterCore
from g3_limiter.storage.memory import MemoryStorage

TEST_SALT = "test-salt-do-not-use-in-production"


class FakeClock:
    """A monotonic clock that only moves when a test tells it to."""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> float:
        self.now += seconds
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def storage(clock: FakeClock) -> Iterator[MemoryStorage]:
    backend = MemoryStorage(clock=clock)
    yield backend
    backend.close()


@pytest.fixture
def make_settings(clock: FakeClock) -> Callable[..., Settings]:
    def factory(**overrides: object) -> Settings:
        # Aliases so tests can use the same keyword names as init_auth_limiter.
        aliases = {
            "limit": "default_limit",
            "cooldown": "cooldown_seconds",
            "account_cooldown": "account_cooldown_seconds",
        }
        for alias, target in aliases.items():
            if alias in overrides:
                overrides[target] = overrides.pop(alias)

        from g3_limiter.limits import RateLimit

        if isinstance(overrides.get("default_limit"), str):
            overrides["default_limit"] = RateLimit.parse(overrides["default_limit"])  # type: ignore[arg-type]

        params: dict[str, object] = {
            "key_salt": TEST_SALT,
            "namespace": "auth",
            "default_limit": RateLimit.parse("5/minute"),
            "cooldown_seconds": 60.0,
            "enabled": True,
            "headers": True,
        }
        params.update(overrides)
        return Settings(**params).validated()  # type: ignore[arg-type]

    return factory


@pytest.fixture
def make_core(
    make_settings: Callable[..., Settings], storage: MemoryStorage, clock: FakeClock
) -> Callable[..., LimiterCore]:
    def factory(**overrides: object) -> LimiterCore:
        settings = make_settings(**overrides)
        return LimiterCore(settings, storage, clock=clock)

    return factory


@pytest.fixture
def make_app(clock: FakeClock) -> Callable[..., Flask]:
    """Build a Flask app with an :class:`AuthLimiter` attached."""

    def factory(
        *,
        limit: str = "5/minute",
        clock_override: Callable[[], float] | None = None,
        **limiter_kwargs: object,
    ) -> Flask:
        app = Flask(__name__)
        app.config.update(TESTING=True)
        limiter_kwargs.setdefault("key_salt", TEST_SALT)
        AuthLimiter(
            app,
            limit=limit,
            storage=MemoryStorage(clock=clock_override or clock),
            clock=clock_override or clock,
            **limiter_kwargs,
        )
        return app

    return factory


@pytest.fixture
def app(make_app: Callable[..., Flask]) -> Flask:
    return make_app()


@pytest.fixture
def client(app: Flask):
    return app.test_client()


@pytest.fixture
def resolve_salt() -> Callable[..., str]:
    return resolve_key_salt


@pytest.fixture(scope="session")
def redis_url() -> str | None:
    """Redis connection string for integration tests, or ``None`` to skip them."""
    return os.environ.get("REDIS_URL") or None


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "redis: requires a live Redis server (set REDIS_URL to run)",
    )
