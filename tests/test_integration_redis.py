"""Coverage of the limits that only show up when storage is genuinely shared.

The memory backend and the Redis backend implement the same contract, so a rule
can be enforced end-to-end on either. These tests run the *engine* over Redis to
prove the composition works, not just the storage primitives in isolation.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator

import pytest
import redis

from great_limiter import AuthLimiter
from great_limiter.config import Settings
from great_limiter.core import LimiterCore
from great_limiter.identifiers import Identity
from great_limiter.storage.redis import RedisStorage

pytestmark = pytest.mark.redis


def _client() -> redis.Redis:
    url = __import__("os").environ.get("REDIS_URL")
    if url:
        client = redis.Redis.from_url(url, decode_responses=True)
        client.ping()
        return client
    if __import__("os").environ.get("GREAT_LIMITER_FAKE_REDIS", "1") == "0":
        pytest.skip("no Redis available")
    fakeredis = pytest.importorskip("fakeredis")
    return fakeredis.FakeStrictRedis(decode_responses=True)


@pytest.fixture
def namespace() -> str:
    return f"itest:{uuid.uuid4().hex[:8]}"


@pytest.fixture
def core(namespace: str) -> Iterator[LimiterCore]:
    storage = RedisStorage(client=_client(), prefix="great_limiter")
    settings = Settings(
        key_salt="integration-salt-not-secret",
        namespace=namespace,
        default_limit="3/minute",
        identifier=("ip", "account"),
        cooldown_seconds=30.0,
    ).validated()
    engine = LimiterCore(settings, storage)
    try:
        yield engine
    finally:
        engine.clear_all()
        storage.close()


def test_same_rules_apply_on_redis(core: LimiterCore) -> None:
    identity = Identity(ip="1.2.3.4", account="a@b.com")
    assert [core.check(identity, path="/login", method="POST").allowed for _ in range(4)] == [
        True,
        True,
        True,
        False,
    ]


def test_ip_and_account_rules_on_redis(core: LimiterCore) -> None:
    """The two rules defend against different attacks, which is the point.

    IP rule: 3/min. Account rule: 9/min (the 3x account_limit_multiplier).
    """
    # Spraying one IP across many accounts exhausts the tight IP rule.
    spray = [
        core.check(
            Identity(ip="1.1.1.1", account=f"g{index}@b.com"), path="/login", method="POST"
        ).allowed
        for index in range(4)
    ]
    assert spray == [True, True, True, False]

    # Hammering one account from many IPs never touches the IP rule, so the
    # account rule is what has to stop it. Its limit is 9/min, so the first nine
    # attempts are allowed and the tenth is refused.
    distributed = [
        core.check(
            Identity(ip=f"10.0.0.{index}", account="victim@b.com"),
            path="/login",
            method="POST",
        ).allowed
        for index in range(10)
    ]
    assert distributed == [True] * 9 + [False]


def test_cooldown_on_redis(core: LimiterCore) -> None:
    identity = Identity(ip="1.2.3.4")
    for _ in range(3):
        core.check(identity, path="/login", method="POST")
    assert not core.check(identity, path="/login", method="POST").allowed
    cooldown = core.check(identity, path="/login", method="POST")
    assert "cooldown" in (cooldown.policy or "")
    assert cooldown.retry_after == pytest.approx(30, abs=2)


def test_reset_on_redis(core: LimiterCore) -> None:
    identity = Identity(ip="1.2.3.4", account="a@b.com")
    for _ in range(3):
        core.check(identity, path="/login", method="POST")
    assert not core.check(identity, path="/login", method="POST").allowed
    core.reset(identity, path="/login", method="POST")
    assert core.check(identity, path="/login", method="POST").allowed


def test_many_engines_share_one_limiter(namespace: str) -> None:
    """The distributed case: separate Engine objects, one Redis, one rule set.

    This is the property a single-process memory backend cannot provide, and the
    reason the atomic Lua scripts exist.
    """
    client = _client()
    salt = "shared-salt-for-this-test"
    settings = Settings(
        key_salt=salt, namespace=namespace, default_limit="50/minute", identifier=("ip",)
    ).validated()
    engines = [
        LimiterCore(settings, RedisStorage(client=client, prefix="great_limiter"))
        for _ in range(4)
    ]
    identity = Identity(ip="9.9.9.9")
    try:
        allowed = sum(
            1
            for engine in engines
            for _ in range(20)
            if engine.check(identity, path="/login", method="POST").allowed
        )
        # 4 engines x 20 requests = 80 attempts against a limit of 50. Without
        # atomic increments some would be lost and more than 50 would pass.
        assert allowed == 50
    finally:
        engines[0].clear_all()
        for engine in engines:
            engine.storage.close()


def test_concurrent_requests_never_exceed_the_limit(namespace: str) -> None:
    """Threads racing on one rule must not collectively pass the limit."""
    client = _client()
    settings = Settings(
        key_salt="concurrency-salt",
        namespace=namespace,
        default_limit="100/minute",
        identifier=("ip",),
    ).validated()
    storage = RedisStorage(client=client, prefix="great_limiter")
    engine = LimiterCore(settings, storage)
    identity = Identity(ip="8.8.8.8")
    threads = 8
    per_thread = 40
    allowed = []
    lock = threading.Lock()
    barrier = threading.Barrier(threads)

    def worker() -> None:
        local = 0
        barrier.wait()
        for _ in range(per_thread):
            if engine.check(identity, path="/login", method="POST").allowed:
                local += 1
        with lock:
            allowed.append(local)

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()

    try:
        assert sum(allowed) <= 100
        assert sum(allowed) == 100
    finally:
        engine.clear_all()
        storage.close()


def test_flask_app_on_redis(namespace: str) -> None:
    """The Flask layer behaves identically over Redis."""
    from flask import Flask, jsonify

    client = _client()
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = AuthLimiter(
        app,
        limit="2/minute",
        storage=RedisStorage(client=client, prefix="great_limiter"),
        namespace=namespace,
        key_salt="flask-redis-salt",
    )

    @app.post("/login")
    @limiter.limit()
    def login():  # type: ignore[no-untyped-def]
        return jsonify(ok=True)

    http = app.test_client()
    statuses = [http.post("/login", json={"email": "a@b.com"}).status_code for _ in range(3)]
    assert statuses == [200, 200, 429]
    try:
        limiter.core.clear_all()
    finally:
        limiter.storage.close()
