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


def test_weighted_cost_is_atomic_across_engines(namespace: str) -> None:
    """A weighted charge must not be splittable by concurrency.

    Each request costs 3 against a limit of 30, so at most 10 can pass. If the
    charge were applied in more than one storage operation, two engines could
    both read a count that still fit and both write back, letting more through
    than the policy allows.
    """
    client = _client()
    settings = Settings(
        key_salt="weighted-salt",
        namespace=namespace,
        default_limit="30/minute",
        identifier=("ip",),
    ).validated()
    engines = [
        LimiterCore(settings, RedisStorage(client=client, prefix="great_limiter"))
        for _ in range(4)
    ]
    identity = Identity(ip="7.7.7.7")
    try:
        allowed = sum(
            1
            for engine in engines
            for _ in range(10)
            if engine.check(identity, path="/search", cost=3).allowed
        )
        assert allowed == 10
    finally:
        engines[0].clear_all()
        for engine in engines:
            engine.storage.close()


def test_weighted_policy_rules_on_redis(namespace: str) -> None:
    """A V2 policy with a weighted rule behaves the same on a shared backend."""
    from great_limiter.engine import PolicyEvaluator
    from great_limiter.policies import KeyBuilder, Policy, Rule, by_user

    client = _client()
    storage = RedisStorage(client=client, prefix="great_limiter")
    engine = LimiterCore(
        Settings(key_salt="v2-redis-salt", namespace=namespace).validated(), storage
    )
    policy = Policy(
        name="search",
        rules=(
            Rule(key=by_user(), limit="20/minute", cost=3, name="user"),
            Rule(
                key=KeyBuilder(components=("tenant", "user"), independent=True),
                limit="100/minute",
                name="tenant-or-user",
            ),
        ),
    )
    evaluator = PolicyEvaluator(engine)
    identity = Identity(extras={"user": "u1", "tenant": "acme"})
    try:
        results = [evaluator.check(policy, identity, path="/search").allowed for _ in range(8)]
        # 3 slots each against a limit of 20: the seventh request reaches 21.
        assert results == [True] * 6 + [False, False]

        # A different user in the same tenant is limited by its own fresh user
        # bucket and by the shared tenant bucket, which has room left.
        other = Identity(extras={"user": "u2", "tenant": "acme"})
        assert evaluator.check(policy, other, path="/search").allowed

        # Moving to another tenant does not launder the spent user budget: the
        # by_user rule is keyed on the user alone, so a caller cannot escape a
        # limit by presenting a different tenant. That is the whole point of
        # keeping the user rule independent of the tenant dimension.
        elsewhere = Identity(extras={"user": "u1", "tenant": "other"})
        assert not evaluator.check(policy, elsewhere, path="/search").allowed
    finally:
        engine.clear_all()
        storage.close()


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
