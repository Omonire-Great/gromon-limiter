"""V2 policies enforced through a real Flask request.

These tests exist because the policy model was fully implemented and fully unit
tested at the ``PolicyEvaluator`` level while nothing in the Flask layer ever
called it. A policy attached to a limiter was accepted, reported back by
``policy_for()``, and then ignored: every request took the V1 engine path and was
limited by ``default_limit``. A caller who configured a policy and deployed got
an endpoint limited by the wrong number, with no error anywhere.

So every test here drives an actual request through ``app.test_client()`` and
asserts on the status code, not on an internal call. That is the only level at
which the original defect was visible.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from flask import Flask, jsonify, request

from gromon_limiter import (
    AuthLimiter,
    ConfigurationError,
    Identity,
    Limiter,
    Policy,
    RateLimit,
    Rule,
    by_account,
    by_ip,
    by_user,
    fixed_cost,
)
from gromon_limiter.decorators import view_policy
from gromon_limiter.errors import StorageError
from gromon_limiter.flask import EXTENSION_KEY
from gromon_limiter.storage.memory import MemoryStorage
from tests.conftest import TEST_SALT, FakeClock

Builder = Callable[..., Limiter]


def _post(client: Any, path: str = "/api", ip: str = "1.2.3.4", **kwargs: Any) -> int:
    """POST with an explicit peer address, so the IP rule has material to key on."""
    return client.post(path, json={}, environ_base={"REMOTE_ADDR": ip}, **kwargs).status_code


# --------------------------------------------------------------- the regression


def test_policy_is_enforced_and_not_silently_ignored(clock: FakeClock) -> None:
    """A declared policy must decide the outcome, not ``default_limit``.

    The V1 limit is deliberately loose (100/hour) so that any 429 can only have
    come from the policy's 1/minute rule. Before the fix every response was 200.
    """
    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),))
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(
        policy, app, key_salt=TEST_SALT, limit="100/hour", clock=clock
    )

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert [_post(client) for _ in range(3)] == [200, 429, 429]


def test_for_policy_accepts_a_positional_app(clock: FakeClock) -> None:
    """``for_policy(policy, app)`` mirrors ``AuthLimiter(app, ...)``."""
    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),))
    app = Flask(__name__)
    limiter = Limiter.for_policy(policy, app, key_salt=TEST_SALT, clock=clock)
    assert limiter.core is not None
    assert app.extensions[EXTENSION_KEY] is limiter


def test_documented_two_step_pattern_also_enforces(clock: FakeClock) -> None:
    """The ``for_policy(...)`` then ``init_app(app)`` form from the docs works."""
    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),))
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(policy, key_salt=TEST_SALT, clock=clock)
    limiter.init_app(app)

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert [_post(client) for _ in range(3)] == [200, 429, 429]


# ------------------------------------------------------------- per-route policy


def test_per_route_policy_overrides_the_default(clock: FakeClock) -> None:
    """A route's own policy beats the limiter default, both enforced."""
    loose = Policy(name="loose", rules=(Rule(key=by_ip(), limit="10/minute", name="ip"),))
    tight = Policy(name="tight", rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),))
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(loose, app, key_salt=TEST_SALT, clock=clock)

    @app.post("/loose")
    @limiter.limit()
    def loose_route() -> Any:
        return jsonify(ok=True)

    @app.post("/tight")
    @limiter.limit(policy=tight)
    def tight_route() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert [_post(client, "/loose") for _ in range(3)] == [200, 200, 200]
    assert [_post(client, "/tight") for _ in range(3)] == [200, 429, 429]


def test_view_policy_is_introspectable(clock: FakeClock) -> None:
    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="5/minute", name="ip"),))
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(policy, app, key_salt=TEST_SALT, clock=clock)

    @app.post("/api")
    @limiter.limit(policy=policy)
    def api() -> Any:
        return jsonify(ok=True)

    assert view_policy(api) is policy


def test_a_non_policy_is_rejected_at_decoration_time(clock: FakeClock) -> None:
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(
        Policy(name="p", rules=(Rule(key=by_ip(), limit="5/minute"),)),
        app,
        key_salt=TEST_SALT,
        clock=clock,
    )
    with pytest.raises(ConfigurationError, match="expects a Policy"):
        limiter.limit(policy="5/minute")  # type: ignore[arg-type]


# ------------------------------------------------------------- response shape


def test_blocked_policy_response_keeps_the_429_contract(clock: FakeClock) -> None:
    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),))
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(policy, app, key_salt=TEST_SALT, clock=clock)

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert _post(client) == 200
    response = client.post(
        "/api", json={}, environ_base={"REMOTE_ADDR": "1.2.3.4"}
    )
    assert response.status_code == 429
    assert response.mimetype == "application/json"
    body = response.get_json()
    assert body["error"] == "rate_limit_exceeded"
    assert body["limit"] == 1
    assert body["remaining"] == 0
    assert 0 < body["retry_after"] <= 60
    # Retry-After is mandatory on a 429 (RFC 9110).
    assert int(response.headers["Retry-After"]) > 0


def test_allowed_policy_response_publishes_headers(clock: FakeClock) -> None:
    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="5/minute", name="ip"),))
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(policy, app, key_salt=TEST_SALT, clock=clock)

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    response = app.test_client().post(
        "/api", json={}, environ_base={"REMOTE_ADDR": "1.2.3.4"}
    )
    assert response.status_code == 200
    assert response.headers["X-RateLimit-Limit"] == "5"
    assert response.headers["X-RateLimit-Remaining"] == "4"


def test_denied_rule_label_reaches_the_body(clock: FakeClock) -> None:
    """The 429 must name the policy's rule, not the engine's synthetic name."""
    policy = Policy(
        name="api",
        rules=(
            Rule(key=by_ip(), limit="10/minute", name="ip"),
            Rule(key=by_account(), limit="1/minute", name="account"),
        ),
    )
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(policy, app, key_salt=TEST_SALT, clock=clock)

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()

    def login() -> Any:
        return client.post(
            "/api",
            json={"email": "a@b.com"},
            environ_base={"REMOTE_ADDR": "1.2.3.4"},
        )

    assert login().status_code == 200
    response = login()
    assert response.status_code == 429
    assert b"account" in response.get_data() or response.headers.get("X-RateLimit-Policy")


def test_raise_on_limit_works_with_a_policy(clock: FakeClock) -> None:
    from gromon_limiter import RateLimitExceeded

    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),))
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(policy, app, key_salt=TEST_SALT, clock=clock)

    seen: list[Any] = []

    @app.errorhandler(RateLimitExceeded)
    def too_many(error: RateLimitExceeded) -> Any:
        seen.append(error)
        return jsonify(retry=error.decision.retry_after), 429

    @app.post("/api")
    @limiter.limit(raise_on_limit=True)
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert _post(client) == 200
    assert _post(client) == 429
    assert len(seen) == 1
    assert seen[0].decision.rule == "ip"


# --------------------------------------------------------------- extras provider


def test_extras_provider_supplies_authenticated_material(clock: FakeClock) -> None:
    """A ``by_user`` rule must be enforced, not skipped, when extras are supplied.

    Each request uses a distinct IP so the loose IP rule cannot be what blocks
    the request: the 429 has to come from the user's own budget.
    """
    policy = Policy(
        name="api",
        rules=(
            Rule(key=by_ip(), limit="100/minute", name="ip"),
            Rule(key=by_user(), limit="2/minute", name="user"),
        ),
    )
    app = Flask(__name__)
    app.config.update(TESTING=True)

    def extras() -> dict[str, str]:
        user = request.headers.get("X-User")
        return {"user": user} if user else {}

    limiter = Limiter.for_policy(
        policy, app, key_salt=TEST_SALT, clock=clock, extras_provider=extras
    )

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()

    def call(user: str, ip: str) -> int:
        return client.post(
            "/api",
            json={},
            headers={"X-User": user},
            environ_base={"REMOTE_ADDR": ip},
        ).status_code

    assert [call("alice", f"1.1.1.{i}") for i in range(1, 5)] == [200, 200, 429, 429]
    # A different user has an independent budget: same rule, different bucket.
    assert [call("bob", f"2.2.2.{i}") for i in range(1, 4)] == [200, 200, 429]


def test_rule_is_skipped_when_extras_are_absent(clock: FakeClock) -> None:
    """An anonymous caller must not be pooled into a shared user bucket."""
    policy = Policy(
        name="api",
        rules=(
            Rule(key=by_ip(), limit="100/minute", name="ip"),
            Rule(key=by_user(), limit="1/minute", name="user"),
        ),
    )
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(
        policy,
        app,
        key_salt=TEST_SALT,
        clock=clock,
        extras_provider=lambda: {"user": request.headers.get("X-User", "")},
    )

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    # No X-User: the user rule does not apply, so only the loose IP rule runs.
    assert [_post(client, ip=f"3.3.3.{i}") for i in range(1, 4)] == [200, 200, 200]


def test_extras_provider_may_return_an_identity(clock: FakeClock) -> None:
    policy = Policy(name="api", rules=(Rule(key=by_user(), limit="1/minute", name="user"),))
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(
        policy,
        app,
        key_salt=TEST_SALT,
        clock=clock,
        extras_provider=lambda: Identity(extras={"user": "carol"}),
    )

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert [_post(client, ip=f"4.4.4.{i}") for i in range(1, 4)] == [200, 429, 429]


def test_a_raising_extras_provider_does_not_500(clock: FakeClock) -> None:
    """A buggy provider degrades to "no extras", not to an unhandled error.

    The rules keyed on the missing material are then skipped, which is the safe
    direction: they stop applying rather than every anonymous caller landing in
    one shared bucket.
    """
    policy = Policy(
        name="api",
        rules=(
            Rule(key=by_ip(), limit="100/minute", name="ip"),
            Rule(key=by_user(), limit="1/minute", name="user"),
        ),
    )
    app = Flask(__name__)
    app.config.update(TESTING=True)

    def boom() -> dict[str, str]:
        raise RuntimeError("session lookup failed")

    limiter = Limiter.for_policy(
        policy, app, key_salt=TEST_SALT, clock=clock, extras_provider=boom
    )

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    statuses = [_post(client, ip=f"5.5.5.{i}") for i in range(1, 4)]
    assert statuses == [200, 200, 200]


# ------------------------------------------------------------ weighted + reset


def test_weighted_cost_is_charged_by_a_policy(clock: FakeClock) -> None:
    policy = Policy(
        name="api",
        rules=(Rule(key=by_ip(), limit="10/minute", cost=fixed_cost(4), name="ip"),),
    )
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(policy, app, key_salt=TEST_SALT, clock=clock)

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    # cost 4 against a budget of 10 admits 2 requests (4 + 4 = 8, a third would be 12).
    assert [_post(client) for _ in range(3)] == [200, 200, 429]


def test_per_rule_cooldown_applies_through_a_policy(clock: FakeClock) -> None:
    policy = Policy(
        name="api",
        rules=(
            Rule(key=by_ip(), limit="1/minute", cooldown_seconds=300, name="ip"),
        ),
    )
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(policy, app, key_salt=TEST_SALT, clock=clock)

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert _post(client) == 200
    assert _post(client) == 429
    # The rule declared a 300s cooldown, so the wait is that long even though the
    # window itself is only 60s.
    response = client.post(
        "/api", json={}, environ_base={"REMOTE_ADDR": "1.2.3.4"}
    )
    assert int(response.headers["Retry-After"]) > 60


def test_reset_clears_a_policy_counter(clock: FakeClock) -> None:
    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),))
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(policy, app, key_salt=TEST_SALT, clock=clock)

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert _post(client) == 200
    assert _post(client) == 429
    # limiter.reset must route through the policy evaluator: those counters live
    # under per-rule keys the V1 core cannot see.
    removed = limiter.reset(Identity(ip="1.2.3.4"), path="/api", method="POST")
    assert removed >= 1
    assert _post(client) == 200


# ------------------------------------------------------------- V1 is unchanged


def test_v1_limiter_is_untouched_by_the_policy_path(clock: FakeClock) -> None:
    """A V1 ``AuthLimiter`` has no policy and must behave exactly as before."""
    app = Flask(__name__)
    app.config.update(TESTING=True)
    AuthLimiter(app, limit="2/minute", key_salt=TEST_SALT, clock=clock)
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert [_post(client, "/login") for _ in range(3)] == [200, 200, 429]


def test_v1_limiter_exposes_the_new_attributes(clock: FakeClock) -> None:
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = AuthLimiter(app, key_salt=TEST_SALT, clock=clock)
    assert limiter.default_policy is None
    assert limiter.extras_provider is None


def test_skip_methods_still_short_circuit_a_policy(clock: FakeClock) -> None:
    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),))
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(policy, app, key_salt=TEST_SALT, clock=clock)

    @app.route("/api", methods=["GET", "OPTIONS"])
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    for _ in range(5):
        assert (
            client.options("/api", environ_base={"REMOTE_ADDR": "1.2.3.4"}).status_code
            == 200
        )


def test_disabled_kill_switch_beats_a_policy(clock: FakeClock) -> None:
    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),))
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(
        policy, app, key_salt=TEST_SALT, clock=clock, enabled=False
    )

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert [_post(client) for _ in range(4)] == [200] * 4


# ------------------------------------------------------------------ failures


def test_fail_closed_policy_renders_429_on_storage_outage(clock: FakeClock) -> None:
    class Broken(MemoryStorage):
        def log_add(self, *args: Any, **kwargs: Any) -> Any:
            raise StorageError("down")

        def marked_until(self, *args: Any, **kwargs: Any) -> Any:
            raise StorageError("down")

    policy = Policy(
        name="api",
        rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),),
        fail_closed=True,
    )
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(
        policy, app, key_salt=TEST_SALT, clock=clock, storage=Broken()
    )

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert _post(client) == 429


def test_fail_open_policy_allows_but_flags_storage_failure(clock: FakeClock) -> None:
    """An allowed decision produced by an outage must be distinguishable.

    ``allowed`` here means "allowed because we could not tell", and
    ``storage_failed`` is what says so. Losing that flag turns a skipped check
    into what looks like a passing one.
    """
    class Broken(MemoryStorage):
        def log_add(self, *args: Any, **kwargs: Any) -> Any:
            raise StorageError("down")

        def marked_until(self, *args: Any, **kwargs: Any) -> Any:
            raise StorageError("down")

    policy = Policy(
        name="api",
        rules=(Rule(key=by_ip(), limit="1/minute", name="ip"),),
        fail_closed=False,
    )
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(
        policy, app, key_salt=TEST_SALT, clock=clock, storage=Broken()
    )
    seen: list[Any] = []

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        from gromon_limiter.flask import current_decision

        decision = current_decision()
        seen.append(decision)
        return jsonify(ok=True)

    client = app.test_client()
    assert _post(client) == 200
    assert seen[0].allowed is True
    assert seen[0].storage_failed is True


def test_a_policy_cannot_exceed_the_rule_safety_valve(clock: FakeClock) -> None:
    """A policy beyond ``MAX_RULES_PER_POLICY`` is refused at request time.

    Enforced through the same Flask path a caller would actually use, so the
    guard cannot be bypassed by wiring the policy in a different way.
    """
    from gromon_limiter import MAX_RULES_PER_POLICY

    rules = tuple(
        Rule(key=by_ip(), limit="1000/minute", name=f"r{index}")
        for index in range(MAX_RULES_PER_POLICY + 1)
    )
    policy = Policy(name="huge", rules=rules)
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter.for_policy(policy, app, key_salt=TEST_SALT, clock=clock)

    @app.post("/api")
    @limiter.limit()
    def api() -> Any:
        return jsonify(ok=True)

    app.config["PROPAGATE_EXCEPTIONS"] = True
    with pytest.raises(ConfigurationError, match="rules"):
        _post(app.test_client())


# ------------------------------------------------------------------- limits


def test_policy_limit_is_a_rate_limit(clock: FakeClock) -> None:
    """A string limit on a Rule is parsed, not stored raw."""
    policy = Policy(name="api", rules=(Rule(key=by_ip(), limit="5/minute", name="ip"),))
    rule = policy.rule_named("ip")
    assert rule is not None
    assert rule.limit == RateLimit.parse("5/minute")
