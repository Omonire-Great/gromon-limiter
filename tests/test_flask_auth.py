"""Flask integration: status codes, headers, body handling and configuration."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from flask import Flask, jsonify, request

from great_limiter import AuthLimiter, Limiter
from great_limiter.errors import ConfigurationError, RateLimitExceeded, StorageError
from great_limiter.flask import EXTENSION_KEY
from great_limiter.storage.memory import MemoryStorage
from tests.conftest import TEST_SALT, FakeClock

Factory = Callable[..., Flask]


def make_client(app: Flask, ip: str = "1.2.3.4") -> Any:
    return app.test_client()


# ----------------------------------------------------------------- basic 429 shape


def test_blocked_request_returns_429_json(make_app: Factory) -> None:
    app = make_app(limit="2/minute")
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit("2/minute")
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    assert client.post("/login", json={"email": "a@b.com"}).status_code == 200
    assert client.post("/login", json={"email": "a@b.com"}).status_code == 200

    response = client.post("/login", json={"email": "a@b.com"})
    assert response.status_code == 429
    assert response.mimetype == "application/json"
    body = response.get_json()
    assert body["error"] == "rate_limit_exceeded"
    assert body["limit"] == 2
    assert body["remaining"] == 0
    assert 0 < body["retry_after"] <= 60


def test_retry_after_header_is_present_and_sane(make_app: Factory) -> None:
    app = make_app(limit="1/minute")
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    client.post("/login", json={})
    response = client.post("/login", json={})
    assert int(response.headers["Retry-After"]) > 0
    assert int(response.headers["Retry-After"]) <= 60


def test_rate_limit_headers_on_successful_responses(make_app: Factory) -> None:
    app = make_app(limit="3/minute")
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    response = client.post("/login", json={})
    assert response.status_code == 200
    assert response.headers["X-RateLimit-Limit"] == "3"
    assert response.headers["X-RateLimit-Remaining"] == "2"
    assert int(response.headers["X-RateLimit-Reset"]) > 0


def test_headers_can_be_disabled(make_app: Factory) -> None:
    """``headers=False`` suppresses the X-RateLimit-* series but keeps Retry-After.

    A 429 without Retry-After is non-compliant and hostile to clients, so it is
    always sent; the same information is in the JSON body either way.
    """
    app = make_app(limit="1/minute", headers=False)
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    allowed = client.post("/login", json={})
    assert "X-RateLimit-Limit" not in allowed.headers
    assert "X-RateLimit-Remaining" not in allowed.headers

    blocked = client.post("/login", json={})
    assert blocked.status_code == 429
    assert "X-RateLimit-Limit" not in blocked.headers
    assert "Retry-After" in blocked.headers
    # The values remain available in the body.
    assert blocked.get_json()["limit"] == 1


def test_custom_status_code(make_app: Factory) -> None:
    app = make_app(limit="1/minute", status_code=403)
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    client.post("/login", json={})
    assert client.post("/login", json={}).status_code == 403


# ---------------------------------------------------------------- body handling


def test_json_body_is_still_readable_by_the_view(make_app: Factory) -> None:
    """The limiter must not consume the request body."""
    app = make_app(limit="5/minute")
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        payload = request.get_json(silent=True)
        return jsonify(received=payload)

    response = make_client(app).post("/login", json={"email": "a@b.com", "password": "x"})
    assert response.get_json()["received"] == {"email": "a@b.com", "password": "x"}


def test_form_body_is_still_readable_by_the_view(make_app: Factory) -> None:
    app = make_app(limit="5/minute")
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(email=request.form.get("email"))

    response = make_client(app).post("/login", data={"email": "a@b.com"})
    assert response.get_json()["email"] == "a@b.com"


def test_malformed_json_does_not_break_the_limiter(make_app: Factory) -> None:
    app = make_app(limit="1/minute")
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    broken = client.post(
        "/login", data="{not json", content_type="application/json"
    )
    assert broken.status_code == 200
    repeat = client.post("/login", data="{not json", content_type="application/json")
    assert repeat.status_code == 429


def test_account_identifier_is_read_from_form(make_app: Factory) -> None:
    """Same account via a different route/IP must still be limited by account."""
    app = make_app(limit="1/minute", identifier=("account",), account_limit_multiplier=1)
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    first = client.post("/login", data={"email": "Victim@Example.com"})
    assert first.status_code == 200
    second = client.post(
        "/login",
        data={"email": "victim@example.com"},
        environ_base={"REMOTE_ADDR": "9.9.9.9"},
    )
    assert second.status_code == 429


def test_account_identifier_from_query_string(make_app: Factory) -> None:
    app = make_app(limit="1/minute", identifier=("account",), account_limit_multiplier=1)
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    assert client.post("/login?email=a@b.com").status_code == 200
    assert client.post("/login?email=A@B.com").status_code == 429


def test_custom_account_fields(make_app: Factory) -> None:
    app = make_app(
        limit="1/minute",
        identifier=("account",),
        account_limit_multiplier=1,
        account_fields=("jira_account",),
    )
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    assert client.post("/login", json={"jira_account": "u1"}).status_code == 200
    assert client.post("/login", json={"jira_account": "u1"}).status_code == 429
    # A field we are not configured to read must not create a shared bucket.
    assert client.post("/login", json={"email": "other@b.com"}).status_code == 200


# ------------------------------------------------------------------ proxy handling


def test_forwarded_header_is_ignored_without_trusted_proxies(make_app: Factory) -> None:
    app = make_app(limit="1/minute", identifier=("ip",))
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    # Same real peer, a different claimed forwarded IP each time. All requests
    # must land in the same bucket: the header is attacker-controlled here.
    assert client.post("/login", json={}, headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 200
    assert client.post("/login", json={}, headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 429
    assert client.post("/login", json={}, headers={"X-Forwarded-For": "3.3.3.3"}).status_code == 429


def test_forwarded_header_is_used_for_a_trusted_proxy(make_app: Factory) -> None:
    app = make_app(limit="1/minute", identifier=("ip",), trusted_proxies=["10.0.0.0/8"])
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    base = {"REMOTE_ADDR": "10.0.0.5"}

    def post_as(forwarded_ip: str) -> Any:
        return client.post(
            "/login",
            json={},
            headers={"X-Forwarded-For": forwarded_ip},
            environ_base=base,
        )

    assert post_as("5.5.5.5").status_code == 200
    assert post_as("5.5.5.5").status_code == 429
    # A different real client behind the same proxy gets its own budget.
    assert post_as("6.6.6.6").status_code == 200


def test_spoofed_forwarded_header_cannot_evade(make_app: Factory) -> None:
    app = make_app(limit="1/minute", identifier=("ip",), trusted_proxies=["10.0.0.0/8"])
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    # The peer (127.0.0.1) is NOT a configured proxy, so the forwarding headers
    # are attacker-controlled and ignored. Rotating them must not buy a new bucket.
    peer = {"REMOTE_ADDR": "203.0.113.1"}
    first = client.post(
        "/login", json={}, headers={"X-Forwarded-For": "7.7.7.7"}, environ_base=peer
    )
    assert first.status_code == 200
    second = client.post(
        "/login", json={}, headers={"X-Forwarded-For": "8.8.8.8"}, environ_base=peer
    )
    assert second.status_code == 429
    third = client.post("/login", json={}, environ_base=peer)
    assert third.status_code == 429


# -------------------------------------------------------------------- per-route


def test_decorator_limit_overrides_default_per_route(make_app: Factory) -> None:
    app = make_app(limit="10/minute")
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit("1/minute")
    def login() -> Any:
        return jsonify(ok=True)

    @app.post("/verify")
    @limiter.limit()
    def verify() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    assert client.post("/login", json={}).status_code == 200
    assert client.post("/login", json={}).status_code == 429
    for _ in range(5):
        assert client.post("/verify", json={}).status_code == 200


def test_decorator_rejects_malformed_limit_at_definition_time(make_app: Factory) -> None:
    app = make_app(limit="1/minute")
    limiter = app.extensions[EXTENSION_KEY]
    with pytest.raises(ConfigurationError):
        limiter.limit("5/fortnight")


def test_decorator_without_initialised_limiter_raises() -> None:
    """Decorating is allowed; the error surfaces when the view is called."""
    limiter = AuthLimiter()

    @limiter.limit("5/minute")
    def view() -> Any:
        return "ok"

    with pytest.raises(ConfigurationError, match="never bound"):
        view()


def test_options_requests_are_skipped(make_app: Factory) -> None:
    app = make_app(limit="1/minute", identifier=("ip",))
    limiter = app.extensions[EXTENSION_KEY]

    @app.route("/login", methods=["POST", "OPTIONS"])
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    for _ in range(10):
        assert client.options("/login").status_code == 200
    assert client.post("/login", json={}).status_code == 200


def test_raise_on_limit_uses_error_handler(make_app: Factory) -> None:
    app = make_app(limit="1/minute")
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit(raise_on_limit=True)
    def login() -> Any:
        return jsonify(ok=True)

    @app.errorhandler(RateLimitExceeded)
    def handle(error: RateLimitExceeded) -> Any:
        return jsonify(custom=True, retry=error.decision.retry_after), 429

    client = make_client(app)
    assert client.post("/login", json={}).status_code == 200
    response = client.post("/login", json={})
    assert response.status_code == 429
    assert response.get_json()["custom"] is True


def test_success_resets_counters(make_app: Factory) -> None:
    """A successful login clears the counters for that identity."""
    from great_limiter.identifiers import Identity

    app = make_app(limit="2/minute", identifier=("ip", "account"))
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        # A real application calls this once the credentials check out.
        limiter.core.reset(
            Identity(ip=request.remote_addr, account="a@b.com"),
            path="/login",
            method="POST",
        )
        return jsonify(ok=True)

    client = make_client(app)
    for _ in range(10):
        assert client.post("/login", json={"email": "a@b.com"}).status_code == 200


def test_reset_helper_is_exposed_on_the_limiter(make_app: Factory) -> None:
    from great_limiter.identifiers import Identity

    app = make_app(limit="1/minute", identifier=("ip",))
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    assert client.post("/login", json={}).status_code == 200
    assert client.post("/login", json={}).status_code == 429

    limiter.core.reset(Identity(ip="127.0.0.1"), path="/login", method="POST")
    assert client.post("/login", json={}).status_code == 200


# ------------------------------------------------------------------ configuration


def test_init_twice_on_same_app_raises(make_app: Factory) -> None:
    app = make_app(limit="1/minute")
    with pytest.raises(ConfigurationError):
        AuthLimiter(app, limit="1/minute", key_salt=TEST_SALT)


def test_same_instance_init_twice_is_idempotent() -> None:
    app = Flask(__name__)
    limiter = AuthLimiter()
    limiter.init_app(app, limit="1/minute", key_salt=TEST_SALT)
    limiter.init_app(app, limit="1/minute", key_salt=TEST_SALT)
    assert app.extensions[EXTENSION_KEY] is limiter


def test_init_app_after_construction_works() -> None:
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = AuthLimiter(limit="1/minute", key_salt=TEST_SALT)
    limiter.init_app(app)

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert client.post("/login", json={}).status_code == 200
    assert client.post("/login", json={}).status_code == 429


def test_disabled_limiter_passes_everything_through(make_app: Factory) -> None:
    app = make_app(limit="1/minute", enabled=False)
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    for _ in range(10):
        assert client.post("/login", json={}).status_code == 200


def test_unknown_storage_is_rejected() -> None:
    app = Flask(__name__)
    with pytest.raises(ConfigurationError):
        AuthLimiter(app, storage="dynamodb", key_salt=TEST_SALT)


def test_general_limiter_is_backwards_compatible() -> None:
    """V2's ``Limiter`` is a drop-in superset of V1's ``AuthLimiter``."""
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter(app, limit="1/minute", key_salt=TEST_SALT)

    @app.post("/api/products")
    @limiter.limit("1/minute")
    def products() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert client.post("/api/products").status_code == 200
    assert client.post("/api/products").status_code == 429


def test_v1_code_runs_unchanged_on_the_v2_limiter() -> None:
    """The V1 call signature must keep working on the V2 class."""
    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = Limiter()
    limiter.init_app(app, limit="1/minute", key_salt=TEST_SALT)

    @app.post("/login")
    @limiter.limit("1/minute")
    def login() -> Any:
        return jsonify(ok=True)

    client = app.test_client()
    assert client.post("/login", json={}).status_code == 200
    assert client.post("/login", json={}).status_code == 429


def test_storage_can_be_injected(make_app: Factory, clock: FakeClock) -> None:
    app = Flask(__name__)
    app.config.update(TESTING=True)
    backend = MemoryStorage(clock=clock)
    limiter = AuthLimiter(app, limit="1/minute", storage=backend, key_salt=TEST_SALT, clock=clock)
    assert limiter.storage is backend


# --------------------------------------------------------------- failure behaviour


def test_storage_outage_fails_closed(make_app: Factory) -> None:
    class Broken(MemoryStorage):
        def log_add(self, *args: Any, **kwargs: Any) -> Any:
            raise StorageError("down")

        def marked_until(self, *args: Any, **kwargs: Any) -> Any:
            raise StorageError("down")

    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = AuthLimiter(
        app,
        limit="1/minute",
        storage=Broken(),
        key_salt=TEST_SALT,
        identifier=("ip",),
    )

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    response = app.test_client().post("/login", json={})
    assert response.status_code == 429
    assert response.get_json()["error"] == "rate_limit_exceeded"
    assert response.headers["Retry-After"]


def test_storage_outage_can_fail_open(make_app: Factory) -> None:
    class Broken(MemoryStorage):
        def log_add(self, *args: Any, **kwargs: Any) -> Any:
            raise StorageError("down")

        def marked_until(self, *args: Any, **kwargs: Any) -> Any:
            raise StorageError("down")

    app = Flask(__name__)
    app.config.update(TESTING=True)
    limiter = AuthLimiter(
        app,
        limit="1/minute",
        storage=Broken(),
        key_salt=TEST_SALT,
        identifier=("ip",),
        fail_open=True,
    )

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    assert app.test_client().post("/login", json={}).status_code == 200


# ------------------------------------------------------------------------ extras


def test_multiple_routes_do_not_share_a_budget(make_app: Factory) -> None:
    app = make_app(limit="1/minute", identifier=("ip",))
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    @app.post("/admin/login")
    @limiter.limit()
    def admin_login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    assert client.post("/login", json={}).status_code == 200
    assert client.post("/admin/login", json={}).status_code == 200
    assert client.post("/login", json={}).status_code == 429
    assert client.post("/admin/login", json={}).status_code == 429


def test_error_body_is_valid_json_bytes(make_app: Factory) -> None:
    app = make_app(limit="1/minute")
    limiter = app.extensions[EXTENSION_KEY]

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    client = make_client(app)
    client.post("/login", json={})
    raw = client.post("/login", json={}).get_data(as_text=True)
    assert json.loads(raw)["error"] == "rate_limit_exceeded"


def test_unlimited_view_still_publishes_headers(make_app: Factory) -> None:
    app = make_app(limit="5/minute")
    limiter = app.extensions[EXTENSION_KEY]

    @app.get("/health")
    def health() -> Any:
        return jsonify(ok=True)

    @app.post("/login")
    @limiter.limit()
    def login() -> Any:
        return jsonify(ok=True)

    response = make_client(app).get("/health")
    assert response.status_code == 200
    assert "X-RateLimit-Limit" not in response.headers
