"""Engine behaviour: decisions, cooldowns, scoping and failure modes."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from omonire_limiter.config import Settings
from omonire_limiter.core import LimiterCore, build_body, build_headers, build_payload
from omonire_limiter.errors import ConfigurationError, RateLimitExceeded, StorageError
from omonire_limiter.identifiers import Identity
from omonire_limiter.storage.memory import MemoryStorage
from tests.conftest import TEST_SALT, FakeClock


def test_allows_up_to_the_limit_then_blocks(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="3/minute", identifier=("ip",))
    identity = Identity(ip="1.2.3.4")

    for expected_remaining in (2, 1, 0):
        decision = core.check(identity, path="/login", method="POST")
        assert decision.allowed
        assert decision.remaining == expected_remaining
        assert decision.limit == 3

    blocked = core.check(identity, path="/login", method="POST")
    assert not blocked.allowed
    assert blocked.remaining == 0
    assert blocked.retry_after is not None
    assert 0 < blocked.retry_after <= 60


def test_blocked_response_headers_and_payload(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="1/minute", identifier=("ip",))
    identity = Identity(ip="1.2.3.4")
    core.check(identity, path="/login", method="POST")
    decision = core.check(identity, path="/login", method="POST")

    headers = build_headers(decision)
    assert headers["Retry-After"] == "60"
    assert headers["X-RateLimit-Limit"] == "1"
    assert headers["X-RateLimit-Remaining"] == "0"
    assert headers["X-RateLimit-Policy"] == "1/60s"

    payload = build_payload(decision)
    assert payload["error"] == "rate_limit_exceeded"
    assert payload["limit"] == 1
    assert payload["remaining"] == 0
    assert payload["retry_after"] == 60
    assert build_body(decision).startswith("{")


def test_never_includes_identifiers_in_output(make_core: Callable[..., LimiterCore]) -> None:
    """Headers and bodies must not echo the account identifier back."""
    core = make_core(default_limit="1/minute", identifier=("ip", "account"))
    identity = Identity(ip="1.2.3.4", account="victim@example.com")
    core.check(identity, path="/login", method="POST")
    decision = core.check(identity, path="/login", method="POST")

    serialised = build_body(decision) + repr(build_headers(decision))
    assert "victim@example.com" not in serialised
    assert "1.2.3.4" not in serialised


def test_check_or_raise(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="1/minute", identifier=("ip",))
    identity = Identity(ip="1.2.3.4")
    core.check_or_raise(identity, path="/login")
    with pytest.raises(RateLimitExceeded) as excinfo:
        core.check_or_raise(identity, path="/login")
    assert excinfo.value.decision.remaining == 0


# ------------------------------------------------------------------------ cooldowns


def test_cooldown_blocks_repeatedly_without_consuming_hits(
    make_core: Callable[..., LimiterCore], clock: FakeClock
) -> None:
    core = make_core(
        default_limit="1/minute", identifier=("ip",), cooldown=30, algorithm="fixed_window"
    )
    identity = Identity(ip="1.2.3.4")

    # First request fills the single slot.
    assert core.check(identity, path="/login", method="POST").allowed

    # Second request breaches the limit. The cooldown is armed as a side effect,
    # but the caller is still told to wait for the full 60s window, which is when
    # the counter actually clears. Advertising the shorter 30s cooldown here
    # would invite a retry that is guaranteed to fail.
    breach = core.check(identity, path="/login", method="POST")
    assert not breach.allowed
    assert breach.retry_after == pytest.approx(60, abs=1)

    # On the next request the cooldown marker is checked first and now governs
    # the answer, giving the shorter 30s. Hammering must not extend it: a client
    # that keeps retrying cannot push its own release time further out.
    cooldown_answers = []
    for _ in range(20):
        again = core.check(identity, path="/login", method="POST")
        assert not again.allowed
        assert "cooldown" in (again.policy or "")
        cooldown_answers.append(again.retry_after)
    assert set(cooldown_answers) == {30.0}

    clock.advance(31)
    # The cooldown has lapsed, but the counter itself is still over the limit, so
    # the request stays blocked. The cooldown is a fast lockout layer *on top of*
    # the window, not a replacement for it.
    after_cooldown = core.check(identity, path="/login", method="POST")
    assert not after_cooldown.allowed
    assert "cooldown" not in (after_cooldown.policy or "")

    # Only once the window rolls over does the caller get back in.
    clock.advance(60)
    assert core.check(identity, path="/login", method="POST").allowed


def test_cooldown_expires_on_its_own_never_permanently(
    make_core: Callable[..., LimiterCore], clock: FakeClock
) -> None:
    """A short cooldown still lets the caller back in once its window passes."""
    core = make_core(
        default_limit="1/minute", identifier=("account",), account_limit_multiplier=1, cooldown=10
    )
    identity = Identity(ip="1.2.3.4", account="a@b.com")
    assert core.check(identity, path="/login", method="POST").allowed
    assert not core.check(identity, path="/login", method="POST").allowed

    # Advance past both the cooldown and the window: the account is usable again.
    # There is no code path anywhere in this library that locks an account
    # permanently, and no unbounded retry counter that could grow forever.
    clock.advance(61)
    assert core.check(identity, path="/login", method="POST").allowed


def test_cooldown_can_be_disabled(make_core: Callable[..., LimiterCore], clock: FakeClock) -> None:
    core = make_core(default_limit="1/minute", identifier=("ip",), cooldown=0)
    identity = Identity(ip="1.2.3.4")
    core.check(identity, path="/login", method="POST")
    assert not core.check(identity, path="/login", method="POST").allowed
    clock.advance(61)
    # Without a cooldown the window itself is what expires.
    assert core.check(identity, path="/login", method="POST").allowed


def test_account_cooldown_can_differ_from_ip_cooldown(
    make_core: Callable[..., LimiterCore], clock: FakeClock, storage: MemoryStorage
) -> None:
    """Each rule's cooldown uses its own configured duration."""
    core = make_core(
        default_limit="1/minute",
        identifier=("account", "ip"),
        account_limit_multiplier=1,
        cooldown=60,
        account_cooldown=5,
    )
    identity = Identity(ip="1.2.3.4", account="a@b.com")
    assert core.check(identity, path="/login", method="POST").allowed
    assert not core.check(identity, path="/login", method="POST").allowed

    # The account rule is evaluated first, so its 5s cooldown is what applies.
    short = core.check(identity, path="/login", method="POST")
    assert not short.allowed
    assert short.rule == "account"
    assert short.retry_after == pytest.approx(5, abs=1)

    # Inspect the stored marker to confirm the account rule was armed with the
    # account cooldown (5s) and not the shared IP cooldown (60s).
    algorithm = core.settings.algorithm
    scope = core.scope_for("/login", "POST")
    account_counter = core.storage_key(
        algorithm, scope, core.rule_key(("account",), identity, "default:account")
    )
    assert storage.marked_until(f"{account_counter}:cooldown", now=clock.now) == pytest.approx(
        clock.now + 5
    )


def test_only_the_breached_rule_is_armed(
    make_core: Callable[..., LimiterCore], clock: FakeClock, storage: MemoryStorage
) -> None:
    """Only the rule that actually breached gets a cooldown.

    Arming every rule on any breach would punish unrelated dimensions: one
    account's lockout would put every user behind that IP into cooldown too.
    """
    core = make_core(
        default_limit="1/minute", identifier=("account", "ip"), account_limit_multiplier=1
    )
    identity = Identity(ip="1.2.3.4", account="a@b.com")
    core.check(identity, path="/login", method="POST")
    assert not core.check(identity, path="/login", method="POST").allowed

    algorithm = core.settings.algorithm
    scope = core.scope_for("/login", "POST")
    account_counter = core.storage_key(
        algorithm, scope, core.rule_key(("account",), identity, "default:account")
    )
    ip_counter = core.storage_key(
        algorithm, scope, core.rule_key(("ip",), identity, "default:ip")
    )
    assert storage.marked_until(f"{account_counter}:cooldown", now=clock.now) is not None
    assert storage.marked_until(f"{ip_counter}:cooldown", now=clock.now) is None


def test_short_cooldown_still_leaves_the_counter_in_charge(
    make_core: Callable[..., LimiterCore], clock: FakeClock
) -> None:
    """A cooldown is an extra lockout layer, not a way around the limit.

    Once a short cooldown lapses, the caller is still held by the rule's own
    window, so a short cooldown cannot be used to buy unlimited attempts.
    """
    core = make_core(
        default_limit="1/minute", identifier=("ip",), account_limit_multiplier=1, cooldown=5
    )
    identity = Identity(ip="1.2.3.4")
    assert core.check(identity, path="/login", method="POST").allowed
    assert not core.check(identity, path="/login", method="POST").allowed

    clock.advance(6)  # cooldown gone, 60s window still running
    still_blocked = core.check(identity, path="/login", method="POST")
    assert not still_blocked.allowed
    assert "cooldown" not in (still_blocked.policy or "")

    # The attempt at t+6 is itself recorded, so the caller has to wait a full
    # window from *that* moment. A breach always consumes a slot: otherwise an
    # attacker could keep the window rolling forward indefinitely.
    clock.advance(61)
    assert core.check(identity, path="/login", method="POST").allowed


# ---------------------------------------------------------------- ip + account


def test_ip_and_account_are_tracked_independently(
    make_core: Callable[..., LimiterCore]
) -> None:
    core = make_core(default_limit="2/minute", identifier=("ip", "account"))
    attacker = Identity(ip="1.1.1.1", account="victim@example.com")

    # Spray across several accounts: the IP rule fills up first.
    for index in range(2):
        assert core.check(
            Identity(ip="1.1.1.1", account=f"guess{index}@example.com"),
            path="/login",
            method="POST",
        ).allowed
    assert not core.check(attacker, path="/login", method="POST").allowed


def test_account_rule_catches_distributed_attack(
    make_core: Callable[..., LimiterCore]
) -> None:
    """Several IPs guessing the same account: the account rule must engage."""
    core = make_core(
        default_limit="2/minute", identifier=("account",), account_limit_multiplier=1
    )
    def attempt(ip: str) -> bool:
        return core.check(
            Identity(ip=ip, account="v@x.com"), path="/login", method="POST"
        ).allowed

    assert attempt("1.1.1.1")
    assert attempt("2.2.2.2")
    blocked = core.check(Identity(ip="3.3.3.3", account="v@x.com"), path="/login", method="POST")
    assert not blocked.allowed
    assert blocked.rule == "account"


def test_account_limit_is_looser_than_ip_limit_by_default(
    make_core: Callable[..., LimiterCore]
) -> None:
    """A tight account limit would let an attacker lock a real user out."""
    core = make_core(default_limit="2/minute", identifier=("ip", "account"))
    rules = {name: limit for name, limit, _ in core.rules_for(None)}
    assert rules["account"].limit == 6


def test_missing_component_skips_its_rule(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="1/minute", identifier=("ip", "account"))
    # No account in the request: only the IP rule applies, and it allows.
    first = core.check(Identity(ip="1.2.3.4"), path="/login", method="POST")
    assert first.allowed
    assert first.rule == "ip"
    assert not core.check(Identity(ip="1.2.3.4"), path="/login", method="POST").allowed


def test_no_identifier_at_all_is_allowed_not_shared(
    make_core: Callable[..., LimiterCore]
) -> None:
    core = make_core(default_limit="1/minute", identifier=("ip", "account"))
    decision = core.check(Identity(), path="/login", method="POST")
    assert decision.allowed
    assert "no identifier" in decision.message


def test_distinct_accounts_get_distinct_buckets(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="1/minute", identifier=("account",))

    def attempt(account: str) -> bool:
        return core.check(
            Identity(ip="1.1.1.1", account=account), path="/login", method="POST"
        ).allowed

    assert attempt("a@x.com")
    assert attempt("b@x.com")


def test_account_is_case_insensitive(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="1/minute", identifier=("account",), account_limit_multiplier=1)
    from omonire_limiter.identifiers import normalize_account

    core.check(
        Identity(ip="1.1.1.1", account=normalize_account("A@X.com")),
        path="/login",
        method="POST",
    )
    blocked = core.check(
        Identity(ip="1.1.1.1", account=normalize_account("a@x.COM")), path="/login", method="POST"
    )
    assert not blocked.allowed


# -------------------------------------------------------------------------- scope


def test_scope_endpoint_isolates_routes(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="1/minute", identifier=("ip",), scope="endpoint")
    identity = Identity(ip="1.2.3.4")
    assert core.check(identity, path="/login", method="POST").allowed
    assert core.check(identity, path="/register", method="POST").allowed
    assert core.check(identity, path="/login", method="GET").allowed
    assert not core.check(identity, path="/login", method="POST").allowed


def test_scope_global_shares_one_budget(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="2/minute", identifier=("ip",), scope="global")
    identity = Identity(ip="1.2.3.4")
    assert core.check(identity, path="/a").allowed
    assert core.check(identity, path="/b").allowed
    assert not core.check(identity, path="/c").allowed


def test_scope_method_isolates_only_on_method(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="2/minute", identifier=("ip",), scope="method")
    identity = Identity(ip="1.2.3.4")
    assert core.check(identity, path="/a", method="POST").allowed
    assert core.check(identity, path="/b", method="POST").allowed
    assert not core.check(identity, path="/c", method="POST").allowed
    # A different method has a separate budget.
    assert core.check(identity, path="/a", method="GET").allowed


def test_skip_methods(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="1/minute", identifier=("ip",), skip_methods=("OPTIONS",))
    identity = Identity(ip="1.2.3.4")
    for _ in range(50):
        assert core.check(identity, path="/login", method="OPTIONS").allowed
    assert core.check(identity, path="/login", method="POST").allowed
    assert not core.check(identity, path="/login", method="POST").allowed


# ------------------------------------------------------------------- reset/enabled


def test_reset_clears_counters_and_cooldown(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="1/minute", identifier=("ip", "account"))
    identity = Identity(ip="1.2.3.4", account="a@b.com")
    core.check(identity, path="/login", method="POST")
    assert not core.check(identity, path="/login", method="POST").allowed

    assert core.reset(identity, path="/login", method="POST") == 2
    assert core.check(identity, path="/login", method="POST").allowed


def test_disabled_limiter_allows_everything(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="1/minute", identifier=("ip",), enabled=False)
    identity = Identity(ip="1.2.3.4")
    for _ in range(10):
        assert core.check(identity, path="/login", method="POST").allowed


def test_clear_all_removes_namespace(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="1/minute", identifier=("ip",))
    core.check(Identity(ip="1.2.3.4"), path="/login", method="POST")
    assert core.clear_all() >= 1
    assert core.check(Identity(ip="1.2.3.4"), path="/login", method="POST").allowed


def test_clear_all_leaves_other_namespaces_alone(
    make_core: Callable[..., LimiterCore],
) -> None:
    """A shared Redis can host several limiters; clearing one must not clear all."""
    login = make_core(default_limit="1/minute", identifier=("ip",), namespace="login")
    other = make_core(default_limit="1/minute", identifier=("ip",), namespace="admin")

    identity = Identity(ip="1.2.3.4")
    for core in (login, other):
        core.check(identity, path="/x", method="POST")

    login.clear_all()

    assert login.check(identity, path="/x", method="POST").allowed
    # The untouched limiter is still exhausted, so its keys survived.
    assert not other.check(identity, path="/x", method="POST").allowed


def test_enforce_raises_instead_of_returning_a_blocked_decision(
    make_core: Callable[..., LimiterCore],
) -> None:
    core = make_core(default_limit="1/minute", identifier=("ip",))
    identity = Identity(ip="1.2.3.4")
    assert core.check(identity, path="/login", method="POST", enforce=True).allowed

    with pytest.raises(RateLimitExceeded) as excinfo:
        core.check(identity, path="/login", method="POST", enforce=True)
    # The exception carries the same information the 429 body would.
    assert excinfo.value.decision.limit == 1
    assert excinfo.value.decision.rule == "ip"
    assert excinfo.value.decision.retry_after is not None


def test_check_or_raise_is_enforcing(make_core: Callable[..., LimiterCore]) -> None:
    core = make_core(default_limit="1/minute", identifier=("ip",))
    identity = Identity(ip="1.2.3.4")
    assert core.check_or_raise(identity, path="/login", method="POST").allowed
    with pytest.raises(RateLimitExceeded):
        core.check_or_raise(identity, path="/login", method="POST")


# ------------------------------------------------------------------ failure modes


class BrokenStorage(MemoryStorage):
    name = "broken"

    def increment(self, *args, **kwargs):  # type: ignore[override]
        raise StorageError("simulated backend outage")

    def log_add(self, *args, **kwargs):  # type: ignore[override]
        raise StorageError("simulated backend outage")

    def marked_until(self, *args, **kwargs):  # type: ignore[override]
        raise StorageError("simulated backend outage")


def test_fail_closed_by_default(make_settings, clock: FakeClock) -> None:
    settings = make_settings(identifier=("ip",))
    core = LimiterCore(settings, BrokenStorage(clock=clock), clock=clock)
    with pytest.raises(StorageError):
        core.check(Identity(ip="1.2.3.4"), path="/login", method="POST")


def test_fail_open_allows_when_storage_is_down(make_settings, clock: FakeClock) -> None:
    settings = make_settings(identifier=("ip",), fail_open=True)
    core = LimiterCore(settings, BrokenStorage(clock=clock), clock=clock)
    decision = core.check(Identity(ip="1.2.3.4"), path="/login", method="POST")
    assert decision.allowed
    assert "fail-open" in decision.message


# ------------------------------------------------------------------------ config


def test_settings_reject_bad_configuration() -> None:
    with pytest.raises(ConfigurationError):
        Settings(key_salt=TEST_SALT, identifier=())
    with pytest.raises(ConfigurationError):
        Settings(key_salt=TEST_SALT, identifier=("nope",))
    with pytest.raises(ConfigurationError):
        Settings(key_salt=TEST_SALT, identifier=("ip", "ip"))
    with pytest.raises(ConfigurationError):
        Settings(key_salt=TEST_SALT, scope="whatever")
    with pytest.raises(ConfigurationError):
        Settings(key_salt=TEST_SALT, algorithm="magic")
    with pytest.raises(ConfigurationError):
        Settings(key_salt=TEST_SALT, namespace="has space")
    with pytest.raises(ConfigurationError):
        Settings(key_salt=TEST_SALT, account_limit_multiplier=0.5)
    with pytest.raises(ConfigurationError):
        Settings(key_salt=TEST_SALT, cooldown_seconds=-1)
    with pytest.raises(ConfigurationError):
        Settings(key_salt=TEST_SALT, status_code=500)
    with pytest.raises(ConfigurationError):
        Settings(key_salt=TEST_SALT, account_fields=())


def test_extra_identifiers_must_be_declared() -> None:
    with pytest.raises(ConfigurationError):
        Settings(key_salt=TEST_SALT, identifier=("user",))
    settings = Settings(
        key_salt=TEST_SALT, identifier=("user",), extra_identifier_fields=frozenset({"user"})
    )
    assert settings.identifier == ("user",)


def test_redis_requires_explicit_stable_salt(monkeypatch: pytest.MonkeyPatch) -> None:
    from omonire_limiter.config import SALT_ENV_VAR, resolve_key_salt

    monkeypatch.delenv(SALT_ENV_VAR, raising=False)
    with pytest.raises(ConfigurationError):
        resolve_key_salt(None, storage_name="redis")

    monkeypatch.setenv(SALT_ENV_VAR, "a" * 32)
    assert resolve_key_salt(None, storage_name="redis") == "a" * 32


def test_short_salt_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from omonire_limiter.config import resolve_key_salt

    with pytest.raises(ConfigurationError):
        resolve_key_salt("tooshort", storage_name="memory")


def test_memory_storage_gets_a_ephemeral_salt_with_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from omonire_limiter.config import SALT_ENV_VAR, resolve_key_salt

    monkeypatch.delenv(SALT_ENV_VAR, raising=False)
    with caplog.at_level("WARNING", logger="omonire_limiter"):
        salt = resolve_key_salt(None, storage_name="memory")
    assert len(salt) >= 16
    assert any("key salt" in record.message for record in caplog.records)
