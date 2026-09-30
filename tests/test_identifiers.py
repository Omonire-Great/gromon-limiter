"""Identity resolution.

The security-critical property here is that a caller cannot forge its IP by
setting ``X-Forwarded-For``. These tests encode that as an explicit contract.
"""

from __future__ import annotations

import pytest

from omonire_limiter.identifiers import (
    Identity,
    TrustedProxies,
    client_ip,
    fingerprint,
    normalize_account,
    normalize_ip,
)

# ------------------------------------------------------------------ normalize_ip


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1.2.3.4", "1.2.3.4"),
        ("  1.2.3.4  ", "1.2.3.4"),
        ("::1", "::1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("::ffff:1.2.3.4", "1.2.3.4"),
        ("0:0:0:0:0:0:0:1", "::1"),
    ],
)
def test_normalize_ip_canonicalises(raw: str, expected: str) -> None:
    assert normalize_ip(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", None, "not-an-ip", "1.2.3.4.5", "999.1.1.1"])
def test_normalize_ip_rejects_junk(raw: str | None) -> None:
    assert normalize_ip(raw) is None


# ------------------------------------------------------------- normalize_account


def test_normalize_account_trims_and_lowercases() -> None:
    assert normalize_account("  John.Doe@Example.COM ") == "john.doe@example.com"


def test_normalize_account_rejects_blank_and_wrong_types() -> None:
    assert normalize_account("") is None
    assert normalize_account("   ") is None
    assert normalize_account(None) is None
    assert normalize_account(b"bytes") is None
    assert normalize_account({"a": 1}) is None
    assert normalize_account([]) is None


def test_normalize_accepts_numeric_identifiers() -> None:
    assert normalize_account(12345) == "12345"


def test_normalize_truncates_long_input() -> None:
    assert len(normalize_account("a" * 5000)) == 256


# -------------------------------------------------------------------- fingerprint


def test_fingerprint_is_stable_and_opaque() -> None:
    first = fingerprint("salt", "account=john@example.com")
    second = fingerprint("salt", "account=john@example.com")
    assert first == second
    assert "john" not in first
    assert len(first) == 32


def test_fingerprint_depends_on_salt() -> None:
    assert fingerprint("salt-a", "ip=1.2.3.4") != fingerprint("salt-b", "ip=1.2.3.4")


def test_fingerprint_separates_parts() -> None:
    # A naive concatenation would collide: ip="1.2.3.4", account="5" vs
    # ip="1.2.3.45", account="" style ambiguity.
    assert fingerprint("s", "ip=1.2.3.4", "account=x") != fingerprint(
        "s", "ip=1.2.3.4", "account=y"
    )


# ---------------------------------------------------------------------- Identity


def test_identity_material_for_ignores_missing_parts() -> None:
    identity = Identity(ip="1.2.3.4", account=None)
    assert identity.material_for(("ip", "account")) == ("ip=1.2.3.4",)
    assert identity.material_for(("account",)) == ()


def test_identity_material_for_reads_extras() -> None:
    identity = Identity(ip="1.2.3.4", extras={"user": "u-7"})
    assert identity.material_for(("ip", "user")) == ("ip=1.2.3.4", "user=u-7")


def test_identity_get_reads_extras() -> None:
    identity = Identity(extras={"user": "u-7"})
    assert identity.get("user") == "u-7"
    assert identity.get("missing") is None


# ----------------------------------------------------------------- trusted proxies


def test_no_trusted_proxies_ignores_forwarding_headers() -> None:
    resolved = client_ip(
        remote_addr="10.0.0.5",
        forwarded_for="1.2.3.4",
        real_ip="1.2.3.4",
        trusted_proxies=TrustedProxies(),
    )
    assert resolved == "10.0.0.5"


def test_untrusted_peer_cannot_spoof_forwarded_header() -> None:
    # This is the attack the whole proxy allow-list exists for.
    resolved = client_ip(
        remote_addr="203.0.113.9",
        forwarded_for="1.2.3.4",
        real_ip="1.2.3.4",
        trusted_proxies=TrustedProxies(["10.0.0.0/8"]),
    )
    assert resolved == "203.0.113.9"


def test_trusted_proxy_forwarded_header_is_honoured() -> None:
    resolved = client_ip(
        remote_addr="10.0.0.5",
        forwarded_for="203.0.113.7",
        trusted_proxies=TrustedProxies(["10.0.0.0/8"]),
    )
    assert resolved == "203.0.113.7"


def test_chain_is_walked_past_every_trusted_hop() -> None:
    # client -> proxy1 (trusted) -> proxy2 (trusted) -> origin
    resolved = client_ip(
        remote_addr="10.0.0.5",
        forwarded_for="203.0.113.7, 10.1.1.1, 10.2.2.2",
        trusted_proxies=TrustedProxies(["10.0.0.0/8"]),
    )
    assert resolved == "203.0.113.7"


def test_injected_forwarded_entry_is_ignored() -> None:
    # Attacker prepends a fake IP to the header. Walking right-to-left and
    # stopping at the first untrusted hop keeps the value the last proxy saw.
    resolved = client_ip(
        remote_addr="10.0.0.5",
        forwarded_for="9.9.9.9, 203.0.113.7",
        trusted_proxies=TrustedProxies(["10.0.0.0/8"]),
    )
    assert resolved == "203.0.113.7"


def test_real_ip_used_when_no_forwarded_header() -> None:
    resolved = client_ip(
        remote_addr="10.0.0.5",
        real_ip="203.0.113.7",
        trusted_proxies=TrustedProxies(["10.0.0.5"]),
    )
    assert resolved == "203.0.113.7"


def test_real_ip_from_a_trusted_peer_is_not_treated_as_client() -> None:
    resolved = client_ip(
        remote_addr="10.0.0.5",
        real_ip="10.0.0.5",
        trusted_proxies=TrustedProxies(["10.0.0.0/8"]),
    )
    assert resolved == "10.0.0.5"


def test_trusted_proxies_accepts_single_address_and_cidr() -> None:
    assert TrustedProxies(["10.0.0.5"]).contains("10.0.0.5")
    assert TrustedProxies(["10.0.0.0/8"]).contains("10.9.9.9")
    assert not TrustedProxies(["10.0.0.0/8"]).contains("11.9.9.9")
    assert TrustedProxies(["::1/128"]).contains("::1")
    assert not TrustedProxies(["::1/128"]).contains("::2")
    # IPv4 rules must not accidentally match IPv6 (or vice versa).
    assert not TrustedProxies(["10.0.0.0/8"]).contains("::1")
    assert not TrustedProxies(["10.0.0.0/8"]).contains("10.9.9.9".replace("10", "11"))


def test_unparseable_proxy_entries_never_widen_trust() -> None:
    trusted = TrustedProxies(["garbage", "", "10.0.0.0/8"])
    assert not trusted.contains("garbage")
    assert trusted.contains("10.1.1.1")


def test_empty_trusted_proxies_is_falsy() -> None:
    assert not TrustedProxies()
    assert not TrustedProxies(["", "  "])


def test_normalisation_makes_equivalent_addresses_share_a_bucket() -> None:
    a = client_ip(remote_addr="::ffff:1.2.3.4")
    b = client_ip(remote_addr="1.2.3.4")
    assert a == b


def test_all_trusted_chain_falls_back_to_leftmost() -> None:
    resolved = client_ip(
        remote_addr="10.0.0.5",
        forwarded_for="10.1.1.1, 10.2.2.2",
        trusted_proxies=TrustedProxies(["10.0.0.0/8"]),
    )
    assert resolved == "10.1.1.1"


def test_garbage_forwarded_chain_falls_back_to_peer() -> None:
    resolved = client_ip(
        remote_addr="10.0.0.5",
        forwarded_for="unknown, garbage",
        trusted_proxies=TrustedProxies(["10.0.0.0/8"]),
    )
    assert resolved == "10.0.0.5"
