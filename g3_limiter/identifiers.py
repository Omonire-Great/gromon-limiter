"""Turning a request into stable, non-identifying limiter identities.

Two rules drive this module:

1. **Never trust a client supplied IP header unless the peer is a configured
   proxy.** Otherwise any caller can forge ``X-Forwarded-For`` and evade every
   IP based limit.
2. **Never put raw user input in a storage key.** Account identifiers are
   normalised and then replaced by a keyed (HMAC-SHA256) fingerprint, so
   ``john@example.com`` cannot be read out of Redis, slow-log or keyspace scan
   output. A stable salt is what makes the fingerprint usable across restarts
   and across instances; the salt is a secret and belongs in the environment.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

__all__ = [
    "Identity",
    "TrustedProxies",
    "client_ip",
    "fingerprint",
    "new_salt",
    "normalize_account",
    "normalize_ip",
]

#: Maximum accepted length of a normalised account identifier. Longer values are
#: truncated before hashing to keep key building cheap and bounded.
MAX_ACCOUNT_LENGTH = 256

#: Environment variable consulted when no salt is passed explicitly.
SALT_ENV_VAR = "G3_LIMITER_KEY_SALT"

#: Unit separator; cannot occur in the fingerprint input, so different
#: combinations of parts can never collide by concatenation.
_SEP = "\x1f"


def new_salt() -> str:
    """Generate a cryptographically random salt."""
    return secrets.token_urlsafe(32)


def normalize_ip(value: str | None) -> str | None:
    """Return the canonical text form of an IP address, or ``None`` if invalid.

    Canonicalisation matters: ``::1`` and ``0:0:0:0:0:0:0:1`` must not consume
    two separate buckets, and IPv4-mapped IPv6 (``::ffff:127.0.0.1``) must not
    bypass an IPv4 rule.
    """
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    # Collapse ::ffff:1.2.3.4 to 1.2.3.4 so IPv4 and IPv4-mapped clients share
    # a single bucket.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(address)


def normalize_account(value: object) -> str | None:
    """Normalise an account identifier (email, username, phone, ...).

    Emails are case-insensitive by convention, so the value is trimmed,
    lowercased and truncated. Returns ``None`` when nothing usable was supplied.
    """
    if value is None or isinstance(value, (bytes, bytearray)):
        return None
    if not isinstance(value, str):
        if isinstance(value, (int, float, bool)):
            value = str(value)
        else:
            return None
    candidate = value.strip().lower()
    if not candidate:
        return None
    return candidate[:MAX_ACCOUNT_LENGTH]


def fingerprint(salt: str, *parts: str | None) -> str:
    """Return a short, stable, non-reversible identifier for ``parts``.

    HMAC-SHA256 truncated to 128 bits: collision-resistant enough for bucketing,
    short enough to keep Redis keys readable, and one-way so that key material
    does not disclose who was rate limited.
    """
    payload = _SEP.join(part for part in parts if part).encode("utf-8", "replace")
    return hmac.new(salt.encode("utf-8"), payload, hashlib.sha256).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class Identity:
    """The resolved identity of a single request.

    Only the parts that were actually found are set; a request without a JSON
    body simply has ``account is None``.
    """

    ip: str | None = None
    account: str | None = None
    extras: Mapping[str, str] = field(default_factory=dict)

    def get(self, name: str) -> str | None:
        """Return an extra identifier by name (``"user"``, ``"api_key"``, ...)."""
        value = self.extras.get(name)
        return value if isinstance(value, str) and value else None

    def material_for(self, components: Iterable[str]) -> tuple[str, ...]:
        """Collect the raw parts named by ``components``.

        Missing parts are silently skipped so that a rule configured for
        ``ip+account`` still works (as an IP-only rule) when the request carried
        no account identifier.
        """
        parts: list[str] = []
        for component in components:
            if component == "ip":
                value = self.ip
            elif component == "account":
                value = self.account
            else:
                value = self.extras.get(component)
            if value:
                parts.append(f"{component}={value}")
        return tuple(parts)


class TrustedProxies:
    """Compiled allow-list of proxies whose forwarding headers may be trusted.

    Entries may be plain addresses (``10.0.0.7``) or CIDR blocks
    (``10.0.0.0/8``, ``::1/128``). An empty instance trusts nobody, which is the
    safe default for an application running without a reverse proxy.
    """

    __slots__ = ("_networks", "_raw")

    def __init__(self, entries: Iterable[str] = ()) -> None:
        self._raw = tuple(entries)
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for entry in self._raw:
            text = entry.strip()
            if not text:
                continue
            try:
                networks.append(ipaddress.ip_network(text, strict=False))
            except ValueError:
                # An unparseable entry can never be matched, so it can never
                # widen trust. Silently ignore, keeping the safe behaviour.
                continue
        self._networks = tuple(networks)

    def __bool__(self) -> bool:
        return bool(self._networks)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"TrustedProxies({list(self._raw)!r})"

    def contains(self, address: str | None) -> bool:
        """True when ``address`` is inside the configured proxy networks."""
        normalized = normalize_ip(address)
        if normalized is None or not self._networks:
            return False
        try:
            parsed = ipaddress.ip_address(normalized)
        except ValueError:  # pragma: no cover - normalize_ip already validated
            return False
        return any(parsed in network for network in self._networks)

    def client_from_chain(self, chain: Iterable[str]) -> str | None:
        """Walk an ``X-Forwarded-For`` chain right-to-left past known proxies."""
        entries = [normalize_ip(entry) for entry in chain]
        entries = [entry for entry in entries if entry is not None]
        for entry in reversed(entries):
            if not self.contains(entry):
                return entry
        # Every hop is a trusted proxy: the left-most entry is the closest we
        # have to the real client.
        return entries[0] if entries else None


def client_ip(
    *,
    remote_addr: str | None,
    forwarded_for: str | None = None,
    real_ip: str | None = None,
    trusted_proxies: TrustedProxies | None = None,
) -> str | None:
    """Resolve the client IP address of a request.

    ``remote_addr`` is the socket peer, which is the only value the server
    observed itself. Forwarding headers are consulted **only** when that peer is
    a configured trusted proxy; otherwise the peer is returned verbatim and the
    headers are ignored completely. This is what prevents header spoofing.
    """
    peer = normalize_ip(remote_addr)
    trusted = trusted_proxies or TrustedProxies()
    if not trusted:
        return peer
    if not trusted.contains(peer):
        # Untrusted peer: forwarding headers are attacker-controlled.
        return peer

    if forwarded_for:
        resolved = trusted.client_from_chain(forwarded_for.split(","))
        if resolved:
            return resolved
    candidate = normalize_ip(real_ip)
    if candidate and not trusted.contains(candidate):
        return candidate
    return peer
