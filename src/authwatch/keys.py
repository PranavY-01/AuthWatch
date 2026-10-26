"""Canonical grouping keys for source IPs and usernames.

Raw values are kept for display; rules group only on these keys.
"""

import ipaddress
import unicodedata


def ip_key(v: object) -> tuple[str, str | None]:
    """Return ``(canonical address, IPv6 scope id or None)``; raise ValueError if not an IP string.

    IPv4-mapped IPv6 collapses to IPv4, IPv6 is lower-cased and compressed, and a scope id
    is stripped from the key. Integers are rejected before ``ipaddress`` can accept them.
    """
    if not isinstance(v, str):
        raise ValueError("source_ip must be a string")
    addr = ipaddress.ip_address(v)  # IPv6 scope ids parsed natively; IPv4 '%' rejected
    zone = getattr(addr, "scope_id", None)
    if addr.version == 6:
        if zone:
            addr = ipaddress.IPv6Address(v.partition("%")[0])
        if addr.ipv4_mapped:
            addr = addr.ipv4_mapped
    return str(addr), zone


def username_key(u: str) -> tuple[str | None, bool]:
    """Return ``(key or None, suspicious)``.

    NFKC -> casefold -> NFKC (casefold alone leaves some code points non-normalized), then
    format characters (Cf) are removed. ``suspicious`` is true when format or control
    characters were present. An empty result has no key and is uncorrelatable.
    """
    k = unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", u).casefold())
    suspicious = any(unicodedata.category(c) in ("Cf", "Cc") for c in k)
    k = "".join(c for c in k if unicodedata.category(c) != "Cf")
    return (k or None), suspicious
