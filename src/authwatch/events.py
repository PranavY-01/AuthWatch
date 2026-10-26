"""Compact internal events, deduplication, rule input selection and the global sort key
(Spec §6.5, errata E5, decisions D1 and D4)."""

import hashlib
import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from authwatch.keys import ip_key, username_key
from authwatch.models import AuthEvent
from authwatch.timeparse import parse_ts, to_us

OUTCOME_RANK = {"failure": 0, "unknown": 1, "success": 2}

# Uncorrelatable reason keys, checked in this order (first match wins).
UNKNOWN_OUTCOME = "unknown_outcome"
MISSING_TIMESTAMP = "missing_timestamp"
MISSING_SOURCE_IP = "missing_source_ip"
MISSING_USERNAME = "missing_username"

W_USER_SUSPICIOUS = "username_has_format_or_control_chars"
W_USER_EMPTY = "username_empty_after_normalization"
W_IP_SCOPE = "ip_scope_id_ignored"
W_IP_CANON = "ip_canonicalized"


@dataclass(slots=True)
class Event:
    """What detection sees: canonical keys and integer UTC microseconds, never raw syntax."""

    order: int
    line: int
    ts_us: int | None
    outcome: str
    user: str | None
    user_raw: str | None
    ip: str | None
    record_id: str | None
    product: str
    host: str | None
    port: int | None
    warnings: tuple[str, ...]
    content: str | None = None  # fingerprint for record_id deduplication


def SORT_KEY(e: Event) -> tuple[int, int, int]:
    """The one global order: instant, then failure < unknown < success, then input order."""
    return (e.ts_us, OUTCOME_RANK[e.outcome], e.order)


class Interner:
    """Share one string object per distinct value so a million events hold few copies."""

    def __init__(self) -> None:
        self._seen: dict[str, str] = {}

    def __call__(self, s: str | None) -> str | None:
        if s is None:
            return None
        return self._seen.setdefault(s, s)


def build_event(ae: AuthEvent, line: int, order: int, interner: Interner) -> Event:
    """Derive canonical keys and microsecond time from a validated AuthEvent."""
    warnings = list(ae.parse_warnings)
    ts_us = to_us(parse_ts(ae.timestamp)) if ae.timestamp is not None else None
    user = None
    if ae.username is not None:
        user, suspicious = username_key(ae.username)
        if suspicious:
            warnings.append(W_USER_SUSPICIOUS)
        if user is None:
            warnings.append(W_USER_EMPTY)
    ip = None
    if ae.source_ip is not None:
        ip, zone = ip_key(ae.source_ip)
        if zone:
            warnings.append(W_IP_SCOPE)
        if ip != ae.source_ip.partition("%")[0]:
            warnings.append(W_IP_CANON)
    content = None
    if ae.record_id is not None:
        data = ae.model_dump(exclude={"parse_warnings"})
        data["timestamp"] = ts_us
        data["source_ip"] = ip
        blob = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        content = hashlib.sha256(blob.encode("ascii")).hexdigest()
    return Event(
        order=order, line=line, ts_us=ts_us, outcome=ae.outcome,
        user=interner(user), user_raw=interner(ae.username), ip=interner(ip),
        record_id=ae.record_id, product=interner(ae.source_product),
        host=interner(ae.source_host), port=ae.source_port, warnings=tuple(warnings),
        content=content,
    )


def dedupe(events: Iterable[Event]) -> tuple[list[Event], int, list[Event]]:
    """Drop repeats of ``(source_product, source_host, record_id)`` with identical content.

    Never deduplicates on content alone. A repeat with different content is kept and
    returned as a conflict (partial coverage).
    """
    first: dict[tuple, str | None] = {}
    kept: list[Event] = []
    conflicts: list[Event] = []
    dropped = 0
    for e in events:
        if e.record_id is None:
            kept.append(e)
            continue
        ident = (e.product, e.host, e.record_id)
        if ident not in first:
            first[ident] = e.content
            kept.append(e)
        elif first[ident] == e.content:
            dropped += 1
        else:
            conflicts.append(e)
            kept.append(e)
    return kept, dropped, conflicts


def select(events: Iterable[Event], outcomes: frozenset[str], need_ip: bool,
           need_user: bool) -> tuple[list[Event], Counter]:
    """Split a rule's relevant events into usable (sorted) and uncorrelatable (counted)."""
    usable: list[Event] = []
    unc: Counter = Counter()
    for e in events:
        if e.outcome not in outcomes:
            continue
        if e.outcome == "unknown":
            unc[UNKNOWN_OUTCOME] += 1
        elif e.ts_us is None:
            unc[MISSING_TIMESTAMP] += 1
        elif need_ip and e.ip is None:
            unc[MISSING_SOURCE_IP] += 1
        elif need_user and e.user is None:
            unc[MISSING_USERNAME] += 1
        else:
            usable.append(e)
    usable.sort(key=SORT_KEY)
    return usable, unc
