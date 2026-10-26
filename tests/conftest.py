"""Shared helpers: record/file builders, in-memory events and platform skip markers."""

import json
import os
import sys
from pathlib import Path

import pytest

from authwatch.events import Event

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"

IS_WINDOWS = sys.platform.startswith("win")
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def _symlinks_supported() -> bool:
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / "t"
        target.write_bytes(b"x")
        try:
            os.symlink(target, Path(d) / "l")
        except (OSError, NotImplementedError):
            return False
    return True


needs_symlink = pytest.mark.skipif(not _symlinks_supported(),
                                   reason="symlinks need Developer Mode or admin on Windows")
posix_only = pytest.mark.skipif(IS_WINDOWS, reason="POSIX permission semantics")
not_root = pytest.mark.skipif(IS_ROOT, reason="root ignores file permissions")


def record(**overrides) -> dict:
    """A valid schema-1.0 failure record; override or drop (value ...) any field."""
    rec = {
        "schema_version": "1.0",
        "event_type": "authentication",
        "timestamp": "2026-10-26T10:00:00Z",
        "outcome": "failure",
        "username": "alice",
        "source_ip": "203.0.113.50",
        "source_os": "synthetic",
        "source_product": "authwatch-fixture",
    }
    for key, value in overrides.items():
        if value is ...:
            rec.pop(key, None)
        else:
            rec[key] = value
    return rec


def ts(offset_s: int) -> str:
    """Fixture base time plus an offset in seconds, as RFC 3339 UTC."""
    from authwatch.timeparse import iso_utc, parse_ts, to_us
    return iso_utc(to_us(parse_ts("2026-10-26T10:00:00Z")) + offset_s * 1_000_000)


def jsonl(records) -> bytes:
    lines = [r if isinstance(r, (bytes, str)) else json.dumps(r) for r in records]
    return b"".join((ln.encode("utf-8") if isinstance(ln, str) else ln) + b"\n" for ln in lines)


def write(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def ev(ts_s, *, key="k", user=None, ip=None, outcome="failure", order=0, line=None) -> Event:
    """An in-memory Event for engine tests. ``ts_s`` is used directly as ts_us."""
    return Event(order=order, line=order + 1 if line is None else line, ts_us=ts_s,
                 outcome=outcome, user=user if user is not None else key, user_raw=user,
                 ip=ip if ip is not None else key, record_id=None, product="p", host=None,
                 port=None, warnings=())
