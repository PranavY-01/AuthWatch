"""Write the deterministic synthetic fixtures (Spec §15.2): clean.jsonl, attacks.jsonl and
broken.jsonl. Documentation address ranges only (RFC 5737).

Usage: python samples/make_samples.py [OUTPUT_DIR]     (default: this script's directory)
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = datetime(2026, 10, 26, 10, 0, 0, tzinfo=timezone.utc)


def _ts(offset_s: int) -> str:
    return (BASE + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event(offset_s: int, outcome: str, user: str, ip: str, port: int,
           reason: str | None = None) -> dict:
    return {
        "auth_method": "password",
        "event_id": None,
        "event_type": "authentication",
        "failure_reason": (reason or "bad_credential") if outcome == "failure" else None,
        "logon_type": None,
        "outcome": outcome,
        "parse_warnings": [],
        "parser_name": None,
        "record_id": None,
        "schema_version": "1.0",
        "source_host": "example-host",
        "source_ip": ip,
        "source_os": "synthetic",
        "source_port": port,
        "source_product": "authwatch-fixture",
        "timestamp": _ts(offset_s),
        "username": user,
    }


def benign() -> list[dict]:
    """S5: bob fails twice then succeeds; carol succeeds three times."""
    return [
        _event(100, "failure", "bob", "198.51.100.20", 50100),
        _event(130, "failure", "bob", "198.51.100.20", 50101),
        _event(160, "success", "bob", "198.51.100.20", 50102),
        _event(500, "success", "carol", "198.51.100.30", 50200),
        _event(900, "success", "carol", "198.51.100.30", 50201),
        _event(1300, "success", "carol", "198.51.100.30", 50202),
    ]


def attacks() -> list[dict]:
    rows = []
    # S1 brute force (lines 1-9)
    rows += [_event(1800 + 15 * i, "failure", "alice", "203.0.113.50", 40000 + i)
             for i in range(9)]
    # S2 success after failures, from a new address (line 10)
    rows.append(_event(1980, "success", "alice", "198.51.100.7", 40100))
    # S3 spray: one IP, twelve accounts (lines 11-22)
    rows += [_event(2400 + 10 * i, "failure", f"user{i:02d}", "192.0.2.99", 41000 + i,
                    "unknown_account") for i in range(12)]
    # S4 distributed failures on one account (lines 23-28)
    rows += [_event(3000 + 30 * i, "failure", "admin", f"203.0.113.{i + 1}", 42000 + i)
             for i in range(6)]
    # S5 benign (lines 29-34)
    rows += benign()
    # S6 boundary negative: five failures spanning exactly 300 s (lines 35-39)
    rows += [_event(t, "failure", "dave", "198.51.100.200", 43000 + i)
             for i, t in enumerate((4200, 4260, 4320, 4380, 4500))]
    return rows


def _line(rec: dict) -> bytes:
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def broken_lines() -> list[bytes]:
    """Lines 40-45 of broken.jsonl, one defect each."""
    good = _line(_event(4600, "failure", "erin", "203.0.113.77", 44000))
    no_ip = _event(4610, "failure", "erin", "203.0.113.77", 44001)
    del no_ip["source_ip"]
    typo = _event(4620, "failure", "erin", "203.0.113.77", 44002)
    typo["sourceip"] = typo.pop("source_ip")
    return [
        good.replace(b'"outcome":"failure"', b'"outcome":"failure","outcome":"success"'),
        good.replace(b'"source_port":44000', b'"source_port":NaN'),
        good.replace(b'"source_ip":"203.0.113.77"', b'"source_ip":"203.0.113.999"'),
        _line(no_ip),
        _line(typo),
        good[: len(good) // 2],
    ]


def write_all(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    attack_lines = [_line(r) for r in attacks()]
    files = {
        "clean.jsonl": [_line(r) for r in benign()],
        "attacks.jsonl": attack_lines,
        "broken.jsonl": attack_lines + broken_lines(),
    }
    for name, lines in files.items():
        (out_dir / name).write_bytes(b"".join(ln + b"\n" for ln in lines))


if __name__ == "__main__":
    write_all(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent)
