"""CSV alert export with formula-injection escaping (Spec §8.6, D12) and the normalized
JSONL writer (Spec §8.2, D9)."""

import csv
import io
import json
import unicodedata
from collections.abc import Iterable

CSV_COLUMNS = ("alert_id", "rule_id", "severity", "title", "subject", "first_seen", "last_seen",
               "count", "peak_in_window", "threshold", "window_seconds", "description")


def csv_safe(s: str) -> str:
    """Prefix a cell that a spreadsheet could read as a formula (also after leading
    whitespace, and for compatibility forms such as fullwidth ＝)."""
    lead = unicodedata.normalize("NFKC", s.lstrip(" \t\r\n"))[:1]
    return "'" + s if s and (s[0] in "=+-@\t\r\n" or lead in ("=", "+", "-", "@")) else s


def write_csv(findings: Iterable[dict]) -> bytes:
    """One row per alert, header first, UTF-8, LF line endings. Evidence is not included."""
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for f in findings:
        d = f["details"]
        row = (d["alert_id"], f["event"], d["severity"], d["title"], f["subject"],
               d["first_seen"], d["last_seen"], d["count"], d["peak_in_window"], d["threshold"],
               d["window_seconds"], d["description"])
        writer.writerow([csv_safe(str(v)) for v in row])
    return buf.getvalue().encode("utf-8")


def normalized_jsonl(records: Iterable[dict]) -> bytes:
    """Schema-1.0 events, one compact ASCII JSON object per line with sorted keys."""
    return b"".join(
        json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        + b"\n" for r in records)
