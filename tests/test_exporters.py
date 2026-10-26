import csv
import io

import pytest

from authwatch.exporters import CSV_COLUMNS, csv_safe, normalized_jsonl, write_csv
from conftest import SAMPLES
from test_cli import aw


@pytest.mark.parametrize("value", ["=HYPERLINK(\"http://x\")", " =1+1", "\n=1+1", "\uff1d1+1",
                                   "+1", "-1", "@SUM(A1)", "\t=1", "\r=1", "  \t-cmd"])
def test_formula_prefixes_escaped(value):
    """Case 60: values starting with =, space-=, newline-=, fullwidth ＝, +, - or @ get a quote."""
    assert csv_safe(value) == "'" + value


@pytest.mark.parametrize("value", ["alice", "", "ip:1.2.3.4", "user:=x", "a=b", "12"])
def test_safe_values_unchanged(value):
    assert csv_safe(value) == value


def test_csv_header_rows_and_escaping():
    findings = [{"event": "AW-002", "subject": "user:x", "details": {
        "alert_id": "a" * 16, "severity": "MEDIUM", "title": "t", "first_seen": "f",
        "last_seen": "l", "count": 5, "peak_in_window": 5, "threshold": 5,
        "window_seconds": 300, "description": "=cmd|' /C calc'!A0\nline2"}}]
    data = write_csv(findings)
    assert b"\r\n" not in data
    rows = list(csv.reader(io.StringIO(data.decode("utf-8"))))
    assert rows[0] == list(CSV_COLUMNS) and len(rows) == 2
    assert rows[1][-1].startswith("'=cmd")


def test_csv_from_cli(tmp_path):
    out, rep = tmp_path / "a.csv", tmp_path / "r.json"
    proc = aw("analyze", SAMPLES / "attacks.jsonl", "--csv", out, "--report", rep)
    assert proc.returncode == 1
    rows = list(csv.reader(io.StringIO(out.read_text(encoding="utf-8"))))
    assert len(rows) == 7 and rows[1][1] == "AW-004"
    assert aw("analyze", SAMPLES / "attacks.jsonl", "--csv", out).returncode == 2  # exists
    assert aw("analyze", SAMPLES / "attacks.jsonl", "--csv", out, "--force-report").returncode == 1
    same = tmp_path / "same.out"
    assert aw("analyze", SAMPLES / "attacks.jsonl", "--csv", same, "--report", same).returncode == 2


def test_normalized_jsonl_format():
    data = normalized_jsonl([{"b": 1, "a": "ａ"}])
    assert data == b'{"a":"\\uff41","b":1}\n'
