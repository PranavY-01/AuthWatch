"""Tests for the inspection commands: explain, diff, validate and rules."""

import io
import json
import shutil

import pytest
from rich.console import Console

from authwatch.errors import ConfigError, VerificationError
from authwatch.render import render_explain
from authwatch.reports import (candidate_inputs, diff_exit_code, diff_reports, find_alert,
                               load_report, read_evidence, record_fields, verify)
from conftest import SAMPLES, jsonl, record, ts, write
from test_cli import ENV, aw

AW004_ID = None  # filled by the fixture below


@pytest.fixture
def analyzed(tmp_path):
    """attacks.jsonl copied into tmp_path and analyzed; returns (input, report path, report)."""
    inp = tmp_path / "attacks.jsonl"
    shutil.copy(SAMPLES / "attacks.jsonl", inp)
    rep = tmp_path / "attacks.report.json"
    assert aw("analyze", inp, "--report", rep).returncode == 1
    return inp, rep, json.loads(rep.read_text(encoding="utf-8"))


def alert_of(report, rule):
    return next(f for f in report["findings"] if f["event"] == rule)


# ------------------------------------------------------------------------------------ explain
def test_explain_verifies_and_shows_evidence(analyzed):
    inp, rep, report = analyzed
    alert_id = alert_of(report, "AW-004")["details"]["alert_id"]
    proc = aw("explain", alert_id[:8], "--report", rep)
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "VERIFIED" in out and report["input"]["sha256"][:12] in out
    assert "Success after repeated failures on the same account" in out
    for minute in ("10:30:00", "10:32:00", "10:33:00"):  # first, last failure, the success
        assert f"2026-10-26T{minute}Z" in out
    assert "198.51.100.7" in out and "new source IP" in out


def test_explain_json_lists_the_exact_lines(analyzed):
    inp, rep, report = analyzed
    alert = alert_of(report, "AW-004")
    proc = aw("explain", alert["details"]["alert_id"], "--report", rep, "--format", "json")
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["verified"] is True and data["alert"] == alert
    assert [row["line"] for row in data["lines"]] == list(range(1, 11))
    assert [row["role"] for row in data["lines"]] == ["failure"] * 9 + ["success"]
    file_lines = inp.read_text(encoding="utf-8").splitlines()
    for row in data["lines"]:
        assert row["text"] == file_lines[row["line"] - 1]
        assert row["fields"]["outcome"] == row["role"]


def test_explain_finds_input_in_current_directory(analyzed, tmp_path):
    inp, rep, report = analyzed
    elsewhere = tmp_path / "reports"
    elsewhere.mkdir()
    moved = elsewhere / rep.name
    shutil.move(rep, moved)
    alert_id = report["findings"][0]["details"]["alert_id"]
    assert aw("explain", alert_id, "--report", moved, cwd=tmp_path).returncode == 0
    assert aw("explain", alert_id, "--report", moved, cwd=elsewhere).returncode == 2
    assert aw("explain", alert_id, "--report", moved, "--input", inp,
              cwd=elsewhere).returncode == 0


def test_explain_refuses_a_changed_file(analyzed):
    """The hash check: one changed byte and no evidence is shown (exit 4)."""
    inp, rep, report = analyzed
    data = inp.read_bytes()
    inp.write_bytes(data.replace(b"203.0.113.50", b"203.0.113.51", 1))
    alert_id = report["findings"][0]["details"]["alert_id"]
    proc = aw("explain", alert_id, "--report", rep, "--format", "json")
    assert proc.returncode == 4 and proc.stdout == ""
    assert "sha256 mismatch" in proc.stderr and "refusing to show evidence" in proc.stderr
    inp.write_bytes(data + b"\n")  # appended bytes count too
    assert aw("explain", alert_id, "--report", rep).returncode == 4


@pytest.mark.parametrize("alert_id", ["ffffffff", "zz12", "abc", "9e00a620x"])
def test_explain_bad_ids_exit_2(analyzed, alert_id):
    _, rep, _ = analyzed
    assert aw("explain", alert_id, "--report", rep).returncode == 2


def test_explain_rejects_non_reports(analyzed, tmp_path):
    inp, rep, _ = analyzed
    assert aw("explain", "abcd", "--report", inp).returncode == 2           # a log, not a report
    assert aw("explain", "abcd", "--report", tmp_path / "nope.json").returncode == 2
    assert aw("explain", "abcd", "--report", tmp_path).returncode == 2     # a directory
    dup = write(tmp_path, "dup.json", b'{"envelope":{"tool":"AuthWatch"},"envelope":{}}')
    assert aw("explain", "abcd", "--report", dup).returncode == 2


def test_explain_raw_mode_and_terminal_safety(tmp_path):
    recs = [record(timestamp=ts(i), username="[red]x\x1b[2J:smile:") for i in range(5)]
    inp = write(tmp_path, "evil.jsonl", jsonl(recs))
    rep = tmp_path / "r.json"
    aw("analyze", inp, "--report", rep)
    alert_id = json.loads(rep.read_text(encoding="utf-8"))["findings"][0]["details"]["alert_id"]
    fields = aw("explain", alert_id, "--report", rep)
    assert fields.returncode == 0
    assert "\x1b" not in fields.stdout and "[red]x\\x1b[2J:smile:" in fields.stdout
    raw = aw("explain", alert_id, "--report", rep, "--raw")
    assert raw.returncode == 0 and "\x1b" not in raw.stdout
    assert '"username": "[red]x\\u001b[2J:smile:"' in raw.stdout  # the file's own JSON escape


def test_explain_warns_when_report_was_redacted(tmp_path):
    inp = tmp_path / "attacks.jsonl"
    shutil.copy(SAMPLES / "attacks.jsonl", inp)
    rep = tmp_path / "r.json"
    aw("analyze", inp, "--report", rep, "--redact-usernames",
       env=dict(ENV, AUTHWATCH_REDACT_KEY="k" * 32))
    report = json.loads(rep.read_text(encoding="utf-8"))
    alert_id = report["findings"][0]["details"]["alert_id"]
    proc = aw("explain", alert_id, "--report", rep)
    assert proc.returncode == 0 and "real usernames" in proc.stdout


def test_explain_truncated_episode_caption(tmp_path):
    recs = [record(timestamp=ts(i), source_ip="203.0.113.9") for i in range(80)]
    inp = write(tmp_path, "flood.jsonl", jsonl(recs))
    rep = tmp_path / "r.json"
    aw("analyze", inp, "--report", rep)
    report = json.loads(rep.read_text(encoding="utf-8"))
    alert = alert_of(report, "AW-001")
    proc = aw("explain", alert["details"]["alert_id"], "--report", rep, "--format", "json")
    assert len(json.loads(proc.stdout)["lines"]) == 50
    assert "first 25 and last 25 of 80" in aw("explain", alert["details"]["alert_id"],
                                              "--report", rep).stdout


def test_explain_with_openssh_input(tmp_path):
    from test_openssh import AUTHORED_LOG
    inp = write(tmp_path, "auth.log", AUTHORED_LOG.encode())
    rep = tmp_path / "r.json"
    aw("analyze", inp, "--input-format", "openssh", "--assume-year", "2026", "--assume-tz", "Z",
       "--report", rep)
    report = json.loads(rep.read_text(encoding="utf-8"))
    proc = aw("explain", alert_of(report, "AW-004")["details"]["alert_id"], "--report", rep)
    assert proc.returncode == 0 and "Accepted password for alice" in proc.stdout


def test_render_explain_escapes_record_text():
    buf = io.StringIO()
    finding = {"event": "AW-001", "subject": "ip:x", "details": {
        "alert_id": "a" * 16, "severity": "MEDIUM", "title": "t", "evidence": {"lines": [1]},
        "caveats": ["[blink]c[/blink]"], "description": "d\x1b[2J"}}
    render_explain({"finding": finding, "report_label": "r.json", "sha256": "0" * 64, "size": 1,
                    "input_path": "in", "redacted": False, "raw": True,
                    "lines": [{"line": 1, "role": "failure", "text": "evil\x1b[2J[red]x[/red]",
                               "fields": None}]},
                   Console(file=buf, force_terminal=True, width=150, highlight=False, emoji=False))
    out = buf.getvalue()
    assert "\x1b[2J" not in out and "[red]x[/red]" in out and "[blink]c[/blink]" in out


# ------------------------------------------------------------------------- reports (library)
def test_find_alert_prefix_rules():
    report = {"findings": [{"details": {"alert_id": "abcd1111aaaaaaaa"}},
                           {"details": {"alert_id": "abcd2222bbbbbbbb"}}]}
    assert find_alert(report, "ABCD1")["details"]["alert_id"].startswith("abcd1")
    with pytest.raises(ConfigError, match="matches 2 alerts"):
        find_alert(report, "abcd")
    with pytest.raises(ConfigError):
        find_alert(report, "abc")


def test_candidate_inputs_ignore_paths(tmp_path):
    rep = tmp_path / "r.json"
    assert candidate_inputs({"input": {"label": "a.jsonl"}}, rep) == [tmp_path / "a.jsonl",
                                                                       __import__("pathlib").Path("a.jsonl")]
    for label in ("../a.jsonl", "sub/a.jsonl", "", "..", None, 5):
        assert candidate_inputs({"input": {"label": label}}, rep) == []


def test_read_evidence_hash_matches_analyze(analyzed):
    inp, _, report = analyzed
    ev = read_evidence(inp, {1, 39, 999})
    assert ev.sha256 == report["input"]["sha256"] and ev.size == report["input"]["size_bytes"]
    assert set(ev.lines) == {1, 39}
    verify(ev, report, inp)
    with pytest.raises(VerificationError):
        verify(ev, {"input": {"sha256": "0" * 64, "size_bytes": ev.size}}, inp)


def test_record_fields():
    assert record_fields('{"outcome":"failure","username":"a"}')["username"] == "a"
    for bad in (None, "not json", "[1]", '{"a":1,"a":2}'):
        assert record_fields(bad) is None


# --------------------------------------------------------------------------------------- diff
def day2_report(tmp_path):
    """Day 2: the spray stops, admin's burst grows, frank is new."""
    lines = (SAMPLES / "attacks.jsonl").read_text(encoding="utf-8").splitlines()
    extra = [json.dumps(dict(json.loads(lines[22]), timestamp=f"2026-10-26T10:52:{40 + i * 5}Z"))
             for i in range(3)]
    extra += [json.dumps(dict(json.loads(lines[0]), username="frank", source_ip="198.51.100.66",
                              timestamp=f"2026-10-26T12:00:{i * 10:02d}Z")) for i in range(6)]
    inp = write(tmp_path, "day2.jsonl", ("\n".join(lines[:10] + lines[22:] + extra) + "\n").encode())
    rep = tmp_path / "day2.report.json"
    aw("analyze", inp, "--report", rep)
    return rep


def test_diff_new_ongoing_resolved(analyzed, tmp_path):
    _, day1, _ = analyzed
    day2 = day2_report(tmp_path)
    proc = aw("diff", day1, day2, "--format", "json")
    assert proc.returncode == 1
    result = json.loads(proc.stdout)
    assert sorted(f["subject"] for f in result["new_alerts"]) == ["ip:198.51.100.66", "user:frank"]
    assert sorted(f["subject"] for f in result["resolved"]) == ["ip:192.0.2.99", "ip:192.0.2.99"]
    ongoing = {(o["finding"]["event"], o["finding"]["subject"]): (o["old_count"], o["new_count"])
               for o in result["ongoing"]}
    assert ongoing == {("AW-004", "user:alice"): (9, 9), ("AW-001", "ip:203.0.113.50"): (9, 9),
                       ("AW-002", "user:alice"): (9, 9), ("AW-002", "user:admin"): (6, 9)}
    assert result["warnings"] == [] and result["complete"] is True
    text = aw("diff", day1, day2).stdout
    assert "NEW ALERTS" in text and "6 → 9" in text and "no longer reported" in text


def test_diff_same_report_no_new(analyzed):
    _, rep, _ = analyzed
    proc = aw("diff", rep, rep, "--format", "json")
    result = json.loads(proc.stdout)
    assert proc.returncode == 0 and not result["new_alerts"] and not result["resolved"]
    assert len(result["ongoing"]) == 6 and "both runs analyzed the same file" in result["warnings"]
    assert "NO NEW ALERTS" in aw("diff", rep, rep).stdout


def test_diff_incomplete_exit_4(analyzed, tmp_path):
    _, day1, _ = analyzed
    broken = tmp_path / "b.json"
    aw("analyze", SAMPLES / "broken.jsonl", "--report", broken)
    proc = aw("diff", day1, broken)
    assert proc.returncode == 4 and "INCOMPLETE" in proc.stdout and "incomplete" in proc.stdout


def test_diff_warns_on_different_parameters_and_ephemeral_keys(analyzed, tmp_path):
    _, day1, report = analyzed
    other = tmp_path / "o.json"
    aw("analyze", SAMPLES / "attacks.jsonl", "--report", other, "--fail-threshold", "6",
       "--redact-usernames")
    result = diff_reports(report, load_report(other))
    assert any("not comparable" in w for w in result["warnings"])
    assert any("ephemeral" in w for w in result["warnings"])
    assert diff_exit_code(result) == 1


def test_diff_rejects_non_reports(analyzed, tmp_path):
    _, rep, _ = analyzed
    assert aw("diff", rep, SAMPLES / "clean.jsonl").returncode == 2
    assert aw("diff", tmp_path / "missing.json", rep).returncode == 2


# ----------------------------------------------------------------------------------- validate
def test_validate_clean_file():
    proc = aw("validate", SAMPLES / "attacks.jsonl")
    assert proc.returncode == 0 and "VALID" in proc.stdout and "all 39 records" in proc.stdout


def test_validate_lists_every_problem_line():
    proc = aw("validate", SAMPLES / "broken.jsonl", "--format", "json")
    assert proc.returncode == 4
    result = json.loads(proc.stdout)
    assert result["valid"] is False and result["errors_total"] == 6
    assert [(e["subject"], e["message"]) for e in result["errors"]] == [
        ("line:40", "duplicate_key"), ("line:41", "invalid_value"),
        ("line:42", "schema_invalid:source_ip"), ("line:43", "schema_invalid:source_ip"),
        ("line:44", "schema_invalid:source_ip,unknown_field"), ("line:45", "invalid_json")]
    text = aw("validate", SAMPLES / "broken.jsonl", "--max-errors", "2").stdout
    assert "the same key appears twice" in text and "4 more" in text and "INVALID" in text


def test_validate_reports_limits_and_warnings(tmp_path):
    recs = [record(timestamp=None), record(source_ip=None), record(outcome="unknown"),
            record(source_ip="::ffff:203.0.113.50"), record(record_id="r", outcome="success"),
            record(record_id="r")]
    proc = aw("validate", write(tmp_path, "v.jsonl", jsonl(recs)), "--format", "json")
    result = json.loads(proc.stdout)
    assert proc.returncode == 0 and result["valid"] is True   # format only: all records are valid
    assert result["limits"] == {"outcome is unknown": 1, "timestamp is null": 1,
                                "username is null or empty": 0, "source_ip is null": 1,
                                "record_id repeated with different content": 1}
    assert result["warnings"] == {"ip_canonicalized": 1}
    assert "coverage gaps" in aw("validate", write(tmp_path, "v2.jsonl", jsonl(recs))).stdout


def test_validate_empty_utf16_and_bad_options(tmp_path):
    assert aw("validate", write(tmp_path, "e.jsonl", b"")).returncode == 4
    u16 = write(tmp_path, "u.jsonl", jsonl([record()]).decode().encode("utf-16"))
    assert aw("validate", u16).returncode == 3
    assert aw("validate", SAMPLES / "clean.jsonl", "--max-errors", "0").returncode == 2
    assert aw("validate", tmp_path / "missing.jsonl").returncode == 2


# -------------------------------------------------------------------------------------- rules
def test_rules_listing():
    proc = aw("rules", "--format", "json")
    assert proc.returncode == 0
    rows = json.loads(proc.stdout)["rules"]
    assert [(r["rule_id"], r["threshold"], r["window_seconds"], r["attack"]) for r in rows] == [
        ("AW-001", 5, 300, ["T1110"]), ("AW-002", 5, 300, ["T1110.001"]),
        ("AW-003", 10, 600, ["T1110.003"]), ("AW-004", 5, 900, ["T1110", "T1078"])]
    text = aw("rules").stdout
    assert "--spray-threshold" in text and "T1110.003" in text and "HIGH" in text
