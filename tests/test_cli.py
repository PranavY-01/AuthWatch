"""Integration tests: real subprocesses, real exit codes and streams."""

import hashlib
import json
import os
import re
import subprocess
import sys

import pytest

from authwatch import cli, rules
from authwatch.rules import RULES
from conftest import SAMPLES, jsonl, not_root, record, ts, write

ENV = {k: v for k, v in os.environ.items() if not k.startswith(("AUTHWATCH_", "PYTHONUTF8"))}


def aw(*args, cwd=None, env=None):
    return subprocess.run([sys.executable, "-m", "authwatch", *map(str, args)],
                          capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=cwd, env=env or ENV)


def report_of(tmp_path, *args):
    out = tmp_path / "r.json"
    proc = aw("analyze", *args, "--report", out)
    return proc, json.loads(out.read_text(encoding="utf-8"))


# Expected alerts (rule, subject, first/last seen, count, peak) for attacks.jsonl with default parameters.
EXPECTED = [
    ("AW-004", "user:alice", "2026-10-26T10:30:00Z", "2026-10-26T10:33:00Z", 9, 9),
    ("AW-001", "ip:203.0.113.50", "2026-10-26T10:30:00Z", "2026-10-26T10:32:00Z", 9, 9),
    ("AW-002", "user:alice", "2026-10-26T10:30:00Z", "2026-10-26T10:32:00Z", 9, 9),
    ("AW-001", "ip:192.0.2.99", "2026-10-26T10:40:00Z", "2026-10-26T10:41:50Z", 12, 12),
    ("AW-003", "ip:192.0.2.99", "2026-10-26T10:40:00Z", "2026-10-26T10:41:50Z", 12, 12),
    ("AW-002", "user:admin", "2026-10-26T10:50:00Z", "2026-10-26T10:52:30Z", 6, 6),
]


def expected_for_implemented_rules():
    return [row for row in EXPECTED if row[0] in RULES]


def summarize(report):
    return [(f["event"], f["subject"], f["details"]["first_seen"], f["details"]["last_seen"],
             f["details"]["count"], f["details"]["peak_in_window"]) for f in report["findings"]]


def test_version_and_help():
    proc = aw("--version")
    assert proc.returncode == 0 and proc.stdout == "authwatch 1.1.0\n"
    assert aw("--help").returncode == 0
    assert aw("analyze", "--help").returncode == 0
    assert aw("analyze", "x", "--no-such-option").returncode == 2


def test_bare_command_shows_welcome_screen():
    proc = aw()
    assert proc.returncode == 0 and proc.stderr == ""
    for word in ("A U T H W A T C H", "Commands", "explain", "diff", "validate", "rules",
                 "Exit codes"):
        assert word in proc.stdout
    assert aw("--version").stdout == "authwatch 1.1.0\n"


def test_version_matches_metadata():
    import importlib.metadata

    import authwatch
    assert authwatch.__version__ == importlib.metadata.version("authwatch") == "1.1.0"


def test_clean_sample_exit_0(tmp_path):
    """Case 65: a complete run with zero alerts exits 0, status clean."""
    proc, rep = report_of(tmp_path, SAMPLES / "clean.jsonl")
    assert proc.returncode == 0, proc.stderr
    assert rep["status"] == "clean" and rep["result"] == "clean" and rep["coverage"]["complete"]
    assert "CLEAN" in proc.stdout and "NOT a clean result" not in proc.stdout


def test_attacks_sample_alerts(tmp_path):
    """attacks.jsonl -> alerts_detected, exit 1, the expected alerts, no dave."""
    proc, rep = report_of(tmp_path, SAMPLES / "attacks.jsonl")
    assert proc.returncode == 1, proc.stderr
    assert rep["status"] == "alerts_detected" and rep["coverage"]["complete"]
    assert summarize(rep) == expected_for_implemented_rules()
    assert not any("dave" in json.dumps(f) or "198.51.100.200" in f["subject"]
                   for f in rep["findings"])
    data = (SAMPLES / "attacks.jsonl").read_bytes()
    assert rep["input"] == {"label": "attacks.jsonl", "format": "jsonl",
                            "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
    lines = data.split(b"\n")
    for f in rep["findings"]:
        for n in f["details"]["evidence"]["lines"]:
            rec = json.loads(lines[n - 1])
            assert rec["outcome"] == "failure"
    c = rep["coverage"]["counters"]
    assert c["lines_total"] == c["records_read"] == c["events_analyzed"] == 39
    tl = rep["coverage"]["timeline"]
    assert (tl["earliest"], tl["latest"], tl["largest_gap_seconds"]) == \
        ("2026-10-26T10:01:40Z", "2026-10-26T11:15:00Z", 1050)
    assert (tl["gap_start"], tl["gap_end"]) == ("2026-10-26T10:52:30Z", "2026-10-26T11:10:00Z")


BROKEN_ERRORS = [
    (40, "duplicate_key"), (41, "invalid_value"), (42, "schema_invalid:source_ip"),
    (43, "schema_invalid:source_ip"), (44, "schema_invalid:source_ip,unknown_field"),
    (45, "invalid_json"),
]


def test_broken_sample_incomplete_with_alerts(tmp_path):
    """Case 54: alerts found and invalid lines present -> exit 4, alerts kept in the report."""
    proc, rep = report_of(tmp_path, SAMPLES / "broken.jsonl")
    assert proc.returncode == 4, proc.stderr
    assert rep["status"] == "incomplete" and rep["result"] == "alerts_detected"
    assert rep["coverage"]["reasons"] == ["invalid_records"]
    assert summarize(rep) == expected_for_implemented_rules()
    assert [(int(e["subject"].split(":")[1]), e["message"]) for e in rep["errors"]] == BROKEN_ERRORS
    assert all(e["kind"] == "INVALID_RECORD" for e in rep["errors"])
    assert "INCOMPLETE" in proc.stdout and "Coverage gaps" in proc.stdout
    assert re.search(r"\b44\s+schema_invalid:source_ip,unknown_field\b", proc.stdout)
    c = rep["coverage"]["counters"]
    assert c["records_read"] == c["events_normalized"] + c["records_invalid"] \
        + c["records_unsupported"] + c["records_irrelevant"]


@pytest.mark.parametrize("data", [b"", b"\n   \n\r\n"], ids=["empty", "blank-only"])
def test_empty_input_is_incomplete(tmp_path, data):
    """Case 1: an empty file, or only blank lines -> no_events, incomplete, exit 4."""
    p = write(tmp_path, "empty.jsonl", data)
    proc, rep = report_of(tmp_path, p)
    assert proc.returncode == 4
    assert rep["status"] == "incomplete" and rep["result"] == "clean"
    assert rep["coverage"]["reasons"] == ["no_events"]
    assert "this is NOT a clean result" in proc.stdout


def test_utf16_input_exit_3(tmp_path):
    """Case 6 / Case 75: UTF-16 input (PowerShell 5.1 Out-File) -> exit 3 with a re-save hint,
    no report written."""
    text = jsonl([record()]).decode()
    for i, data in enumerate([text.encode("utf-16"), text.encode("utf-16-le")]):
        p = write(tmp_path, f"u{i}.jsonl", data)
        out = tmp_path / f"r{i}.json"
        proc = aw("analyze", p, "--report", out)
        assert proc.returncode == 3
        assert "re-save it as UTF-8" in proc.stderr
        assert not out.exists() and proc.stdout == ""


def test_missing_or_directory_input_exit_2(tmp_path):
    """Case 16: input path missing or a directory -> exit 2."""
    assert aw("analyze", tmp_path / "missing.jsonl").returncode == 2
    assert aw("analyze", tmp_path).returncode == 2


@not_root
@pytest.mark.skipif(sys.platform.startswith("win"), reason="chmod 000 does not block reads on Windows")
def test_unreadable_input_real_permissions(tmp_path):
    """Case 17: an input the OS refuses to open -> exit 4 (real permissions)."""
    p = write(tmp_path, "x.jsonl", jsonl([record()]))
    p.chmod(0)
    try:
        assert aw("analyze", p).returncode == 4
    finally:
        p.chmod(0o600)


def run_main(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["authwatch", *map(str, args)])
    with pytest.raises(SystemExit) as info:
        cli.main()
    return info.value.code


def test_unreadable_input_injected(tmp_path, monkeypatch, capsys):
    """Case 17: an input the OS refuses to open -> exit 4 (injected PermissionError)."""
    p = write(tmp_path, "x.jsonl", jsonl([record()]))
    real_open = open

    def guarded_open(file, mode="r", *a, **k):
        if str(file) == str(p) and "b" in mode:
            raise PermissionError("denied")
        return real_open(file, mode, *a, **k)

    monkeypatch.setattr("builtins.open", guarded_open)
    assert run_main(monkeypatch, "analyze", p) == 4
    assert "cannot open input" in capsys.readouterr().err


def test_ctrl_c_exit_130_no_report(tmp_path, monkeypatch, capsys):
    """Case 63: Ctrl+C -> exit 130 and no report file."""
    def interrupt(*_a, **_k):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run_rules", interrupt)
    out = tmp_path / "r.json"
    assert run_main(monkeypatch, "analyze", SAMPLES / "attacks.jsonl", "--report", out) == 130
    assert not out.exists()
    assert "Interrupted." in capsys.readouterr().err


def test_injected_crash_exit_4_never_1(tmp_path, monkeypatch, capsys):
    """Case 64: an unexpected internal exception exits 4, never 1, and writes no report."""
    def crash(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(rules, "build_alert", crash)
    out = tmp_path / "r.json"
    code = run_main(monkeypatch, "analyze", SAMPLES / "attacks.jsonl", "--report", out,
                    "--format", "json")
    captured = capsys.readouterr()
    assert code == 4 and not out.exists()
    assert captured.out == "" and "internal error" in captured.err


def test_json_format_stdout_is_only_the_report(tmp_path):
    """--format json prints the report and nothing else; it parses with json.tool."""
    proc = aw("analyze", SAMPLES / "attacks.jsonl", "--format", "json")
    assert proc.returncode == 1
    rep = json.loads(proc.stdout)
    assert rep["envelope"]["schema"] == "7d7b-report" and rep["envelope"]["tool"] == "AuthWatch"
    tool = subprocess.run([sys.executable, "-m", "json.tool"], input=proc.stdout,
                          capture_output=True, text=True, timeout=60)
    assert tool.returncode == 0


def test_report_written_and_matches_stdout(tmp_path):
    out = tmp_path / "r.json"
    proc = aw("analyze", SAMPLES / "attacks.jsonl", "--format", "json", "--report", out)
    assert out.read_bytes().decode("ascii") == proc.stdout
    assert b"\r\n" not in out.read_bytes()


def test_output_collisions_exit_2_and_input_untouched(tmp_path):
    """Integration 7: report path equal to the input, a hard link to it, or a foreign file
    -> exit 2 and the original byte-identical."""
    p = write(tmp_path, "in.jsonl", (SAMPLES / "attacks.jsonl").read_bytes())
    original = p.read_bytes()
    link = tmp_path / "link.jsonl"
    os.link(p, link)
    foreign = write(tmp_path, "foreign.txt", b"keep me")
    for target in (p, link):
        assert aw("analyze", p, "--report", target, "--force-report").returncode == 2
    assert aw("analyze", p, "--report", foreign).returncode == 2
    assert p.read_bytes() == original and foreign.read_bytes() == b"keep me"
    assert aw("analyze", p, "--report", foreign, "--force-report").returncode == 1
    assert json.loads(foreign.read_text(encoding="utf-8"))["envelope"]["tool"] == "AuthWatch"


def test_existing_report_overwritten_without_force(tmp_path):
    out = tmp_path / "r.json"
    assert aw("analyze", SAMPLES / "clean.jsonl", "--report", out).returncode == 0
    assert aw("analyze", SAMPLES / "attacks.jsonl", "--report", out).returncode == 1
    assert json.loads(out.read_text(encoding="utf-8"))["status"] == "alerts_detected"


@pytest.mark.parametrize("args", [["--fail-threshold", "1"], ["--fail-window", "0s"],
                                  ["--fail-window", "5x"], ["--lookback", "60s"],
                                  ["--spray-threshold", "100001"], ["--fail-threshold", "abc"],
                                  ["--format", "xml"]])
def test_bad_configuration_exit_2(args, tmp_path):
    """Integration 8: out-of-range thresholds and bad durations exit 2 with no report."""
    out = tmp_path / "r.json"
    proc = aw("analyze", SAMPLES / "attacks.jsonl", "--report", out, *args)
    assert proc.returncode == 2 and not out.exists() and proc.stdout == ""


def test_determinism(tmp_path):
    """Integration 9: two runs give byte-identical reports apart from run_id and times."""
    blobs = []
    for i in range(2):
        out = tmp_path / f"r{i}.json"
        aw("analyze", SAMPLES / "broken.jsonl", "--report", out)
        text = out.read_text(encoding="utf-8")
        text = re.sub(r'"(run_id|started_at|completed_at)": "[^"]*"', r'"\1": "X"', text)
        blobs.append(text)
    assert blobs[0] == blobs[1]


def test_events_without_ip_incomplete(tmp_path):
    """Matrix: events with no usable IP while AW-001 is enabled -> incomplete, exit 4."""
    recs = [record(timestamp=ts(i), source_ip=None, username=f"u{i}") for i in range(3)]
    p = write(tmp_path, "noip.jsonl", jsonl(recs))
    proc, rep = report_of(tmp_path, p)
    assert proc.returncode == 4 and rep["status"] == "incomplete"
    assert "uncorrelatable:AW-001" in rep["coverage"]["reasons"]
    assert rep["coverage"]["rules"]["AW-001"]["by_reason"] == {"missing_source_ip": 3}


def test_benign_plus_invalid_line(tmp_path):
    """Matrix: a benign file plus one invalid line -> incomplete / clean, exit 4."""
    p = write(tmp_path, "b.jsonl", (SAMPLES / "clean.jsonl").read_bytes() + b"{oops\n")
    proc, rep = report_of(tmp_path, p)
    assert proc.returncode == 4 and (rep["status"], rep["result"]) == ("incomplete", "clean")


def test_terminal_output_escapes_usernames(tmp_path):
    recs = [record(timestamp=ts(i), username="[red]x\x1b[2J:smile:") for i in range(5)]
    proc = aw("analyze", write(tmp_path, "e.jsonl", jsonl(recs)))
    assert proc.returncode == 1
    assert "\x1b" not in proc.stdout
    assert "user:[red]x\\x1b[2j:smile:" in proc.stdout  # subject is the casefolded key


def test_samples_regenerate_byte_identical(tmp_path):
    """make_samples.py is deterministic: regenerating gives the committed bytes."""
    proc = subprocess.run([sys.executable, str(SAMPLES / "make_samples.py"), str(tmp_path)],
                          capture_output=True, timeout=60)
    assert proc.returncode == 0
    for name in ("clean.jsonl", "attacks.jsonl", "broken.jsonl"):
        assert (tmp_path / name).read_bytes() == (SAMPLES / name).read_bytes(), name
    assert len((SAMPLES / "clean.jsonl").read_bytes().splitlines()) == 6
    assert len((SAMPLES / "attacks.jsonl").read_bytes().splitlines()) == 39
    broken = (SAMPLES / "broken.jsonl").read_bytes()
    assert broken.startswith((SAMPLES / "attacks.jsonl").read_bytes())
    assert len(broken.splitlines()) == 45


def _alert_identity(rep):
    return sorted((f["details"]["alert_id"], f["subject"], f["details"]["first_seen"],
                   f["details"]["last_seen"], f["details"]["count"],
                   f["details"]["peak_in_window"]) for f in rep["findings"])


def test_shuffle_invariance(tmp_path):
    """Case 36: shuffling the records changes no alert (ids included); disorder is counted."""
    import random
    lines = (SAMPLES / "attacks.jsonl").read_bytes().splitlines(keepends=True)
    _, base = report_of(tmp_path, SAMPLES / "attacks.jsonl")
    for seed in range(3):
        shuffled = lines[:]
        random.Random(seed).shuffle(shuffled)
        p = write(tmp_path, f"s{seed}.jsonl", b"".join(shuffled))
        proc, rep = report_of(tmp_path, p)
        assert proc.returncode == 1
        assert _alert_identity(rep) == _alert_identity(base)
        assert rep["coverage"]["timeline"]["out_of_order_records"] > 0


def test_key_spelling_invariance(tmp_path):
    """Case 31: case, fullwidth and zero-width variants of a username change no alert."""
    lines = (SAMPLES / "attacks.jsonl").read_bytes().splitlines(keepends=True)
    variants = ["ALICE", "\uff41\uff4c\uff49\uff43\uff45", "alice\u200b", "Alice"]
    for i, variant in zip((1, 3, 5, 7), variants):
        lines[i] = lines[i].replace(b'"username":"alice"',
                                    b'"username":' + json.dumps(variant).encode())
    p = write(tmp_path, "v.jsonl", b"".join(lines))
    _, base = report_of(tmp_path, SAMPLES / "attacks.jsonl")
    proc, rep = report_of(tmp_path, p)
    assert proc.returncode == 1
    assert rep["findings"] == base["findings"]
    assert rep["coverage"]["counters"]["events_with_warnings"] == 1


def test_alert_cap_degrades_coverage(tmp_path, monkeypatch, capsys):
    """Case 43: when a rule hits the alert cap, the run is incomplete (exit 4) and the
    suppressed episodes are counted."""
    import functools
    monkeypatch.setattr(cli, "run_rules", functools.partial(rules.run_rules, cap=1))
    out = tmp_path / "r.json"
    assert run_main(monkeypatch, "analyze", SAMPLES / "attacks.jsonl", "--report", out) == 4
    rep = json.loads(out.read_text(encoding="utf-8"))
    assert "alert_cap_reached:AW-001" in rep["coverage"]["reasons"]
    assert rep["coverage"]["rules"]["AW-001"]["alerts_suppressed"] == 1
    assert rep["summary"]["AW-001"] == 1
    assert "alert cap reached" in capsys.readouterr().out
