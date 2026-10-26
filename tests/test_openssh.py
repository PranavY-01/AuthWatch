"""OpenSSH adapter tests against AUTHORED samples (shapes from OpenSSH's documented message
formats). No real sshd log has been run through these patterns yet."""

import json
from datetime import timezone

import pytest

from authwatch.adapters.openssh import REGEXES, OpenSSHAdapter, classify
from authwatch.errors import ConfigError
from authwatch.models import EVENT, INVALID, IRRELEVANT, UNSUPPORTED
from authwatch.reader import Line
from authwatch.timeparse import parse_assumed_tz
from test_cli import aw
from conftest import write

PLUS530 = parse_assumed_tz("+05:30")


def adapt(text, year=2026, tz=timezone.utc, adapter=None):
    adapter = adapter or OpenSSHAdapter(year, tz)
    raw = text.encode("utf-8") if isinstance(text, str) else text
    return adapter.adapt(Line(1, raw))


H = "Oct 26 10:30:00 web1 sshd[1234]: "


def test_failed_and_accepted_lines():
    ev, cls, _ = adapt(H + "Failed password for alice from 203.0.113.50 port 51234 ssh2")
    assert cls == EVENT
    assert (ev.outcome, ev.username, ev.source_ip, ev.source_port, ev.failure_reason,
            ev.auth_method, ev.source_host, ev.timestamp, ev.parser_name, ev.source_os,
            ev.source_product) == ("failure", "alice", "203.0.113.50", 51234, "bad_credential",
                                   "password", "web1", "2026-10-26T10:30:00Z", "openssh-v1",
                                   "linux", "openssh")
    ev, cls, _ = adapt(H + "Accepted publickey for alice from 198.51.100.7 port 40100 ssh2: "
                           "ED25519 SHA256:AbCdEf0123456789+/xyz")
    assert cls == EVENT and ev.outcome == "success" and ev.auth_method == "publickey"
    ev, _, _ = adapt(H + "Failed keyboard-interactive/pam for bob from 192.0.2.1 port 22 ssh2")
    assert ev.auth_method == "keyboard-interactive" and ev.failure_reason == "bad_credential"
    ev, _, _ = adapt(H + "Failed publickey for bob from 192.0.2.1 port 22 ssh2: RSA SHA256:x")
    assert ev.failure_reason is None


def test_rfc3339_header_is_self_describing():
    line = ("2026-10-26T10:30:00+05:30 web1 sshd-session[99]: Failed password for alice from "
            "203.0.113.50 port 22 ssh2")
    ev, cls, _ = adapt(line, year=None, tz=None)
    assert cls == EVENT and ev.timestamp == "2026-10-26T10:30:00+05:30"
    assert adapt("2026-10-26T10:30:00 web1 sshd[1]: Failed password for a from 192.0.2.1 port 1 "
                 "ssh2", year=None, tz=None)[1:] == (INVALID, "invalid_timestamp")


def test_syslog_requires_assumptions():
    """Case 66: classic syslog timestamps without --assume-year / --assume-tz -> ConfigError."""
    for year, tz in ((None, timezone.utc), (2026, None), (None, None)):
        with pytest.raises(ConfigError):
            adapt(H + "Failed password for a from 192.0.2.1 port 1 ssh2", year=year, tz=tz)
    with pytest.raises(ConfigError):  # also for lines that would be irrelevant
        adapt("Oct 26 10:30:00 web1 cron[1]: job", year=None, tz=None)


def test_syslog_assumed_offset_applied():
    ev, _, _ = adapt(H + "Failed password for a from 192.0.2.1 port 1 ssh2", tz=PLUS530)
    assert ev.timestamp == "2026-10-26T05:00:00Z"


def test_year_rollover_and_feb_29():
    """Case 67: December -> January increments the assumed year; 29 February in a non-leap
    assumed year is an invalid record."""
    a = OpenSSHAdapter(2026, timezone.utc)
    msg = " web1 sshd[1]: Failed password for a from 192.0.2.1 port 1 ssh2"
    assert adapt("Dec 31 23:59:59" + msg, adapter=a)[0].timestamp == "2026-12-31T23:59:59Z"
    assert adapt("Jan  1 00:00:01" + msg, adapter=a)[0].timestamp == "2027-01-01T00:00:01Z"
    assert adapt("Mar  1 00:00:00" + msg, adapter=a)[0].timestamp == "2027-03-01T00:00:00Z"
    assert adapt("Feb 29 10:00:00" + msg)[1:] == (INVALID, "invalid_timestamp")
    assert adapt("Feb 29 10:00:00" + msg, year=2028)[1] == EVENT
    assert adapt("Foo 29 10:00:00" + msg)[1:] == (INVALID, "invalid_timestamp")


def test_username_cannot_spoof_source():
    """Case 68: a username containing ` from 8.8.8.8 port 1 ssh2` cannot change the source; the
    genuine tail written last by sshd wins."""
    ev, cls, _ = adapt(H + "Failed password for invalid user x from 8.8.8.8 port 1 ssh2 from "
                           "203.0.113.5 port 2222 ssh2")
    assert cls == EVENT
    assert ev.source_ip == "203.0.113.5" and ev.source_port == 2222
    assert ev.username == "x from 8.8.8.8 port 1 ssh2" and ev.failure_reason == "unknown_account"


def test_invalid_user_counted_once():
    """Case 69: `Invalid user x` plus `Failed password for invalid user x` -> one event; the
    first line (and pam_unix duplicates) are irrelevant."""
    lines = [H + "Invalid user x from 203.0.113.5 port 2222",
             H + "pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=203.0.113.5",
             H + "Failed password for invalid user x from 203.0.113.5 port 2222 ssh2"]
    assert [adapt(ln)[1] for ln in lines] == [IRRELEVANT, IRRELEVANT, EVENT]


def test_repeat_summary_unsupported():
    """Case 70: `message repeated N times` lines are unsupported (they under-count)."""
    for msg in ["message repeated 5 times: [ Failed password for root from 192.0.2.1 port 22 ssh2]",
                "last message repeated 3 times", "message repeated 1 time"]:
        assert adapt(H + msg)[1:] == (UNSUPPORTED, "repeat_summary")


def test_unknown_messages_and_shapes_unsupported():
    """Case 71: an unknown sshd message or a non-syslog line is unsupported."""
    assert adapt(H + "Accepted certificate ID \"x\" (serial 1) signed by CA")[1:] == \
        (UNSUPPORTED, "unsupported_sshd_message")
    assert adapt(H + "Failed password for alice from 203.0.113.50 port 22")[1:] == \
        (UNSUPPORTED, "unsupported_sshd_message")   # no ssh2 tail
    for line in ["random text", "", "Oct 26 web1 sshd: x", "{\"json\": true}"]:
        assert adapt(line or " ")[1:] == (UNSUPPORTED, "unsupported_line_shape")


def test_other_processes_irrelevant():
    """Case 72: lines from processes other than sshd* are irrelevant."""
    assert adapt("Oct 26 10:30:00 web1 CRON[77]: (root) CMD (run-parts)")[1] == IRRELEVANT
    assert adapt("Oct 26 10:30:00 web1 su: Failed password for root from 192.0.2.1 port 1 "
                 "ssh2")[1] == IRRELEVANT
    for msg in ["Connection closed by authenticating user a 192.0.2.1 port 22 [preauth]",
                "Disconnected from user a 192.0.2.1 port 22", "Received disconnect from 192.0.2.1",
                "Server listening on 0.0.0.0 port 22.", "pam_unix(sshd:session): session opened"]:
        assert adapt(H + msg)[1] == IRRELEVANT, msg


def test_attacker_fields_sanitized_not_rejected():
    """Case 73: an over-long username, invalid UTF-8 in the username, a port over 65535 and an
    unparseable IP are sanitized with a warning; the event is kept."""
    ev, cls, _ = adapt(H + "Failed password for " + "u" * 300 + " from 192.0.2.1 port 22 ssh2")
    assert cls == EVENT and len(ev.username) == 256 and "username_truncated" in ev.parse_warnings
    raw = (H + "Failed password for ").encode() + b"bad\xff\xfeuser" + \
        b" from 192.0.2.1 port 22 ssh2"
    ev, cls, _ = adapt(raw)
    assert cls == EVENT and "�" in ev.username and "invalid_utf8_replaced" in ev.parse_warnings
    ev, cls, _ = adapt(H + "Failed password for a from 192.0.2.1 port 70000 ssh2")
    assert cls == EVENT and ev.source_port is None and "source_port_out_of_range" in ev.parse_warnings
    ev, cls, _ = adapt(H + "Failed password for a from 192.0.2.999 port 22 ssh2")
    assert cls == EVENT and ev.source_ip is None and "source_ip_unparseable" in ev.parse_warnings
    ev, cls, _ = adapt(H + "Failed password for a from 192.0.2.1 port abc ssh2")
    assert cls == EVENT and ev.source_port is None
    ev, cls, _ = adapt(H + "Failed password for invalid user  from 192.0.2.1 port 22 ssh2")
    assert cls == EVENT and ev.username == "" and ev.failure_reason == "unknown_account"
    ev, cls, _ = adapt(H + "Failed password for [red]\x1b[2J from 192.0.2.1 port 22 ssh2")
    assert cls == EVENT


def test_classify_and_regex_table():
    assert classify("Failed none for x from 192.0.2.1 port 1 ssh2") == "failed"
    assert classify("Accepted password for x from 192.0.2.1 port 1 ssh2") == "accepted"
    assert set(REGEXES) == {"syslog", "rfc3339", "failed", "accepted", "repeat"}


AUTHORED_LOG = "\n".join([
    "Oct 26 10:29:58 web1 sshd[1200]: Server listening on 0.0.0.0 port 22.",
    *[f"Oct 26 10:30:{i:02d} web1 sshd[13{i:02d}]: Failed password for alice from 203.0.113.50 "
      f"port {50000 + i} ssh2" for i in range(0, 50, 10)],
    "Oct 26 10:31:00 web1 sshd[1400]: Accepted password for alice from 198.51.100.7 port 40100 ssh2",
    "Oct 26 10:31:01 web1 systemd[1]: Started session.",
]) + "\n"


def test_openssh_end_to_end(tmp_path):
    p = write(tmp_path, "auth.log", AUTHORED_LOG.encode())
    out = tmp_path / "r.json"
    proc = aw("analyze", p, "--input-format", "openssh", "--assume-year", "2026",
              "--assume-tz", "Z", "--report", out)
    assert proc.returncode == 1, proc.stderr
    rep = json.loads(out.read_text(encoding="utf-8"))
    assert rep["coverage"]["complete"] and rep["coverage"]["counters"]["records_irrelevant"] == 2
    assert {f["event"] for f in rep["findings"]} == {"AW-001", "AW-002", "AW-004"}
    assert rep["parameters"]["assume_year"] == 2026 and rep["parameters"]["assume_tz"] == "Z"
    assert rep["input"]["format"] == "openssh"


def test_openssh_missing_assumptions_exit_2(tmp_path):
    """Case 66: syslog input without --assume-year / --assume-tz exits 2 with no report."""
    p = write(tmp_path, "auth.log", AUTHORED_LOG.encode())
    out = tmp_path / "r.json"
    proc = aw("analyze", p, "--input-format", "openssh", "--report", out)
    assert proc.returncode == 2 and not out.exists() and "--assume-year" in proc.stderr
    assert aw("analyze", p, "--input-format", "openssh", "--assume-year", "2026",
              "--assume-tz", "Europe/London").returncode == 2
    assert aw("analyze", p, "--input-format", "openssh", "--assume-year", "1969",
              "--assume-tz", "Z").returncode == 2


def test_openssh_repeat_summary_incomplete(tmp_path):
    log = AUTHORED_LOG + "Oct 26 10:32:00 web1 sshd[1500]: message repeated 4 times: [ Failed " \
                         "password for alice from 203.0.113.50 port 22 ssh2]\n"
    p = write(tmp_path, "auth.log", log.encode())
    proc = aw("analyze", p, "--input-format", "openssh", "--assume-year", "2026",
              "--assume-tz", "Z")
    assert proc.returncode == 4
    assert "unsupported_records" in proc.stdout and "disable repeat reduction" in proc.stdout


def test_openssh_no_sshd_lines_is_no_events(tmp_path):
    p = write(tmp_path, "auth.log", b"Oct 26 10:30:00 web1 cron[1]: x\n")
    proc = aw("analyze", p, "--input-format", "openssh", "--assume-year", "2026",
              "--assume-tz", "Z", "--format", "json")
    assert proc.returncode == 4 and json.loads(proc.stdout)["coverage"]["reasons"] == ["no_events"]


def test_normalize_round_trip(tmp_path):
    """D10: normalize output is accepted unchanged by analyze and gives the same alerts."""
    p = write(tmp_path, "auth.log", AUTHORED_LOG.encode())
    norm = tmp_path / "events.jsonl"
    proc = aw("normalize", p, "--output", norm, "--input-format", "openssh",
              "--assume-year", "2026", "--assume-tz", "Z")
    assert proc.returncode == 0, proc.stderr
    lines = norm.read_bytes().splitlines()
    assert len(lines) == 6 and all(json.loads(ln)["parser_name"] == "openssh-v1" for ln in lines)
    assert list(json.loads(lines[0])) == sorted(json.loads(lines[0]))
    direct = json.loads(aw("analyze", p, "--input-format", "openssh", "--assume-year", "2026",
                           "--assume-tz", "Z", "--format", "json").stdout)
    via = json.loads(aw("analyze", norm, "--format", "json").stdout)
    strip = lambda rep: [(f["details"]["alert_id"], f["details"]["count"]) for f in rep["findings"]]
    assert strip(direct) == strip(via) and via["coverage"]["complete"]


def test_normalize_jsonl_identity(tmp_path):
    from conftest import SAMPLES
    norm = tmp_path / "n.jsonl"
    assert aw("normalize", SAMPLES / "attacks.jsonl", "--output", norm).returncode == 0
    assert norm.read_bytes() == (SAMPLES / "attacks.jsonl").read_bytes()


def test_normalize_incomplete_still_writes(tmp_path):
    from conftest import SAMPLES
    norm = tmp_path / "n.jsonl"
    proc = aw("normalize", SAMPLES / "broken.jsonl", "--output", norm)
    assert proc.returncode == 4 and "6 invalid" in proc.stderr
    assert len(norm.read_bytes().splitlines()) == 39
    empty = write(tmp_path, "e.jsonl", b"")
    assert aw("normalize", empty, "--output", tmp_path / "e.out").returncode == 4
    assert aw("normalize", SAMPLES / "attacks.jsonl", "--output", norm).returncode == 2  # exists


def test_normalize_redacts(tmp_path):
    from conftest import SAMPLES
    norm = tmp_path / "n.jsonl"
    proc = aw("normalize", SAMPLES / "attacks.jsonl", "--output", norm, "--redact-usernames")
    assert proc.returncode == 0
    text = norm.read_text(encoding="utf-8")
    assert "alice" not in text and '"username":"u:' in text
