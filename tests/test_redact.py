import json
import re

import pytest

from authwatch.errors import ConfigError
from authwatch.keys import username_key
from authwatch.redact import NoRedaction, Redactor, from_environment
from authwatch.rules import Params, run_rules
from conftest import SAMPLES, record, ts
from test_cli import ENV, aw
from test_rules import events_from

KEY = b"k" * 32


def test_variants_share_a_token():
    """Case 61: Alice and fullwidth ａｌｉｃｅ give the same token; tokens are stable for a key."""
    r = Redactor(KEY)
    a = r.display(username_key("Alice")[0])
    b = r.display(username_key("ａｌｉｃｅ")[0])
    assert a == b == Redactor(KEY).display("alice")
    assert re.fullmatch(r"u:[0-9a-f]{12}", a)
    assert a != Redactor(b"j" * 32).display("alice")
    assert r.display(None) == "<none>"


def test_short_key_rejected():
    """Case 62: a redaction key shorter than 32 bytes is a ConfigError (exit 2)."""
    with pytest.raises(ConfigError):
        Redactor(b"short")
    with pytest.raises(ConfigError):
        from_environment({"AUTHWATCH_REDACT_KEY": "x" * 31})
    assert from_environment({"AUTHWATCH_REDACT_KEY": "x" * 32}).key_source == "env"
    assert from_environment({}).key_source == "ephemeral"


def test_alert_ids_built_from_tokens():
    """Case 61: alert ids hash the displayed (redacted) subject, stable for a given key."""
    recs = [record(timestamp=ts(i)) for i in range(5)]
    plain = run_rules(events_from(recs), Params(), ["AW-002"], NoRedaction())[0].alerts[0]
    red1 = run_rules(events_from(recs), Params(), ["AW-002"], Redactor(KEY))[0].alerts[0]
    red2 = run_rules(events_from(recs), Params(), ["AW-002"], Redactor(KEY))[0].alerts[0]
    assert red1.finding["details"]["alert_id"] == red2.finding["details"]["alert_id"]
    assert red1.finding["details"]["alert_id"] != plain.finding["details"]["alert_id"]
    assert red1.subject == "user:" + Redactor(KEY).token("alice")


USERNAMES = ["alice", "admin", "bob", "carol", "dave"] + [f"user{i:02d}" for i in range(12)]


def test_no_username_in_any_output(tmp_path):
    """Integration 10: with --redact-usernames no username appears in stdout or the report."""
    out = tmp_path / "r.json"
    env = dict(ENV, AUTHWATCH_REDACT_KEY="k" * 32)
    for fmt in ("text", "json"):
        proc = aw("analyze", SAMPLES / "attacks.jsonl", "--redact-usernames", "--report", out,
                  "--format", fmt, env=env)
        assert proc.returncode == 1
        blob = (proc.stdout + proc.stderr + out.read_text(encoding="utf-8")).lower()
        for name in USERNAMES:
            assert name not in blob, name
    rep = json.loads(out.read_text(encoding="utf-8"))
    assert rep["parameters"]["redaction"] == {"enabled": True, "algorithm": "hmac-sha256/12",
                                              "key_source": "env"}
    assert len(rep["findings"]) == 6


def test_short_env_key_exit_2(tmp_path):
    proc = aw("analyze", SAMPLES / "attacks.jsonl", "--redact-usernames",
              env=dict(ENV, AUTHWATCH_REDACT_KEY="short"))
    assert proc.returncode == 2 and proc.stdout == ""


def test_env_key_ignored_without_flag(tmp_path):
    proc = aw("analyze", SAMPLES / "attacks.jsonl", "--format", "json",
              env=dict(ENV, AUTHWATCH_REDACT_KEY="short"))
    assert proc.returncode == 1 and json.loads(proc.stdout)["parameters"]["redaction"] is None


def test_ephemeral_key_source(tmp_path):
    proc = aw("analyze", SAMPLES / "attacks.jsonl", "--redact-usernames", "--format", "json")
    assert json.loads(proc.stdout)["parameters"]["redaction"]["key_source"] == "ephemeral"


def test_rules_selection_recorded(tmp_path):
    proc = aw("analyze", SAMPLES / "attacks.jsonl", "--rules", "AW-004, AW-001", "--format", "json")
    rep = json.loads(proc.stdout)
    assert rep["parameters"]["rules"] == ["AW-001", "AW-004"]
    assert set(rep["summary"]) == {"AW-001", "AW-004", "errors"}
    assert set(rep["coverage"]["rules"]) == {"AW-001", "AW-004"}
    assert {f["event"] for f in rep["findings"]} == {"AW-001", "AW-004"}
    assert aw("analyze", SAMPLES / "attacks.jsonl", "--rules", "AW-009").returncode == 2
