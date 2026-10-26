import json

import pytest
from pydantic import ValidationError

from authwatch.adapters.jsonl import JsonlAdapter
from authwatch.events import Interner, build_event
from authwatch.models import EVENT, AuthEvent, reason_for
from authwatch.reader import Line
from conftest import record

ADAPTER = JsonlAdapter()


def reason(rec) -> str | None:
    raw = rec if isinstance(rec, bytes) else json.dumps(rec).encode()
    _, cls, why = ADAPTER.adapt(Line(1, raw))
    return None if cls == EVENT else why


def test_valid_minimal_and_full_records():
    assert reason(record()) is None
    full = record(source_port=22, event_id="4625", record_id="r1", source_host="h",
                  failure_reason="bad_credential", auth_method="password", logon_type=3,
                  parser_name="jsonl-v1", parse_warnings=["w"])
    assert reason(full) is None


def test_mistyped_field_name():
    """Case 19: `sourceip` instead of `source_ip` -> schema_invalid:source_ip,unknown_field."""
    rec = record(source_ip=...)
    rec["sourceip"] = "203.0.113.50"
    assert reason(rec) == "schema_invalid:source_ip,unknown_field"


def test_unknown_field_name_never_echoed():
    rec = record()
    rec["\x1b[31mEVIL"] = 1
    assert reason(rec) == "schema_invalid:unknown_field"


@pytest.mark.parametrize("field", ["timestamp", "username", "source_ip", "outcome",
                                   "schema_version", "event_type", "source_os", "source_product"])
def test_required_keys(field):
    """Case 20: a missing required (or required-nullable) key -> schema_invalid."""
    assert reason(record(**{field: ...})) == f"schema_invalid:{field}"


@pytest.mark.parametrize("field,value", [("outcome", "FAILURE"), ("outcome", "denied"),
                                         ("schema_version", "1.1"), ("schema_version", 1.0),
                                         ("event_type", "logon"), ("failure_reason", "bad")])
def test_bad_enum_values(field, value):
    """Case 21: enum values are case-sensitive and closed; schema_version must be "1.0"."""
    rec = record(**{field: value})
    assert reason(rec) == f"schema_invalid:{field}"


@pytest.mark.parametrize("value", [True, 22.0, 70000, -1, "22"])
def test_port_strictness(value):
    """Case 22: true, 22.0 and 70000 as port are rejected."""
    assert reason(record(source_port=value)) == "schema_invalid:source_port"


def test_integer_ip_rejected():
    """Case 23: the integer 3232235801 as source_ip is rejected."""
    assert reason(record(source_ip=3232235801)) == "schema_invalid:source_ip"


def test_scoped_ip_forms_in_schema():
    """Case 24: IPv4 with a zone is invalid; IPv6 with a zone is valid and warned at build time."""
    assert reason(record(source_ip="1.2.3.4%eth0")) == "schema_invalid:source_ip"
    ae = AuthEvent.model_validate(record(source_ip="fe80::1%eth0"))
    e = build_event(ae, 1, 0, Interner())
    assert e.ip == "fe80::1" and "ip_scope_id_ignored" in e.warnings


def test_lone_surrogate_and_nul():
    """Case 25: lone surrogates and NUL characters in strings are rejected at validation."""
    assert reason(b'{"schema_version":"1.0","event_type":"authentication",'
                  b'"timestamp":"2026-10-26T10:00:00Z","outcome":"failure",'
                  b'"username":"a\\ud800","source_ip":null,"source_os":"x",'
                  b'"source_product":"y"}') == "schema_invalid:username"
    assert reason(record(username="a\u0000b")) == "schema_invalid:username"
    assert reason(record(source_host="h\u0000")) == "schema_invalid:source_host"
    assert reason(record(parse_warnings=["\ud800"])) == "schema_invalid:parse_warnings"


def test_failure_reason_requires_failure():
    """Case 26: failure_reason with outcome success is invalid."""
    assert reason(record(outcome="success", failure_reason="locked")) == \
        "schema_invalid:failure_reason"
    assert reason(record(outcome="failure", failure_reason="locked")) is None


def test_invalid_timestamp_reason():
    assert reason(record(timestamp="2026-10-26T10:00:00")) == "invalid_timestamp"
    assert reason(record(timestamp=1729936800)) == "schema_invalid:timestamp"
    assert reason(record(timestamp="bad", username=5)) == "schema_invalid:timestamp,username"


def test_null_timestamp_is_valid_event():
    """Case 30: timestamp null is a valid event with no time."""
    ae = AuthEvent.model_validate(record(timestamp=None))
    assert build_event(ae, 1, 0, Interner()).ts_us is None


def test_length_caps():
    assert reason(record(username="u" * 256)) is None
    assert reason(record(username="u" * 257)) == "schema_invalid:username"
    assert reason(record(record_id="r" * 129)) == "schema_invalid:record_id"
    assert reason(record(parse_warnings=["w"] * 17)) == "schema_invalid:parse_warnings"
    assert reason(record(parse_warnings=["w" * 201])) == "schema_invalid:parse_warnings"
    assert reason(record(source_os="Linux")) == "schema_invalid:source_os"


def test_reason_field_list_truncated():
    rec = {"schema_version": "x"}
    with pytest.raises(ValidationError) as info:
        AuthEvent.model_validate(rec)
    code = reason_for(info.value)
    assert code.startswith("schema_invalid:") and len(code) <= len("schema_invalid:") + 40


def test_build_event_warnings_and_interning():
    interner = Interner()
    a = build_event(AuthEvent.model_validate(record(username="alice​",
                                                    source_ip="::ffff:203.0.113.50")),
                    1, 0, interner)
    b = build_event(AuthEvent.model_validate(record(username="ALICE")), 2, 1, interner)
    assert a.user == b.user == "alice" and a.user is b.user
    assert a.ip == "203.0.113.50" and a.ip is b.ip
    assert "username_has_format_or_control_chars" in a.warnings
    assert "ip_canonicalized" in a.warnings
    c = build_event(AuthEvent.model_validate(record(username="​")), 3, 2, interner)
    assert c.user is None and "username_empty_after_normalization" in c.warnings
