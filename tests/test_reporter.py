import json

from authwatch.cli import ingest
from authwatch.adapters.jsonl import JsonlAdapter
from authwatch.coverage import Counters, ErrorLog, derive, timeline
from authwatch.events import dedupe
from authwatch.reporter import build_report, to_json_bytes
from authwatch.rules import RULE_IDS, Params, run_rules
from conftest import SAMPLES, jsonl, record, write


def make_report(path):
    ing = ingest(path, JsonlAdapter())
    analyzed, dropped, conflicts = dedupe(ing.events)
    ing.counters.duplicates_dropped = dropped
    ing.counters.duplicate_conflicts = len(conflicts)
    ing.counters.events_analyzed = len(analyzed)
    runs = run_rules(analyzed, Params(), RULE_IDS)
    status, result, complete, reasons = derive(ing.counters, runs, len(analyzed))
    return build_report(run_id="r", started_at="s", completed_at="c", status=status,
                        result=result, input_info={"label": path.name}, parameters={},
                        complete=complete, reasons=reasons, counters=ing.counters,
                        rule_runs=runs, timeline=timeline(analyzed), errors=ing.errors), ing


def test_report_shape_and_counts():
    rep, _ = make_report(SAMPLES / "attacks.jsonl")
    assert list(rep) == ["envelope", "status", "result", "input", "parameters", "coverage",
                         "summary", "findings", "errors", "errors_truncated"]
    env = rep["envelope"]
    assert (env["schema"], env["schema_version"], env["tool"], env["tool_version"]) == \
        ("7d7b-report", 1, "AuthWatch", "1.1.0")
    for rule_id in RULE_IDS:
        assert rep["summary"][rule_id] == sum(f["event"] == rule_id for f in rep["findings"])
    assert rep["summary"]["errors"] == 0
    json.loads(to_json_bytes(rep))


def test_json_bytes_ascii_lf():
    data = to_json_bytes({"a": "ａｌｉｃｅ "})
    assert data.endswith(b"}\n") and b"\r" not in data
    data.decode("ascii")


def test_findings_sorted_by_severity_then_time():
    rep, _ = make_report(SAMPLES / "attacks.jsonl")
    keys = [(f["details"]["severity"] != "HIGH", f["details"]["first_seen"], f["event"],
             f["subject"]) for f in rep["findings"]]
    assert keys == sorted(keys)


def test_counter_invariant_over_mixed_file(tmp_path):
    """The counter invariant holds over a file mixing valid, invalid, blank and duplicate records."""
    data = jsonl([record(), "{bad", record(record_id="r1"), record(record_id="r1"),
                  record(record_id="r1", outcome="success"), "[1]"]) + b"\n\n"
    rep, ing = make_report(write(tmp_path, "m.jsonl", data))
    c = rep["coverage"]["counters"]
    assert ing.counters.invariant_holds()
    assert (c["lines_total"], c["blank_lines"], c["records_read"], c["events_normalized"],
            c["records_invalid"], c["duplicates_dropped"], c["duplicate_conflicts"],
            c["events_analyzed"]) == (8, 2, 6, 4, 2, 1, 1, 3)


def test_errors_capped_at_1000(tmp_path):
    data = b"{bad\n" * 1500 + jsonl([record()])
    rep, _ = make_report(write(tmp_path, "many.jsonl", data))
    assert len(rep["errors"]) == 1000 and rep["errors_truncated"] is True
    assert rep["summary"]["errors"] == 1500


def test_counters_and_errorlog_types():
    assert Counters().invariant_holds()
    assert not ErrorLog().truncated
