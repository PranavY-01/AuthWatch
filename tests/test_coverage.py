from collections import Counter

import pytest

from authwatch.coverage import Counters, ErrorLog, derive, exit_code, timeline
from authwatch.rules import RuleRun
from conftest import ev


def run(rule="AW-001", alerts=0, unc=None, suppressed=0):
    return RuleRun(rule, [object()] * alerts, Counter(unc or {}), suppressed)


def test_status_table():
    """All five rows of the status table."""
    c = Counters(records_read=1, events_normalized=1, events_analyzed=1)
    assert derive(c, [run()], 1) == ("clean", "clean", True, [])
    assert derive(c, [run(alerts=2)], 1) == ("alerts_detected", "alerts_detected", True, [])
    bad = Counters(records_read=2, events_normalized=1, records_invalid=1, events_analyzed=1)
    assert derive(bad, [run()], 1) == ("incomplete", "clean", False, ["invalid_records"])
    assert derive(bad, [run(alerts=1)], 1) == ("incomplete", "alerts_detected", False,
                                                ["invalid_records"])
    assert derive(c, [run()], 1, fatal=True)[0] == "error"


@pytest.mark.parametrize("counters,runs,analyzed,reason", [
    (Counters(), [], 0, "no_events"),
    (Counters(records_invalid=1), [], 1, "invalid_records"),
    (Counters(records_unsupported=1), [], 1, "unsupported_records"),
    (Counters(duplicate_conflicts=1), [], 1, "duplicate_conflicts"),
    (Counters(), [run("AW-002", unc={"missing_username": 3})], 1, "uncorrelatable:AW-002"),
    (Counters(), [run("AW-003", suppressed=4)], 1, "alert_cap_reached:AW-003"),
])
def test_every_reason_code(counters, runs, analyzed, reason):
    status, _, complete, reasons = derive(counters, runs, analyzed)
    assert reasons == [reason] and not complete and status == "incomplete"


def test_irrelevant_and_blank_are_not_gaps():
    c = Counters(lines_total=5, blank_lines=2, records_read=3, events_normalized=1,
                 records_irrelevant=2, duplicates_dropped=0, events_analyzed=1)
    assert derive(c, [run()], 1)[2] is True


def test_exit_codes():
    assert [exit_code(s) for s in ("clean", "alerts_detected", "incomplete")] == [0, 1, 4]


def test_error_log_cap():
    log = ErrorLog(cap=3)
    for i in range(5):
        log.add("INVALID_RECORD", i, "invalid_json")
    assert len(log.items) == 3 and log.total == 5 and log.truncated
    assert log.items[0] == {"kind": "INVALID_RECORD", "subject": "line:0",
                            "message": "invalid_json"}


def test_timeline_block():
    S = 1_000_000
    evs = [ev(10 * S, order=0), ev(5 * S, order=1), ev(40 * S, order=2), ev(20 * S, order=3),
           ev(None, order=4)]
    t = timeline(evs)
    assert t == {"earliest": "1970-01-01T00:00:05Z", "latest": "1970-01-01T00:00:40Z",
                 "largest_gap_seconds": 20, "gap_start": "1970-01-01T00:00:20Z",
                 "gap_end": "1970-01-01T00:00:40Z", "out_of_order_records": 2}


def test_timeline_empty_and_single():
    assert timeline([]) == {"earliest": None, "latest": None, "largest_gap_seconds": 0,
                            "gap_start": None, "gap_end": None, "out_of_order_records": 0}
    one = timeline([ev(0)])
    assert one["earliest"] == one["latest"] == "1970-01-01T00:00:00Z"
    assert one["gap_start"] is None and one["largest_gap_seconds"] == 0
