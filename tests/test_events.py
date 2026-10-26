import random

from authwatch.events import (MISSING_SOURCE_IP, MISSING_TIMESTAMP, MISSING_USERNAME, SORT_KEY,
                              UNKNOWN_OUTCOME, Interner, build_event, dedupe, select)
from authwatch.models import AuthEvent
from conftest import record

FAILS = frozenset({"failure", "unknown"})


def build(i, **overrides):
    return build_event(AuthEvent.model_validate(record(**overrides)), i + 1, i, INTERNER)


INTERNER = Interner()


def test_sort_by_instant_not_file_order():
    """Case 36: out-of-order input sorts by instant; ties keep input order."""
    evs = [build(0, timestamp="2026-10-26T10:00:05Z"), build(1, timestamp="2026-10-26T10:00:01Z"),
           build(2, timestamp="2026-10-26T10:00:05Z"), build(3, timestamp="2026-10-26T15:30:03+05:30")]
    assert [e.line for e in sorted(evs, key=SORT_KEY)] == [2, 4, 1, 3]
    shuffled = evs[:]
    random.Random(1).shuffle(shuffled)
    assert [e.line for e in sorted(shuffled, key=SORT_KEY)] == [2, 4, 1, 3]


def test_failure_sorts_before_success_at_equal_time():
    """Case 37: at the same timestamp a failure sorts before an unknown, before a success."""
    evs = [build(0, outcome="success"), build(1, outcome="unknown"), build(2, outcome="failure")]
    assert [e.outcome for e in sorted(evs, key=SORT_KEY)] == ["failure", "unknown", "success"]


def test_same_record_id_same_content_dropped():
    """Case 48: a repeated record_id with identical content is dropped and counted."""
    a = build(0, record_id="r1", source_host="h")
    b = build(1, record_id="r1", source_host="h", parse_warnings=["differs only in warnings"])
    c = build(2, record_id="r1", source_host="h", timestamp="2026-10-26T10:00:00+00:00")
    kept, dropped, conflicts = dedupe([a, b, c])
    assert kept == [a] and dropped == 2 and conflicts == []


def test_same_record_id_different_content_is_conflict():
    """Case 49: a repeated record_id with different content is kept and reported as a conflict."""
    a = build(0, record_id="r1")
    b = build(1, record_id="r1", outcome="success")
    kept, dropped, conflicts = dedupe([a, b])
    assert kept == [a, b] and dropped == 0 and conflicts == [b]


def test_record_id_scoped_by_product_and_host():
    a = build(0, record_id="r1", source_host="h1")
    b = build(1, record_id="r1", source_host="h2", outcome="success")
    assert dedupe([a, b]) == ([a, b], 0, [])


def test_identical_content_without_record_id_not_deduplicated():
    """Case 50: identical content without record_id is never deduplicated."""
    a, b = build(0), build(1)
    assert dedupe([a, b]) == ([a, b], 0, [])


def test_unknown_outcome_is_uncorrelatable():
    """Case 46: outcome unknown is uncorrelatable for every rule."""
    evs = [build(0, outcome="unknown"), build(1)]
    usable, unc = select(evs, FAILS, True, False)
    assert [e.line for e in usable] == [2] and unc == {UNKNOWN_OUTCOME: 1}
    usable, unc = select(evs, frozenset({"failure", "success", "unknown"}), False, True)
    assert unc == {UNKNOWN_OUTCOME: 1}


def test_failure_without_ip():
    """Case 47: a failure with no IP is usable by the account rule but uncorrelatable for the
    IP rules."""
    evs = [build(0, source_ip=None)]
    assert select(evs, FAILS, True, False)[1] == {MISSING_SOURCE_IP: 1}
    usable, unc = select(evs, FAILS, False, True)
    assert len(usable) == 1 and not unc


def test_select_reason_order_and_irrelevance():
    evs = [build(0, timestamp=None, source_ip=None), build(1, username="​"),
           build(2, outcome="success", timestamp=None)]
    usable, unc = select(evs, FAILS, True, True)
    assert usable == [] and unc == {MISSING_TIMESTAMP: 1, MISSING_USERNAME: 1}
    usable, unc = select(evs, frozenset({"failure", "success", "unknown"}), False, True)
    assert unc == {MISSING_TIMESTAMP: 2, MISSING_USERNAME: 1}
