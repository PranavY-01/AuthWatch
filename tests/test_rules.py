import pytest

from authwatch.errors import ConfigError
from authwatch.events import Interner, build_event
from authwatch.models import AuthEvent
from authwatch.rules import Params, alert_id, parse_rules, run_rules
from conftest import record, ts


def events_from(records):
    interner = Interner()
    return [build_event(AuthEvent.model_validate(r), i + 1, i, interner)
            for i, r in enumerate(records)]


def burst(n, start=0, step=10, **kw):
    return [record(timestamp=ts(start + i * step), **kw) for i in range(n)]


@pytest.mark.parametrize("kwargs", [
    {"fail_threshold": 1}, {"fail_threshold": 100_001}, {"spray_threshold": 1},
    {"fail_window_s": 0}, {"fail_window_s": 7 * 86400 + 1}, {"spray_window_s": 0},
    {"lookback_s": 299}, {"lookback_s": 30 * 86400 + 1},
])
def test_params_bounds(kwargs):
    """Case 45: threshold 1, window 0, lookback below window and absurd values are refused."""
    with pytest.raises(ConfigError):
        Params(**kwargs).validate()


def test_params_extremes_allowed():
    Params(fail_threshold=2, spray_threshold=100_000, fail_window_s=1, lookback_s=1).validate()
    Params(fail_window_s=7 * 86400, spray_window_s=7 * 86400, lookback_s=30 * 86400).validate()


def test_lookback_message():
    with pytest.raises(ConfigError, match="lookback must be at least the fail window"):
        Params(lookback_s=10).validate()


def test_parse_rules():
    assert parse_rules(" AW-002 ,AW-001,AW-002") == ["AW-001", "AW-002"]
    for bad in ["", "aw-001", "AW-999", "AW-001,,AW-002", ","]:
        with pytest.raises(ConfigError):
            parse_rules(bad)


def test_alert_id_canonical():
    a = alert_id("AW-001", "ip:1.2.3.4", "2026-10-26T10:00:00Z", {"threshold": 5, "window_s": 300})
    assert a == alert_id("AW-001", "ip:1.2.3.4", "2026-10-26T10:00:00Z",
                         {"window_s": 300, "threshold": 5})
    assert len(a) == 16 and int(a, 16) >= 0
    assert alert_id("a|b", "c", "t", {}) != alert_id("a", "b|c", "t", {})


def test_aw001_alert_fields():
    evs = events_from(burst(6, source_ip="203.0.113.50"))
    run = run_rules(evs, Params(), ["AW-001"])[0]
    assert len(run.alerts) == 1
    f = run.alerts[0].finding
    d = f["details"]
    assert f["event"] == "AW-001" and f["category"] == "detection"
    assert f["subject"] == "ip:203.0.113.50"
    assert d["severity"] == "MEDIUM" and d["attack"] == ["T1110"]
    assert (d["first_seen"], d["last_seen"]) == ("2026-10-26T10:00:00Z", "2026-10-26T10:00:50Z")
    assert (d["count"], d["peak_in_window"], d["threshold"], d["window_seconds"]) == (6, 6, 5, 300)
    assert d["evidence"]["lines"] == [1, 2, 3, 4, 5, 6]
    assert d["evidence"]["usernames"] == [{"value": "alice", "count": 6}]
    assert d["description"] == ("6 failed authentication attempts from 203.0.113.50 between "
                                "2026-10-26T10:00:00Z and 2026-10-26T10:00:50Z; 5 or more "
                                "within 300s (peak 6 in one window).")
    assert len(d["caveats"]) == 1


def test_aw002_counts_distributed_sources_and_dynamic_caveat():
    recs = [record(timestamp=ts(i * 10), source_ip=f"203.0.113.{i + 1}", username="admin")
            for i in range(5)]
    recs.append(record(timestamp=None, username="admin"))
    run = run_rules(events_from(recs), Params(), ["AW-002"])[0]
    d = run.alerts[0].finding["details"]
    assert run.alerts[0].subject == "user:admin"
    assert "from 5 source IP(s)" in d["description"]
    assert d["caveats"][-1] == "1 relevant events could not be used by this rule (see coverage)."
    assert run.uncorrelatable == {"missing_timestamp": 1}


def test_key_spelling_variants_merge_into_one_alert():
    names = ["alice", "ALICE", "ａｌｉｃｅ", "alice​", "Alice"]
    recs = [record(timestamp=ts(i), username=n, source_ip=f"198.51.100.{i}")
            for i, n in enumerate(names)]
    run = run_rules(events_from(recs), Params(), ["AW-002"])[0]
    assert [a.subject for a in run.alerts] == ["user:alice"]
    assert run.alerts[0].finding["details"]["count"] == 5


def test_failures_only_count():
    recs = burst(4, source_ip="192.0.2.1") + [record(timestamp=ts(45), outcome="success",
                                                     source_ip="192.0.2.1")]
    assert run_rules(events_from(recs), Params(), ["AW-001"])[0].alerts == []


ALL = ["AW-001", "AW-002", "AW-003", "AW-004"]


def test_aw001_and_aw003_both_fire_for_one_ip():
    """Case 51: a spray from one IP fires AW-001 by volume and AW-003 by distinct accounts."""
    recs = [record(timestamp=ts(i * 10), username=f"user{i:02d}", source_ip="192.0.2.99")
            for i in range(12)]
    runs = {r.rule_id: r for r in run_rules(events_from(recs), Params(), ALL)}
    assert [a.subject for a in runs["AW-001"].alerts] == ["ip:192.0.2.99"]
    assert [a.subject for a in runs["AW-003"].alerts] == ["ip:192.0.2.99"]
    d = runs["AW-003"].alerts[0].finding["details"]
    assert (d["count"], d["peak_in_window"], d["threshold"], d["window_seconds"]) == (12, 12, 10, 600)
    assert d["attack"] == ["T1110.003"]
    assert d["description"].startswith("192.0.2.99 failed against 12 distinct accounts")
    assert runs["AW-002"].alerts == []


def aw004(recs):
    runs = {r.rule_id: r for r in run_rules(events_from(recs), Params(), ["AW-004"])}
    return runs["AW-004"].alerts


def test_aw004_ip_changed_flag():
    """Case 52: a success from the same IP -> ip_changed false; from a new IP -> true."""
    fails = burst(5, source_ip="203.0.113.50")
    same = aw004(fails + [record(timestamp=ts(60), outcome="success", source_ip="203.0.113.50")])
    new = aw004(fails + [record(timestamp=ts(60), outcome="success", source_ip="198.51.100.7")])
    none = aw004(fails + [record(timestamp=ts(60), outcome="success", source_ip=None)])
    assert same[0].finding["details"]["evidence"]["ip_changed"] is False
    d = new[0].finding["details"]
    assert d["evidence"]["ip_changed"] is True and d["severity"] == "HIGH"
    assert d["evidence"]["success_line"] == 6 and d["evidence"]["success_ip"] == "198.51.100.7"
    assert d["description"].endswith("success came from a source IP not seen in the failures.")
    assert (d["first_seen"], d["last_seen"], d["window_seconds"]) == (ts(0), ts(60), 900)
    nd = none[0].finding["details"]
    assert nd["evidence"]["ip_changed"] is None and nd["evidence"]["success_ip"] is None
    assert nd["description"].endswith("an unknown source IP.")


def test_aw004_failures_consumed():
    """Case 53: a second success right after an alerting one does not alert again."""
    recs = burst(5) + [record(timestamp=ts(60), outcome="success"),
                       record(timestamp=ts(61), outcome="success")]
    assert len(aw004(recs)) == 1


def test_aw004_non_alerting_success_does_not_clear():
    recs = burst(3) + [record(timestamp=ts(35), outcome="success")] + burst(2, start=40) + \
        [record(timestamp=ts(70), outcome="success")]
    alerts = aw004(recs)
    assert len(alerts) == 1 and alerts[0].finding["details"]["count"] == 5


def test_aw004_cross_ip_failures_count():
    recs = [record(timestamp=ts(i), source_ip=f"203.0.113.{i + 1}") for i in range(5)]
    recs.append(record(timestamp=ts(10), outcome="success", source_ip="203.0.113.1"))
    assert aw004(recs)[0].finding["details"]["evidence"]["ip_changed"] is False


def test_aw004_lookback_boundary():
    recs = burst(5, step=100) + [record(timestamp=ts(400 + 900), outcome="success")]
    assert aw004(recs) == []   # the failure at 400 is exactly 900 s old: outside
