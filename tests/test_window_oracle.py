"""Window-engine oracle tests (Spec §12.3, errata E7).

The oracle recomputes every window from scratch (O(n^2)) straight from the definition and
is deliberately independent of authwatch.window.
"""

import random
from collections import defaultdict

import pytest

from authwatch.events import SORT_KEY
from authwatch.window import MAX_EVIDENCE_LINES, run_count_metric
from conftest import ev

STREAMS = 3000


# ---------------------------------------------------------------- oracle (from E7 text)
def oracle(events, threshold, window, distinct=False):
    """Episodes as (first_line, last_line, count, peak), sorted."""
    ordered = sorted(events, key=lambda e: (e.ts_us, e.order))
    by_key = defaultdict(list)
    for e in ordered:
        by_key[e.ip].append(e)
    found = []
    for evs in by_key.values():
        n = len(evs)
        windows, metric = [], []
        for i in range(n):
            w = [j for j in range(i + 1) if evs[j].ts_us > evs[i].ts_us - window]
            windows.append(w)
            metric.append(len({evs[j].user for j in w}) if distinct else len(w))
        i = 0
        while i < n:
            if metric[i] >= threshold:
                s = i
                while i + 1 < n and metric[i + 1] >= threshold:
                    i += 1
                r = i
                members = sorted(set(windows[s]) | set(range(s + 1, r + 1)))
                found.append((evs[members[0]].line, evs[members[-1]].line, len(members),
                              max(metric[s:r + 1])))
            i += 1
    return sorted(found)


def implementation(events, threshold, window, sweep_every, distinct=False):
    usable = sorted(events, key=SORT_KEY)
    if distinct:
        from authwatch.window import run_distinct_metric
        eps, _ = run_distinct_metric(usable, lambda e: e.ip, lambda e: e.user, threshold, window,
                                     sweep_every=sweep_every)
    else:
        eps, _ = run_count_metric(usable, lambda e: e.ip, threshold, window,
                                  sweep_every=sweep_every)
    return sorted((ep.first_line, ep.last_line, ep.count, ep.peak) for ep in eps)


def random_stream(rng):
    n_keys = rng.randint(1, 3)
    n = rng.randint(0, 60)
    times = sorted(rng.randint(0, 400) for _ in range(n))
    if rng.random() < 0.5:  # deliberate ties
        times = [t - t % rng.choice((5, 10, 20)) for t in times]
    rng.shuffle(times)       # input order differs from time order
    events = []
    for i, t in enumerate(times):
        key = f"k{rng.randrange(n_keys)}"
        events.append(ev(t, key=key, user=f"u{rng.randrange(6)}", ip=key, order=i))
    return events, rng.randint(2, 6), rng.choice((10, 60, 300))


@pytest.mark.parametrize("sweep_every", [4096, 1, 0], ids=["default-sweep", "sweep-1", "no-sweep"])
def test_count_metric_matches_oracle(sweep_every):
    """Case 42: the count metric matches the brute-force oracle on 3 000 seeded streams, with the
    sweep interval at its default, at 1, and disabled - sweeping never changes results."""
    rng = random.Random(20261026)
    mismatches = []
    for i in range(STREAMS):
        events, threshold, window = random_stream(rng)
        want = oracle(events, threshold, window)
        got = implementation(events, threshold, window, sweep_every)
        if want != got:
            mismatches.append(i)
    assert mismatches == []


def boundary(times, threshold=5, window=300):
    events = [ev(t, key="ip", order=i) for i, t in enumerate(times)]
    eps, _ = run_count_metric(sorted(events, key=SORT_KEY), lambda e: e.ip, threshold, window)
    return eps


def test_event_exactly_w_old_is_outside():
    """Case 38: an event exactly W old is outside the window (0,100,200,300,300 -> no alert;
    1,100,200,300,300 -> alert)."""
    assert boundary([0, 100, 200, 300, 300]) == []
    eps = boundary([1, 100, 200, 300, 300])
    assert len(eps) == 1 and eps[0].count == 5 and eps[0].peak == 5


def test_burst_straddling_bucket_edge_detected():
    """Case 39: failures at 180, 200, 240, 310, 330 straddle a 300 s bucket edge but alert."""
    eps = boundary([180, 200, 240, 310, 330])
    assert len(eps) == 1 and eps[0].count == 5


def test_flood_is_one_episode_with_bounded_evidence():
    """Case 40: a 500-failure flood produces one alert whose evidence holds at most 50 lines."""
    eps = boundary(list(range(500)))
    assert len(eps) == 1
    ep = eps[0]
    assert ep.count == 500 and ep.peak == 300
    lines, truncated = ep.lines()
    assert truncated and len(lines) == MAX_EVIDENCE_LINES
    assert lines[:25] == list(range(1, 26)) and lines[-25:] == list(range(476, 501))


def test_two_bursts_separated_by_more_than_w():
    """Case 41: two bursts separated by a quiet period longer than W give two alerts."""
    eps = boundary([0, 1, 2, 3, 4, 1000, 1001, 1002, 1003, 1004])
    assert [(e.count, e.first_line, e.last_line) for e in eps] == [(5, 1, 5), (5, 6, 10)]


def test_burst_quiet_burst_within_one_window_merges():
    """A burst, a short quiet gap and a second burst inside one window stay one episode."""
    eps = boundary([0, 1, 2, 3, 4, 100, 101, 102])
    assert len(eps) == 1 and eps[0].count == 8 and eps[0].peak == 8


def test_evidence_lines_in_chronological_order():
    events = [ev(t, key="ip", order=i) for i, t in enumerate([50, 40, 30, 20, 10])]
    eps, _ = run_count_metric(sorted(events, key=SORT_KEY), lambda e: e.ip, 5, 300)
    assert eps[0].lines() == ([5, 4, 3, 2, 1], False)


def test_evidence_between_26_and_50_lists_every_line():
    eps = boundary(list(range(40)))
    lines, truncated = eps[0].lines()
    assert lines == list(range(1, 41)) and not truncated


def test_sweep_closes_open_episode_before_eviction():
    """Case 42: a key swept from memory while its episode is open keeps that episode."""
    events = [ev(t, key="a", order=t) for t in range(5)]
    events += [ev(1000 + i, key="b", order=100 + i) for i in range(3)]
    stats = {}
    eps, _ = run_count_metric(sorted(events, key=SORT_KEY), lambda e: e.ip, 5, 300,
                              sweep_every=1, stats=stats)
    assert [(e.key, e.count) for e in eps] == [("a", 5)]
    assert stats["keys_at_end"] == 1  # 'a' was evicted, 'b' remains


def test_alert_cap_counts_suppressed():
    """Case 43: once the cap is reached further episodes are only counted as suppressed; the
    earliest episodes are kept, independent of the sweep interval."""
    events = []
    for k in range(30):
        events += [ev(k * 1000 + i, key=f"ip{k:02d}", order=k * 10 + i) for i in range(2)]
    usable = sorted(events, key=SORT_KEY)
    for sweep in (0, 1, 4096):
        eps, suppressed = run_count_metric(usable, lambda e: e.ip, 2, 300, sweep_every=sweep,
                                           cap=10)
        assert suppressed == 20
        assert [e.key for e in eps] == [f"ip{k:02d}" for k in range(10)]


def test_many_distinct_keys_bounded_state():
    """Case 44: one million distinct keys keep per-key state bounded by the sweep."""
    usable = [ev(i, key=i, order=i) for i in range(1_000_000)]  # one event per key, 1 us apart
    stats = {}
    eps, suppressed = run_count_metric(usable, lambda e: e.ip, 2, 300, stats=stats)
    assert eps == [] and suppressed == 0
    assert stats["max_keys"] <= 4096 + 300


def test_single_key_flood_bounded_evidence():
    """A one-million-failure single-key flood is one alert with <= 50 evidence lines."""
    usable = [ev(i, key="ip", order=i) for i in range(1_000_000)]
    eps, _ = run_count_metric(usable, lambda e: e.ip, 5, 300)
    assert len(eps) == 1 and eps[0].count == 1_000_000
    lines, truncated = eps[0].lines()
    assert truncated and len(lines) == 50
    assert len(eps[0].users.counts) == 1
