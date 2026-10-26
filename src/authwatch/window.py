"""Sliding-window episode engine.

Window semantics are frozen: the window ending at event time ``t`` holds events with
``t - W < ts <= t``. An episode opens when the metric reaches the threshold, absorbs every
later event of its key while the metric stays at or above it, and closes when an event of
that key finds the metric below it. Each episode becomes one alert.

State is bounded: an episode keeps counts, the first and last 25 line numbers and capped
value counters, never its event list. Keys idle for a full window are swept every
``sweep_every`` events (closing their open episode first), and at most ``cap`` episodes
per rule are kept.
"""

from collections import Counter, OrderedDict, deque
from collections.abc import Callable, Hashable, Sequence

from authwatch.events import Event

EVIDENCE_HEAD = 25
EVIDENCE_TAIL = 25
MAX_EVIDENCE_LINES = EVIDENCE_HEAD + EVIDENCE_TAIL
MAX_TRACKED = 1000
SWEEP_EVERY = 4096
ALERT_CAP = 10_000


class CappedCounter:
    """Counts at most ``cap`` distinct values; events with further values are only counted."""

    __slots__ = ("counts", "untracked", "cap")

    def __init__(self, cap: int = MAX_TRACKED) -> None:
        self.counts: dict[str, int] = {}
        self.untracked = 0
        self.cap = cap

    def add(self, value: str | None) -> None:
        if value is None:
            return
        counts = self.counts
        if value in counts:
            counts[value] += 1
        elif len(counts) < self.cap:
            counts[value] = 1
        else:
            self.untracked += 1


class Episode:
    """One sustained run at or above threshold for one key, with bounded evidence."""

    __slots__ = ("key", "count", "peak", "first_us", "first_order", "last_us", "head", "tail",
                 "users", "ips", "success", "ip_changed")

    def __init__(self, key: Hashable) -> None:
        self.key = key
        self.count = 0
        self.peak = 0
        self.first_us: int | None = None
        self.first_order: int | None = None
        self.last_us: int | None = None
        self.head: list[int] = []
        self.tail: deque[int] = deque(maxlen=EVIDENCE_TAIL)
        self.users = CappedCounter()
        self.ips = CappedCounter()
        self.success: Event | None = None      # AW-004 only
        self.ip_changed: bool | None = None    # AW-004 only

    @classmethod
    def opened(cls, key: Hashable, window: Sequence[Event], metric: int) -> "Episode":
        ep = cls(key)
        for e in window:
            ep.add(e)
        ep.peak = metric
        return ep

    def add(self, e: Event) -> None:
        if self.count == 0:
            self.first_us = e.ts_us
            self.first_order = e.order
        self.count += 1
        self.last_us = e.ts_us
        if len(self.head) < EVIDENCE_HEAD:
            self.head.append(e.line)
        self.tail.append(e.line)
        self.users.add(e.user)
        self.ips.add(e.ip)

    def extend(self, e: Event, metric: int) -> None:
        self.add(e)
        if metric > self.peak:
            self.peak = metric

    @property
    def first_line(self) -> int:
        return self.head[0]

    @property
    def last_line(self) -> int:
        return self.tail[-1]

    def lines(self) -> tuple[list[int], bool]:
        """Evidence line numbers in chronological order: all if <= 50, else first and last 25."""
        if self.count <= EVIDENCE_HEAD:
            return list(self.head), False
        if self.count <= MAX_EVIDENCE_LINES:
            return self.head + list(self.tail)[-(self.count - EVIDENCE_HEAD):], False
        return self.head + list(self.tail), True


def _episode_order(ep: Episode) -> tuple:
    return (ep.first_us, ep.first_order, str(ep.key))


class _Sink:
    """Keeps the ``cap`` earliest episodes by (first_us, first_order, key) and counts the rest.

    Choosing by a total order instead of by emission order keeps the result independent of
    when episodes are closed, so sweeping cannot change which episodes are recorded.
    """

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.items: list[Episode] = []
        self.total = 0

    def add(self, ep: Episode) -> None:
        self.total += 1
        self.items.append(ep)
        if len(self.items) > self.cap + 1024:
            self._trim()

    def _trim(self) -> None:
        self.items.sort(key=_episode_order)
        del self.items[self.cap:]

    def result(self) -> tuple[list[Episode], int]:
        self._trim()
        return self.items, self.total - len(self.items)


class _KeyState:
    __slots__ = ("dq", "aux", "open")

    def __init__(self, distinct: bool) -> None:
        self.dq: deque[Event] = deque()
        self.aux: Counter | None = Counter() if distinct else None
        self.open: Episode | None = None


def _run_window(usable: Sequence[Event], key_fn: Callable[[Event], Hashable],
                aux_fn: Callable[[Event], Hashable] | None, threshold: int, window_us: int,
                sweep_every: int, cap: int, stats: dict | None) -> tuple[list[Episode], int]:
    # Keys ordered by their newest event; since input is time-sorted, the front is always
    # the key that has been idle longest, so a sweep only touches keys it evicts.
    states: OrderedDict[Hashable, _KeyState] = OrderedDict()
    sink = _Sink(cap)
    distinct = aux_fn is not None
    max_keys = 0
    for n, e in enumerate(usable, 1):
        k = key_fn(e)
        st = states.get(k)
        if st is None:
            st = states[k] = _KeyState(distinct)
        else:
            states.move_to_end(k)
        dq = st.dq
        dq.append(e)
        if distinct:
            st.aux[aux_fn(e)] += 1
        cutoff = e.ts_us - window_us
        while dq[0].ts_us <= cutoff:                  # (t - W, t]; e itself always stays
            old = dq.popleft()
            if distinct:
                a = aux_fn(old)
                left = st.aux[a] - 1
                if left:
                    st.aux[a] = left
                else:
                    del st.aux[a]
        metric = len(st.aux) if distinct else len(dq)
        if metric >= threshold:
            if st.open is None:
                st.open = Episode.opened(k, dq, metric)
            else:
                st.open.extend(e, metric)
        elif st.open is not None:
            sink.add(st.open)
            st.open = None
        if len(states) > max_keys:
            max_keys = len(states)
        if sweep_every and n % sweep_every == 0:
            horizon = e.ts_us - window_us
            while states:
                k0, st0 = next(iter(states.items()))
                if st0.dq[-1].ts_us > horizon:
                    break
                del states[k0]
                if st0.open is not None:              # close and keep before forgetting the key
                    sink.add(st0.open)
    for st in states.values():
        if st.open is not None:
            sink.add(st.open)
    if stats is not None:
        stats["max_keys"] = max_keys
        stats["keys_at_end"] = len(states)
    return sink.result()


def run_count_metric(usable: Sequence[Event], key_fn: Callable[[Event], Hashable],
                     threshold: int, window_us: int, *, sweep_every: int = SWEEP_EVERY,
                     cap: int = ALERT_CAP, stats: dict | None = None
                     ) -> tuple[list[Episode], int]:
    """Episodes where the number of events per key in the window reaches ``threshold``.

    ``usable`` must be sorted by the global sort key. ``sweep_every=0`` disables sweeping.
    Returns (episodes, suppressed episode count).
    """
    return _run_window(usable, key_fn, None, threshold, window_us, sweep_every, cap, stats)


def run_distinct_metric(usable: Sequence[Event], key_fn: Callable[[Event], Hashable],
                        aux_fn: Callable[[Event], Hashable], threshold: int, window_us: int, *,
                        sweep_every: int = SWEEP_EVERY, cap: int = ALERT_CAP,
                        stats: dict | None = None) -> tuple[list[Episode], int]:
    """Episodes where the number of distinct ``aux_fn`` values per key in the window reaches
    ``threshold`` (AW-003: distinct accounts per source IP). ``count`` stays the number of
    events in the episode; ``peak`` is the peak number of distinct values."""
    return _run_window(usable, key_fn, aux_fn, threshold, window_us, sweep_every, cap, stats)


def detect_fail_then_success(usable: Sequence[Event], threshold: int, lookback_us: int, *,
                             sweep_every: int = SWEEP_EVERY, cap: int = ALERT_CAP,
                             stats: dict | None = None) -> tuple[list[Episode], int]:
    """AW-004: a success preceded by >= ``threshold`` failures for the same account within
    ``(t - lookback, t]``.

    ``usable`` holds failures and successes sorted by the global key, so failures come
    before a success at an equal timestamp. Failures that produced an alert are consumed;
    successes that do not alert leave the failures in place.
    """
    fails: OrderedDict[Hashable, deque[Event]] = OrderedDict()
    sink = _Sink(cap)
    max_keys = 0
    for n, e in enumerate(usable, 1):
        cutoff = e.ts_us - lookback_us
        dq = fails.get(e.user)
        if e.outcome == "failure":
            if dq is None:
                dq = fails[e.user] = deque()
            else:
                fails.move_to_end(e.user)
            while dq and dq[0].ts_us <= cutoff:
                dq.popleft()
            dq.append(e)
        elif dq:
            while dq and dq[0].ts_us <= cutoff:
                dq.popleft()
            if len(dq) >= threshold:
                ep = Episode(e.user)
                for f in dq:
                    ep.add(f)
                ep.peak = ep.count
                ep.last_us = e.ts_us
                ep.success = e
                ep.ip_changed = None if e.ip is None else e.ip not in {f.ip for f in dq}
                sink.add(ep)
                del fails[e.user]                   # consumed
        if len(fails) > max_keys:
            max_keys = len(fails)
        if sweep_every and n % sweep_every == 0:
            horizon = e.ts_us - lookback_us
            while fails:
                u0, dq0 = next(iter(fails.items()))
                if dq0 and dq0[-1].ts_us > horizon:
                    break
                del fails[u0]
    if stats is not None:
        stats["max_keys"] = max_keys
        stats["keys_at_end"] = len(fails)
    return sink.result()
