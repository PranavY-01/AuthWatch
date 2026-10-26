"""Counters, coverage reasons, status derivation, the error log and the timeline block."""

from collections.abc import Sequence
from dataclasses import asdict, dataclass

from authwatch.timeparse import iso_utc

ERRORS_CAP = 1000
_EXIT = {"clean": 0, "alerts_detected": 1, "incomplete": 4}


@dataclass
class Counters:
    lines_total: int = 0
    blank_lines: int = 0
    records_read: int = 0
    events_normalized: int = 0
    records_invalid: int = 0
    records_unsupported: int = 0
    records_irrelevant: int = 0
    events_with_warnings: int = 0
    duplicates_dropped: int = 0
    duplicate_conflicts: int = 0
    events_analyzed: int = 0

    def as_dict(self) -> dict:
        return asdict(self)

    def invariant_holds(self) -> bool:
        return (self.records_read == self.events_normalized + self.records_invalid
                + self.records_unsupported + self.records_irrelevant
                and self.events_analyzed == self.events_normalized - self.duplicates_dropped)


class ErrorLog:
    """``errors[]`` entries ``{kind, subject, message}``; keeps the first 1 000, counts all."""

    def __init__(self, cap: int = ERRORS_CAP) -> None:
        self.cap = cap
        self.items: list[dict] = []
        self.total = 0

    def add(self, kind: str, line_no: int, message: str) -> None:
        self.total += 1
        if len(self.items) < self.cap:
            self.items.append({"kind": kind, "subject": f"line:{line_no}", "message": message})

    @property
    def truncated(self) -> bool:
        return self.total > len(self.items)


def derive(counters: Counters, rule_runs: Sequence, events_analyzed: int, fatal: bool = False
           ) -> tuple[str, str, bool, list[str]]:
    """Return (status, result, coverage complete, reasons). ``result`` says whether alerts were
    found; ``status`` also accounts for coverage, so partial coverage is never ``clean``."""
    reasons = []
    if events_analyzed == 0:
        reasons.append("no_events")
    if counters.records_invalid:
        reasons.append("invalid_records")
    if counters.records_unsupported:
        reasons.append("unsupported_records")
    if counters.duplicate_conflicts:
        reasons.append("duplicate_conflicts")
    for r in rule_runs:
        if sum(r.uncorrelatable.values()):
            reasons.append(f"uncorrelatable:{r.rule_id}")
        if r.suppressed:
            reasons.append(f"alert_cap_reached:{r.rule_id}")
    complete = not reasons
    alerts = sum(len(r.alerts) for r in rule_runs)
    result = "alerts_detected" if alerts else "clean"
    if fatal:
        status = "error"
    elif not complete:
        status = "incomplete"
    else:
        status = result
    return status, result, complete, reasons


def exit_code(status: str) -> int:
    """Exit code for a non-fatal status (fatal outcomes exit through their exception)."""
    return _EXIT[status]


def timeline(events: Sequence) -> dict:
    """Earliest/latest instant, largest silent gap and out-of-order count over the analyzed
    events (given in input order). Signals for the analyst, not coverage failures."""
    stamps = [e.ts_us for e in events if e.ts_us is not None]
    out_of_order = 0
    running_max = None
    for t in stamps:
        if running_max is not None and t < running_max:
            out_of_order += 1
        if running_max is None or t > running_max:
            running_max = t
    block = {"earliest": None, "latest": None, "largest_gap_seconds": 0, "gap_start": None,
             "gap_end": None, "out_of_order_records": out_of_order}
    if not stamps:
        return block
    ordered = sorted(stamps)
    block["earliest"] = iso_utc(ordered[0])
    block["latest"] = iso_utc(ordered[-1])
    best = None
    for a, b in zip(ordered, ordered[1:]):
        if best is None or b - a > best[1] - best[0]:
            best = (a, b)
    if best is not None:
        block["largest_gap_seconds"] = (best[1] - best[0]) // 1_000_000
        block["gap_start"] = iso_utc(best[0])
        block["gap_end"] = iso_utc(best[1])
    return block
