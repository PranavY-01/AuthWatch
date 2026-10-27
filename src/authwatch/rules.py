"""Rule catalogue, parameter validation and alert construction."""

import hashlib
import json
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

from authwatch.errors import ConfigError
from authwatch.events import Event, select
from authwatch.redact import NoRedaction
from authwatch.timeparse import iso_utc
from authwatch.window import (ALERT_CAP, SWEEP_EVERY, CappedCounter, Episode,
                              detect_fail_then_success, run_count_metric, run_distinct_metric)

US = 1_000_000
SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
TOP_VALUES = 10

THRESHOLD_MIN, THRESHOLD_MAX = 2, 100_000
WINDOW_MIN_S, WINDOW_MAX_S = 1, 7 * 86400
LOOKBACK_MAX_S = 30 * 86400

FAILURES = frozenset({"failure", "unknown"})
ALL_OUTCOMES = frozenset({"failure", "success", "unknown"})

_CAVEAT_SHARED_IP = ("Shared addresses (NAT, proxies, VPN exits) can make many users look like one "
                     "source; an IP address does not identify a person.")
_CAVEAT_ACCOUNT = ("Stale saved passwords and service retry loops produce the same pattern; check "
                   "whether the sources are expected.")
_CAVEAT_SUCCESS = ("A user who finally remembers the password looks the same; check whether the "
                   "success came from a new source.")


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    title: str
    severity: str
    attack: tuple[str, ...]
    outcomes: frozenset[str]
    need_ip: bool
    need_user: bool
    caveat: str


RULES: dict[str, RuleSpec] = {
    "AW-001": RuleSpec("AW-001", "Failed-login burst from one source IP", "MEDIUM", ("T1110",),
                       FAILURES, True, False, _CAVEAT_SHARED_IP),
    "AW-002": RuleSpec("AW-002", "Repeated failures against one account", "MEDIUM",
                       ("T1110.001",), FAILURES, False, True, _CAVEAT_ACCOUNT),
    "AW-003": RuleSpec("AW-003", "One source IP failing against many accounts", "MEDIUM",
                       ("T1110.003",), FAILURES, True, True, _CAVEAT_SHARED_IP),
    "AW-004": RuleSpec("AW-004", "Success after repeated failures on the same account", "HIGH",
                       ("T1110", "T1078"), ALL_OUTCOMES, False, True, _CAVEAT_SUCCESS),
}
RULE_IDS = tuple(sorted(RULES))


@dataclass
class Params:
    fail_threshold: int = 5
    fail_window_s: int = 300
    spray_threshold: int = 10
    spray_window_s: int = 600
    lookback_s: int = 900

    def validate(self) -> None:
        """Bounds for every parameter, whichever rules are enabled."""
        for name, value in (("--fail-threshold", self.fail_threshold),
                            ("--spray-threshold", self.spray_threshold)):
            if not THRESHOLD_MIN <= value <= THRESHOLD_MAX:
                raise ConfigError(f"{name} must be between {THRESHOLD_MIN} and {THRESHOLD_MAX}")
        for name, value in (("--fail-window", self.fail_window_s),
                            ("--spray-window", self.spray_window_s)):
            if not WINDOW_MIN_S <= value <= WINDOW_MAX_S:
                raise ConfigError(f"{name} must be between 1s and 7d")
        if self.lookback_s < self.fail_window_s:
            raise ConfigError("lookback must be at least the fail window")
        if self.lookback_s > LOOKBACK_MAX_S:
            raise ConfigError("--lookback must be at most 30d")


# What each rule groups by and measures, and which options tune it.
_RULE_SHAPE = {
    "AW-001": ("source IP", "failures in window", "--fail-threshold", "fail_threshold",
               "--fail-window", "fail_window_s"),
    "AW-002": ("account", "failures in window", "--fail-threshold", "fail_threshold",
               "--fail-window", "fail_window_s"),
    "AW-003": ("source IP", "distinct accounts failing in window", "--spray-threshold",
               "spray_threshold", "--spray-window", "spray_window_s"),
    "AW-004": ("account", "failures in lookback before a success", "--fail-threshold",
               "fail_threshold", "--lookback", "lookback_s"),
}


def rule_catalogue(params: Params | None = None) -> list[dict]:
    """Every rule with its key, metric, thresholds and ATT&CK tags (for ``authwatch rules``)."""
    params = params or Params()
    rows = []
    for rule_id in RULE_IDS:
        spec = RULES[rule_id]
        key, metric, t_opt, t_attr, w_opt, w_attr = _RULE_SHAPE[rule_id]
        rows.append({"rule_id": rule_id, "title": spec.title, "severity": spec.severity,
                     "groups_by": key, "metric": metric,
                     "threshold": getattr(params, t_attr), "threshold_option": t_opt,
                     "window_seconds": getattr(params, w_attr), "window_option": w_opt,
                     "attack": list(spec.attack), "caveat": spec.caveat})
    return rows


def parse_rules(text: str) -> list[str]:
    """``--rules``: comma-separated known ids; trimmed, de-duplicated, sorted ascending."""
    chosen = {part.strip() for part in text.split(",")}
    if not chosen or chosen == {""}:
        raise ConfigError("--rules must name at least one rule")
    unknown = sorted(r for r in chosen if r not in RULES)
    if unknown:
        raise ConfigError(f"unknown rule id in --rules; known rules: {', '.join(RULE_IDS)}")
    return sorted(chosen)


def alert_id(rule: str, subject: str, first_seen: str, params: dict) -> str:
    """First 16 hex chars of SHA-256 over a canonical JSON list (no delimiter collisions)."""
    blob = json.dumps([rule, subject, first_seen, params], separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


@dataclass
class Alert:
    rule_id: str
    severity: str
    subject: str
    first_us: int
    finding: dict

    def sort_key(self) -> tuple:
        return (SEVERITY_RANK[self.severity], self.first_us, self.rule_id, self.subject)


@dataclass
class RuleRun:
    rule_id: str
    alerts: list[Alert]
    uncorrelatable: Counter = field(default_factory=Counter)
    suppressed: int = 0

    @property
    def uncorrelatable_total(self) -> int:
        return sum(self.uncorrelatable.values())


def _top(counter: CappedCounter, show) -> list[dict]:
    items = [(show(value), count) for value, count in counter.counts.items()]
    items.sort(key=lambda vc: (-vc[1], vc[0]))
    return [{"value": v, "count": c} for v, c in items[:TOP_VALUES]]


def _describe(spec: RuleSpec, ep: Episode, subject_text: str, threshold: int, window_s: int,
              first: str, last: str) -> str:
    if spec.rule_id == "AW-001":
        return (f"{ep.count} failed authentication attempts from {subject_text} between {first} "
                f"and {last}; {threshold} or more within {window_s}s "
                f"(peak {ep.peak} in one window).")
    if spec.rule_id == "AW-002":
        return (f"{ep.count} failed authentication attempts against account {subject_text} "
                f"between {first} and {last} from {len(ep.ips.counts)} source IP(s); "
                f"{threshold} or more within {window_s}s (peak {ep.peak} in one window).")
    if spec.rule_id == "AW-003":
        return (f"{subject_text} failed against {ep.peak} distinct accounts within a "
                f"{window_s}s window (threshold {threshold}); {ep.count} failure events "
                f"between {first} and {last}.")
    if ep.ip_changed is None:
        source = "an unknown source IP"
    elif ep.ip_changed:
        source = "a source IP not seen in the failures"
    else:
        source = "a source IP also seen in the failures"
    return (f"A successful authentication for account {subject_text} at {last} followed "
            f"{ep.count} failures within the {window_s}s lookback (threshold {threshold}); "
            f"success came from {source}.")


def build_alert(spec: RuleSpec, ep: Episode, threshold: int, window_s: int, redactor,
                uncorrelatable: int) -> Alert:
    """Turn an episode into an alert in the shared finding shape."""
    show_user = redactor.display
    by_ip = spec.rule_id in ("AW-001", "AW-003")
    subject_text = ep.key if by_ip else show_user(ep.key)
    subject = f"ip:{subject_text}" if by_ip else f"user:{subject_text}"
    first, last = iso_utc(ep.first_us), iso_utc(ep.last_us)
    lines, truncated = ep.lines()
    evidence: dict = {"lines": lines, "lines_truncated": truncated}
    if ep.success is not None:
        evidence["success_line"] = ep.success.line
        evidence["success_ip"] = ep.success.ip
        evidence["ip_changed"] = ep.ip_changed
    evidence["usernames"] = _top(ep.users, show_user)
    evidence["source_ips"] = _top(ep.ips, lambda v: v)
    evidence["distinct"] = {"usernames": len(ep.users.counts), "source_ips": len(ep.ips.counts)}
    evidence["untracked"] = {"usernames": ep.users.untracked, "source_ips": ep.ips.untracked}
    caveats = [spec.caveat]
    if uncorrelatable:
        caveats.append(f"{uncorrelatable} relevant events could not be used by this rule "
                       "(see coverage).")
    details = {
        "alert_id": alert_id(spec.rule_id, subject, first,
                             {"threshold": threshold, "window_s": window_s}),
        "title": spec.title,
        "severity": spec.severity,
        "attack": list(spec.attack),
        "first_seen": first,
        "last_seen": last,
        "count": ep.count,
        "peak_in_window": ep.peak,
        "threshold": threshold,
        "window_seconds": window_s,
        "description": _describe(spec, ep, subject_text, threshold, window_s, first, last),
        "evidence": evidence,
        "caveats": caveats,
    }
    finding = {"event": spec.rule_id, "category": "detection", "subject": subject,
               "details": details}
    return Alert(spec.rule_id, spec.severity, subject, ep.first_us, finding)


def reason_text(finding: dict) -> str:
    """Short terminal 'Reason' column for an alert."""
    d = finding["details"]
    rule = finding["event"]
    if rule == "AW-001":
        return f"{d['count']} failures from one IP"
    if rule == "AW-002":
        return f"{d['count']} failures, {d['evidence']['distinct']['source_ips']} source IP(s)"
    if rule == "AW-003":
        return f"{d['peak_in_window']} distinct accounts failed from one IP"
    if d["evidence"].get("ip_changed"):
        return f"success from a new IP after {d['count']} failures"
    return f"success after {d['count']} failures"


def _ip(e: Event) -> str:
    return e.ip


def _user(e: Event) -> str:
    return e.user


def _detect(rule_id: str, usable: list[Event], params: Params, sweep_every: int, cap: int
            ) -> tuple[list[Episode], int, int, int]:
    """Run one rule's detector; returns (episodes, suppressed, threshold, window seconds)."""
    if rule_id == "AW-001":
        eps, sup = run_count_metric(usable, _ip, params.fail_threshold,
                                    params.fail_window_s * US, sweep_every=sweep_every, cap=cap)
        return eps, sup, params.fail_threshold, params.fail_window_s
    if rule_id == "AW-002":
        eps, sup = run_count_metric(usable, _user, params.fail_threshold,
                                    params.fail_window_s * US, sweep_every=sweep_every, cap=cap)
        return eps, sup, params.fail_threshold, params.fail_window_s
    if rule_id == "AW-003":
        eps, sup = run_distinct_metric(usable, _ip, _user, params.spray_threshold,
                                       params.spray_window_s * US, sweep_every=sweep_every,
                                       cap=cap)
        return eps, sup, params.spray_threshold, params.spray_window_s
    if rule_id == "AW-004":
        eps, sup = detect_fail_then_success(usable, params.fail_threshold, params.lookback_s * US,
                                            sweep_every=sweep_every, cap=cap)
        return eps, sup, params.fail_threshold, params.lookback_s
    raise ValueError("unknown rule")


def run_rules(events: Sequence[Event], params: Params, enabled: Sequence[str], redactor=None, *,
              sweep_every: int = SWEEP_EVERY, cap: int = ALERT_CAP) -> list[RuleRun]:
    """Run each enabled rule over the analyzed events (any order; each rule sorts its input)."""
    redactor = redactor or NoRedaction()
    runs = []
    for rule_id in sorted(enabled):
        spec = RULES[rule_id]
        usable, unc = select(events, spec.outcomes, spec.need_ip, spec.need_user)
        episodes, suppressed, threshold, window_s = _detect(rule_id, usable, params,
                                                            sweep_every, cap)
        total_unc = sum(unc.values())
        alerts = [build_alert(spec, ep, threshold, window_s, redactor, total_unc)
                  for ep in episodes]
        runs.append(RuleRun(rule_id, alerts, unc, suppressed))
    return runs
