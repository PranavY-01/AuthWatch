"""Working with saved reports: loading, finding an alert, verifying the analyzed file and
pulling its evidence lines, and comparing two runs. No terminal or CLI code here."""

import json
from dataclasses import dataclass, field
from pathlib import Path

from authwatch.errors import ConfigError, OperationalError, VerificationError
from authwatch.reader import InputDigest, parse_json_line, read_lines

REPORT_LIMIT = 256 * 1024 * 1024
MIN_ID_PREFIX = 4
_HEX = frozenset("0123456789abcdef")
# Parameters that change alert ids (and so whether two runs are comparable).
_ID_PARAMETERS = ("rules", "fail_threshold", "fail_window_s", "spray_threshold",
                  "spray_window_s", "lookback_s", "redaction")


def load_report(path: Path) -> dict:
    """Read an AuthWatch report; anything else is a ConfigError (exit 2).

    Reports are parsed with the same duplicate-key and non-finite rejection as input,
    because a report file may have been edited by someone else.
    """
    if path.is_dir():  # Windows raises PermissionError, not IsADirectoryError, for this
        raise ConfigError(f"report path is a directory: {path}")
    try:
        with open(path, "rb") as f:
            data = f.read(REPORT_LIMIT + 1)
    except FileNotFoundError:
        raise ConfigError(f"report not found: {path}") from None
    except OSError as exc:
        raise OperationalError(f"cannot read report: {path}") from exc
    if len(data) > REPORT_LIMIT:
        raise ConfigError(f"report is larger than 256 MiB: {path}")
    try:
        report = parse_json_line(data)
    except (ValueError, RecursionError):
        raise ConfigError(f"not a valid AuthWatch report (unreadable JSON): {path}") from None
    envelope = report.get("envelope") if isinstance(report, dict) else None
    if not (isinstance(envelope, dict) and envelope.get("tool") == "AuthWatch"
            and envelope.get("schema") == "7d7b-report"):
        raise ConfigError(f"not an AuthWatch report: {path}")
    if not (isinstance(report.get("findings"), list) and isinstance(report.get("input"), dict)
            and all(_is_finding(f) for f in report["findings"])):
        raise ConfigError(f"AuthWatch report is malformed (findings or input): {path}")
    return report


def _is_finding(f: object) -> bool:
    return (isinstance(f, dict) and isinstance(f.get("details"), dict)
            and isinstance(f["details"].get("alert_id"), str)
            and isinstance(f.get("event"), str) and isinstance(f.get("subject"), str))


def find_alert(report: dict, alert_id: str) -> dict:
    """The finding whose id equals ``alert_id`` or starts with it (at least 4 hex chars)."""
    wanted = alert_id.strip().lower()
    if len(wanted) < MIN_ID_PREFIX or not set(wanted) <= _HEX:
        raise ConfigError(f"an alert id is {MIN_ID_PREFIX}-16 hex characters, e.g. 3fa9c0d1")
    matches = [f for f in report["findings"] if f["details"]["alert_id"].startswith(wanted)]
    if not matches:
        raise ConfigError(f"no alert with id {wanted} in this report")
    if len(matches) > 1:
        raise ConfigError(f"alert id prefix {wanted} matches {len(matches)} alerts; give more "
                          "characters")
    return matches[0]


def candidate_inputs(report: dict, report_path: Path) -> list[Path]:
    """Where to look for the analyzed file when --input is not given: its base name next to
    the report, then in the current directory. A label with a path in it is not used."""
    label = report["input"].get("label")
    if not isinstance(label, str) or not label or Path(label).name != label or label in (".", ".."):
        return []
    return [report_path.parent / label, Path(label)]


@dataclass
class Evidence:
    sha256: str
    size: int
    lines: dict[int, str | None] = field(default_factory=dict)  # None: line not readable


def read_evidence(path: Path, wanted: set[int]) -> Evidence:
    """Hash the whole file exactly as ``analyze`` does and keep the wanted lines' text."""
    digest = InputDigest()
    found: dict[int, str | None] = {}
    try:
        with open(path, "rb") as f:
            for line in read_lines(f, digest):
                if line.no in wanted:
                    found[line.no] = (None if line.raw is None
                                      else line.raw.decode("utf-8", errors="replace"))
    except OSError as exc:
        raise OperationalError(f"cannot read input: {path}") from exc
    return Evidence(digest.hexdigest(), digest.size, found)


def verify(evidence: Evidence, report: dict, path: Path) -> None:
    """Refuse to show evidence from a file that is not the one the report analyzed."""
    expected = report["input"].get("sha256")
    size = report["input"].get("size_bytes")
    if evidence.sha256 != expected or (isinstance(size, int) and evidence.size != size):
        raise VerificationError(
            f"sha256 mismatch: {path} is not the file this report analyzed (it changed, or it "
            "is a different file); refusing to show evidence")


RECORD_FIELDS = ("timestamp", "outcome", "username", "source_ip", "source_port")


def record_fields(text: str | None) -> dict | None:
    """The key fields of a JSONL evidence line, or None if it is not a JSON object."""
    if text is None:
        return None
    try:
        obj = parse_json_line(text.encode("utf-8"))
    except (ValueError, RecursionError):
        return None
    if not isinstance(obj, dict):
        return None
    return {k: obj.get(k) for k in RECORD_FIELDS}


def evidence_line_numbers(finding: dict) -> list[int]:
    ev = finding["details"].get("evidence") or {}
    lines = [n for n in ev.get("lines", []) if isinstance(n, int) and n > 0]
    success = ev.get("success_line")
    if isinstance(success, int) and success > 0 and success not in lines:
        lines.append(success)
    return lines


def _comparable_parameters(report: dict) -> dict:
    params = report.get("parameters") if isinstance(report.get("parameters"), dict) else {}
    return {k: params.get(k) for k in _ID_PARAMETERS}


def diff_reports(old: dict, new: dict) -> dict:
    """New, resolved and ongoing alerts between two runs, matched by alert id.

    An alert id hashes the rule, subject, first-seen time and thresholds, so the same
    episode seen again (even with more events) keeps its id.
    """
    old_by_id = {f["details"]["alert_id"]: f for f in old["findings"]}
    new_by_id = {f["details"]["alert_id"]: f for f in new["findings"]}
    warnings = []
    if _comparable_parameters(old) != _comparable_parameters(new):
        warnings.append("the two runs used different rules, thresholds, windows or redaction; "
                        "alert ids are not comparable, so most alerts will look new/resolved")
    for name, rep in (("old", old), ("new", new)):
        red = (rep.get("parameters") or {}).get("redaction")
        if isinstance(red, dict) and red.get("key_source") == "ephemeral":
            warnings.append(f"the {name} run used an ephemeral redaction key; its user alert ids "
                            "cannot match another run (set AUTHWATCH_REDACT_KEY)")
        if rep.get("status") == "incomplete":
            warnings.append(f"the {name} run is incomplete (coverage partial); alerts it lacks "
                            "may simply not have been seen")
    if old["input"].get("sha256") == new["input"].get("sha256"):
        warnings.append("both runs analyzed the same file")
    ongoing = []
    for alert_id, f in new_by_id.items():
        if alert_id in old_by_id:
            ongoing.append({"alert_id": alert_id,
                            "old_count": old_by_id[alert_id]["details"].get("count"),
                            "new_count": f["details"].get("count"), "finding": f})
    return {
        "old": _run_summary(old),
        "new": _run_summary(new),
        "warnings": warnings,
        "new_alerts": [f for i, f in new_by_id.items() if i not in old_by_id],
        "resolved": [f for i, f in old_by_id.items() if i not in new_by_id],
        "ongoing": ongoing,
        "complete": old.get("status") != "incomplete" and new.get("status") != "incomplete",
    }


def _run_summary(report: dict) -> dict:
    env = report["envelope"]
    return {"label": report["input"].get("label"), "sha256": report["input"].get("sha256"),
            "status": report.get("status"), "run_id": env.get("run_id"),
            "completed_at": env.get("completed_at"), "alerts": len(report["findings"])}


def diff_exit_code(result: dict) -> int:
    """4 if either run was incomplete, else 1 if anything is new, else 0."""
    if not result["complete"]:
        return 4
    return 1 if result["new_alerts"] else 0


def to_json_bytes(obj: dict) -> bytes:
    return (json.dumps(obj, indent=2, ensure_ascii=True) + "\n").encode("ascii")
