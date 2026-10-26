"""Report assembly in the shared ``7d7b-report`` envelope (Spec §8.3, §8.5, decision D6)."""

import json
from collections.abc import Sequence

from authwatch import __version__
from authwatch.coverage import Counters, ErrorLog

ENVELOPE_SCHEMA = "7d7b-report"
ENVELOPE_VERSION = 1
TOOL = "AuthWatch"


def build_report(*, run_id: str, started_at: str, completed_at: str, status: str, result: str,
                 input_info: dict, parameters: dict, complete: bool, reasons: list[str],
                 counters: Counters, rule_runs: Sequence, timeline: dict,
                 errors: ErrorLog) -> dict:
    """Everything except ``envelope.run_id`` / ``started_at`` / ``completed_at`` is a pure
    function of the input bytes and parameters."""
    alerts = sorted((a for r in rule_runs for a in r.alerts), key=lambda a: a.sort_key())
    summary = {r.rule_id: len(r.alerts) for r in rule_runs}
    summary["errors"] = errors.total
    return {
        "envelope": {
            "schema": ENVELOPE_SCHEMA, "schema_version": ENVELOPE_VERSION,
            "tool": TOOL, "tool_version": __version__,
            "run_id": run_id, "started_at": started_at, "completed_at": completed_at,
        },
        "status": status,
        "result": result,
        "input": input_info,
        "parameters": parameters,
        "coverage": {
            "complete": complete,
            "reasons": reasons,
            "counters": counters.as_dict(),
            "rules": {
                r.rule_id: {
                    "uncorrelatable": r.uncorrelatable_total,
                    "by_reason": {k: r.uncorrelatable[k] for k in sorted(r.uncorrelatable)
                                  if r.uncorrelatable[k]},
                    "alerts_suppressed": r.suppressed,
                } for r in rule_runs
            },
            "timeline": timeline,
        },
        "summary": summary,
        "findings": [a.finding for a in alerts],
        "errors": list(errors.items),
        "errors_truncated": errors.truncated,
    }


def to_json_bytes(report: dict) -> bytes:
    """ASCII-only, indented, LF-terminated JSON (independent of console code pages)."""
    return (json.dumps(report, indent=2, ensure_ascii=True) + "\n").encode("ascii")
