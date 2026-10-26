"""Command-line interface (Typer). Orchestrates the engine; owns all exit-code mapping
(Spec §7.3, §9, errata E2, E10, E11)."""

import functools
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer

from authwatch import __version__
from authwatch.adapters.jsonl import JsonlAdapter
from authwatch.coverage import Counters, ErrorLog, derive, exit_code, timeline
from authwatch.errors import AuthWatchError, OperationalError
from authwatch.events import Event, Interner, build_event, dedupe
from authwatch.models import EVENT, INVALID, IRRELEVANT, UNSUPPORTED
from authwatch.outputs import check_input, check_output_path, write_atomic
from authwatch.reader import SAMPLE_SIZE, InputDigest, check_whole_input, read_lines
from authwatch.render import err_console, render_summary, safe_display
from authwatch.reporter import build_report, to_json_bytes
from authwatch.rules import RULE_IDS, Params, run_rules
from authwatch.timeparse import parse_duration

app = typer.Typer(pretty_exceptions_enable=False, add_completion=False, no_args_is_help=True,
                  help="AuthWatch: authentication-log analyzer with honest coverage reporting.")


class OutputFormat(str, Enum):
    text = "text"
    json = "json"


def guarded(fn):
    """Map every outcome to an exit code. An unexpected crash exits 4, never 1."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            code = fn(*args, **kwargs)
        except typer.Exit:
            raise
        except KeyboardInterrupt:
            err_console.print("Interrupted.", soft_wrap=True)
            code = 130
        except AuthWatchError as exc:
            err_console.print(f"error: {safe_display(str(exc))}", soft_wrap=True)
            code = exc.exit_code
        except Exception as exc:  # never let a crash look like a finding
            err_console.print(f"internal error: {safe_display(repr(exc))}", soft_wrap=True)
            code = 4
        raise typer.Exit(code)
    return wrapper


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Ingested:
    counters: Counters
    errors: ErrorLog
    digest: InputDigest
    events: list[Event] = field(default_factory=list)


def ingest(path: Path, adapter) -> Ingested:
    """Read, adapt and count every record. Fatal problems raise; record problems are counted."""
    counters, errors, digest = Counters(), ErrorLog(), InputDigest()
    result = Ingested(counters, errors, digest)
    interner = Interner()
    try:
        f = open(path, "rb")
    except OSError as exc:
        raise OperationalError(f"cannot open input: {path}") from exc
    with f:
        try:
            check_whole_input(f.read(SAMPLE_SIZE))
            f.seek(0)
            for line in read_lines(f, digest):
                counters.lines_total += 1
                if line.blank:
                    counters.blank_lines += 1
                    continue
                counters.records_read += 1
                if line.problem is not None:
                    counters.records_invalid += 1
                    errors.add("INVALID_RECORD", line.no, line.problem)
                    continue
                auth_event, cls, reason = adapter.adapt(line)
                if cls == EVENT:
                    counters.events_normalized += 1
                    event = build_event(auth_event, line.no, counters.events_normalized, interner)
                    if event.warnings:
                        counters.events_with_warnings += 1
                    result.events.append(event)
                elif cls == INVALID:
                    counters.records_invalid += 1
                    errors.add("INVALID_RECORD", line.no, reason)
                elif cls == UNSUPPORTED:
                    counters.records_unsupported += 1
                    errors.add("UNSUPPORTED_RECORD", line.no, reason)
                elif cls == IRRELEVANT:
                    counters.records_irrelevant += 1
                else:
                    raise RuntimeError("adapter returned an unknown classification")
        except OSError as exc:
            raise OperationalError(f"error while reading input: {path}") from exc
    return result


def _write_stdout(data: bytes) -> None:
    """Write bytes unchanged (no CRLF translation on Windows)."""
    sys.stdout.flush()
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        sys.stdout.write(data.decode("ascii"))
    else:
        buffer.write(data)
        buffer.flush()


def _version_callback(value: bool) -> None:
    if value:
        sys.stdout.write(f"authwatch {__version__}\n")
        raise typer.Exit(0)


@app.callback()
def _root(
    version: Annotated[bool, typer.Option("--version", callback=_version_callback, is_eager=True,
                                          help="Show the version and exit.")] = False,
) -> None:
    """AuthWatch: authentication-log analyzer with honest coverage reporting."""


@app.command("analyze", help="Analyze an authentication log and report alerts and coverage.")
@guarded
def analyze(
    input_path: Annotated[Path, typer.Argument(metavar="INPUT", help="File to analyze.",
                                               show_default=False)],
    fail_threshold: Annotated[int, typer.Option("--fail-threshold",
                                                help="Failures per window for AW-001/002.")] = 5,
    fail_window: Annotated[str, typer.Option("--fail-window",
                                             help="Window for AW-001/002, e.g. 300s, 5m.")] = "300s",
    spray_threshold: Annotated[int, typer.Option("--spray-threshold",
                                                 help="Distinct accounts per window for AW-003.")] = 10,
    spray_window: Annotated[str, typer.Option("--spray-window", help="Window for AW-003.")] = "600s",
    lookback: Annotated[str, typer.Option("--lookback",
                                          help="Failure lookback before a success (AW-004).")] = "900s",
    report: Annotated[Optional[Path], typer.Option("--report", help="Write the JSON report here.",
                                                   show_default=False)] = None,
    force_report: Annotated[bool, typer.Option("--force-report",
                                               help="Allow overwriting an existing non-report file.")] = False,
    fmt: Annotated[OutputFormat, typer.Option("--format",
                                              help="text summary, or the JSON report on stdout.")] = OutputFormat.text,
) -> int:
    started = _now()
    params = Params(fail_threshold=fail_threshold, fail_window_s=parse_duration(fail_window),
                    spray_threshold=spray_threshold, spray_window_s=parse_duration(spray_window),
                    lookback_s=parse_duration(lookback))
    params.validate()
    enabled = list(RULE_IDS)
    check_input(input_path)
    if report is not None:
        check_output_path(report, input_path, [], probe_report=True, force=force_report)

    ing = ingest(input_path, JsonlAdapter())
    counters = ing.counters
    analyzed, dropped, conflicts = dedupe(ing.events)
    counters.duplicates_dropped = dropped
    counters.duplicate_conflicts = len(conflicts)
    for e in conflicts:
        ing.errors.add("DUPLICATE_CONFLICT", e.line, "duplicate_conflict")
    counters.events_analyzed = len(analyzed)
    runs = run_rules(analyzed, params, enabled)
    status, result, complete, reasons = derive(counters, runs, len(analyzed))

    parameters = {
        "rules": enabled,
        "fail_threshold": params.fail_threshold, "fail_window_s": params.fail_window_s,
        "spray_threshold": params.spray_threshold, "spray_window_s": params.spray_window_s,
        "lookback_s": params.lookback_s,
        "redaction": None,
        "input_format": "jsonl", "assume_year": None, "assume_tz": None,
    }
    input_info = {"label": input_path.name, "format": "jsonl",
                  "sha256": ing.digest.hexdigest(), "size_bytes": ing.digest.size}
    report_dict = build_report(
        run_id=str(uuid.uuid4()), started_at=started, completed_at=_now(), status=status,
        result=result, input_info=input_info, parameters=parameters, complete=complete,
        reasons=reasons, counters=counters, rule_runs=runs, timeline=timeline(analyzed),
        errors=ing.errors)
    data = to_json_bytes(report_dict)
    if report is not None:
        write_atomic(report, data)
    if fmt is OutputFormat.json:
        _write_stdout(data)
    else:
        render_summary(report_dict)
    return exit_code(status)


def main() -> None:
    """Console-script entry point."""
    # Pipes on Windows default to the ANSI code page; emit UTF-8 there so output does not
    # depend on it, and never crash on a character the stream cannot encode.
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        try:
            if encoding == "utf8":
                stream.reconfigure(errors="backslashreplace")
            else:
                stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    app(prog_name="authwatch")
