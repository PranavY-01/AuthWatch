"""Command-line interface (Typer). Orchestrates the engine; owns all exit-code mapping."""

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
from authwatch.adapters.openssh import OpenSSHAdapter
from authwatch.coverage import Counters, ErrorLog, derive, exit_code, timeline
from authwatch.errors import AuthWatchError, ConfigError, OperationalError
from authwatch.events import Event, Interner, build_event, dedupe
from authwatch.exporters import normalized_jsonl, write_csv
from authwatch.keys import username_key
from authwatch.models import EVENT, INVALID, IRRELEVANT, UNSUPPORTED
from authwatch.outputs import check_input, check_output_path, write_atomic
from authwatch.reader import SAMPLE_SIZE, InputDigest, check_whole_input, read_lines
from authwatch.redact import NoRedaction, from_environment
from authwatch.render import console, err_console, render_summary, safe_display
from authwatch.reporter import build_report, to_json_bytes
from authwatch.rules import RULE_IDS, Params, parse_rules, run_rules
from authwatch.timeparse import parse_assumed_tz, parse_duration

app = typer.Typer(pretty_exceptions_enable=False, add_completion=False, no_args_is_help=True,
                  help="AuthWatch: authentication-log analyzer with honest coverage reporting.")

ASSUME_YEAR_MIN, ASSUME_YEAR_MAX = 1970, 2100


class InputFormat(str, Enum):
    jsonl = "jsonl"
    openssh = "openssh"


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
    records: list[dict] = field(default_factory=list)


def ingest(path: Path, adapter, keep_records: bool = False) -> Ingested:
    """Read, adapt and count every record. Fatal problems raise; record problems are counted.

    ``keep_records`` keeps the validated records (for normalize) instead of building Events.
    """
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
                    if keep_records:
                        result.records.append(auth_event.model_dump())
                        continue
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


_FORMAT_HELP = ("jsonl (normalized events) or openssh (EXPERIMENTAL: validated only against "
                "authored samples).")


def _prepare(input_format: InputFormat, assume_year: Optional[int], assume_tz: Optional[str]):
    """Validate the syslog assumptions and build the adapter for the chosen format."""
    if assume_year is not None and not ASSUME_YEAR_MIN <= assume_year <= ASSUME_YEAR_MAX:
        raise ConfigError(f"--assume-year must be between {ASSUME_YEAR_MIN} and {ASSUME_YEAR_MAX}")
    tz = parse_assumed_tz(assume_tz) if assume_tz is not None else None
    if input_format is InputFormat.openssh:
        return OpenSSHAdapter(assume_year, tz)
    return JsonlAdapter()


def _redactor(redact_usernames: bool):
    return from_environment(os.environ) if redact_usernames else NoRedaction()


InputArg = Annotated[Path, typer.Argument(metavar="INPUT", help="Input file.", show_default=False)]
InputFormatOpt = Annotated[InputFormat, typer.Option("--input-format", help=_FORMAT_HELP)]
AssumeYearOpt = Annotated[Optional[int], typer.Option(
    "--assume-year", help="Year for classic syslog timestamps (openssh).", show_default=False)]
AssumeTzOpt = Annotated[Optional[str], typer.Option(
    "--assume-tz", help="Fixed offset for classic syslog timestamps: Z, UTC or +HH:MM.",
    show_default=False)]
RedactOpt = Annotated[bool, typer.Option("--redact-usernames",
                                         help="Replace usernames in all output with keyed tokens.")]
ForceOpt = Annotated[bool, typer.Option("--force-report",
                                        help="Allow overwriting an existing non-report file.")]


@app.command("analyze", help="Analyze an authentication log and report alerts and coverage.")
@guarded
def analyze(
    input_path: InputArg,
    input_format: InputFormatOpt = InputFormat.jsonl,
    assume_year: AssumeYearOpt = None,
    assume_tz: AssumeTzOpt = None,
    fail_threshold: Annotated[int, typer.Option("--fail-threshold",
                                                help="Failures per window for AW-001/002.")] = 5,
    fail_window: Annotated[str, typer.Option("--fail-window",
                                             help="Window for AW-001/002, e.g. 300s, 5m.")] = "300s",
    spray_threshold: Annotated[int, typer.Option("--spray-threshold",
                                                 help="Distinct accounts per window for AW-003.")] = 10,
    spray_window: Annotated[str, typer.Option("--spray-window", help="Window for AW-003.")] = "600s",
    lookback: Annotated[str, typer.Option("--lookback",
                                          help="Failure lookback before a success (AW-004).")] = "900s",
    rules: Annotated[Optional[str], typer.Option("--rules",
                                                 help="Comma-separated rule ids, e.g. AW-001,AW-004.",
                                                 show_default="all")] = None,
    report: Annotated[Optional[Path], typer.Option("--report", help="Write the JSON report here.",
                                                   show_default=False)] = None,
    csv_path: Annotated[Optional[Path], typer.Option("--csv", help="Write an alert table as CSV.",
                                                     show_default=False)] = None,
    force_report: ForceOpt = False,
    fmt: Annotated[OutputFormat, typer.Option("--format",
                                              help="text summary, or the JSON report on stdout.")] = OutputFormat.text,
    redact_usernames: RedactOpt = False,
) -> int:
    started = _now()
    params = Params(fail_threshold=fail_threshold, fail_window_s=parse_duration(fail_window),
                    spray_threshold=spray_threshold, spray_window_s=parse_duration(spray_window),
                    lookback_s=parse_duration(lookback))
    params.validate()
    enabled = parse_rules(rules) if rules is not None else list(RULE_IDS)
    adapter = _prepare(input_format, assume_year, assume_tz)
    check_input(input_path)
    if report is not None:
        check_output_path(report, input_path, [csv_path] if csv_path else [], probe_report=True,
                          force=force_report)
    if csv_path is not None:
        check_output_path(csv_path, input_path, [report] if report else [], probe_report=False,
                          force=force_report)
    redactor = _redactor(redact_usernames)

    ing = ingest(input_path, adapter)
    counters = ing.counters
    analyzed, dropped, conflicts = dedupe(ing.events)
    counters.duplicates_dropped = dropped
    counters.duplicate_conflicts = len(conflicts)
    for e in conflicts:
        ing.errors.add("DUPLICATE_CONFLICT", e.line, "duplicate_conflict")
    counters.events_analyzed = len(analyzed)
    runs = run_rules(analyzed, params, enabled, redactor)
    status, result, complete, reasons = derive(counters, runs, len(analyzed))

    parameters = {
        "rules": enabled,
        "fail_threshold": params.fail_threshold, "fail_window_s": params.fail_window_s,
        "spray_threshold": params.spray_threshold, "spray_window_s": params.spray_window_s,
        "lookback_s": params.lookback_s,
        "redaction": redactor.describe(),
        "input_format": input_format.value, "assume_year": assume_year, "assume_tz": assume_tz,
    }
    input_info = {"label": input_path.name, "format": input_format.value,
                  "sha256": ing.digest.hexdigest(), "size_bytes": ing.digest.size}
    report_dict = build_report(
        run_id=str(uuid.uuid4()), started_at=started, completed_at=_now(), status=status,
        result=result, input_info=input_info, parameters=parameters, complete=complete,
        reasons=reasons, counters=counters, rule_runs=runs, timeline=timeline(analyzed),
        errors=ing.errors)
    data = to_json_bytes(report_dict)
    if report is not None:
        write_atomic(report, data)
    if csv_path is not None:
        write_atomic(csv_path, write_csv(report_dict["findings"]))
    if fmt is OutputFormat.json:
        _write_stdout(data)
    else:
        render_summary(report_dict)
    return exit_code(status)


@app.command("normalize", help="Write validated events as schema-1.0 JSONL (input to analyze).")
@guarded
def normalize(
    input_path: InputArg,
    output: Annotated[Path, typer.Option("--output", help="Normalized JSONL output path.",
                                         show_default=False)],
    input_format: InputFormatOpt = InputFormat.jsonl,
    assume_year: AssumeYearOpt = None,
    assume_tz: AssumeTzOpt = None,
    redact_usernames: RedactOpt = False,
    force_report: ForceOpt = False,
) -> int:
    adapter = _prepare(input_format, assume_year, assume_tz)
    check_input(input_path)
    check_output_path(output, input_path, [], probe_report=False, force=force_report)
    redactor = _redactor(redact_usernames)
    ing = ingest(input_path, adapter, keep_records=True)
    if redact_usernames:
        for rec in ing.records:
            if rec["username"] is not None:
                key, _ = username_key(rec["username"])
                rec["username"] = redactor.token(key) if key is not None else ""
    write_atomic(output, normalized_jsonl(ing.records))
    c = ing.counters
    written = len(ing.records)
    console.print(f"normalize: wrote {written} events to {safe_display(output.name)} "
                  f"({c.records_read} records read, {c.records_irrelevant} irrelevant)",
                  soft_wrap=True)
    if c.records_invalid or c.records_unsupported or not written:
        err_console.print(f"warning: incomplete normalization - {c.records_invalid} invalid, "
                          f"{c.records_unsupported} unsupported, {written} events written",
                          soft_wrap=True)
        for err in ing.errors.items[:10]:
            err_console.print(f"  {err['subject'].replace(':', ' ', 1)}  {err['message']}",
                              soft_wrap=True)
        return 4
    return 0


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
