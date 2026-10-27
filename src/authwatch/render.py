"""Terminal output (Rich). Every untrusted string goes through ``safe_display``.
This and cli.py are the only modules that import Rich."""

import os

from rich import box
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from authwatch import __version__
from authwatch.rules import reason_text

console = Console(highlight=False, emoji=False)
err_console = Console(stderr=True, highlight=False, emoji=False)

DISPLAY_MAX = 200
RECORD_MAX = 1000
TERMINAL_ALERTS = 20
TERMINAL_ERRORS = 10
PIPE_WIDTH = 120
ACCENT = "bright_cyan"
NOTE = "alerts are investigation leads, not proof of compromise"

SEVERITY_BADGE = {"HIGH": "bold white on red3", "MEDIUM": "bold black on yellow3",
                  "LOW": "bold white on blue"}
STATUS_LOOK = {  # label, badge style, border colour
    "clean": ("CLEAN", "bold white on green4", "green"),
    "alerts_detected": ("ALERTS DETECTED", "bold black on yellow3", "yellow"),
    "incomplete": ("INCOMPLETE", "bold white on red3", "red"),
}
REASON_HINTS = {
    "line_too_long": "line longer than 64 KiB",
    "nul_byte": "line contains a NUL byte",
    "invalid_utf8": "bytes are not valid UTF-8",
    "invalid_json": "not parseable JSON (truncated, malformed, or a BOM after line 1)",
    "duplicate_key": "the same key appears twice in one object",
    "invalid_value": "NaN, Infinity, an overflowing number or a huge integer",
    "nesting_too_deep": "JSON nested too deeply",
    "not_an_object": "line is a JSON array or bare value, not an object",
    "invalid_timestamp": "timestamp must be RFC 3339 with Z or an offset, e.g. 2026-10-26T10:30:00Z",
    "duplicate_conflict": "same record_id as an earlier line, different content",
}


def _printable(s: str, limit: int = DISPLAY_MAX) -> str:
    out = []
    for ch in s:
        if ch.isprintable():
            out.append(ch)
        else:
            cp = ord(ch)
            out.append(f"\\x{cp:02x}" if cp < 0x100 else f"\\u{cp:04x}")
    text = "".join(out)
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def safe_display(s: object, limit: int = DISPLAY_MAX) -> str:
    """Make an untrusted string inert: non-printables become escapes, Rich markup is escaped,
    and the result is truncated (200 characters unless ``limit`` says otherwise)."""
    return escape(_printable(str(s), limit))


def _value(v: object) -> str:
    """A record field for display; a missing value is shown as a dim dash."""
    return "[dim]—[/]" if v is None else safe_display(v)


def reason_hint(code: str) -> str:
    if code.startswith("schema_invalid:"):
        fields = code.split(":", 1)[1].replace("unknown_field", "an unknown field")
        return f"wrong type, missing or not allowed: {fields}"
    return REASON_HINTS.get(code, "")


# ----------------------------------------------------------------------------- building blocks
def _fit(out: Console) -> None:
    """Pipes and files get a fixed, roomy width so tables do not wrap at 80 columns."""
    if not out.is_terminal and "COLUMNS" not in os.environ and out.width < PIPE_WIDTH:
        out.width = PIPE_WIDTH


def badge(text: str, style: str) -> str:
    return f"[{style}] {text} [/]"


def severity_badge(severity: str) -> str:
    return badge(f"{severity:^6}", SEVERITY_BADGE.get(severity, "bold reverse"))


def _header(out: Console, command: str, subject: str, detail: str = "") -> None:
    body = f"[bold]{command}[/]  [bold {ACCENT}]{subject}[/]"
    if detail:
        body += f"  [dim]·[/]  {detail}"
    out.print(Panel(body, title=f"[bold {ACCENT}]AuthWatch[/] [dim]{__version__}[/]",
                    title_align="left", border_style=ACCENT, box=box.ROUNDED, padding=(0, 1)))


def _facts(rows: list[tuple[str, str]]) -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=f"bold {ACCENT}", no_wrap=True)
    grid.add_column()
    for label, value in rows:
        grid.add_row(label, value)
    return grid


def _count(n: int, bad: bool = False) -> str:
    if bad and n:
        return f"[bold red]{n}[/]"
    return f"[bold]{n}[/]"


def _result(out: Console, label: str, style: str, colour: str, message: str,
            *notes: str) -> None:
    lines = [f"{badge(label, style)}  [bold]{message}[/]"]
    lines += [f"[dim]{n}[/]" for n in notes]
    out.print(Panel("\n".join(lines), border_style=colour, box=box.HEAVY, padding=(0, 1)))


def _alert_table(findings: list[dict], title: str, title_style: str, *,
                 count_text=None, extra=None) -> Table:
    table = Table(title=f"[{title_style}]{title}[/]", title_justify="left", box=box.ROUNDED,
                  header_style=f"bold {ACCENT}", border_style="grey50", pad_edge=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", style="bold", no_wrap=True)
    table.add_column("Subject", no_wrap=True)
    table.add_column("Count", justify="right", no_wrap=True)
    table.add_column("Window", justify="right", no_wrap=True)
    table.add_column(extra[0] if extra else "Why")
    table.add_column("Alert id", style="dim", no_wrap=True)
    for f in findings:
        d = f["details"]
        count = count_text(f) if count_text else f"[bold]{d.get('count')}[/]"
        last = safe_display(extra[1](f)) if extra else safe_display(reason_text(f))
        table.add_row(severity_badge(str(d.get("severity"))), safe_display(f["event"]),
                      safe_display(f["subject"]), count, f"{d.get('window_seconds')}s", last,
                      safe_display(str(d.get("alert_id"))[:8]))
    return table


# ----------------------------------------------------------------------------------- analyze
def render_summary(report: dict, out: Console | None = None) -> None:
    out = out or console
    _fit(out)
    inp, cov = report["input"], report["coverage"]
    c, tl = cov["counters"], cov.get("timeline") or {}
    status, findings = report["status"], report["findings"]

    _header(out, "analyze", safe_display(inp["label"]),
            f"{inp['format']}  [dim]·[/]  sha256 [bold]{inp['sha256'][:12]}[/]…")
    records = (f"{_count(c['records_read'])} read · {_count(c['events_normalized'])} events · "
               f"{_count(c['records_invalid'], True)} invalid · "
               f"{_count(c['records_unsupported'], True)} unsupported · "
               f"{_count(c['records_irrelevant'])} irrelevant · "
               f"{_count(c['duplicates_dropped'])} duplicates dropped")
    if c["duplicate_conflicts"]:
        records += f" · {_count(c['duplicate_conflicts'], True)} duplicate conflicts"
    facts = [("Records", records)]
    if cov["complete"]:
        facts.append(("Coverage", "[bold green]complete[/] · every record was analyzed"))
    else:
        facts.append(("Coverage", f"[bold red]PARTIAL[/] · {', '.join(cov['reasons'])}"))
    if tl.get("earliest"):
        facts.append(("Time span", f"{tl['earliest']} [dim]to[/] {tl['latest']}"))
    if tl.get("out_of_order_records") or tl.get("largest_gap_seconds"):
        facts.append(("Timeline", f"{tl['out_of_order_records']} out-of-order records · "
                                  f"largest gap {tl['largest_gap_seconds']}s"))
    out.print(_facts(facts))
    out.print()

    if not cov["complete"]:
        out.print(_gaps_panel(report))
    if findings:
        table = _alert_table(findings[:TERMINAL_ALERTS],
                             f"{len(findings)} alert{'s' if len(findings) != 1 else ''}",
                             "bold yellow")
        if len(findings) > TERMINAL_ALERTS:
            table.caption = f"… {len(findings) - TERMINAL_ALERTS} more alerts in the report"
        out.print(table)
        out.print()

    n = len(findings)
    label, style, colour = STATUS_LOOK[status]
    if status == "clean":
        _result(out, label, style, colour,
                f"{c['events_analyzed']} events analyzed, no rule fired",
                "this does not prove the system is secure", NOTE)
    elif status == "alerts_detected":
        first_id = safe_display(str(findings[0]["details"].get("alert_id"))[:8])
        _result(out, label, style, colour, f"{n} alerts · {NOTE}",
                f"inspect one: authwatch explain {first_id} --report <report.json>")
    elif n == 0:
        _result(out, label, style, colour,
                "no alerts in the analyzable data — this is NOT a clean result (exit 4)", NOTE)
    else:
        lost = c["records_invalid"] + c["records_unsupported"]
        why = f"{lost} records could not be analyzed" if lost else "coverage is partial"
        _result(out, label, style, colour,
                f"{n} alerts found, but {why} — activity may be unseen (exit 4)", NOTE)


def _gaps_panel(report: dict) -> Panel:
    cov = report["coverage"]
    parts: list = []
    for rule_id, rc in cov["rules"].items():
        if rc["uncorrelatable"]:
            detail = ", ".join(f"{k} {v}" for k, v in rc["by_reason"].items())
            parts.append(f"[bold]{rule_id}[/] could not use {rc['uncorrelatable']} relevant "
                         f"events ({detail})")
        if rc["alerts_suppressed"]:
            parts.append(f"[bold]{rule_id}[/] alert cap reached: {rc['alerts_suppressed']} more "
                         "episodes were counted but not recorded")
    errors = report["errors"]
    if errors:
        table = Table(box=box.SIMPLE_HEAD, header_style="bold red", pad_edge=False)
        table.add_column("Line", justify="right", style="bold", no_wrap=True)
        table.add_column("Reason", style="red")
        table.add_column("Meaning", style="dim")
        for err in errors[:TERMINAL_ERRORS]:
            table.add_row(safe_display(err["subject"].split(":", 1)[-1]),
                          safe_display(err["message"]), safe_display(reason_hint(err["message"])))
        parts.append(table)
    more = report["summary"]["errors"] - min(len(errors), TERMINAL_ERRORS)
    if more > 0:
        parts.append(f"[dim]… {more} more errors in the report[/]")
    if any(e["message"] == "repeat_summary" for e in errors):
        parts.append("[yellow]hint:[/] 'message repeated N times' lines hide events; disable "
                     "repeat reduction in the syslog daemon")
    return Panel(Group(*parts), title="[bold red]Coverage gaps[/]", title_align="left",
                 border_style="red", box=box.ROUNDED)


# ----------------------------------------------------------------------------------- explain
def render_explain(data: dict, out: Console | None = None) -> None:
    out = out or console
    _fit(out)
    f = data["finding"]
    d = f["details"]
    ev = d.get("evidence") or {}
    _header(out, "explain", safe_display(str(d.get("alert_id"))),
            f"from {safe_display(data['report_label'])}")

    facts = [
        ("Subject", f"[bold]{safe_display(f['subject'])}[/]"),
        ("First seen", safe_display(d.get("first_seen"))),
        ("Last seen", safe_display(d.get("last_seen"))),
        ("Count", f"[bold]{safe_display(d.get('count'))}[/] events · peak "
                  f"[bold]{safe_display(d.get('peak_in_window'))}[/] in one window"),
        ("Threshold", f"{safe_display(d.get('threshold'))} within "
                      f"{safe_display(d.get('window_seconds'))}s"),
        ("ATT&CK", safe_display(", ".join(map(str, d.get("attack") or [])) or "—")),
    ]
    if "success_line" in ev:
        changed = ev.get("ip_changed")
        facts.append(("Success", f"line {safe_display(ev.get('success_line'))} from "
                                 f"{safe_display(ev.get('success_ip') or 'unknown IP')}"
                                 + (" · [bold red]new source IP[/]" if changed else "")))
    body = Group(_facts(facts), "", safe_display(d.get("description"), RECORD_MAX),
                 *[f"[yellow]caveat:[/] [dim]{safe_display(c, RECORD_MAX)}[/]"
                   for c in d.get("caveats") or []])
    title = (f"{severity_badge(str(d.get('severity')))} [bold]{safe_display(f['event'])}[/] "
             f"{safe_display(d.get('title'))}")
    out.print(Panel(body, title=title, title_align="left", border_style="yellow",
                    box=box.ROUNDED, padding=(0, 1)))

    if data.get("redacted"):
        out.print(Panel("This report was redacted, but the evidence lines below come from the "
                        "original file and show [bold]real usernames[/].",
                        border_style="red", box=box.ROUNDED))
    out.print()
    out.print(f"{badge('VERIFIED', STATUS_LOOK['clean'][1])}  sha256 [bold]{data['sha256'][:12]}[/]… "
              f"matches the report · {data['size']} bytes · {safe_display(data['input_path'])}",
              soft_wrap=True)
    out.print()
    table = Table(title="[bold]Evidence from the original file[/]", title_justify="left",
                  box=box.ROUNDED, header_style=f"bold {ACCENT}", border_style="grey50")
    table.add_column("Line", justify="right", style="bold", no_wrap=True)
    fielded = not data.get("raw") and all(r.get("fields") for r in data["lines"])
    if not fielded:
        table.add_column("Role", no_wrap=True)
    if fielded:
        for name in ("Timestamp", "Outcome", "Username", "Source IP", "Port"):
            table.add_column(name, no_wrap=name != "Username", overflow="fold")
    else:
        table.add_column("Record", overflow="fold")
    for row in data["lines"]:
        role = "[bold green]success[/]" if row["role"] == "success" else "[red]failure[/]"
        if fielded:
            f = row["fields"]
            outcome = str(f["outcome"])
            colour = {"success": "green", "failure": "red"}.get(outcome, "yellow")
            cells = [_value(f["timestamp"]), f"[{colour}]{_value(f['outcome'])}[/]",
                     f"[bold]{_value(f['username'])}[/]", _value(f["source_ip"]),
                     _value(f["source_port"])]
        elif row["text"] is None:
            cells = ["[dim](line not readable)[/]"]
        else:
            cells = [safe_display(row["text"], RECORD_MAX)]
        row_style = "bold on grey23" if row["role"] == "success" else None
        if fielded:
            table.add_row(str(row["line"]), *cells, style=row_style)
        else:
            table.add_row(str(row["line"]), role, *cells, style=row_style)
    if ev.get("lines_truncated"):
        table.caption = (f"showing the first 25 and last 25 of {safe_display(d.get('count'))} "
                         "events; the report keeps no more")
    out.print(table)


# -------------------------------------------------------------------------------------- diff
def render_diff(result: dict, out: Console | None = None) -> None:
    out = out or console
    _fit(out)
    old, new = result["old"], result["new"]
    _header(out, "diff", f"{safe_display(old['label'])} → {safe_display(new['label'])}")

    def run_line(r: dict) -> str:
        look = STATUS_LOOK.get(r["status"])
        status = badge(look[0], look[1]) if look else safe_display(r["status"])
        return (f"{status} · {r['alerts']} alerts · completed {safe_display(r['completed_at'])} "
                f"· sha256 {safe_display(str(r['sha256'])[:12])}…")

    out.print(_facts([("Old run", run_line(old)), ("New run", run_line(new))]))
    out.print()
    if result["warnings"]:
        out.print(Panel("\n".join(f"[yellow]•[/] {safe_display(w, RECORD_MAX)}"
                                  for w in result["warnings"]),
                        title="[bold yellow]Read before trusting the comparison[/]",
                        title_align="left", border_style="yellow", box=box.ROUNDED))

    first_seen = ("First seen", lambda f: f["details"].get("first_seen"))
    if result["new_alerts"]:
        out.print(_alert_table(result["new_alerts"], f"{len(result['new_alerts'])} new",
                               "bold red", extra=first_seen))
    if result["ongoing"]:
        counts = {o["alert_id"]: o for o in result["ongoing"]}

        def growth(f: dict) -> str:
            o = counts[f["details"]["alert_id"]]
            if o["old_count"] == o["new_count"]:
                return f"[bold]{o['new_count']}[/]"
            return f"{o['old_count']} → [bold]{o['new_count']}[/]"

        out.print(_alert_table([o["finding"] for o in result["ongoing"]],
                               f"{len(result['ongoing'])} ongoing", "bold yellow",
                               count_text=growth, extra=first_seen))
    if result["resolved"]:
        out.print(_alert_table(result["resolved"],
                               f"{len(result['resolved'])} no longer reported", "bold green",
                               extra=first_seen))

    summary = (f"{len(result['new_alerts'])} new · {len(result['ongoing'])} ongoing · "
               f"{len(result['resolved'])} no longer reported")
    if not result["complete"]:
        _result(out, "INCOMPLETE", STATUS_LOOK["incomplete"][1], "red", summary,
                "a run had partial coverage: 'no longer reported' may only mean 'not seen' "
                "(exit 4)")
    elif result["new_alerts"]:
        _result(out, "NEW ALERTS", STATUS_LOOK["incomplete"][1], "red", summary, NOTE)
    else:
        _result(out, "NO NEW ALERTS", STATUS_LOOK["clean"][1], "green", summary, NOTE)


# ---------------------------------------------------------------------------------- validate
def render_validate(result: dict, out: Console | None = None, max_errors: int = 50) -> None:
    out = out or console
    _fit(out)
    c = result["counters"]
    _header(out, "validate", safe_display(result["label"]), "schema 1.0 (JSONL)")
    out.print(_facts([
        ("Lines", f"{_count(c['lines_total'])} total · {_count(c['blank_lines'])} blank · "
                  f"{_count(c['records_read'])} records"),
        ("Records", f"{_count(c['events_normalized'])} valid · "
                    f"{_count(c['records_invalid'], True)} invalid"),
    ]))
    out.print()
    errors = result["errors"]
    if errors:
        table = Table(title=f"[bold red]{result['errors_total']} problem lines[/]",
                      title_justify="left", box=box.ROUNDED, header_style="bold red",
                      border_style="grey50")
        table.add_column("Line", justify="right", style="bold", no_wrap=True)
        table.add_column("Reason", style="red")
        table.add_column("What to fix", style="dim")
        for err in errors[:max_errors]:
            table.add_row(safe_display(err["subject"].split(":", 1)[-1]),
                          safe_display(err["message"]), safe_display(reason_hint(err["message"])))
        if result["errors_total"] > min(len(errors), max_errors):
            table.caption = (f"… {result['errors_total'] - min(len(errors), max_errors)} more "
                             "(use --max-errors or --format json)")
        out.print(table)
    limits = [(k, v) for k, v in result["limits"].items() if v]
    if limits or result["warnings"]:
        table = Table(title="[bold yellow]Valid, but worth knowing[/]", title_justify="left",
                      box=box.ROUNDED, header_style="bold yellow", border_style="grey50")
        table.add_column("Finding")
        table.add_column("Records", justify="right", style="bold")
        for k, v in limits:
            table.add_row(safe_display(k), str(v))
        for k, v in sorted(result["warnings"].items()):
            table.add_row(f"warning: {safe_display(k)}", str(v))
        if limits:
            table.caption = "analyze reports these as coverage gaps (incomplete, exit 4)"
        out.print(table)
    if result["valid"]:
        _result(out, "VALID", STATUS_LOOK["clean"][1], "green",
                f"all {c['events_normalized']} records match event schema 1.0")
    elif c["records_read"] == 0:
        _result(out, "INVALID", STATUS_LOOK["incomplete"][1], "red",
                "no records found (empty or blank-only file)")
    else:
        _result(out, "INVALID", STATUS_LOOK["incomplete"][1], "red",
                f"{c['records_invalid']} of {c['records_read']} records do not match event "
                "schema 1.0")


# ------------------------------------------------------------------------------------- rules
def render_rules(rows: list[dict], out: Console | None = None) -> None:
    out = out or console
    _fit(out)
    _header(out, "rules", f"{len(rows)} detection rules", "defaults shown; tune with the options")
    table = Table(box=box.ROUNDED, header_style=f"bold {ACCENT}", border_style="grey50")
    table.add_column("Rule", style="bold", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Detects")
    table.add_column("Groups by", no_wrap=True)
    table.add_column("Fires when")
    table.add_column("Tune with", style="dim")
    table.add_column("ATT&CK", style="magenta", no_wrap=True)
    for r in rows:
        table.add_row(r["rule_id"], severity_badge(r["severity"]), r["title"], r["groups_by"],
                      f"≥ [bold]{r['threshold']}[/] {r['metric']} ({r['window_seconds']}s)",
                      f"{r['threshold_option']}\n{r['window_option']}", "\n".join(r["attack"]))
    out.print(table)
    out.print("[dim]Bounds: thresholds 2–100000 · windows 1s–7d · lookback ≥ fail window and "
              "≤ 30d. Select rules with --rules AW-001,AW-004.[/]", soft_wrap=True)
