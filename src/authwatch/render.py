"""Terminal summary (Rich). Every untrusted string goes through ``safe_display``.
This and cli.py are the only modules that import Rich."""

from rich.console import Console
from rich.markup import escape

from authwatch.rules import reason_text

console = Console(highlight=False, emoji=False)
err_console = Console(stderr=True, highlight=False, emoji=False)

DISPLAY_MAX = 200
TERMINAL_ALERTS = 20
TERMINAL_ERRORS = 10
SEVERITY_STYLE = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "cyan"}
NOTE = "alerts are investigation leads, not proof of compromise"


def _printable(s: str) -> str:
    out = []
    for ch in s:
        if ch.isprintable():
            out.append(ch)
        else:
            cp = ord(ch)
            out.append(f"\\x{cp:02x}" if cp < 0x100 else f"\\u{cp:04x}")
    text = "".join(out)
    if len(text) > DISPLAY_MAX:
        text = text[:DISPLAY_MAX] + "…"
    return text


def safe_display(s: object) -> str:
    """Make an untrusted string inert: non-printables become escapes, Rich markup is escaped,
    and the result is truncated to 200 characters."""
    return escape(_printable(str(s)))


def _padded(s: str, width: int) -> str:
    visible = _printable(s)
    return escape(visible) + " " * max(0, width - len(visible))


def render_summary(report: dict, out: Console | None = None) -> None:
    out = out or console

    def say(text: str = "") -> None:
        out.print(text, soft_wrap=True)

    inp = report["input"]
    cov = report["coverage"]
    c = cov["counters"]
    tl = cov.get("timeline") or {}
    status = report["status"]
    findings = report["findings"]

    say(f"[bold]AuthWatch {report['envelope']['tool_version']}[/bold] · analyze "
        f"{safe_display(inp['label'])} ({inp['format']}) · sha256 {inp['sha256'][:12]}…")
    records = (f"Records    {c['records_read']} read · {c['events_normalized']} events · "
               f"{c['records_invalid']} invalid · {c['records_unsupported']} unsupported · "
               f"{c['records_irrelevant']} irrelevant · {c['duplicates_dropped']} duplicates dropped")
    if c["duplicate_conflicts"]:
        records += f" · {c['duplicate_conflicts']} duplicate conflicts"
    say(records)

    span = f" · {tl['earliest']} to {tl['latest']}" if tl.get("earliest") else ""
    if cov["complete"]:
        say(f"Coverage   [green]complete[/green]{span}")
    else:
        say(f"Coverage   [bold red]PARTIAL[/bold red] · {', '.join(cov['reasons'])}{span}")
        for rule_id, rc in cov["rules"].items():
            if rc["uncorrelatable"]:
                detail = ", ".join(f"{k} {v}" for k, v in rc["by_reason"].items())
                say(f"  {rule_id} could not use {rc['uncorrelatable']} relevant events ({detail})")
            if rc["alerts_suppressed"]:
                say(f"  {rule_id} alert cap reached: {rc['alerts_suppressed']} more episodes "
                    "were counted but not recorded")
        errors = report["errors"]
        for err in errors[:TERMINAL_ERRORS]:
            say(f"  {err['subject'].replace(':', ' ', 1)}  {err['message']}")
        more = report["summary"]["errors"] - min(len(errors), TERMINAL_ERRORS)
        if more > 0:
            say(f"  … {more} more errors in the report")
        if any(e["message"] == "repeat_summary" for e in errors):
            say("  hint: 'message repeated N times' lines hide events; disable repeat reduction "
                "in the syslog daemon")
    if tl.get("out_of_order_records") or tl.get("largest_gap_seconds"):
        say(f"Timeline   {tl['out_of_order_records']} out-of-order records · largest gap "
            f"{tl['largest_gap_seconds']}s")

    if findings:
        say()
        say("  Sev     Rule    Subject              Count  Window  Reason")
        for f in findings[:TERMINAL_ALERTS]:
            d = f["details"]
            style = SEVERITY_STYLE.get(d["severity"], "")
            sev = f"[{style}]{d['severity']:<7}[/{style}]" if style else f"{d['severity']:<7}"
            say(f"  {sev} {f['event']:<7} {_padded(f['subject'], 20)} {d['count']:>5} "
                f"{str(d['window_seconds']) + 's':>7}  {safe_display(reason_text(f))}")
        if len(findings) > TERMINAL_ALERTS:
            say(f"  … {len(findings) - TERMINAL_ALERTS} more alerts in the report")
        say()

    n = len(findings)
    if status == "clean":
        say(f"Result     [bold green]CLEAN[/bold green] · {c['events_analyzed']} events analyzed, "
            "no rule fired · this does not prove the system is secure")
        say(f"Note       {NOTE}")
    elif status == "alerts_detected":
        say(f"Result     [bold yellow]ALERTS DETECTED[/bold yellow] · {n} alerts · {NOTE}")
    elif n == 0:
        say("Result     [bold red]INCOMPLETE[/bold red] · no alerts in the analyzable data — "
            "this is NOT a clean result (exit 4)")
        say(f"Note       {NOTE}")
    else:
        lost = c["records_invalid"] + c["records_unsupported"]
        why = (f"{lost} records could not be analyzed" if lost
               else "coverage is partial")
        say(f"Result     [bold red]INCOMPLETE[/bold red] · {n} alerts found, but {why} — "
            "activity may be unseen (exit 4)")
        say(f"Note       {NOTE}")
