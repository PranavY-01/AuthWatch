# AuthWatch

AuthWatch is a Python command-line tool that analyzes authentication logs. It detects suspicious login patterns with sliding-window rules you can inspect, and it never presents a partial analysis as a clean one.

Day 4 of *7 Days – 7 Cybersecurity Projects* (NetScope → TraceDNS → FileSift → **AuthWatch** → WebGuard → ForenSight → IRFlow).

> **Core principle:** an analysis that could not cover all of its input must never be presented as proof that no suspicious activity occurred.

AuthWatch is a triage tool. It reads a file and writes a report. It never blocks addresses, disables accounts or changes anything on the analyzed system. Its alerts are leads for investigation, not proof of compromise, and an IP address does not identify a person.

## Contents

1. [Problem and aim](#problem-and-aim)
2. [Features and non-goals](#features-and-non-goals)
3. [Architecture](#architecture)
4. [Event schema](#event-schema)
5. [Installation](#installation)
6. [Quick start](#quick-start)
7. [Detection rules](#detection-rules)
8. [Coverage: how to read a result](#coverage-how-to-read-a-result)
9. [Example output](#example-output)
10. [Report format](#report-format)
11. [Exit codes](#exit-codes)
12. [Privacy](#privacy)
13. [Windows notes](#windows-notes)
14. [Tests and performance](#tests-and-performance)
15. [Security considerations and limitations](#security-considerations-and-limitations)
16. [Roadmap and licence](#roadmap-and-licence)

## Problem and aim

Authentication records are voluminous, source-specific and easy to misread. Failed logins have innocent causes, such as typos, stale saved passwords or NAT. They also have hostile ones: password guessing, spraying, and credential stuffing.

Naive scripts make this worse in four ways:

- They count in fixed buckets, so a burst that straddles a bucket edge goes unnoticed.
- They group by raw strings, which an attacker can spell differently to split a count.
- They silently drop lines they cannot parse.
- They then print "no findings".

AuthWatch gives a repeatable, explainable answer and states the limits of that answer. Every alert says which rule fired, on which key, how many events, in which window, and which input lines support it. Every report says what could not be analyzed.

## Features and non-goals

**Built (v1.0.0):**

- Bytes-level JSONL reader that withstands hostile input:
  - splits on `\n` only;
  - handles a BOM and CRLF line endings;
  - rejects UTF-16/32 input as a whole;
  - caps lines at 64 KiB, draining over-long lines in bounded chunks;
  - rejects NUL bytes, duplicate JSON keys, NaN/Infinity, huge integers and deep nesting.
- Strict, versioned event schema 1.0 (pydantic v2 strict mode, unknown fields rejected).
- Strict RFC 3339 timestamps. The offset is mandatory and UTC is never assumed; all time arithmetic uses integer microseconds.
- Canonical grouping keys, so spelling and address-form tricks do not split a count:
  - `Alice`, `ａｌｉｃｅ` and `alice` with a zero-width space group as one account;
  - `::ffff:1.2.3.4` groups with `1.2.3.4`.
- Four rules, AW-001 to AW-004, over a sliding window `(t − W, t]`. Each sustained burst produces one alert.
- Honest coverage accounting. `status` is derived from `result` and `coverage`, and partial coverage exits `4`, never `0`.
- JSON report in the shared `7d7b-report` envelope. It records the input SHA-256, the parameters, per-rule coverage, line-number evidence and deterministic alert ids.
- Terminal summary in which every untrusted string is escaped.
- Output-path safety. AuthWatch refuses to write over the input (including a hard link to it), a directory, a symlink or a foreign file, and all writes are atomic.
- `--rules` selection, `--redact-usernames`, a timeline block, and MITRE ATT&CK tags.
- An **experimental** OpenSSH text adapter and a `normalize` command.
- CSV alert export with spreadsheet formula-injection escaping.

**Not built (by design):** ML or LLM interpretation, live SIEM integration, tailing or streaming, automatic blocking, geo-IP, a Windows EVTX reader, journald/gzip/rotated-file handling, a dashboard, a rules DSL, and any claim that an alert proves compromise.

## Architecture

```text
input file ─▶ reader.py ─▶ adapters/{jsonl,openssh}.py ─▶ models.py (strict AuthEvent)
           bytes, \n only    event | irrelevant |           validation, reason codes
           SHA-256, caps     unsupported | invalid
                   ─▶ events.py ─▶ window.py + rules.py ─▶ coverage.py ─▶ reporter.py / render.py / exporters.py
                     canonical keys,  AW-001 … AW-004       reasons →        JSON · terminal · CSV
                     dedupe, sort     episodes, bounded     status, exit       ─▶ outputs.py (atomic, path-safe)
```

The engine (everything except `cli.py` and `render.py`) imports neither `typer` nor `rich`, so it can be used as a library. Detection modules see only normalized events, never raw source syntax. How to use it day to day is in the [user guide](docs/USER_GUIDE.md); implementation decisions, measured performance and known gaps are in [BUILD_NOTES.md](BUILD_NOTES.md).

## Event schema

One JSON object per line (JSONL), UTF-8:

```json
{"event_type":"authentication","outcome":"failure","schema_version":"1.0","source_ip":"203.0.113.50","source_os":"synthetic","source_product":"authwatch-fixture","timestamp":"2026-10-26T10:30:00Z","username":"alice"}
```

| Field | Required key | Nullable | Notes |
|---|---|---|---|
| `schema_version` | yes | no | exactly `"1.0"` |
| `event_type` | yes | no | exactly `"authentication"` |
| `timestamp` | yes | **yes** | `YYYY-MM-DDTHH:MM:SS[.fraction](Z\|±HH:MM)`, ASCII digits; naive values are invalid |
| `outcome` | yes | no | `success` \| `failure` \| `unknown` |
| `username` | yes | **yes** | ≤ 256 characters |
| `source_ip` | yes | **yes** | IPv4/IPv6 string; an IPv6 scope id is tolerated; integers are rejected |
| `source_os`, `source_product` | yes | no | lower-case tokens |
| `source_port`, `event_id`, `record_id`, `source_host`, `failure_reason`, `auth_method`, `logon_type`, `parser_name`, `parse_warnings` | no | yes | see the [user guide](docs/USER_GUIDE.md#41-the-jsonl-event-format) |

"Nullable" does not mean "optional": a missing `timestamp`, `username` or `source_ip` key is an error, so a typo such as `sourceip` cannot silently become `null`. `failure_reason` is allowed only with `outcome: failure`.

**Version policy:** a minor version bump adds optional fields only; a major bump breaks compatibility. AuthWatch 1.0 accepts exactly `"1.0"`. Deduplication uses `(source_product, source_host, record_id)` only, never the record content: two identical failures in the same second are plausible brute force.

## Installation

Requires Python ≥ 3.11. Runtime dependencies are `typer`, `rich` and `pydantic` (v2).

```bash
python -m venv .venv
. .venv/bin/activate              # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
authwatch --version               # or: python -m authwatch --version
```

## Quick start

```bash
python samples/make_samples.py          # regenerate the synthetic fixtures (documentation IP ranges only)
authwatch analyze samples/clean.jsonl                              # exit 0
authwatch analyze samples/attacks.jsonl --report out/report.json   # exit 1
authwatch analyze samples/broken.jsonl                             # exit 4
authwatch analyze samples/attacks.jsonl --format json | python -m json.tool
```

The demos `examples/demo.sh` (bash) and `examples/demo.ps1` (PowerShell) run all of these in a working directory of your choice. `examples/sample-report.json` was produced by a real run on `samples/attacks.jsonl`.

### Commands

```text
authwatch analyze INPUT
    [--input-format jsonl|openssh] [--assume-year YYYY] [--assume-tz Z|UTC|±HH:MM]
    [--fail-threshold N] [--fail-window DUR] [--spray-threshold N] [--spray-window DUR]
    [--lookback DUR] [--rules AW-001,...] [--report PATH] [--csv PATH] [--force-report]
    [--format text|json] [--redact-usernames]

authwatch normalize INPUT --output PATH
    [--input-format ...] [--assume-year ...] [--assume-tz ...] [--redact-usernames] [--force-report]
```

`DUR` is an integer followed by `s`, `m`, `h` or `d` (`300s`, `5m`, `1h`, `2d`).

The following bounds apply whatever rules are enabled:

- thresholds: 2 to 100 000;
- `fail` and `spray` windows: 1 s to 7 d;
- `lookback`: at least the fail window and at most 30 d;
- `--assume-year`: 1970 to 2100.

### OpenSSH adapter (experimental)

`--input-format openssh` reads sshd lines in two forms:

- classic syslog (`Oct 26 10:30:00 host sshd[1234]: …`). These lines have no year and no timezone, so `--assume-year` and a fixed-offset `--assume-tz` are required, and nothing is guessed.
- RFC 3339-prefixed lines.

Only `Failed …` and `Accepted …` messages become events. Known sshd bookkeeping and other processes are counted as irrelevant. Any other sshd message, and rsyslog's "message repeated N times" summaries, are **unsupported**, which makes coverage partial.

**Status: experimental — validated only against authored samples, not real sshd logs.** Run it against sanitized real samples before relying on it.

`normalize` writes validated events as schema-1.0 JSONL that `analyze` accepts unchanged.

## Detection rules

| Rule | Title | Key | Metric | Default | Severity | ATT&CK (advisory) |
|---|---|---|---|---|---|---|
| AW-001 | Failed-login burst from one source IP | source IP | failures in window | 5 in 300 s | MEDIUM | T1110 |
| AW-002 | Repeated failures against one account | account | failures in window | 5 in 300 s | MEDIUM | T1110.001 |
| AW-003 | One source IP failing against many accounts | source IP | distinct accounts in window | 10 in 600 s | MEDIUM | T1110.003 |
| AW-004 | Success after repeated failures on the same account | account | failures in lookback before a success | 5 in 900 s | HIGH | T1110, T1078 |

### Window semantics

- **Window boundary.** The window ending at event time `t` holds events with `t − W < ts ≤ t`, so an event exactly `W` old is outside it. Five failures at 4200, 4260, 4320, 4380 and 4500 s span exactly 300 s and do **not** alert; the fixture `dave` pins this.
- **Episodes.** An episode opens when the metric reaches the threshold and closes when it drops below it. Each episode is one alert, carrying `count` and `peak_in_window`, so a 500-failure flood is one alert, not 496.
- **Ordering.** Events are sorted by `(instant, failure < unknown < success, input order)`, so a shuffled file gives identical alerts.
- **AW-004** runs per account, so failures from IP A followed by a success from IP B still fire, and the alert records `ip_changed`. Failures that produced an alert are consumed.

### Overlap and limits

A spray from one IP also fires AW-001 by volume; AW-003 adds the classification. Overlapping alerts are expected.

The rules do not catch low-and-slow attacks that stay below threshold in every window, or attackers that rotate both IPs and accounts.

### Choosing thresholds

The defaults are starting values. Model benign failures per key per window as Poisson(λ); the chance that benign activity alone reaches `k` is `P(N ≥ k)`:

| λ | k = 3 | k = 5 | k = 10 |
|---|---|---|---|
| 0.1 | 1.5 × 10⁻⁴ | 7.7 × 10⁻⁸ | 1.1 × 10⁻¹⁶ |
| 0.5 | 1.4 × 10⁻² | 1.7 × 10⁻⁴ | 1.7 × 10⁻¹⁰ |
| 1 | 8.0 × 10⁻² | 3.7 × 10⁻³ | 1.1 × 10⁻⁷ |
| 2 | 3.2 × 10⁻¹ | 5.3 × 10⁻² | 4.7 × 10⁻⁵ |

Real failures are bursty (retry loops, stale saved passwords), so this table is a **lower bound** on false positives. Tune on your own baseline.

## Coverage: how to read a result

Read `coverage` before `findings`.

- `result` says whether any rule fired: `clean` or `alerts_detected`.
- `coverage.complete` says whether everything could be analyzed.
- `status` combines the two.

| status | result | coverage | Meaning | Exit |
|---|---|---|---|---|
| `clean` | `clean` | complete | Everything analyzed; no rule fired | 0 |
| `alerts_detected` | `alerts_detected` | complete | Alerts found; everything analyzed | 1 |
| `incomplete` | `clean` | partial | Nothing fired in what could be analyzed — **not a clean result** | 4 |
| `incomplete` | `alerts_detected` | partial | Alerts are real, **and** other activity may be unseen | 4 |

Coverage is partial when `coverage.reasons` contains any of these:

| Reason | Cause |
|---|---|
| `no_events` | No event survived validation, e.g. empty input |
| `invalid_records` | Some records failed reading or validation |
| `unsupported_records` | A raw-format adapter met lines it could not classify |
| `duplicate_conflicts` | A repeated `record_id` had different content |
| `uncorrelatable:<RULE>` | A relevant event lacked the time, key or known outcome that rule needs (`by_reason` says which) |
| `alert_cap_reached:<RULE>` | The rule produced more than 10 000 episodes |

Blank lines, recognised-irrelevant lines, dropped identical duplicates, out-of-order records and long gaps are **not** coverage gaps. The last two appear as signals in `coverage.timeline`.

If an attacker causes records to be rejected, the cost is a loud `incomplete` run, not a silent miss. Conversely, the OpenSSH adapter sanitizes awkward usernames, ports and addresses with a warning instead of dropping the line.

## Example output

All output below is copied from real runs of `examples/demo.sh` on the committed samples.

Clean run, exit 0:

```text
AuthWatch 1.0.0 · analyze clean.jsonl (jsonl) · sha256 0704984f4c8f…
Records    6 read · 6 events · 0 invalid · 0 unsupported · 0 irrelevant · 0 duplicates dropped
Coverage   complete · 2026-10-26T10:01:40Z to 2026-10-26T10:21:40Z
Timeline   0 out-of-order records · largest gap 400s
Result     CLEAN · 6 events analyzed, no rule fired · this does not prove the system is secure
Note       alerts are investigation leads, not proof of compromise
```

Alerts, exit 1:

```text
AuthWatch 1.0.0 · analyze attacks.jsonl (jsonl) · sha256 f6c083c3f2bf…
Records    39 read · 39 events · 0 invalid · 0 unsupported · 0 irrelevant · 0 duplicates dropped
Coverage   complete · 2026-10-26T10:01:40Z to 2026-10-26T11:15:00Z
Timeline   6 out-of-order records · largest gap 1050s

  Sev     Rule    Subject              Count  Window  Reason
  HIGH    AW-004  user:alice               9    900s  success from a new IP after 9 failures
  MEDIUM  AW-001  ip:203.0.113.50          9    300s  9 failures from one IP
  MEDIUM  AW-002  user:alice               9    300s  9 failures, 1 source IP(s)
  MEDIUM  AW-001  ip:192.0.2.99           12    300s  12 failures from one IP
  MEDIUM  AW-003  ip:192.0.2.99           12    600s  12 distinct accounts failed from one IP
  MEDIUM  AW-002  user:admin               6    300s  6 failures, 6 source IP(s)

Result     ALERTS DETECTED · 6 alerts · alerts are investigation leads, not proof of compromise
```

Incomplete run, exit 4. The same six alerts are still reported:

```text
AuthWatch 1.0.0 · analyze broken.jsonl (jsonl) · sha256 d5e8f1c2698e…
Records    45 read · 39 events · 6 invalid · 0 unsupported · 0 irrelevant · 0 duplicates dropped
Coverage   PARTIAL · invalid_records · 2026-10-26T10:01:40Z to 2026-10-26T11:15:00Z
  line 40  duplicate_key
  line 41  invalid_value
  line 42  schema_invalid:source_ip
  line 43  schema_invalid:source_ip
  line 44  schema_invalid:source_ip,unknown_field
  line 45  invalid_json
Timeline   6 out-of-order records · largest gap 1050s
  …
Result     INCOMPLETE · 6 alerts found, but 6 records could not be analyzed — activity may be unseen (exit 4)
Note       alerts are investigation leads, not proof of compromise
```

An empty file is never clean (exit 4):

```text
Coverage   PARTIAL · no_events
Result     INCOMPLETE · no alerts in the analyzable data — this is NOT a clean result (exit 4)
```

Fatal errors go to stderr and write no report:

```text
error: input starts with a UTF-16/UTF-32 byte-order mark; re-save it as UTF-8 (in PowerShell 5.1 use Out-File -Encoding utf8)      ← exit 3
error: refusing to write over the input file: samples\attacks.jsonl                                                                   ← exit 2
```

Error messages name the line and a stable reason code. They never echo the offending value.

## Report format

The report uses the series envelope (`envelope.schema = "7d7b-report"`), so the Day 7 incident-response tool can ingest any report generically. The top-level keys are:

```text
envelope  status  result  input{label,format,sha256,size_bytes}  parameters
coverage{complete,reasons,counters,rules{<rule>:{uncorrelatable,by_reason,alerts_suppressed}},timeline}
summary  findings[]  errors[]  errors_truncated
```

Each finding is `{event: <rule id>, category: "detection", subject: "ip:…" | "user:…", details}`. The `details` object holds:

- `alert_id`, `title`, `severity`, `attack`;
- `first_seen`, `last_seen`, `count`, `peak_in_window`, `threshold`, `window_seconds`;
- `description` and `caveats`;
- `evidence`: up to 50 input line numbers (first and last 25 when longer), the top 10 usernames and IPs, and for AW-004 also `success_line`, `success_ip` and `ip_changed`.

Because `input.sha256` is recorded, every evidence line number can be verified against the exact file analyzed.

The same input and parameters produce a byte-identical report except for `run_id`, `started_at` and `completed_at`. The report is ASCII JSON with LF line endings. See [examples/sample-report.json](examples/sample-report.json).

`--csv` writes one row per alert. Cells that a spreadsheet could execute as a formula (starting `=`, `+`, `-`, `@`, including after leading whitespace or in fullwidth form) are prefixed with `'`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Complete analysis, no alerts (or a complete `normalize`) |
| 1 | Complete analysis, alerts detected |
| 2 | Invalid arguments or configuration, a missing input, an unsafe or colliding output path, an existing foreign file, missing `--assume-year`/`--assume-tz` for syslog input, or a short redaction key |
| 3 | Input unusable as a whole: UTF-16/32 or binary |
| 4 | Incomplete analysis (any coverage reason), input unreadable by the OS, output write failure, or **any unexpected internal error** |
| 130 | Interrupted (Ctrl+C) |

**Precedence.** Codes 2 and 3 end the run before analysis. After analysis, 4 outranks 1, which outranks 0. Treat any non-zero code as "needs attention", then read `status` and `result`.

Fatal outcomes (2, 3, a fatal 4, 130) write no report and print nothing on stdout in `--format json` mode. A non-fatal 4 (partial coverage) still writes the full report.

## Privacy

> **Failed-login usernames can contain passwords.** People routinely type their password into the username field, so a list of failed usernames can be a list of credentials.

- Reports contain keys, counts and line numbers only, never raw records, and record only the input's base name.
- `--redact-usernames` replaces every username, in every output (terminal, JSON, CSV and `normalize`), with `u:` + 12 hex characters of `HMAC-SHA256(key, username_key)`. Grouping is unaffected, and alert ids are computed from the redacted subject, so ids cannot be used to dictionary-test usernames.
- Set `AUTHWATCH_REDACT_KEY` (at least 32 bytes) for tokens that stay stable across runs. Otherwise a random per-run key is used, and the report shows `key_source: "ephemeral"`.
- **Redaction does not protect the input file, and IP addresses are never redacted.** Store reports in a directory only you can read; on POSIX, report files are created with mode 0600.
- AuthWatch stores nothing between runs.

## Windows notes

Windows is the primary development platform, and v1.0.0 was built and tested on Windows 11.

- **Encoding.** Inputs are read as bytes, and every file AuthWatch writes is UTF-8 or ASCII with LF line endings.
- **PowerShell 5.1.** `>` and `Out-File` write UTF-16, which AuthWatch rejects with exit 3 and a hint. Use `Out-File -Encoding utf8` instead; the BOM it adds is accepted. Setting `$env:PYTHONUTF8 = "1"` (or `chcp 65001`) is recommended.
- **Pipes.** Windows PowerShell 5.1 re-encodes text piped between two native programs, so prefer `--report` plus `python -m json.tool report.json` over `authwatch … | python -m json.tool`.
- **Timezones.** Only fixed offsets are accepted; no IANA timezone database is needed.
- **Atomic writes.** Replacing a file that another program holds open fails with exit 4 and leaves the original intact.
- **Links.** Hard links to the input are detected on NTFS. Symlink refusal works, but its tests are skipped without Developer Mode.
- **Running without the console script.** `python -m authwatch` always works, even when the `authwatch` script is not on `PATH`.

## Tests and performance

```bash
python -m pytest -q
```

The suite (295 passed, 3 skipped on Windows 11 / Python 3.12) includes:

- **Brute-force oracles** for the window engine. An O(n²) reference written from the definition recomputes every window from scratch and is compared with the engine on 3 000 seeded random streams, for the count metric, the distinct-account metric and AW-004. Each comparison runs with sweeping at its default, at every event, and disabled. There were 0 mismatches.
- Shuffle invariance and username-spelling invariance on the fixtures.
- Every case of the project's edge-case register (77 numbered cases; each test names its case).
- Subprocess integration tests that assert real exit codes and streams.

The three skips are symlink tests (they need Developer Mode on Windows) and a real `chmod 000` test (POSIX only; a monkeypatched equivalent runs).

**Measured performance** (Intel Core Ultra 7 255HX, 15.4 GiB RAM, Windows 11, Python 3.12; 1 000 000 JSONL lines of about 205 MB each):

| Scenario | Wall time | Peak working set |
|---|---|---|
| Many keys (~65 k IPs, 5 000 users) | 43.2 s | 371 MiB |
| One-key flood (1 M failures; one alert per rule, 50 evidence lines) | 37.3 s | 366 MiB |
| 1 M distinct IPv6 sources | 67.0 s | 432 MiB |

Memory grows with the number of events, because events are held for the global sort. Per-key detection state and per-alert evidence stay bounded.

## Security considerations and limitations

- A `clean` status means no rule fired in the fully analyzed input. It does not mean the system is secure or the log is complete.
- AuthWatch cannot detect log deletion, tampering before collection, or logs collected after compromise. Collect logs read-only and hash them at collection time; the report records the SHA-256 of what was analyzed.
- Any local user who can write to syslog can forge lines that look like sshd output.
- Timestamps come from the source, so a skewed or forged clock yields wrong windows. `timeline` helps a human notice this, nothing more.
- Low-and-slow attacks that stay under threshold in every window are not detected.
- An IP address is not a person: NAT, proxies and VPN exits make one address many users.
- Case folding deliberately over-merges Linux usernames, which are case-sensitive. `DOMAIN\user`, `user@domain` and bare `user` are not merged.
- Redaction protects reports, not the input, and IP addresses are never redacted.
- The OpenSSH adapter supports only the listed message shapes and is **experimental**; other sshd messages make coverage partial.
- Input content is treated as data only: no `eval`, no shell, and no use of values as format strings. Terminal output escapes control characters, Rich markup and emoji codes.

## Roadmap and licence

**Next (V1.1):**

- a Windows Security adapter (exported XML, events 4624/4625);
- journald JSON, gzip and rotated files, and `--since`/`--until`;
- a low-and-slow rule;
- allow-lists for known scanners and NAT gateways.

**Later:** multi-file input, an OCSF/ECS exporter, baseline-calibrated thresholds, and ingestion by the Day 7 incident-response tool.

MIT licence — see [LICENSE](LICENSE).
