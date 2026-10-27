# AuthWatch — Build Notes

Sections 1–10 record the v1.0.0 build; section 11 records what v1.1.0 added.

The build record for AuthWatch v1.0.0 against its design specification (version 2.0.0, kept
privately; "Spec §" references below point into it) and the
build instructions' errata E1–E14 and decisions D1–D13. It covers what was decided, what
differs from the Spec, what was proven, and what remains unverified.

## 1. Environment actually used

| Item | Value |
|---|---|
| OS | **Windows 11** (10.0.26300), not Linux. The instructions assumed a Linux sandbox; this build ran on the owner's Windows machine |
| Python | 3.12.0 (MSC v.1935, 64-bit) |
| Libraries | pydantic 2.14.1, rich 15.0.0, typer 0.27.3 (vendors Click; `click` is not installed), pytest 9.1.1 |
| Machine | Intel Core Ultra 7 255HX, 15.4 GiB RAM |
| Git | branch `build/v1.0.0`; repo-local identity already configured (`PranavY-01`); global config untouched |

Because the platforms are reversed: **Windows behaviour is tested; Linux/POSIX behaviour is
not.** The POSIX-only checks (0600 file mode, `chmod 000` read refusal) are skipped on
Windows and have not run anywhere. Run `pytest -q` on Linux before calling it verified there.

## 2. Process deviations

| Deviation | Reason |
|---|---|
| Work is on branch `build/v1.0.0`, not `main` | Harness rule: never commit straight onto the default branch. Merge or fast-forward when ready |
| P0 contains a minimal `cli.py` (`--version`, `--help`) | P0's deliverable is "`python -m authwatch --help` works"; P3 replaced it with the full CLI |
| P5 (docs) was done after C1, together with F | So the README, `sample-report.json` and terminal excerpts come from runs of the finished tool instead of being written twice |
| `.gitattributes` added (not in the Spec §14.1 layout) | This machine has `core.autocrlf=true`. Without `eol=lf` and `samples/*.jsonl -text`, a Windows checkout rewrites the committed fixtures to CRLF and the byte-equality sample test fails |
| `LICENSE` kept as the owner's existing file (`Copyright (c) 2026 PranavY-01`) | E12 asks for "AuthWatch contributors" and says the owner should replace the name; the repository already had the owner's MIT licence, so it was kept |
| `demo.ps1` **was executed** (Windows PowerShell 5.1) | The instructions expected it could not run; `demo.sh` was run under Git Bash |
| `tests/test_exporters.py` added | Spec §14.1 lists no exporter test file; §12.2 requires exporter tests |

## 3. Decisions where the Spec and instructions were silent

1. **Reader `Line`** carries a `blank` flag so the caller can count blank lines without a pseudo reason code.
2. **Adapter interface** returns `(AuthEvent | None, classification, reason)`. `cli.ingest` turns the AuthEvent into an `Event`, so adapters never need the interner or input order.
3. **`schema_invalid:` truncation**: the 40-character cap applies to the comma-joined field list, not the whole string.
4. **Duplicate content (D1)**: the fingerprint is SHA-256 over every AuthEvent field except `parse_warnings`, with `timestamp` replaced by its UTC microseconds and `source_ip` by its canonical key. So `…Z` vs `…+00:00` counts as the same content; a different raw username spelling does not.
5. **`ip_canonicalized`** is raised when the key differs from the raw value with any scope id removed. A scope id on its own raises only `ip_scope_id_ignored`.
6. **Alert cap**: when more than 10 000 episodes close, the 10 000 *earliest* by `(first_us, first_order, key)` are kept. This total order makes the kept set independent of when episodes are closed, so sweeping cannot change which alerts are recorded. "Earliest" is a choice; the Spec only says "further episodes are counted".
7. **Sweep implementation**: keys live in an `OrderedDict` ordered by their newest event. Input is time-sorted, so a sweep only walks the keys it evicts. A naive scan would cost O(keys) every 4 096 events, which is quadratic when one window holds a million keys.
8. **AW-004**: after an alert the user's entry is removed from the state map (equivalent to clearing it).
9. **Evidence counters** ignore `None` values, so an IP-less failure adds nothing to `source_ips`. The AW-002 `{n_ips}` text is the number of tracked distinct IPs.
10. **`by_reason`** lists only non-zero reasons, as in the Spec §8.3 example `"by_reason": {}`.
11. **`summary.errors`** is the total number of error entries detected, which can exceed the 1 000 kept in `errors[]` (`errors_truncated` says so).
12. **`errors[]` order**: reader and adapter problems in line order, then duplicate conflicts.
13. **Timeline**: on ties, the first largest gap in sorted order wins.
14. **OpenSSH `unsupported` reason codes**: `unsupported_line_shape`, `unsupported_sshd_message`, `repeat_summary`. The Spec names these three causes but gives them no codes. The terminal prints a "disable repeat reduction" hint when `repeat_summary` occurs (Spec §6.10.3).
15. **OpenSSH timestamps** are built for every header-matched line before the process check. A classic-syslog line from any process therefore triggers the lazy `--assume-*` requirement (D11 says "the first classic-syslog line"), and an impossible date is `invalid` even on a non-sshd line, which errs toward incompleteness. An unknown month abbreviation is `invalid_timestamp` and does not move the rollover tracker.
16. **OpenSSH host names over 255 characters** fail schema validation and are `invalid` (structural). The host comes from the syslog daemon, not the remote attacker.
17. **`normalize --redact-usernames`**: a username with no key (only format characters) is written as `""`, not `"<none>"`. Re-analysis treats both the same way (`missing_username`), and `"<none>"` would become a real, merged key. `normalize` does not deduplicate (D9: "every validated event").
18. **Console encoding**: `main()` switches non-UTF-8 stdout/stderr to UTF-8 with `backslashreplace`. On Windows a pipe or file defaults to the ANSI code page (cp1252), which garbled `·`/`…` and could crash on usernames; a real console already uses UTF-16 console I/O and is unaffected. This matches the Spec's ASCII/UTF-8 file policy. **Caveat:** Windows PowerShell 5.1 decodes *piped* native output with the OEM code page, so `authwatch … | Out-File` may show `Â·` for `·`; the README recommends `$env:PYTHONUTF8=1` / `chcp 65001`, as Spec §14.4 does.
19. **Diagnostics** are printed with Rich `soft_wrap=True`. At the default 80-column width, Rich otherwise breaks long error messages mid-sentence.
20. **`--format json` stdout** is written as raw bytes to `sys.stdout.buffer`, so Windows does not turn LF into CRLF. It is byte-identical to the `--report` file.
21. **Terminal summary**: "to" replaces the Spec's illustrative "→". A `Timeline` line appears when out-of-order records or a non-zero gap exist. A `Note` line repeats "alerts are investigation leads, not proof of compromise" for every status except `alerts_detected`, whose result line already contains it.
22. **Binary input without many NUL bytes** (e.g. random bytes) is not caught by the 10 % NUL heuristic. It becomes per-line `invalid_utf8` / `invalid_json` records, so the run is `incomplete` (exit 4), never clean. Only NUL-heavy data and UTF-16/32 exit 3.
23. **`check_input`** maps an `OSError` raised while inspecting the path to `OperationalError` (exit 4).
24. **`parameters.assume_tz`** records the string exactly as given (`Z`, `UTC`, `+05:30`).

## 4. Deviations from the Spec text (beyond E1–E14 / D1–D13)

| Spec | Built | Why |
|---|---|---|
| §6.10.3 `FAILED`/`ACCEPTED`: `(?P<user>.+)` | `(?P<user>.*)` | With `.+`, sshd's empty-username form `Failed password for invalid user  from …` (two spaces) backtracks into the account name **`invalid user`**. With `.*` it parses as an empty username (`unknown_account`, uncorrelatable for AW-002), which is what happened. Test: `test_attacker_fields_sanitized_not_rejected` |
| §6.10.3 `port (?P<port>[0-9]{1,5})` | `port (?P<port>\S+)` | D11 requires a non-numeric port to be sanitized to `null` with a warning. A strict pattern would make the whole line `unsupported` instead, which conflicts with the sanitization rule of §6.10.1 |
| §6.3 reference `parse_ts` (regex, then `fromisoformat`) | Regex groups build the `datetime` directly, with explicit offset checks | Same behaviour (ASCII, `fullmatch`, `-00:00`, hour 24, ±23:59, `OverflowError` guard), but it does not depend on version-specific `fromisoformat` leniency. Nanoseconds are truncated explicitly |

No other deviations. E1–E14 and D1–D13 were applied as written.

## 5. Hand-derivation corrections

| Where | Old (hand-derived) | Real | Justification |
|---|---|---|---|
| Spec §8.3 `coverage.timeline.out_of_order_records` for `attacks.jsonl` | `0` | `6` | D5: count timestamped events, in input order, whose time is earlier than the maximum seen before them. Lines 29–34 (S5 `bob`/`carol`, offsets 100–1300 s) follow S4 (max 3150 s) in the file, so all six are out of order. The tests pin `6` |
| Spec §15.4 terminal layout | Illustrative | Real output in the README | The Spec marks it "layout indicative" |

Everything else in Spec §15.2 matched on the first real run: the six alerts (rule, subject, first/last seen, count, peak, `ip_changed: true`), the order (HIGH first), no alert for `dave`, the six `broken.jsonl` reason codes, the counters (39/45) and the timeline span and gap (10:01:40 → 11:15:00, 1 050 s, 10:52:30 → 11:10:00).

## 6. Defects found in unproven Spec snippets

| Snippet | Defect | Fix |
|---|---|---|
| §6.10.3 OpenSSH `FAILED`/`ACCEPTED` patterns | Empty-username misparse; a strict port pattern rejects instead of sanitizing | §4 above |
| §6.1 reference reader loop | Reports exception class names (`ValueError`, …) instead of reason codes | E3 mapping with `DuplicateKeyError` / `NonFiniteError` subclasses (`reader.problem_for`) |
| §6.1 "NUL-heavy" heuristic | Undefined; with E3's 10 % threshold, non-NUL binary is not caught | Documented limitation (§3 item 22); still never a false clean |

The other unproven snippets (distinct metric, AW-004, sweep, evidence bounding, cap, `derive`, the full model, the `OverflowError` guard, reader hashing, `write_atomic`) behaved as specified under their tests.

## 7. Unproven items (Spec Appendix B.6) — now tested

| Item | Test(s) | Result | Defects found |
|---|---|---|---|
| Distinct-metric detector | `test_window_oracle.py::test_distinct_metric_matches_oracle` (3 000 streams × 3 sweep settings), `::test_distinct_metric_one_episode_per_burst` | pass, 0 mismatches | none |
| AW-004 detector | `test_window_oracle.py::test_aw004_matches_oracle` (3 000 × 3), `::test_aw004_failure_before_success_at_equal_time`; `test_rules.py::test_aw004_*` | pass, 0 mismatches | none |
| Sweep equivalence | the three oracle tests with `sweep-1` / `no-sweep` / default; `::test_sweep_closes_open_episode_before_eviction` | pass | none |
| Evidence bounding | `::test_flood_is_one_episode_with_bounded_evidence`, `::test_single_key_flood_bounded_evidence` (1 M failures), perf flood (1 M lines → 50 lines) | pass | none |
| Alert cap | `::test_alert_cap_counts_suppressed`, `test_cli.py::test_alert_cap_degrades_coverage`, `test_coverage.py::test_every_reason_code` | pass | none |
| `derive()` and the counter invariant | `test_coverage.py::test_status_table`, `::test_every_reason_code`; `test_reporter.py::test_counter_invariant_over_mixed_file`; `test_cli.py::test_broken_sample_incomplete_with_alerts` | pass | none |
| Full `AuthEvent` model | `test_models.py` (all) | pass | none |
| `OverflowError` guard | `test_timeparse.py::test_overflow_after_conversion_is_value_error` | pass | none |
| UTF-16 / NUL-heavy heuristic | `test_reader.py::test_wide_or_binary_input_rejected_as_whole`, `::test_isolated_nul_is_per_line`; `test_cli.py::test_utf16_input_exit_3` | pass | limitation in §6 |
| Reader hashing | `test_reader.py::test_hash_covers_every_byte_including_drained` | pass | none |
| `write_atomic` | `test_outputs.py::test_write_failure_leaves_original_intact`, `::test_replace_onto_open_file`, `::test_write_atomic_writes` | pass (0600 check skipped on Windows) | none |
| Redaction wiring | `test_redact.py::test_no_username_in_any_output` (text + JSON + report), `::test_alert_ids_built_from_tokens`, `test_openssh.py::test_normalize_redacts` | pass | none |
| `normalize` | `test_openssh.py::test_normalize_round_trip`, `::test_normalize_jsonl_identity`, `::test_normalize_incomplete_still_writes` | pass | none |
| The CLI | `test_cli.py` (subprocess + in-process `main()`) | pass | stderr wrapping and console encoding (§3 items 18–19), found and fixed |
| Report builder | `test_reporter.py`, `test_cli.py::test_determinism` | pass | none |
| All OpenSSH patterns | `test_openssh.py` (**authored samples only**) | pass | §4 |

## 8. Tests skipped, and why

Final suite on Windows 11 / Python 3.12: **295 passed, 3 skipped** at v1.0.0, and **323 passed, 3 skipped** at v1.1.0 (`pytest -q -rs`). The same three tests are skipped in both:

| Test | Reason |
|---|---|
| `test_outputs.py::test_symlink_to_input_refused` | Creating symlinks needs Developer Mode or admin on Windows; not available on this account |
| `test_outputs.py::test_symlink_report_path_refused` | Same |
| `test_cli.py::test_unreadable_input_real_permissions` | `chmod 000` does not block reads on Windows (the monkeypatched twin `test_unreadable_input_injected` runs) |

## 9. Performance (D13)

Measured in-process (`cli.main()` with `--report`) on the machine in §1, wall time from
`time.perf_counter`, peak working set from `K32GetProcessMemoryInfo`. Inputs were generated
in the session scratchpad and are not committed.

| Scenario (1 000 000 JSONL lines, ~205 MB each) | Wall time | Peak working set | Result |
|---|---|---|---|
| (a) many keys: ~65 k IPs, 5 000 users, 1 in 17 a success, 4 events/s | 43.2 s | 371 MiB | `clean`, exit 0, 1 000 000 events analyzed |
| (b) one-key flood: 1 M failures, one IP and one user, 10 events/s | 37.3 s | 366 MiB | `alerts_detected`, exit 1: one AW-001 and one AW-002 alert, 50 evidence lines each |
| (c) 1 M distinct IPv6 sources (`2001:db8::/32`), 4 events/s | 67.0 s | 432 MiB | `clean`, exit 0, 1 000 000 events analyzed |

Roughly 15–27 k events/s, dominated by per-line JSON parsing and pydantic validation. Memory
is O(events): every `Event` is kept for the global sort, about 370–430 bytes per event
including parse overhead. Per-key detection state stays bounded (the tests assert ≤ 4 396
live keys for 1 M distinct keys, and ≤ 50 evidence lines for a 1 M-event episode).

A first attempt at (c) generated invalid IPv6 literals past 65 535 (a bug in the
measurement script, not AuthWatch). AuthWatch reported that run as `incomplete` with
934 464 `schema_invalid:source_ip` errors and exit 4 — the honest-coverage behaviour, as
intended. The figures above come from the corrected input.

## 10. Not verified

- **Linux / POSIX**: no test has run on Linux. POSIX-only assertions are skipped here.
- **OpenSSH adapter on real logs**: the patterns are validated only against authored samples. Spec phase S3 requires sanitized real samples (`journalctl -u ssh` from WSL or a VM) before the adapter can be called supported. The README and `--help` label it experimental.
- **Symlink refusal** (needs Developer Mode on Windows) and the **0600 report mode** (POSIX).
- Whether spreadsheet software treats fullwidth `＝` as a formula. It is escaped regardless.
- **Package name**: PyPI and GitHub availability of `authwatch` were not re-checked (no network calls were made).

## 11. Version 1.1.0: inspection commands and terminal redesign

### What was added

| Addition | Where | Tests |
|---|---|---|
| `authwatch explain ALERT_ID --report R [--input P] [--raw]` | `reports.py` (load, find, hash, lines), `cli.py`, `render.render_explain` | `test_inspect.py::test_explain_*`, `test_render_explain_escapes_record_text` |
| `authwatch diff OLD NEW` | `reports.diff_reports`, `render.render_diff` | `test_inspect.py::test_diff_*` |
| `authwatch validate FILE [--max-errors N]` | `cli.validate`, `render.render_validate` | `test_inspect.py::test_validate_*` |
| `authwatch rules` | `rules.rule_catalogue`, `render.render_rules` | `test_inspect.py::test_rules_listing` |
| Terminal redesign: header panel, facts grid, rounded tables, severity and status badges, a red "Coverage gaps" panel with a meaning for every reason code, alert ids in the alert table | `render.py` | existing CLI tests plus the new ones |
| Real colour screenshots | `docs/screenshots/*.svg`, recorded from real runs with Rich's `save_svg` | — |

`reports.py`, like the rest of the engine, imports neither Rich nor Typer (the import grep covers it).

### Decisions

1. **`explain` finds the input** by the report's base-name label: first next to the report, then in the current directory, unless `--input` is given. A label containing a path separator, `.` or `..` is never used, so a crafted report cannot point `explain` at another file.
2. **`explain` re-hashes the whole file** with the same reader `analyze` uses, so the line numbering and the SHA-256 are computed identically. A different hash or size raises the new `VerificationError` (exit 4) before any evidence is printed. Exit 4 was chosen over 2 because a changed evidence file is an operational finding, not a typo.
3. **Alert-id prefixes**: at least 4 hex characters, case-insensitive. An ambiguous prefix is refused (exit 2) and the error says how many alerts it matches.
4. **Reports are parsed defensively**, with the input's duplicate-key and non-finite rejection, a 256 MiB cap, and a structural check (`envelope.tool == "AuthWatch"`, `envelope.schema == "7d7b-report"`, a well-formed `findings[]`). A report may have been edited by someone else.
5. **The `explain` field view** (timestamp, outcome, username, source IP, port) is used only for JSONL input. OpenSSH evidence, or `--raw`, shows each line in full (escaped, up to 1 000 characters, wrapped). When the report was redacted, `explain` warns that the evidence shows real usernames, because it reads the original file.
6. **`diff` matches by alert id**, which hashes the rule, subject, first-seen time and thresholds, so a growing episode stays "ongoing". Alerts present only in the older run are labelled **"no longer reported"**, not "resolved", because absence usually means the activity is outside the newer file's time range. `diff` warns when parameters or redaction differ (ids not comparable), when a run used an ephemeral key, when a run was incomplete, and when both runs analyzed the same file.
7. **`diff` exit codes** follow the analyze precedence: 4 if either run was incomplete, else 1 if anything is new, else 0. A partial run can never make a comparison look quiet.
8. **`validate` is format-only.** Exit 0 means every non-blank line is a valid schema-1.0 event and there is at least one; exit 4 means invalid lines or no records. Valid records that `analyze` will report as gaps (`unknown` outcome, null timestamp, username or IP, conflicting `record_id`) and normalization warnings are listed as information but do not fail validation.
9. **Version bumped to 1.1.0** (new commands; the report envelope is unchanged), so reports state which build made them.
10. **Pipes and files render at 120 columns** (unless `COLUMNS` is set), because Rich defaults to 80 off a terminal and the tables would wrap. The colour itself appears only on a terminal.
11. **Error and internal-error messages** are now displayed with a 1 000-character limit. A long Windows path pushed the useful part past the 200-character cut used for untrusted values. Untrusted values keep the 200-character limit.

### Verified for v1.1.0

- `pytest -q -rs`: 323 passed, 3 skipped (the same three as v1.0.0).
- `examples/demo.sh` (Git Bash) and `examples/demo.ps1` (Windows PowerShell 5.1), both extended with `explain`, `validate` and `rules`: every step gave its expected exit code.
- The import, `eval`/`exec`, `click`, `splitlines`/`json.load(` and stub greps are clean across `src/`, including `reports.py`; case traceability is still 73/73.
- No Rich markup leaks (no literal `[bold]` or `[/]`) in the plain output of any command; hostile usernames render escaped in both the field and `--raw` views of `explain`.
- The screenshots were rasterized with headless Edge and inspected visually.
