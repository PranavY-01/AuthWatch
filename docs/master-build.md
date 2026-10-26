# AuthWatch — Master Build Document

## Day 4 | 7 Days – 7 Cybersecurity Projects

| Field | Value |
|---|---|
| **Document type** | All-in-one project specification: methodology, core engine, system design, build plan, expected result |
| **Project** | AuthWatch |
| **Document version** | 2.0.0 — supersedes the 1.0 planning baseline (preflight review and patch verification incorporated) |
| **Tool version targeted** | 1.0.0 |
| **Status** | Contract frozen — ready for implementation. Items tagged `[UNVERIFIED]` are reference designs the implementer must prove with the tests in Section 12 |
| **Primary language** | Python 3.11+ |
| **Interface** | CLI-first |
| **Development environment** | Windows, synthetic records (no Linux runtime required for the core) |
| **Build window** | ≈ 3 h 35 min for the Must tier · ≈ 5 h 20 min including the Should tier (Section 13) |
| **Category** | Detection Engineering · Authentication Analytics · Defensive Security |

---

## Table of Contents

0. [Document Control and Changelog](#0-document-control-and-changelog)
1. [Executive Summary](#1-executive-summary)
2. [Project Context](#2-project-context)
3. [Scope and Delivery Tiers](#3-scope-and-delivery-tiers)
4. [Requirements](#4-requirements)
5. [Methodology — The Detection Model](#5-methodology--the-detection-model)
6. [Core Engine Design](#6-core-engine-design)
7. [System Architecture](#7-system-architecture)
8. [Data Model and File Formats](#8-data-model-and-file-formats)
9. [CLI Contract](#9-cli-contract)
10. [Security Design and Threat Model](#10-security-design-and-threat-model)
11. [Edge Cases and Failure Handling](#11-edge-cases-and-failure-handling)
12. [Testing Strategy](#12-testing-strategy)
13. [Implementation Plan](#13-implementation-plan)
14. [Repository and Packaging](#14-repository-and-packaging)
15. [Expected Build Result](#15-expected-build-result)
16. [Definition of Done](#16-definition-of-done)
17. [GitHub and Release Strategy](#17-github-and-release-strategy)
18. [Future Roadmap](#18-future-roadmap)
19. [Frozen Decision Register](#19-frozen-decision-register)
20. [Final Build Principle](#20-final-build-principle)
- [Appendix A — Findings Traceability](#appendix-a--findings-traceability)
- [Appendix B — Verification Record](#appendix-b--verification-record)
- [Appendix C — Instructions for Future Coding Assistants](#appendix-c--instructions-for-future-coding-assistants)
- [Appendix D — Glossary](#appendix-d--glossary)

---

# 0. Document Control and Changelog

## 0.1 Purpose of this revision

The 1.0 planning baseline (the "knowledge capsule") fixed the direction: a Python CLI that normalizes authentication records into a versioned schema, applies deterministic rules, and reports evidence-backed alerts, tested first on Windows with synthetic JSONL. A pre-implementation review then found that several of its rules were stated without a mechanism, and that some default Python behaviours silently violate them. A second pass tested the proposed fixes themselves and found defects in roughly half of them.

This revision freezes the implementation contract. Every rule now has an algorithm, a data representation, and a test. Everything the baseline marked **DECIDED** is preserved; everything it marked **OPEN** is now closed in Section 19.

## 0.2 Changes from the planning baseline

Finding IDs (C = critical, H = high, M = medium, L = low, N = new while drafting) are traced to tests in Appendix A.

| # | ID | Area | Planning baseline | Resolution | Section |
|---|---|---|---|---|---|
| 1 | C1 | Coverage | "Zero alerts is not a runtime error"; invalid or unusable records could vanish into a clean result | Separate `result` and `coverage`; `status` is derived; partial coverage exits `4`, never `0` | 5.4, 6.8 |
| 2 | N2 | Empty input | Not considered | Input with no analyzable events is `incomplete` (`no_events`), never clean | 6.8 |
| 3 | C2 | Window semantics | Fixed vs rolling left open | Sliding window `(t − W, t]` with **episode merging** (one alert per sustained burst) | 6.6 |
| 4 | C3 | Grouping key | One key to be chosen | Four rules, each with an explicit key: IP, account, distinct-accounts-per-IP, failure→success | 6.7 |
| 5 | C4 | Key canonicalization | Not considered | `ip_key` / `username_key`; raw values kept for display, canonical keys used for grouping | 6.4 |
| 6 | C5 | Duplicate JSON keys | Not considered | Rejected at parse time (a `failure` could otherwise flip to `success`) | 6.1 |
| 7 | H1 | Timestamps | "ISO 8601 / RFC 3339" | Strict ASCII RFC 3339 profile; offset mandatory; naive values invalid; integer-microsecond arithmetic | 6.3 |
| 8 | H2 | Unknown fields | "Permitted" | `extra="forbid"`; nullable fields are required keys (a typo can no longer become a silent `null`) | 6.2 |
| 9 | H3 | Terminal injection | "Avoid unsafe formatting" | `safe_display()` on every untrusted string; consoles created with `highlight=False, emoji=False` | 10.5 |
| 10 | H4 | CSV injection | Not considered | `csv_safe()`; CSV demoted to the Could tier | 8.6 |
| 11 | H5 | Export overwrites input | Not considered | Path-identity check (symlinks **and** hard links), atomic write, report-overwrite guard | 9.4 |
| 12 | H6 | Reader robustness | "Blank line behaviour" | Bytes-level reader: split on `\n` only, BOM, CRLF, UTF-16 detection, 64 KiB line cap with bounded drain, NUL and non-UTF-8 handling | 6.1 |
| 13 | H7 | Privacy | `raw_event` is the only privacy question | `raw_event` removed from schema 1.0; evidence is line references + input hash; optional keyed username redaction | 6.11 |
| 14 | H8 | Type strictness | "Dataclasses or Pydantic" | Pydantic v2 strict mode; booleans, floats, NaN, integer IPs and lone surrogates rejected | 6.2 |
| 15 | M1 | Series contract | Tool-specific output | Shared `7d7b-report` envelope, FileSift exit-code precedence, crash → exit `4` | 8.5, 9.2, 9.5 |
| 16 | M2 | Provenance | Not specified | Input SHA-256 and size, parameters, rule coverage, timeline in every report | 8.3 |
| 17 | M3 | Alert ids | Open | Deterministic `sha256` over a canonical JSON list | 6.9 |
| 18 | N3 | Alert-id privacy | Not considered | The id hashes the **displayed** (redacted) subject, so it cannot be used to dictionary-test usernames | 6.9 |
| 19 | M4 | Duplicates | Open | Deduplicate on `record_id` only, never on content | 6.5 |
| 20 | M5 | Rule C linkage | "Comparable identity" | AW-004 keyed on the account (not the IP pair); failures sort before a success at equal time; failures consumed on alert | 6.7 |
| 21 | M6 | Config bounds | Open | Thresholds 2–100 000; windows 1 s–7 d; lookback ≥ window, ≤ 30 d; explicit duration syntax | 9.1 |
| 22 | M7 | Memory | Not considered | Periodic key sweep, bounded evidence, alert cap | 6.6 |
| 23 | M8 | Tamper visibility | Not considered | `timeline` block: largest gap and out-of-order count | 8.3 |
| 24 | M9 | Normalization never exercised | Real adapters deferred entirely | OpenSSH text adapter and `normalize` command as Should tier | 6.10 |
| 25 | L1–L3 | Hygiene | Open | `event_type` is a literal; hosts combine; stack frozen | 19 |
| 26 | N1 | Evasion by invalidity | Not considered | Adapters **sanitize** attacker-controlled fields with a warning; they never reject a recognised auth line because of its username | 6.10, 10.4 |
| 27 | N4 | Repeat-suppressed logs | Not considered | "message repeated N times" lines are `unsupported` (they under-count) → partial coverage | 6.10 |
| 28 | N5 | Timestamp overflow | Not considered | `OverflowError` after UTC conversion is caught and reported as an invalid record | 6.3 |
| 29 | N6 | Determinism | Not considered | No wall clock in detection or validation; a future-date warning was considered and **dropped** | 6.3 |
| 30 | N7 | Windows pitfalls | "Runs on Windows" | Explicit UTF-8 everywhere; fixed-offset timezones only (no `tzdata` dependency); POSIX-only tests skipped | 14.4 |
| 31 | N9 | Rule overlap | — | AW-001 already catches spraying by volume; AW-003 adds classification and a distinct-account signal; overlap is documented | 6.7 |
| 32 | N10 | Alert flooding as a distraction | Not considered | Deterministic severity ordering; 10 000-alert cap that degrades coverage honestly | 6.6 |
| 33 | — | Time realism | 2–4 h for everything | MoSCoW tiers with cut rule; honest budget | 3.3, 13 |
| 34 | — | Open decisions | 19 open | All closed in the Frozen Decision Register | 19 |

## 0.3 Self-corrections made while drafting

These are statements in the earlier review that this revision corrects. They are listed so the document does not inherit them.

1. **AW-003 was overstated.** The review said a spray rule "closes the biggest evasion gap". In fact AW-001 (failures per source IP) already fires on a spray by raw volume. AW-003 adds technique-specific classification and a distinct-account threshold; it is a Should-tier refinement, not a Must-tier gap closure.
2. **The future-timestamp warning was dropped.** It would make reports depend on the wall clock and break reproducibility (N6). The `timeline` block exposes the earliest and latest event times so an analyst can judge.
3. **`username_key` was not idempotent.** The first version produced non-normalized keys for 26 code points and an empty key for zero-width-only names. The corrected version is in Section 6.4.
4. **Eight patch snippets contained bugs** (timestamp regex, IP scope parsing, username key, CSV escaping, alert-id hashing, reader drain, hard-link detection, sort-key contradiction), and two weaker designs needed changes (eviction could drop open episodes; AW-003 emitted one hit per event). Corrected versions are in the relevant sections; the list is in Appendix B.

## 0.4 Status legend for code in this document

| Tag | Meaning |
|---|---|
| `[VERIFIED]` | Executed during planning (Python 3.13, Linux) and behaved as described. Re-run on Windows during the build. |
| `[PARTIAL]` | Some constraints were executed; the rest are reference design. The note beside the snippet says which. |
| `[UNVERIFIED]` | Reference design that has not been executed. It is the specification of intended behaviour, not evidence that it works. |

Snippets are reference designs, not copy-paste code. Where a snippet and the prose disagree, the prose and the tests win.

---

# 1. Executive Summary

AuthWatch is a lightweight, Python-based **authentication-log analyzer**. It reads authentication records, converts supported records into a common, versioned event model, applies deterministic detection rules over sliding time windows, and reports evidence-backed alerts that explain *why* each alert fired and *which records* support it.

Its defining property is **honest coverage reporting**. AuthWatch distinguishes "no suspicious pattern found" from "no suspicious pattern found *in the part of the input I could actually analyze*". A run that rejected records, could not correlate events, or saw nothing at all is reported as incomplete — never as clean.

It is an analysis and triage tool. It never blocks IP addresses, disables accounts, or changes system settings.

## 1.1 One-line description

AuthWatch is a Python CLI that normalizes authentication records, detects suspicious login patterns with transparent sliding-window rules, and produces evidence-backed alerts for defensive triage — and never presents a partial analysis as a clean one.

## 1.2 Primary use case

An analyst or administrator exports authentication records (synthetic JSONL during development; OpenSSH logs once the adapter exists), runs `authwatch analyze`, and receives a terminal summary plus a machine-readable JSON report. Each alert states the rule, the grouping key, the count and time window, the line numbers of the supporting records, and the caveats that could make it a false positive. The exit code tells automation whether to look closer.

## 1.3 Problem statement

Authentication records are voluminous, source-specific and easy to misread. Failed logins have innocent causes (typos, stale credentials, NAT) and hostile ones (guessing, spraying, credential stuffing). Naive scripts compound the problem: they count in fixed buckets that bursts straddle, group by raw strings an attacker can vary, silently drop lines they cannot parse, and print "no findings" afterwards. AuthWatch provides a repeatable, explainable answer and states the limits of that answer.

## 1.4 Goals

1. A strict, versioned, JSON-compatible event schema that rejects ambiguity instead of guessing.
2. A bytes-level reader that survives hostile and Windows-typical input without crashing or mis-splitting records.
3. Canonical grouping keys so attacker-chosen spelling cannot split a count.
4. Deterministic sliding-window detection with documented boundary and tie-break semantics.
5. Four explainable rules (AW-001 to AW-004), each with an explicit key, window and severity.
6. Explicit coverage accounting: invalid, unsupported and uncorrelatable records are first-class results.
7. A report in the series envelope with full provenance, plus a documented exit-code contract.
8. A core engine with no dependency on the CLI or terminal libraries.
9. A reproducible GitHub release with fixtures, a demo, and tests that include a brute-force oracle for the window engine.

## 1.5 Core principle

> **An analysis that could not cover all of its input must never be presented as proof that no suspicious activity occurred.**

Every design decision in this document traces back to this sentence. It is the Day 3 principle of FileSift restated for authentication data.

---

# 2. Project Context

## 2.1 The 7 Days, 7 Builds roadmap

| Day | Project | Primary security capability |
|---|---|---|
| Day 1 | NetScope | Network reconnaissance and port-state analysis |
| Day 2 | TraceDNS | DNS investigation and email-security analysis |
| Day 3 | FileSift | File integrity monitoring |
| **Day 4** | **AuthWatch** | **Authentication-event analysis and suspicious-login detection** |
| Day 5 | WebGuard | Web security assessment |
| Day 6 | ForenSight | Digital forensic investigation |
| Day 7 | IRFlow | Incident response workflow automation |

**Progression:** Discover → Validate → Monitor → **Detect** → Assess → Investigate → Automate.

FileSift answers "did the host change?". AuthWatch answers "who is trying to get in, and did anyone succeed after trying?". Its alerts are exactly the kind of findings IRFlow (Day 7) should ingest.

## 2.2 Why authentication logs

Authentication records reveal patterns such as many failures from one source in a short interval, repeated failures against one account, one source failing against many accounts, or a success following repeated failures. These may indicate password guessing, spraying, credential stuffing, user error, or misconfiguration. A pattern alone does not prove malicious intent or compromise.

## 2.3 Why the core is not Linux-only

The first concept focused on Linux SSH logs. The development environment is Windows, and a Linux machine may not be available. The decision, preserved from the baseline, is **DECIDED**: the normalized event model and detection engine do not depend on any operating system. The complete pipeline is built and tested with synthetic JSONL on Windows. A real-source adapter is added only when representative records and tests exist. (WSL or a small VM can supply real OpenSSH samples; they are a convenience, not a prerequisite.)

## 2.4 Why normalize

Logs are not stored uniformly: OpenSSH writes syslog text, Windows writes Event Log records, applications write JSON or CSV, and two JSON sources can use the same field name for different things. Normalization is not "convert a text file to JSON". It means interpreting a supported record and mapping its *meaning* into a common model. Parsing extracts; semantic mapping interprets; normalization standardizes; detection correlates.

## 2.5 Series-level contribution

AuthWatch is the second tool to emit the **shared report envelope** introduced by FileSift (Section 8.5), and reuses FileSift's exit-code precedence, crash handling (`guarded()` wrapper), terminal-safety function and report-overwrite guard. Adopting the contract now keeps IRFlow's Day 7 ingestion generic.

## 2.6 Constraints

- Independently useful and documented on its own.
- Achievable in one working day for the Must tier.
- No privileged access, network calls, databases, or external services.
- Read-only: the tool never modifies the analyzed file, and its only writes are explicitly requested outputs.

---

# 3. Scope and Delivery Tiers

## 3.1 In scope

**Must tier (the minimum shippable tool):**

1. Bytes-level JSONL reader with hostile-input handling (Section 6.1).
2. Strict schema 1.0 validation (Section 6.2) and strict timestamp profile (Section 6.3).
3. Canonical IP and username keys (Section 6.4).
4. Global deterministic ordering and `record_id` deduplication (Section 6.5).
5. Sliding-window engine with episode merging, bounded evidence and memory sweep (Section 6.6).
6. Rules **AW-001** (failures per source IP) and **AW-002** (failures per account).
7. Coverage model, derived status and exit codes (Sections 6.8, 9.2).
8. JSON report in the shared envelope with provenance, deterministic alert ids and line-number evidence.
9. Terminal summary with `safe_display()` escaping.
10. Output-path safety and atomic report writes (Section 9.4).
11. Automated tests, including a brute-force oracle for the window engine.
12. README, fixtures, demo script and a versioned release.

**Should tier (the planned second sitting):**

13. Rule **AW-003** (one source IP failing against many accounts) and **AW-004** (success after repeated failures).
14. `--rules` selection and `--redact-usernames`.
15. OpenSSH text adapter and the `normalize` command.
16. `timeline` tamper-visibility block, MITRE ATT&CK tags on alerts.

**Could tier:**

17. CSV alert export with formula-injection escaping.
18. Rich styling polish.

## 3.2 Explicitly out of scope

Machine-learning or statistical anomaly detection, LLM interpretation of logs, live SIEM/XDR integration, real-time tailing or streaming, automatic blocking or account changes, geo-IP or impossible-travel analysis (needs a database and breaks offline operation), a rules DSL, a Windows EVTX reader (Section 18), journald/gzip/rotated-file handling, web dashboard, any claim that an alert proves compromise or identifies a person, and a requirement to install Linux.

## 3.3 Delivery tiers (MoSCoW)

| Tier | Items | Rule |
|---|---|---|
| **Must** | Items 1–12 above | Never cut; ship late rather than ship a tool that can report a false clean |
| **Should** | Items 13–16 | Attempt after the Must tier passes its Definition of Done; cut in the order given in Section 13.2 |
| **Could** | Items 17–18 | Only if ≥ 30 minutes remain after the Should tier |
| **Won't (this build)** | Section 3.2 and Section 18 | Roadmap |

---

# 4. Requirements

## 4.1 Functional requirements

| ID | Requirement | Expected behaviour | Tier |
|---|---|---|---|
| FR-01 | Read input | Bytes-level JSONL reader: split on `\n` only, tolerate BOM and CRLF, cap line length, report every problem line by number and reason code | Must |
| FR-02 | Validate events | Strict schema 1.0; unknown fields, wrong types, bad enums, bad timestamps and bad IPs make the *record* invalid, not the run | Must |
| FR-03 | Canonicalize keys | Derive `ip_key` and `username_key` for grouping; keep raw values for display | Must |
| FR-04 | Order and deduplicate | One global sort `(timestamp, outcome rank, input order)`; drop repeats of the same `record_id` only | Must |
| FR-05 | Rule AW-001 | Alert on ≥ threshold failures from one source IP inside a sliding window | Must |
| FR-06 | Rule AW-002 | Alert on ≥ threshold failures against one account inside a sliding window | Must |
| FR-07 | Track coverage | Count invalid, unsupported and per-rule uncorrelatable records; derive `status` from `result` and `coverage` | Must |
| FR-08 | Export report | JSON in the shared envelope with input hash, parameters, per-rule coverage, line-number evidence | Must |
| FR-09 | Display summary | Terminal summary with counters, coverage, alerts and escaped untrusted strings | Must |
| FR-10 | Exit status | Documented codes with precedence; unexpected exceptions exit `4`, never `1` | Must |
| FR-11 | Protect outputs | Refuse to write over the input, a directory, a symlink or a foreign file; write atomically | Must |
| FR-12 | Validate configuration | Reject out-of-range thresholds, windows and lookbacks with exit `2` | Must |
| FR-13 | Rule AW-003 | Alert when one source IP fails against ≥ threshold distinct accounts inside a window | Should |
| FR-14 | Rule AW-004 | Alert on a success preceded by ≥ threshold failures on the same account inside a lookback | Should |
| FR-15 | Redact usernames | Replace usernames in all outputs with keyed-HMAC tokens; grouping unaffected | Should |
| FR-16 | Select rules | `--rules` limits the run; the selection is recorded in provenance | Should |
| FR-17 | OpenSSH adapter | Normalize explicitly supported OpenSSH lines; count recognised-irrelevant and unsupported lines separately | Should |
| FR-18 | Normalize command | Write validated normalized events as JSONL (usable as input to `analyze`) | Should |
| FR-19 | Timeline block | Report earliest/latest event, largest silent gap and out-of-order count | Should |
| FR-20 | CSV export | Alert table with formula-injection escaping | Could |

## 4.2 Non-functional requirements

| Attribute | Requirement |
|---|---|
| **Reliability** | Same input and parameters → byte-identical report apart from `run_id` and envelope timestamps. No wall-clock dependence in detection |
| **Safety** | Never executes input content; never modifies the input; never blocks, disables or changes anything |
| **Correctness under failure** | No failure mode produces exit `0` or `status: clean` |
| **Usability** | Plain-language errors naming the line and reason code; never the offending value |
| **Maintainability** | Core engine imports neither `typer` nor `rich` |
| **Testability** | Detection logic tested in memory, with a brute-force oracle; file logic in `tmp_path`; no network, no privileges |
| **Portability** | Windows-first; standard-library filesystem APIs; explicit UTF-8; no timezone database dependency |
| **Performance** | Linear in events with bounded per-key state; design target ≈ 1 million events per file (not yet measured — Section 12.5) |
| **Transparency** | Every report states what was read, what was rejected, what could not be correlated, and which parameters produced each alert |
| **Privacy** | No raw records in reports; optional username redaction; report files created owner-only on POSIX |

---

# 5. Methodology — The Detection Model

## 5.1 The question authentication analytics answers

> *Within the records I could validate and correlate, do any sources or accounts show a pattern of failures, or a failure-then-success sequence, that exceeds a stated threshold within a stated window?*

AuthWatch detects **patterns**. It does not decide whether a pattern is malicious; that is the analyst's job. Every alert is an investigation lead.

## 5.2 Three kinds of statement

A run can make three kinds of statement, and each needs different evidence. Naive tools conflate the second and third.

| Statement | Example | Evidence needed |
|---|---|---|
| **Alert** | "203.0.113.50 produced 9 failures in 120 s" | A positive observation: enough correlatable events inside one window |
| **Absence of alerts** | "Nothing suspicious found" | **Complete coverage** and at least one analyzed event |
| **Uncertainty** | "14 failures had no source IP, so AW-001 was blind to them" | A record of the failure, with a reason code and a count |

## 5.3 Evidence rules

| Statement | Category | Evidence required |
|---|---|---|
| `AW-001` alert | detection | ≥ `fail_threshold` events of outcome `failure` with the same `ip_key`, all with valid timestamps, inside one `(t − W, t]` window |
| `AW-002` alert | detection | Same, keyed by `username_key` |
| `AW-003` alert | detection | ≥ `spray_threshold` **distinct** `username_key` values among failures with the same `ip_key` inside one window |
| `AW-004` alert | detection | A `success` for an account preceded by ≥ `fail_threshold` `failure` events for the same `username_key` inside `(t − L, t]`, where failures sort before the success at equal timestamps |
| Clean result | coverage | `coverage.complete == true`, `events_analyzed ≥ 1`, zero alerts |
| Incomplete result | coverage | Any reason code in Section 5.4 |

## 5.4 Coverage model

Coverage is **complete** only if all of the following hold:

| Condition | Reason code when violated |
|---|---|
| At least one event survived validation and deduplication | `no_events` |
| `records_invalid == 0` | `invalid_records` |
| `records_unsupported == 0` (raw adapters) | `unsupported_records` |
| No repeated `record_id` with different content | `duplicate_conflicts` |
| For every enabled rule, every *relevant* event could be used (had a timestamp, the rule's key fields, and a known outcome) | `uncorrelatable:<RULE>` |
| No rule hit the 10 000-alert cap | `alert_cap_reached:<RULE>` |

**Not** coverage gaps: blank lines; lines an adapter positively recognised as irrelevant (e.g. SSH session bookkeeping); identical duplicates dropped by `record_id`; parse warnings; out-of-order records; long silent gaps. The last two are reported as signals in `timeline`, not as failures.

An event is *relevant* to a rule if its outcome could matter to it: `failure` and `unknown` for AW-001 to AW-003; `failure`, `success` and `unknown` for AW-004. Events with outcome `unknown` are always unusable — a record whose outcome cannot be determined might be a failure, so the rules cannot honestly ignore it. Producers should omit non-authentication records rather than emit `unknown`.

If an attacker causes records to be rejected, the cost is a loud `incomplete` run (exit `4`), not a silent miss. The sanitization rule in Section 6.10 ensures the converse: a recognised authentication line is never rejected *because of* attacker-controlled content.

## 5.5 Trust model for the input

The input log is **untrusted and possibly incomplete**. AuthWatch cannot know whether lines were deleted before it saw the file.

| Trust level | Mechanism | Protects against |
|---|---|---|
| **Structural** (always) | Strict schema, duplicate-key rejection, timestamp and IP validation | Corruption, smuggled or ambiguous records |
| **Chain of custody** (always) | SHA-256 and size of the exact bytes read are recorded in the report | Later dispute over which file was analyzed |
| **Silence signal** (Should) | Largest inter-event gap and out-of-order count in `timeline` | Nothing by itself; makes log gaps visible to the analyst |

**Inherent caveats:** deleted lines leave no trace in a count; any local user who can write to syslog can forge lines (Section 10.6); a log collected after compromise may already be altered. Collect logs read-only and hash them at collection time.

## 5.6 Operating workflow

```text
  COLLECT              HASH                 ANALYZE               TRIAGE               ESCALATE
 ──────────▶  ──────────────────▶  ──────────────────▶  ───────────────────▶  ─────────────────▶
 export logs   record sha256 at    authwatch analyze     read alerts + caveats   hand findings to
 read-only     collection time     → report + exit code  check coverage first    IRFlow / ticketing
```

Triage order: read `coverage` before `findings`. An alert on an `incomplete` run is real; the *absence* of other alerts is not evidence.

## 5.7 Why the window must slide — worked example

Five failures from one source at 180, 200, 240, 310 and 330 seconds, threshold 5, window 300 s. `[VERIFIED]`

| Method | Result |
|---|---|
| Fixed 5-minute buckets `[0,300)`, `[300,600)` | Bucket 0 holds 3, bucket 1 holds 2 → **no alert** |
| Sliding window `(t − 300, t]` at t = 330 | All five events fall inside → **alert** |

Five failures in 150 seconds are missed by fixed buckets purely because of where the clock edge fell. AuthWatch therefore freezes the sliding window.

## 5.8 Threshold guidance (Poisson tail)

Defaults are starting values, not universal baselines. To reason about false positives, model benign failures for one key as Poisson with rate λ per window. The probability that benign activity alone reaches the threshold `k` in a given window is `P(N ≥ k)`. `[VERIFIED]` arithmetic:

| λ (benign failures per key per window) | k = 3 | k = 5 | k = 10 |
|---|---|---|---|
| 0.1 | 1.5 × 10⁻⁴ | 7.7 × 10⁻⁸ | 1.1 × 10⁻¹⁶ |
| 0.5 | 1.4 × 10⁻² | 1.7 × 10⁻⁴ | 1.7 × 10⁻¹⁰ |
| 1 | 8.0 × 10⁻² | 3.7 × 10⁻³ | 1.1 × 10⁻⁷ |
| 2 | 3.2 × 10⁻¹ | 5.3 × 10⁻² | 4.7 × 10⁻⁵ |

How to use it: estimate λ from a quiet baseline period (failures per key per window), then pick `k` so that `P(N ≥ k)` multiplied by the number of keys and windows you scan gives an acceptable expected false-alert count. **Caveat:** real failures are bursty (a user retrying a stale saved password produces clustered failures), so the Poisson model *underestimates* false positives. Treat the table as a lower bound and tune on real data.

---

# 6. Core Engine Design

The core engine consists of modules with no dependency on `typer` or `rich`: `timeparse`, `keys`, `reader`, `models`, `events`, `window`, `rules`, `coverage`, `redact`, `reporter`, `outputs`, and the adapters. Section 7 gives the module map.

## 6.1 Input reader

The reader works on **bytes**, not decoded text, because the way a file is split into lines decides how many records exist.

| Rule | Behaviour |
|---|---|
| Line splitting | Split on `\n` only. Never `str.splitlines()` — it also splits on U+2028, U+2029 and others, turning one valid record into two invalid ones `[VERIFIED]` |
| Terminators | Strip trailing `\r` / `\n`. A final line without a newline is a normal line. Lone `\r` separators are not supported (the file becomes one invalid line) |
| BOM | A UTF-8 BOM on line 1 is removed; a BOM anywhere else is an invalid record |
| Encoding | Records are strict UTF-8. UTF-16/32 (detected by BOM, or by a NUL-heavy first 4 KiB) is a **whole-input failure**, exit `3`, because PowerShell 5.1 `Out-File` writes UTF-16 and 10 000 per-line errors would hide the real cause |
| Line length | A line longer than 64 KiB **including its terminator** is invalid (`line_too_long`). The reader drains it in bounded chunks, so memory per step never exceeds 64 KiB + 1 byte, even for a 10 MB line `[VERIFIED]` |
| NUL | A line containing a NUL byte is invalid (`nul_byte`) |
| Blank lines | Whitespace-only lines are counted (`blank_lines`) and skipped; they are not records |
| JSON parsing | `json.loads` with: duplicate-key rejection; `parse_constant` rejecting `NaN` / `Infinity`; `parse_float` rejecting non-finite values (`1e999` becomes `inf` otherwise); and a catch for `ValueError` (huge integers), `RecursionError` (deep nesting) and `UnicodeDecodeError` — none of which is a `JSONDecodeError` |
| Record type | The parsed value must be a JSON object (`not_an_object` otherwise) |
| Provenance | Every byte read, including drained and rejected lines, is fed to a SHA-256 so the hash covers the exact file analyzed `[UNVERIFIED]` |

Stable record-level reason codes (values from the record are **never** echoed): `line_too_long`, `nul_byte`, `invalid_utf8`, `invalid_json`, `duplicate_key`, `nesting_too_deep`, `invalid_value`, `not_an_object`, `schema_invalid:<field names>`, `invalid_timestamp`. For `schema_invalid`, only field names are listed, truncated to 40 characters; an unknown field is reported as `unknown_field` without its name, because the name is attacker-controllable.

Reference design. This is the loop that was executed during planning; its exception handling reported exception class names, which the production code maps to the reason codes above `[VERIFIED]` (loop and hooks) / `[UNVERIFIED]` (encoding heuristic, hashing):

```python
import json, math

MAX_LINE = 64 * 1024

def _reject_const(c):  raise ValueError(f"non-finite constant {c}")
def _finite_float(s):
    f = float(s)
    if not math.isfinite(f): raise ValueError("non-finite float")
    return f
def reject_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate keys")
    return dict(pairs)

def read(f):                                       # f: binary file object
    out, bad = [], []
    if f.read(2) in (b"\xff\xfe", b"\xfe\xff"):    # production: also the NUL-heavy heuristic -> exit 3
        raise ValueError("UTF-16")
    f.seek(0); lineno = 0
    while raw := f.readline(MAX_LINE + 1):         # bounded read
        lineno += 1
        if len(raw) > MAX_LINE:                    # terminator counts toward the limit
            while raw and not raw.endswith(b"\n"): # drain the rest in bounded chunks
                raw = f.readline(MAX_LINE + 1)
            bad.append((lineno, "line_too_long")); continue
        if lineno == 1 and raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        raw = raw.rstrip(b"\r\n")
        if not raw.strip():
            continue                               # blank: counted, not a record
        if b"\x00" in raw:
            bad.append((lineno, "nul_byte")); continue
        try:
            obj = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_dupes,
                             parse_constant=_reject_const, parse_float=_finite_float)
        except (UnicodeDecodeError, ValueError, RecursionError) as e:
            bad.append((lineno, type(e).__name__)); continue
        if not isinstance(obj, dict):
            bad.append((lineno, "not_an_object")); continue
        out.append((lineno, obj))
    return out, bad
```

## 6.2 Event schema and validation

AuthWatch uses a **custom, versioned, JSON-compatible event schema** (**DECIDED**, preserved from the baseline). JSON is a representation; the schema defines the fields and what they mean. If interoperability matters later, an exporter can map to OCSF or Elastic Common Schema. Field table: Section 8.1.

Validation is Pydantic v2 with `ConfigDict(strict=True, extra="forbid")`:

- **Strict types.** `true` is not an integer; `22.0` is not an integer; an integer is not an IP string.
- **Unknown fields are rejected.** A producer writing `sourceip` for `source_ip` would otherwise yield a silent `null` and the event would fall out of every IP rule.
- **Nullable does not mean optional.** `timestamp`, `username` and `source_ip` are *required keys* that may hold `null`. A missing key is an error; an explicit `null` means "the source did not provide it".
- **Text safety.** Strings must be UTF-8 encodable (a lone surrogate parses as JSON but later crashes the export `[VERIFIED]`) and contain no NUL.
- **Controlled vocabularies.** `outcome` ∈ `success | failure | unknown`; `event_type` is the literal `authentication`; `failure_reason` is an enum and requires `outcome == "failure"`.
- **Length caps** protect memory: username 256, host 255, `record_id` 128, `event_id` 64, 16 warnings of ≤ 200 characters.
- **Version policy.** `schema_version` is `"1.0"`. A minor bump adds optional fields only; a major bump breaks compatibility. The 1.0 tool accepts exactly `"1.0"` and rejects anything else with `schema_invalid`. A version field alone implements no migration.

Reference model `[PARTIAL]` — strictness, `extra="forbid"`, the `Literal` enums, port range, string-only IP, lone-surrogate and NUL rejection, and required-nullable behaviour were executed; the remaining fields and the cross-field rule are design:

```python
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

class AuthEvent(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    schema_version: Literal["1.0"]
    event_type: Literal["authentication"]
    timestamp: Optional[str]                       # required key, nullable; validated by parse_ts
    outcome: Literal["success", "failure", "unknown"]
    username: Optional[str] = Field(max_length=256)
    source_ip: Optional[str]                       # str only; validated by ip_key
    source_os: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]*$", max_length=32)
    source_product: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]*$", max_length=64)
    source_port: Optional[int] = Field(None, ge=0, le=65535)
    event_id: Optional[str] = Field(None, max_length=64)
    record_id: Optional[str] = Field(None, max_length=128)
    source_host: Optional[str] = Field(None, max_length=255)
    failure_reason: Optional[Literal["bad_credential", "unknown_account", "locked",
                                     "disabled", "expired", "other"]] = None
    auth_method: Optional[str] = Field(None, max_length=32)
    logon_type: Optional[int] = Field(None, ge=0, le=255)
    parser_name: Optional[str] = Field(None, max_length=64)
    parse_warnings: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("username", "event_id", "record_id", "source_host", "auth_method", "parser_name")
    @classmethod
    def _text(cls, v):
        if v is not None:
            v.encode("utf-8")                      # lone surrogate -> error here, not at export time
            if "\x00" in v: raise ValueError("NUL")
        return v
    # + field validators calling parse_ts(timestamp) and ip_key(source_ip), and a
    #   model_validator rejecting failure_reason unless outcome == "failure"
```

**`raw_event` is not part of schema 1.0** (closing baseline open decision #2). Raw records are the most sensitive thing in a log, and evidence by **line number plus input hash** is both smaller and verifiable.

## 6.3 Timestamp contract

Timestamps are the basis of every detection, so the profile is strict.

| Rule | Detail |
|---|---|
| Format | RFC 3339 profile: `YYYY-MM-DDTHH:MM:SS[.fraction](Z\|±HH:MM)`, ASCII digits only, uppercase `T`, `Z` or numeric offset **mandatory** |
| Naive timestamps | **Invalid**. UTC is never assumed |
| `-00:00` | Invalid (RFC 3339's "unknown offset") |
| Leap second `:60`, hour 24, impossible dates, offsets beyond ±23:59 | Invalid |
| Precision | Fractions up to 9 digits are accepted and **truncated to microseconds** |
| Internal form | Aware UTC → integer microseconds since the Unix epoch. All window arithmetic is integer; no floats, no string comparison |
| Null timestamp | Valid event; it cannot take part in any time-based rule and counts as uncorrelatable |
| Clock | No rule, validator or warning reads the wall clock |

Why the regex comes first: `datetime.fromisoformat` alone accepts naive values, date-only values, ISO week dates and basic format, and silently truncates nanoseconds `[VERIFIED]`. A pattern using `\d` and `$` is also wrong — `\d` matches non-ASCII digits and `$` matches before a trailing newline `[VERIFIED]` — so the pattern uses `[0-9]` and `fullmatch`.

```python
import re
from datetime import datetime, timezone

_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})")

def parse_ts(s):                                   # [VERIFIED] as shown; the OverflowError guard is [UNVERIFIED]
    if not isinstance(s, str) or not _TS.fullmatch(s) or s.endswith("-00:00"):
        raise ValueError("timestamp must be RFC 3339 (ASCII) with Z or a known offset")
    try:
        return datetime.fromisoformat(s).astimezone(timezone.utc)
    except OverflowError as exc:                   # e.g. 0001-01-01T00:00:00+05:00 underflows after conversion
        raise ValueError("timestamp out of supported range") from exc
```

Extreme but valid timestamps (year 1970 or 2999) are accepted and surface in `timeline` as an enormous gap or an out-of-order record.

## 6.4 Canonical grouping keys

An attacker chooses the spelling of a username (SSH logs it verbatim) and may reach a host over IPv4-mapped IPv6. Counting on raw strings lets them split one attack into several sub-threshold ones. Grouping therefore uses **canonical keys**; raw values stay in the input and are never altered.

```python
import ipaddress, unicodedata

def ip_key(v):                                     # [VERIFIED]
    if not isinstance(v, str): raise ValueError("source_ip must be a string")
    addr = ipaddress.ip_address(v)                 # IPv6 scope ids parsed natively; IPv4 '%' rejected
    zone = getattr(addr, "scope_id", None)
    if addr.version == 6:
        if zone: addr = ipaddress.IPv6Address(v.partition("%")[0])
        if addr.ipv4_mapped: addr = addr.ipv4_mapped
    return str(addr), zone

def username_key(u):                               # [VERIFIED]
    k = unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", u).casefold())
    suspicious = any(unicodedata.category(c) in ("Cf", "Cc") for c in k)
    k = "".join(c for c in k if unicodedata.category(c) != "Cf")
    return (k or None), suspicious                 # None -> uncorrelatable
```

| Decision | Detail |
|---|---|
| IP | String input only (the integer `3232235801` is accepted by `ipaddress` and must be rejected before it). IPv4-mapped IPv6 collapses to IPv4; text is lower-cased and compressed; an IPv6 scope id is stripped from the key and noted as a warning |
| Username | NFKC → casefold → NFKC (casefold alone leaves 26 code points non-normalized `[VERIFIED]`), then format characters (`Cf`, e.g. U+200B) are removed. A username containing format or control characters gets a warning (`username_has_format_or_control_chars`), because invisible characters in a username are suspicious in themselves |
| Empty key | A username that is empty after stripping has no key → `missing_username` (uncorrelatable). Without this, all such names would merge under `""` |
| Case folding | Deliberate trade-off: Linux usernames are case-sensitive, but a false merge costs less than a missed spray |
| Not merged | `DOMAIN\user`, `user@domain` and bare `user` stay distinct in V1; Turkish dotted `İ` folds to `i̇` (not `i`). Both are documented limitations |

## 6.5 Ordering, deduplication and rule input selection

**One global sort key**, used by every rule:

```text
(timestamp_utc_µs, outcome_rank, input_order)      outcome_rank: failure 0 · unknown 1 · success 2
```

- Events are sorted by instant, never by file order, so merged or shuffled logs give identical results. Out-of-order records are counted in `timeline` but do not change the outcome.
- At an equal timestamp a failure sorts **before** a success. (An earlier draft sorted by `(ts, input order)` in the window engine while Rule C required failures first; the contradiction was found while checking the patches `[VERIFIED]`.)
- Ties of equal outcome keep input order, so the result is deterministic.

**Deduplication** (closing baseline open decision #9): drop a later record only if it repeats a `(source_product, source_host, record_id)` seen earlier. **Content is never used**: two identical failures in the same second are plausible brute force at one-second resolution. A repeated `record_id` with *different* content is a `duplicate_conflict` (partial coverage). Records without `record_id` are never deduplicated.

**Rule input selection** `[UNVERIFIED]`:

```python
def select(events, outcomes, need_ip, need_user):
    usable, unc = [], Counter()
    for e in events:
        if e.outcome not in outcomes:      continue                      # irrelevant to this rule
        if e.outcome == "unknown":         unc["unknown_outcome"] += 1
        elif e.ts_us is None:              unc["missing_timestamp"] += 1
        elif need_ip and e.ip is None:     unc["missing_source_ip"] += 1
        elif need_user and e.user is None: unc["missing_username"] += 1
        else:                              usable.append(e)
    usable.sort(key=lambda e: (e.ts_us, OUTCOME_RANK[e.outcome], e.order))
    return usable, unc
```

## 6.6 Window engine

**Semantics (frozen):** for each key, the window ending at event time `t` contains events with `t − W < ts ≤ t`. An event exactly `W` old is **outside** the window. `[VERIFIED]` boundary results with `W = 300 s`, threshold 5:

| Event times (s) | Result |
|---|---|
| 0, 100, 200, 300, 300 | No alert — the event at 0 has left the window |
| 1, 100, 200, 300, 300 | Alert — all five are inside `(0, 300]` |

**Episodes.** A naive "alert whenever the count reaches the threshold" emits one alert per event once a burst is under way (a 500-failure flood would give ~496 alerts). Instead, an **episode** opens when the metric reaches the threshold, absorbs events while it stays at or above it, and closes when it drops below; each episode produces **one alert** carrying `first_seen`, `last_seen`, total `count` and `peak_in_window`. The opening window's earlier events are part of the episode.

Reference design for the count metric. It was compared against an O(n²) brute-force oracle on 3 000 random streams (fixed seeds, 1–3 keys, ties and duplicate timestamps) with **0 mismatches**, the 500-event flood produced 1 alert, and a burst, a quiet gap and a second burst within one window correctly merged `[VERIFIED]`:

```python
from collections import defaultdict, deque
from dataclasses import dataclass

@dataclass
class Episode:
    key: str; events: list; peak: int
    @classmethod
    def start(cls, k, evs): return cls(k, list(evs), len(evs))
    def add(self, ev, n):   self.events.append(ev); self.peak = max(self.peak, n)

def burst(events, key_fn, threshold, window):      # events pre-sorted; window in the same unit as ts
    dqs, open_ep, alerts, skipped = defaultdict(deque), {}, [], 0
    for ev in events:
        k = key_fn(ev)
        if k is None or ev.ts is None:
            skipped += 1; continue                 # production: pre-filtered by select()
        dq = dqs[k]; dq.append(ev)
        while dq[0].ts <= ev.ts - window:          # (t - W, t]
            dq.popleft()
        if len(dq) >= threshold:
            ep = open_ep.get(k)
            if ep is None: open_ep[k] = Episode.start(k, dq)
            else:          ep.add(ev, len(dq))
        elif k in open_ep:
            alerts.append(open_ep.pop(k))
    alerts.extend(open_ep.values())
    return alerts, skipped
```

**Production changes to the verified shape** (all `[UNVERIFIED]`, each with a required test in Section 12.3):

1. **Distinct metric (AW-003).** Keep a `Counter` of the distinct auxiliary value (username key) per key alongside the deque; the metric is `len(counter)` instead of `len(deque)`.
2. **Bounded evidence.** An episode stores a running count, the first 25 and last 25 line numbers, and top-N counters capped at 1 000 distinct keys (overflow counted, not stored) — never the event list. Otherwise one flood keeps every event in memory.
3. **Memory sweep.** Every 4 096 events, forget keys whose newest event is at or before `now − W`. Open episodes of those keys must be **closed and kept before** the key is evicted `[VERIFIED]`:
   ```python
   for k in [k for k, dq in dqs.items() if not dq or dq[-1].ts <= now - window]:
       if k in open_ep: alerts.append(open_ep.pop(k))
       del dqs[k]
   ```
   The sweep must not change results; the oracle test runs with the sweep interval set to 1.
4. **Alert cap.** At most 10 000 alerts per rule are recorded; further episodes are counted in `alerts_suppressed` and make coverage partial (`alert_cap_reached:<RULE>`). This bounds memory and stops an attacker from burying one real alert under thousands of decoys without anyone noticing.

Distinct-metric episodes reuse the same open/extend/close logic; for them `count` is the number of failure events in the episode and `peak_in_window` the peak number of distinct accounts.

## 6.7 Detection rules

All rules are deterministic, read only normalized events, and carry their parameters into the report. Defaults are starting values (Section 5.8).

| Rule | Title | Key | Metric | Defaults | Severity | MITRE ATT&CK (advisory) | Tier |
|---|---|---|---|---|---|---|---|
| **AW-001** | Failed-login burst from one source IP | `ip_key` | failures in window | 5 in 300 s | MEDIUM | T1110 Brute Force | Must |
| **AW-002** | Repeated failures against one account | `username_key` | failures in window | 5 in 300 s | MEDIUM | T1110.001 Password Guessing | Must |
| **AW-003** | One source IP failing against many accounts | `ip_key` | distinct accounts in window | 10 in 600 s | MEDIUM | T1110.003 Password Spraying | Should |
| **AW-004** | Success after repeated failures on the same account | `username_key` | failures in lookback before a success | 5 in 900 s lookback | HIGH | T1110, T1078 Valid Accounts | Should |

Why four rules (closing baseline open decision #6): no single key answers every question. Grouping by IP alone misses a distributed attack on one account; by account alone misses a single source sweeping many accounts; the IP–account pair misses both. AW-001 and AW-002 together are the Must pair. **Honest overlap:** a spray from one IP also fires AW-001 by raw volume; AW-003 adds the classification and a distinct-account threshold. Alerts are signals, not incidents, and overlapping alerts are expected.

**AW-004 semantics** `[UNVERIFIED]`:

- It runs per `username_key`, **not** per IP pair, so "failures from IP A, then success from IP B" — the pattern most worth catching — still fires. The alert records `ip_changed` (the success came from an address not seen among the failures).
- On a success at time `t`, count that account's failures in `(t − lookback, t]`; if ≥ threshold, alert. Failures that produced an alert are **consumed** so a later success needs fresh failures. Successes that did not alert do not clear failures.
- Failures sort before a success at equal timestamps.
- Unknown-outcome events and events lacking timestamp or username are uncorrelatable.

```python
def detect_fail_then_success(usable, threshold, lookback):   # usable: sorted, failure/success only
    fails, alerts = {}, []
    for ev in usable:
        cutoff = ev.ts - lookback
        if ev.outcome == "failure":
            dq = fails.setdefault(ev.user, deque())
            while dq and dq[0].ts <= cutoff: dq.popleft()
            dq.append(ev)
            continue
        dq = fails.get(ev.user)
        if not dq: continue
        while dq and dq[0].ts <= cutoff: dq.popleft()
        if len(dq) >= threshold:
            alerts.append((ev, list(dq)))                    # production: bounded evidence
            dq.clear()
    return alerts
```

**Caveats attached to alerts** (each alert carries its rule's caveat plus any data-quality note): NAT, proxies and VPN exits (AW-001, AW-003); stale saved passwords and service retry loops (AW-002); a user who finally remembers a password (AW-004); clock skew, missing or rotated logs, and duplicate lines; and — dynamically — "N relevant events could not be used by this rule" when its `uncorrelatable` count is non-zero. An IP address does not identify a person.

**Known detection limits:** low-and-slow attacks that stay below threshold in every window; attackers rotating both IPs and accounts; failures with missing fields (counted as uncorrelatable, not silently dropped).

## 6.8 Coverage, result and status derivation

`result` says whether alerts were found. `coverage` says whether the analysis could see everything. `status` is derived from both.

```python
def derive(counters, rule_runs, events_analyzed, fatal=False):          # [UNVERIFIED]
    reasons = []
    if events_analyzed == 0:           reasons.append("no_events")
    if counters.records_invalid:       reasons.append("invalid_records")
    if counters.records_unsupported:   reasons.append("unsupported_records")
    if counters.duplicate_conflicts:   reasons.append("duplicate_conflicts")
    for r in rule_runs:
        if sum(r.uncorrelatable.values()): reasons.append(f"uncorrelatable:{r.rule_id}")
        if r.suppressed:                   reasons.append(f"alert_cap_reached:{r.rule_id}")
    complete = not reasons
    alerts = sum(len(r.alerts) for r in rule_runs)
    result = "alerts_detected" if alerts else "clean"
    if fatal:           status = "error"
    elif not complete:  status = "incomplete"
    else:               status = result
    return status, result, complete, reasons
```

| status | result | coverage | Meaning | Exit |
|---|---|---|---|---|
| `clean` | `clean` | complete | Everything analyzed; no rule fired | `0` |
| `alerts_detected` | `alerts_detected` | complete | Alerts found; everything analyzed | `1` |
| `incomplete` | `clean` | partial | Nothing fired in what could be analyzed — **not a clean result** | `4` |
| `incomplete` | `alerts_detected` | partial | Alerts found **and** other activity may have gone unseen | `4` |
| `error` | — | — | Fatal; no valid analysis; no report written | `2`, `3`, `4` or `130` |

**Counter invariant** (a required test): `records_read = events_normalized + records_invalid + records_unsupported + records_irrelevant`, where `records_read` excludes blank lines. `events_analyzed = events_normalized − duplicates_dropped`.

## 6.9 Alert identity and evidence

**Alert id** (M3): the first 16 hex characters of SHA-256 over a canonical JSON list. The same input and parameters give the same ids; a JSON list avoids delimiter-collision (`"a|b","c"` vs `"a","b|c"`), and the string must be encoded to bytes before hashing `[VERIFIED]`:

```python
import hashlib, json
def alert_id(rule, subject, first_seen, params):
    blob = json.dumps([rule, subject, first_seen, params], separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]
```

`subject` is the **displayed** key. When redaction is on it is the redacted token, so the id cannot be used as an oracle to dictionary-test usernames.

**Alert fields:** `alert_id`, `rule_id`, `title`, `severity`, `attack[]`, `subject` (`ip:<key>` or `user:<key|token>`), `first_seen`, `last_seen`, `count`, `peak_in_window`, `threshold`, `window_seconds` (or lookback), `description`, `evidence`, `caveats[]`.

**Evidence** is bounded: up to 50 input **line numbers** (first 25 and last 25 when longer; `lines_truncated` says so), the top 10 usernames and source IPs with counts, the number of distinct values tracked, and the number of events whose value was not tracked once the 1 000-key cap was hit. AW-004 adds `success_line`, `success_ip` and `ip_changed`. Because the report records the input's SHA-256, each line number can be verified against the exact file.

Alerts are ordered by severity (HIGH first), then `first_seen`, then `rule_id`, then `subject`. The terminal shows the first 20 and says how many more the report holds.

## 6.10 Adapters

An adapter reads one source format and emits validated `AuthEvent`s plus a classification of every record it could not turn into one.

### 6.10.1 The sanitization rule (evasion by invalidity)

> **An adapter sanitizes attacker-controlled fields and records a warning; it rejects a recognised authentication line only for structural reasons.**

If a username that violates a validator makes the *record* invalid, an attacker can hide failures by choosing awkward usernames. So for raw sources: over-long usernames are truncated to 256 characters with a warning; undecodable bytes are replaced with a warning; an unparseable IP becomes `null` with a warning (the event is kept and the relevant rules report it as uncorrelatable); an out-of-range port becomes `null`. Strict rejection applies to the **JSONL contract**, whose producer is a tool, not an attacker.

### 6.10.2 JSONL adapter (Must)

Reads normalized events conforming to schema 1.0. Every non-blank line must validate; there is no "unsupported" category. This is the dependable first input and also the output format of `normalize`. Synthetic data uses documentation address ranges only (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; RFC 3849: `2001:db8::/32`).

### 6.10.3 OpenSSH text adapter (Should)

**Status: PROPOSED.** The patterns below are authored from the documented shapes of OpenSSH messages and have not been run against real logs. Phase S3 must obtain sanitized real samples (WSL or a small VM; `journalctl -u ssh`) and adjust before the adapter is called supported.

Every line is classified as exactly one of:

| Class | Meaning | Effect on coverage |
|---|---|---|
| **event** | A supported `Failed …` or `Accepted …` message | — |
| **irrelevant** | Recognised and safe to ignore (non-`sshd*` process; listed sshd bookkeeping) | none |
| **unsupported** | Unrecognised line shape, unrecognised `sshd` message, or a repeat summary | `unsupported_records` → partial |
| **invalid** | Timestamp cannot be built (e.g. 29 February in a non-leap assumed year) | `invalid_records` → partial |

Headers accepted: classic syslog (`Oct 26 10:30:00 host sshd[1234]: …`, which has **no year and no timezone**) and RFC 3339-prefixed lines (`2026-10-26T10:30:00+05:30 host sshd[1234]: …`, which are self-describing).

For syslog timestamps the operator must pass `--assume-year` and `--assume-tz` (a fixed offset such as `+05:30`, `Z` or `UTC`; IANA names are not accepted — Windows has no timezone database by default and daylight-saving transitions would be ambiguous). Without them the run stops with exit `2`; nothing is guessed. Both values are recorded in provenance. A chronological December → January transition increments the assumed year.

Patterns `[UNVERIFIED]` — matched with `fullmatch`, anchored at both ends:

```python
SYSLOG  = r"(?P<mon>[A-Z][a-z]{2}) +(?P<day>[0-9]{1,2}) (?P<hms>[0-9]{2}:[0-9]{2}:[0-9]{2}) (?P<host>\S+) (?P<proc>[^\s:\[\]]+)(?:\[[0-9]+\])?: (?P<msg>.*)"
RFC3339 = r"(?P<ts>[0-9]{4}-[0-9]{2}-[0-9]{2}T\S+) (?P<host>\S+) (?P<proc>[^\s:\[\]]+)(?:\[[0-9]+\])?: (?P<msg>.*)"
FP      = r"(?:: [A-Z0-9-]+ (?:SHA256|MD5):\S+)?"        # explicit fingerprint suffix, no free text
FAILED  = r"Failed (?P<method>[a-z][a-z-]*(?:/[a-z]+)?) for (?P<inv>invalid user )?(?P<user>.+) from (?P<ip>\S+) port (?P<port>[0-9]{1,5}) ssh2" + FP
ACCEPTED= r"Accepted (?P<method>[a-z][a-z-]*(?:/[a-z]+)?) for (?P<user>.+) from (?P<ip>\S+) port (?P<port>[0-9]{1,5}) ssh2" + FP
REPEAT  = r"(?:last )?message repeated [0-9]+ times?.*"
```

Design points:

- **Greedy username with an end anchor.** `(?P<user>.+)` is greedy and the pattern must reach the end of the line, so the *last* well-formed ` from <ip> port <n> ssh2` tail wins. A username such as `evil from 8.8.8.8 port 1` therefore cannot spoof the source address; the genuine tail is the one sshd wrote last.
- **No double counting.** On a failed attempt for a non-existent user, sshd writes both an `Invalid user …` line and a `Failed password for invalid user …` line. Only the latter is an event; the former, and `pam_unix(sshd:auth)` lines that duplicate it, are *irrelevant*. The event gets `failure_reason = unknown_account` when `invalid user` is present, `bad_credential` for password methods.
- **Repeat summaries are unsupported.** rsyslog's "message repeated N times" collapses N events into one line; counting it as one would under-report. These lines make coverage partial, and the operator is told to disable repeat reduction.
- **Process scope.** Any process whose name starts with `sshd` (covering `sshd-session`, used by recent OpenSSH releases — verify) is in scope; other processes are irrelevant. If the process-name assumption is wrong for a log, no events are produced and the run reports `no_events` rather than a false clean.
- **Event fields:** `source_os: linux`, `source_product: openssh`, `parser_name: openssh-v1`, `source_host` from the header, `auth_method` from the message, `outcome` from `Failed` / `Accepted`.

## 6.11 Privacy and redaction

Failed-login records are sensitive in a way that is easy to miss: **people routinely type their password into the username field**, so a list of failed usernames can be a list of credentials.

| Control | Detail |
|---|---|
| No raw records | Schema 1.0 has no `raw_event`; reports contain keys, counts and line numbers only |
| Basename only | Reports record the input's file name, not its full path |
| Redaction (Should) | `--redact-usernames` replaces every username key in every output (terminal, JSON, CSV, `normalize`) with `u:` + the first 12 hex characters of `HMAC-SHA256(key, username_key)`. Grouping is unaffected because it happens before display |
| Redaction key | `AUTHWATCH_REDACT_KEY` (≥ 32 bytes, else exit `2`) gives stable tokens across runs; if unset a random per-run key is used and the report says `key_source: "ephemeral"` |
| Alert ids | Computed from the displayed subject (Section 6.9) |
| File permissions | Report files are created via a temp file (mode `0600` on POSIX) |
| What redaction does not do | It does not protect the *input* file, and an IP address remains visible. The README must say so |
| Retention | AuthWatch stores nothing between runs |

---

# 7. System Architecture

## 7.1 Pipeline

```text
                         INPUT FILE  (jsonl  |  openssh text)
                                    │  bytes
                                    ▼
                    ┌──────────────────────────────────┐
                    │ reader.py                        │  split on \n · caps · BOM/UTF-16 · NUL
                    │ lines + per-line problems + SHA-256
                    └───────────────┬──────────────────┘
                                    ▼
                    ┌──────────────────────────────────┐
                    │ adapters/jsonl.py | openssh.py   │  parse → semantic mapping
                    │ event | irrelevant | unsupported | invalid
                    └───────────────┬──────────────────┘
                                    ▼
                    ┌──────────────────────────────────┐
                    │ models.py  (strict AuthEvent)    │  validation; warnings
                    └───────────────┬──────────────────┘
                                    ▼
                    ┌──────────────────────────────────┐
                    │ events.py                        │  canonical keys · µs timestamps
                    │ dedupe (record_id) · select · global sort
                    └───────────────┬──────────────────┘
                                    ▼
                    ┌──────────────────────────────────┐
                    │ window.py + rules.py             │  AW-001 … AW-004
                    │ alerts + per-rule uncorrelatable counts
                    └───────────────┬──────────────────┘
                                    ▼
                    ┌──────────────────────────────────┐
                    │ coverage.py                      │  reasons → status / result / exit code
                    └───────────────┬──────────────────┘
                    ┌───────────────┼──────────────────────────┐
                    ▼               ▼                          ▼
             reporter.py       render.py (Rich,           exporters.py
             envelope JSON     escaped output)            CSV (Could)
                    └───────────────┬──────────────────────────┘
                                    ▼
                    outputs.py: path checks + atomic write      →  exit code
```

## 7.2 Module responsibilities

| Module | Responsibility | May import |
|---|---|---|
| `errors.py` | Exception hierarchy; each class carries its exit code | stdlib |
| `timeparse.py` | `parse_ts`, `to_us`, `iso_utc`, `parse_duration` | stdlib |
| `keys.py` | `ip_key`, `username_key` | stdlib |
| `reader.py` | Bytes-level line reader, hashing, per-line problems, JSON parse hooks | stdlib |
| `models.py` | `AuthEvent` and report models (Pydantic v2, strict) | pydantic, `timeparse`, `keys` |
| `adapters/jsonl.py` | JSONL → events + counters | `reader`, `models` |
| `adapters/openssh.py` | OpenSSH text → events + counters (Should) | `reader`, `models`, `timeparse` |
| `events.py` | `Event` dataclass, `build_event`, `dedupe`, `select`, sort key | `models`, `keys`, `timeparse` |
| `window.py` | Sliding-window episodes (count and distinct metrics); AW-004 detector | stdlib |
| `rules.py` | Rule catalogue, `Params` validation, alert construction | `events`, `window`, `redact` |
| `coverage.py` | Counters, reason codes, `derive()` | stdlib |
| `redact.py` | HMAC username redaction (Should) | stdlib |
| `reporter.py` | Report assembly in the shared envelope | `models` |
| `exporters.py` | CSV (Could); normalized JSONL writer (Should) | stdlib |
| `outputs.py` | `same_file`, path checks, atomic write, overwrite guard | stdlib |
| `render.py` | Rich terminal summary; `safe_display` | rich |
| `cli.py` | Typer commands, option parsing, orchestration, `main()` | everything |

**Dependency rule:** nothing below `cli.py` and `render.py` imports `typer` or `rich`. The engine is usable as a library and testable without a terminal. Detection modules read only normalized events and never see raw source syntax.

## 7.3 `analyze` sequence

1. Parse and validate options and durations → else exit `2`.
2. Check the input path (exists, is a file) → else exit `2`; open it → else exit `4`.
3. Check the report/CSV paths (Section 9.4) → else exit `2`.
4. Build the redactor if requested (key too short → exit `2`).
5. Read lines (whole-input encoding failure → exit `3`); adapt each record to an event or a classified problem; count everything.
6. Deduplicate; build canonical events; for each enabled rule: `select` → sort → detect.
7. `derive()` the status; assemble the report; write it atomically if requested.
8. Render the terminal summary (or print the JSON when `--format json`).
9. Exit with the code mapped from the status (Section 9.2).

`normalize` follows steps 1–5, then writes validated events as JSONL and exits `0` (every record accounted for) or `4` (some records invalid or unsupported — the output file is still written, and stderr says so).

---

# 8. Data Model and File Formats

## 8.1 Event schema 1.0

| Field | Type | Key required? | Nullable? | Meaning / constraints |
|---|---|---|---|---|
| `schema_version` | `"1.0"` | yes | no | Contract version |
| `event_type` | `"authentication"` | yes | no | Literal; no other value in V1 |
| `timestamp` | string | yes | **yes** | Strict RFC 3339 profile (Section 6.3) |
| `outcome` | `success` \| `failure` \| `unknown` | yes | no | Controlled vocabulary |
| `username` | string ≤ 256 | yes | **yes** | Account identifier as the source wrote it |
| `source_ip` | string | yes | **yes** | IPv4 or IPv6 literal; IPv6 scope id tolerated; integers rejected |
| `source_os` | token ≤ 32 | yes | no | e.g. `synthetic`, `linux`, `windows` |
| `source_product` | token ≤ 64 | yes | no | e.g. `authwatch-fixture`, `openssh`, `windows-security` |
| `source_port` | int 0–65535 | no | yes | Booleans and floats rejected |
| `event_id` | string ≤ 64 | no | yes | Original source event id (e.g. Windows 4625); rules never depend on it |
| `record_id` | string ≤ 128 | no | yes | Unique record identity within `(source_product, source_host)`; the only basis for deduplication |
| `source_host` | string ≤ 255 | no | yes | Host that generated the record |
| `failure_reason` | enum | no | yes | `bad_credential`, `unknown_account`, `locked`, `disabled`, `expired`, `other`; only with `outcome: failure` |
| `auth_method` | string ≤ 32 | no | yes | e.g. `password`, `publickey` |
| `logon_type` | int 0–255 | no | yes | Reserved for Windows logon types |
| `parser_name` | string ≤ 64 | no | yes | Adapter that produced the event |
| `parse_warnings` | list of ≤ 16 strings ≤ 200 | no | no | Non-fatal data-quality notes |

Not in the schema: `raw_event` (Section 6.2). Engine-added warnings (not stored in the event): `username_has_format_or_control_chars`, `username_empty_after_normalization`, `ip_scope_id_ignored`, `ip_canonicalized`. `events_with_warnings` counts events with adapter or engine warnings.

## 8.2 Normalized JSONL

One JSON object per line, UTF-8, `\n` terminated, keys sorted, ASCII-escaped on output (so the file is independent of console code pages). Synthetic example:

```jsonl
{"auth_method":null,"event_id":null,"event_type":"authentication","failure_reason":null,"logon_type":null,"outcome":"failure","parse_warnings":[],"parser_name":"jsonl-v1","record_id":null,"schema_version":"1.0","source_host":"example-host","source_ip":"203.0.113.50","source_os":"synthetic","source_port":51234,"source_product":"authwatch-fixture","timestamp":"2026-10-26T10:30:00Z","username":"alice"}
{"event_type":"authentication","outcome":"success","schema_version":"1.0","source_ip":"198.51.100.7","source_os":"synthetic","source_product":"authwatch-fixture","timestamp":"2026-10-26T10:33:00Z","username":"alice"}
```

A minimal producer may omit every optional field (second line). Nullable fields that are required keys (`timestamp`, `username`, `source_ip`) must still be present.

## 8.3 Report format

Illustrative, for the fixture in Section 15.2. It was derived by hand from the rule definitions, **not generated by running the tool**; digests are placeholders. A real report comes from a real run.

```json
{
  "envelope": {
    "schema": "7d7b-report", "schema_version": 1,
    "tool": "AuthWatch", "tool_version": "1.0.0",
    "run_id": "<uuid4>", "started_at": "2026-10-26T12:00:00Z", "completed_at": "2026-10-26T12:00:01Z"
  },
  "status": "alerts_detected",
  "result": "alerts_detected",
  "input": { "label": "attacks.jsonl", "format": "jsonl", "sha256": "<64 hex>", "size_bytes": "<n>" },
  "parameters": {
    "rules": ["AW-001", "AW-002", "AW-003", "AW-004"],
    "fail_threshold": 5, "fail_window_s": 300, "spray_threshold": 10, "spray_window_s": 600, "lookback_s": 900,
    "redaction": null
  },
  "coverage": {
    "complete": true,
    "reasons": [],
    "counters": {
      "lines_total": 39, "blank_lines": 0, "records_read": 39, "events_normalized": 39,
      "records_invalid": 0, "records_unsupported": 0, "records_irrelevant": 0,
      "events_with_warnings": 0, "duplicates_dropped": 0, "duplicate_conflicts": 0, "events_analyzed": 39
    },
    "rules": {
      "AW-001": { "uncorrelatable": 0, "by_reason": {}, "alerts_suppressed": 0 },
      "AW-002": { "uncorrelatable": 0, "by_reason": {}, "alerts_suppressed": 0 },
      "AW-003": { "uncorrelatable": 0, "by_reason": {}, "alerts_suppressed": 0 },
      "AW-004": { "uncorrelatable": 0, "by_reason": {}, "alerts_suppressed": 0 }
    },
    "timeline": {
      "earliest": "2026-10-26T10:01:40Z", "latest": "2026-10-26T11:15:00Z",
      "largest_gap_seconds": 1050, "gap_start": "2026-10-26T10:52:30Z", "gap_end": "2026-10-26T11:10:00Z",
      "out_of_order_records": 0
    }
  },
  "summary": { "AW-001": 2, "AW-002": 2, "AW-003": 1, "AW-004": 1, "errors": 0 },
  "findings": [
    {
      "event": "AW-004", "category": "detection", "subject": "user:alice",
      "details": {
        "alert_id": "<16 hex>", "title": "Success after repeated failures on the same account", "severity": "HIGH",
        "attack": ["T1110", "T1078"], "first_seen": "2026-10-26T10:30:00Z", "last_seen": "2026-10-26T10:33:00Z",
        "count": 9, "peak_in_window": 9, "threshold": 5, "window_seconds": 900,
        "description": "A successful authentication for account alice at 2026-10-26T10:33:00Z followed 9 failures within the 900s lookback (threshold 5); success came from a source IP not seen in the failures.",
        "evidence": { "lines": [1, 2, 3, 4, 5, 6, 7, 8, 9], "lines_truncated": false, "success_line": 10,
                      "success_ip": "198.51.100.7", "ip_changed": true,
                      "usernames": [{ "value": "alice", "count": 9 }], "source_ips": [{ "value": "203.0.113.50", "count": 9 }] },
        "caveats": ["A user who finally remembers the password looks the same; check whether the success came from a new source."]
      }
    },
    { "event": "AW-001", "category": "detection", "subject": "ip:203.0.113.50", "details": { "…": "…" } }
  ],
  "errors": [],
  "errors_truncated": false
}
```

Notes: `findings[]` is the envelope's generic list; each AuthWatch alert is one finding whose `event` is the rule id. The `timeline` gap shown is the silence between the last event of scenario S4 (10:52:30) and the first of S6 (11:10:00). A run with problems adds entries such as `{"kind":"INVALID_RECORD","subject":"line:12","message":"duplicate_key"}` to `errors[]` (capped at 1 000; `errors_truncated` says so).

## 8.4 Counters, error kinds and reason codes

| Counter | Meaning |
|---|---|
| `lines_total`, `blank_lines` | Physical lines read; whitespace-only lines |
| `records_read` | Non-blank lines |
| `events_normalized` | Records that became valid events |
| `records_invalid` | Structurally invalid (reader, JSON, schema, timestamp) |
| `records_unsupported` | Raw-adapter lines that could not be classified or are repeat summaries |
| `records_irrelevant` | Raw-adapter lines positively recognised as out of scope |
| `events_with_warnings` | Events carrying any warning |
| `duplicates_dropped`, `duplicate_conflicts` | Repeated `record_id`s; those with differing content |
| `events_analyzed` | `events_normalized − duplicates_dropped` |

Error kinds in `errors[]`: `INVALID_RECORD`, `UNSUPPORTED_RECORD`, `DUPLICATE_CONFLICT`, plus operational kinds (for example `OUTPUT_WRITE_FAILED`). Coverage reason codes are listed in Section 5.4.

## 8.5 Shared report envelope

Every tool in the 7 Days series emits this envelope so the Day 7 incident-response tool can ingest any report generically.

| Field | Required | Description |
|---|---|---|
| `envelope.schema` | yes | Constant `"7d7b-report"` |
| `envelope.schema_version` | yes | Envelope version (integer) |
| `envelope.tool`, `envelope.tool_version` | yes | Producer identity |
| `envelope.run_id` | yes | UUID4 per run |
| `envelope.started_at`, `envelope.completed_at` | yes | UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `status` | yes | Tool-defined; must be able to express incompleteness (AuthWatch: `clean`, `alerts_detected`, `incomplete`) |
| `summary` | yes | Counts by event |
| `findings[]` | yes | `{event, category, subject, details}` |
| `errors[]` | yes | `{kind, subject, message}` |

Tool-specific sections (AuthWatch: `result`, `input`, `parameters`, `coverage`, `errors_truncated`) sit alongside.

## 8.6 CSV export (Could)

One row per alert; columns `alert_id, rule_id, severity, title, subject, first_seen, last_seen, count, peak_in_window, threshold, window_seconds, description`; UTF-8, `\n` line endings, header row. Evidence is not included (it is nested). Every cell passes through `csv_safe`, because usernames flow into cells and a username like `=HYPERLINK(...)` becomes a live formula in a spreadsheet `[VERIFIED]`:

```python
def csv_safe(s):                                   # [VERIFIED]
    lead = unicodedata.normalize("NFKC", s.lstrip(" \t\r\n"))[:1]
    return "'" + s if s and (s[0] in "=+-@\t\r\n" or lead in ("=", "+", "-", "@")) else s
```

The first version of this function missed a leading space, a leading newline and the fullwidth `＝`; the corrected version handles all three. Whether spreadsheets treat fullwidth `＝` as a formula was not tested — it is escaped regardless.

---

# 9. CLI Contract

## 9.1 Commands

```text
authwatch analyze INPUT
    [--input-format jsonl|openssh]        default jsonl
    [--assume-year YYYY] [--assume-tz Z|UTC|±HH:MM]     required for openssh syslog timestamps
    [--fail-threshold N]   default 5      [--fail-window DUR]    default 300s
    [--spray-threshold N]  default 10     [--spray-window DUR]   default 600s
    [--lookback DUR]       default 900s
    [--rules AW-001,AW-002,...]           default: every rule that is implemented
    [--report PATH] [--csv PATH] [--force-report]
    [--format text|json]                  default text; json = report (only) on stdout
    [--redact-usernames]

authwatch normalize INPUT --output PATH        (Should)
    [--input-format ...] [--assume-year ...] [--assume-tz ...] [--redact-usernames] [--force-report]

authwatch --version        authwatch --help        authwatch analyze --help
```

Durations: an integer followed by `s`, `m`, `h` or `d` (`300s`, `5m`, `1h`, `2d`); anything else is exit `2`.

**Bounds (closing baseline open decisions #7 and #8):** thresholds 2–100 000; `fail`/`spray` windows 1 s–7 d; `lookback` ≥ `fail-window` and ≤ 30 d; `--rules` must name known rules. A threshold of 1 would alert on every failure and is refused.

The exact option names are frozen here; an implementer may not rename them without updating this document.

## 9.2 Exit codes

| Code | Meaning |
|---|---|
| `0` | Complete analysis, no alerts (or successful `normalize`) |
| `1` | Complete analysis, alerts detected |
| `2` | Invalid arguments or configuration: bad option or duration, missing input path, unwritable or colliding output path, existing foreign file at an output path, missing assumed year/timezone for syslog input, short redaction key |
| `3` | Input unusable as a whole: UTF-16/32 or binary data |
| `4` | Incomplete analysis or operational failure: any coverage reason, input unreadable by the OS, output write failure, **any unexpected exception** |
| `130` | Interrupted (Ctrl+C) |

**Precedence:** errors detected before analysis (`2`, `3`) end the run immediately. After analysis, `4` (partial coverage) outranks `1` (alerts), which outranks `0`. A run that found alerts **and** had coverage gaps exits `4`; the alerts remain in the report. Automation should treat any non-zero code as "needs attention" and read `status` / `result` in the report for detail.

## 9.3 Output rules

- `--format text`: Rich summary on stdout; warnings and errors on stderr.
- `--format json`: the JSON report, and nothing else, on stdout; all diagnostics on stderr (safe to pipe to `jq`).
- The terminal summary shows: input label and hash prefix, counters, coverage line, the first 20 alerts (severity, rule, subject, count, window, one-line reason), and how many more the report holds.
- Success wording is used only when `status` is `clean` or `alerts_detected`. An `incomplete` run prints the reason codes and the sentence "no alerts in the analyzable data — this is NOT a clean result".
- Fatal outcomes (exit `2`, `3`, a fatal `4`, `130`) write no report file and print nothing on stdout in JSON mode. A non-fatal exit `4` **does** write the report.
- Every untrusted string (usernames, hosts, IPs as text, error text) passes through `safe_display()` first.

## 9.4 Output path safety

| Check | On failure |
|---|---|
| Parent directory exists | exit `2` |
| Path is not a directory or a symlink | exit `2` |
| Path is not the input file — compared by resolved path **and** `os.path.samefile`, which also catches hard links | exit `2` |
| An existing file at the path is an AuthWatch report (`envelope.tool == "AuthWatch"`, ≤ 16 MiB probed) | exit `2` unless `--force-report` |
| Write is atomic: temp file in the same directory → `fsync` → `os.replace` | exit `4`; the original is untouched |

```python
def same_file(a, b):                               # [VERIFIED]  resolve() alone misses hard links
    if Path(a).resolve() == Path(b).resolve(): return True
    try:    return os.path.samefile(a, b)
    except FileNotFoundError: return False

def write_atomic(path, data):                      # [UNVERIFIED] pattern; mkstemp gives mode 0600 on POSIX
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".authwatch-tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True); raise
```

On Windows `os.replace` fails if the destination is open elsewhere; that surfaces as exit `4` with the original intact.

## 9.5 Exit-code mapping

Commands return an integer; a `guarded` decorator owns all exception mapping, so an unexpected crash can never look like "alerts detected". Executed against Typer 0.27.3: `0, 1, 2, 4, 130` were all produced correctly and an unknown option exited `2` `[VERIFIED]`:

```python
import functools, typer

app = typer.Typer(pretty_exceptions_enable=False, add_completion=False, no_args_is_help=True)

def guarded(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            code = fn(*args, **kwargs)                 # commands return an int exit code
        except typer.Exit:
            raise
        except KeyboardInterrupt:
            code = 130
        except AuthWatchError as exc:                  # carries its own exit code (2, 3 or 4)
            code = exc.exit_code                       # message printed via safe_display()
        except Exception:                              # never let a crash look like a finding
            code = 4
        raise typer.Exit(code)
    return wrapper

def main() -> None:                                    # console-script entry point
    app(prog_name="authwatch")
```

Decorate each command with `@app.command(...)` above `@guarded`. Do not import `click` directly — recent Typer versions vendor it. `--version` is an eager option on the app callback.

---

# 10. Security Design and Threat Model

## 10.1 Assets

The integrity of detection results, the confidentiality of usernames and addresses in logs, the analyst's terminal, the original log file, and previously written reports.

## 10.2 Trust boundaries

- **Untrusted:** everything in the input — field values, usernames, hostnames, line lengths, structure, ordering.
- **Untrusted by position:** the input's completeness. AuthWatch cannot know what was deleted before collection.
- **Trusted:** the operator's command-line arguments and environment.

## 10.3 Threats and mitigations

| # | Threat | Impact | Mitigation | Section |
|---|---|---|---|---|
| T1 | Burst straddles a fixed-bucket boundary | Missed detection | Sliding window `(t − W, t]` | 6.6 |
| T2 | Spraying or distributed guessing stays under a single-key threshold | Missed detection | Four rules with different keys | 6.7 |
| T3 | Username spelling variants (case, fullwidth, invisible characters) split counts | Sub-threshold evasion | Canonical `username_key`; invisible-character warning | 6.4 |
| T4 | IPv4-mapped or scoped IPv6 forms split counts | Sub-threshold evasion | Canonical `ip_key` | 6.4 |
| T5 | Duplicate JSON keys flip an outcome | Failure recorded as success | Duplicate-key rejection | 6.1 |
| T6 | Mistyped field name yields a silent `null` | Event drops out of IP rules | `extra="forbid"`; required nullable keys | 6.2 |
| T7 | Malformed lines used to hide failures | False clean | Invalid records make coverage partial (loud) | 5.4 |
| T8 | Awkward usernames used to invalidate recognised auth lines | Failures hidden as invalid | Adapters sanitize, never reject | 6.10.1 |
| T9 | Repeat-suppressed syslog under-counts | Undercount | Repeat summaries are `unsupported` | 6.10.3 |
| T10 | Empty, truncated or wrong-format input | False clean | `no_events` → incomplete | 6.8 |
| T11 | Internal crash mistaken for a result | Wrong automation action | `guarded()` → exit `4` | 9.5 |
| T12 | Terminal control sequences or Rich markup in usernames | Manipulated analyst view | `safe_display`; consoles with `highlight=False, emoji=False` | 10.5 |
| T13 | Spreadsheet formula injection via CSV | Code execution or phishing in Excel | `csv_safe` | 8.6 |
| T14 | `--report` pointed at the input or at a hard link of it | Evidence destroyed | `same_file` check | 9.4 |
| T15 | Interrupted write corrupts an existing report | Lost report | Atomic temp-and-replace | 9.4 |
| T16 | Huge line, deep nesting or giant integer | Crash or memory exhaustion | 64 KiB cap with bounded drain; `RecursionError` / `ValueError` caught | 6.1 |
| T17 | Very many distinct keys or a single-key flood | Memory exhaustion | Key sweep; bounded evidence; capped counters | 6.6 |
| T18 | Thousands of decoy alerts bury a real one | Analyst fatigue | Severity ordering; 10 000-alert cap that degrades coverage honestly | 6.6, 6.9 |
| T19 | Passwords typed into username fields leak through reports | Credential exposure | No raw events; optional redaction; owner-only files; README warning | 6.11 |
| T20 | Alert id used to dictionary-test usernames | Username disclosure | Id hashes the displayed (redacted) subject | 6.9 |
| T21 | Naive or ambiguous timestamps | Wrong ordering and windows | Strict RFC 3339 profile; no assumed timezone | 6.3 |
| T22 | Username embeds ` from <ip> port <n> ssh2` to spoof the source | Misattributed alert | Greedy username + end-anchored pattern + IP validation | 6.10.3 |
| T23 | Execution of log content | Code execution | Input is data only: no `eval`, no shell, no format-string use of values | — |
| T24 | UTF-16 file read as garbage | 10 000 misleading errors | Whole-input failure with a clear message, exit `3` | 6.1 |
| T25 | Forged syslog lines by any local user | False alerts or masking | **Limitation** (10.6) | — |
| T26 | Deleted or edited logs | Undetectable under-count | **Limitation**; input hash; `timeline` gap signal | 5.5 |
| T27 | Forged or skewed timestamps | Wrong windows | **Limitation**; `timeline` | 10.6 |
| T28 | Dependency compromise | Supply-chain risk | Three runtime dependencies (`typer`, `rich`, `pydantic`); lower-bound pins; no network access at runtime | 14.2 |

## 10.4 Evasion matrix

| Attacker technique | Naive tool | AuthWatch |
|---|---|---|
| Spread attempts across many IPs against one account | Missed | AW-002 |
| One IP sweeping many accounts, few tries each | Missed by account-only counting | AW-001 by volume; AW-003 by distinct accounts |
| Time attempts around bucket edges | Missed | Sliding window |
| Vary username spelling | Counts split | Canonical keys |
| Send junk lines to hide real ones | Silent | Loud `incomplete` |
| Pick usernames that break a strict parser | Silent drop | Sanitized and still counted |
| Flood alerts as decoys | Overwhelms | Ordering and cap with honest coverage |
| Stay below threshold forever | Missed | **Not covered** (low-and-slow) |
| Delete log lines before collection | Missed | **Not covered**; hash and gap signal only |

## 10.5 Terminal output safety

`rich.markup.escape()` neutralizes `[red]` but **not** `:emoji:` codes `[VERIFIED]`, so consoles are created with `emoji=False` and `highlight=False`, and every untrusted string goes through `safe_display`. Verified: `[red]root[/red]`, `:smile:`, `admin\x1b[2J` (ESC), and a right-to-left override all rendered literally with no escape byte reaching the output `[VERIFIED]`.

```python
from rich.markup import escape
from rich.console import Console

def safe_display(s: str) -> str:                   # [VERIFIED]; production also truncates to a fixed length
    out = []
    for ch in s:
        if ch.isprintable(): out.append(ch)
        else:
            cp = ord(ch); out.append(f"\\x{cp:02x}" if cp < 0x100 else f"\\u{cp:04x}")
    return escape("".join(out))

console     = Console(highlight=False, emoji=False)
err_console = Console(stderr=True, highlight=False, emoji=False)
```

JSON output needs no such escaping; the encoder handles it.

## 10.6 Security limitations

- A `clean` status means no rule fired in the fully analyzed input. It does not mean the system is secure or the log is complete.
- AuthWatch cannot detect log deletion, tampering before collection, or logs collected after compromise.
- Any local user able to write to syslog can forge lines that look like sshd output.
- Timestamps come from the source; a skewed or forged clock yields wrong windows. `timeline` helps a human notice, nothing more.
- Low-and-slow attacks that stay under threshold in every window are not detected.
- An IP address is not a person. NAT, proxies and VPN exits make one address many users.
- Case folding is a deliberate over-merge for Linux; `DOMAIN\user` / UPN / bare names are not merged.
- Redaction protects reports, not the input; IP addresses are never redacted.
- The OpenSSH adapter supports only the listed message shapes; other sshd messages make coverage partial.
- Alerts are leads for investigation, never proof of compromise.

---

# 11. Edge Cases and Failure Handling

**Test tier:** **U** = in-memory unit test · **F** = real file in `tmp_path` · **M** = monkeypatch / injected failure · **D** = documented limitation, no test.

## 11.1 Register

### Reader and input file

| # | Case | Handling | Tier |
|---|---|---|---|
| 1 | Empty file, or only blank lines | `no_events` → `incomplete`, exit `4` | F |
| 2 | UTF-8 BOM on line 1 / BOM on a later line | Accepted / `invalid_json` for that line | F |
| 3 | CRLF endings; last line without newline | Accepted | F |
| 4 | Lone `\r` separators | One invalid line (`invalid_json`) | F |
| 5 | U+2028 / U+2029 inside a string | One record (split on `\n` only) | F |
| 6 | UTF-16 with or without BOM; binary | Exit `3` | F |
| 7 | Isolated NUL byte in a line | `nul_byte`; other lines unaffected | F |
| 8 | Line over 64 KiB; a 10 MB line | `line_too_long`; bounded memory; next line read correctly | F |
| 9 | Invalid UTF-8 bytes | `invalid_utf8` | F |
| 10 | Malformed / truncated JSON | `invalid_json` | F |
| 11 | Duplicate keys (top-level, nested, escaped-equal such as `"a"` and `"a"`) | `duplicate_key` | U |
| 12 | `NaN`, `Infinity`, `1e999` | `invalid_value` | U |
| 13 | 5 000-digit integer | `invalid_value` (a `ValueError`, not a `JSONDecodeError`) | U |
| 14 | 30 000-deep nesting | `nesting_too_deep` (`RecursionError` caught) | U |
| 15 | Top-level array or scalar | `not_an_object` | U |
| 16 | Input path missing or a directory | Exit `2` | F |
| 17 | Input unreadable by the OS | Exit `4` | M |
| 18 | File still being appended to | Torn last line is an invalid record; hash covers bytes actually read | D |

### Schema and timestamps

| # | Case | Handling | Tier |
|---|---|---|---|
| 19 | Mistyped field name (`sourceip`) | `schema_invalid: source_ip,unknown_field` | U |
| 20 | Required-nullable key missing | `schema_invalid` | U |
| 21 | `"FAILURE"`, unknown enum value, `schema_version` other than `"1.0"` | `schema_invalid` | U |
| 22 | `true` / `22.0` / `70000` as port | `schema_invalid` | U |
| 23 | Integer `3232235801` as `source_ip` | `schema_invalid` | U |
| 24 | `1.2.3.4%eth0`; `fe80::1%eth0` | Invalid / accepted with scope stripped and a warning | U |
| 25 | Lone surrogate or NUL in a string | `schema_invalid` (never reaches export) | U |
| 26 | `failure_reason` with `outcome: success` | `schema_invalid` | U |
| 27 | Naive timestamp; date-only; ISO week; `t`/`z` lowercase; trailing newline; fullwidth digits; `-00:00`; hour 24; Feb 30; `+99:99`; leap second `:60` | `schema_invalid` | U |
| 28 | Timestamp that underflows after UTC conversion (`0001-01-01T00:00:00+05:00`) | `schema_invalid` (`OverflowError` caught) `[UNVERIFIED]` | U |
| 29 | Nanosecond fraction | Truncated to microseconds | U |
| 30 | `timestamp: null` | Valid event; uncorrelatable for every time-based rule → `incomplete` | U |

### Keys, ordering and windows

| # | Case | Handling | Tier |
|---|---|---|---|
| 31 | `Alice`, `ａｌｉｃｅ`, `alice​` | One key `alice`; invisible character raises a warning | U |
| 32 | Username that is only zero-width characters | No key → `missing_username` (uncorrelatable) | U |
| 33 | `::ffff:1.2.3.4`, `::FFFF:1.2.3.4`, `1.2.3.4` | One key `1.2.3.4` | U |
| 34 | `DOMAIN\alice`, `alice@corp`, `alice`; Turkish `İ` | Not merged / folds to `i̇` | D |
| 35 | Mixed UTC offsets for the same instant | Compared as UTC | U |
| 36 | Out-of-order file; shuffled file | Same alerts either way; disorder counted | U |
| 37 | Failure and success at the same timestamp | Failure sorts first | U |
| 38 | Event exactly `W` old | Outside the window | U |
| 39 | Burst straddling a would-be fixed-bucket edge | Detected | U |
| 40 | 500-failure flood | One alert (episode) | U |
| 41 | Two bursts separated by a quiet period longer than `W` | Two alerts | U |
| 42 | Key swept from memory while its episode is open | Episode preserved; sweep interval 1 gives identical results | U |
| 43 | Alert cap reached | Further episodes counted in `alerts_suppressed`; `incomplete` | M |
| 44 | 1 million distinct keys | Bounded memory; no crash (numbers recorded, Section 12.5) | F |

### Rules and counting

| # | Case | Handling | Tier |
|---|---|---|---|
| 45 | Threshold 1, window 0, lookback below window, absurd values | Exit `2` | U |
| 46 | Outcome `unknown` | Uncorrelatable for every rule → `incomplete` | U |
| 47 | Failure with no IP | AW-002 uses it; AW-001/003 count it as uncorrelatable → `incomplete` | U |
| 48 | Same `record_id`, same content | Dropped and counted | U |
| 49 | Same `record_id`, different content | `duplicate_conflict` → `incomplete` | U |
| 50 | Identical content, no `record_id` | **Not** deduplicated | U |
| 51 | AW-001 and AW-003 both fire for one IP | Both alerts, documented | U |
| 52 | AW-004: success from the same IP / a new IP | `ip_changed` false / true | U |
| 53 | AW-004: second success right after an alerting one | No alert (failures consumed) | U |
| 54 | Alerts found and invalid lines present | Exit `4`; alerts kept in the report | F |

### Outputs and process

| # | Case | Handling | Tier |
|---|---|---|---|
| 55 | `--report` equals the input; symlink to it; hard link to it | Exit `2` | F |
| 56 | Report path is a directory or symlink; parent missing | Exit `2` | F |
| 57 | Existing non-AuthWatch file at the report path | Exit `2` unless `--force-report` | F |
| 58 | Write fails mid-way | Previous file intact; no partial file | M |
| 59 | Username contains ESC, `[red]`, `:smile:`, RTL override | Rendered literally | U |
| 60 | Username starts with `=`, ` =`, newline-then-`=`, fullwidth `＝`, `+`, `-`, `@` (CSV) | Prefixed with `'` | U |
| 61 | Redaction on: `Alice` and `ａｌｉｃｅ` | Same token; alert ids stable for a given key | U |
| 62 | Redaction key shorter than 32 bytes | Exit `2` | U |
| 63 | Ctrl+C | Exit `130`, no report | M |
| 64 | Injected internal exception | Exit `4`, never `1` | M |
| 65 | Complete run with zero alerts | Exit `0` | F |

### OpenSSH adapter (Should)

| # | Case | Handling | Tier |
|---|---|---|---|
| 66 | Syslog timestamps without `--assume-year` / `--assume-tz` | Exit `2` | F |
| 67 | December → January rollover; 29 February in a non-leap assumed year | Year increments / `invalid` record | U |
| 68 | Username containing ` from 8.8.8.8 port 1 ssh2` | Real tail wins; source is the genuine IP | U |
| 69 | `Failed password for invalid user x` plus the `Invalid user x` line | One event; the other line is irrelevant | U |
| 70 | "message repeated N times" | `unsupported` → `incomplete` | U |
| 71 | Unknown `sshd` message; non-syslog line | `unsupported` | U |
| 72 | Non-`sshd` process lines | Irrelevant | U |
| 73 | Username over 256 characters; invalid UTF-8 in username; port over 65535; unparseable IP | Sanitized, warning, event kept | U |
| 74 | Forged syslog lines from a local user | Indistinguishable | D |

### Windows

| # | Case | Handling | Tier |
|---|---|---|---|
| 75 | PowerShell 5.1 `Out-File` input (UTF-16) | Exit `3` with a re-save hint | F |
| 76 | `os.replace` onto a file open elsewhere | Exit `4`; original intact | M |
| 77 | Symlink / POSIX-permission tests | Skipped on Windows | — |

## 11.2 Failure-handling principles

1. Never exit `0` or report `clean` with partial coverage or no analyzed events.
2. Never silently drop a record: it is an event, a classified problem, or a counted irrelevant line.
3. Never echo an offending value in an error; report line numbers and reason codes.
4. Never let attacker-controlled content change whether a recognised line is counted.
5. Never group on a raw string an attacker spells; group on canonical keys.
6. Never compare timestamps as strings or assume a timezone.
7. Never let an unexpected exception exit with the "alerts" code.
8. Never print an untrusted string to the terminal unescaped.
9. Never write over the input, a directory, a symlink or a foreign file; never leave a partial output.
10. Never modify the analyzed file or take any response action.

---

# 12. Testing Strategy

## 12.1 Tooling

- `pytest`; `tmp_path` for all file work; no test touches real logs.
- `monkeypatch` for failure injection (`os.replace`, `open`, `os.fsync`, an engine function raising `KeyboardInterrupt` or `RuntimeError`).
- Integration tests run `[sys.executable, "-m", "authwatch", ...]` with `subprocess.run(..., capture_output=True, timeout=60)` so exit codes and streams are the real ones; `130` and crash→`4` are asserted by calling `cli.main()` in-process under `pytest.raises(SystemExit)`.
- The oracle tests use the standard library `random` with fixed seeds — no extra dependency.
- Platform skips: symlinks (privilege on Windows), POSIX permissions, root user.
- All fixtures use documentation address ranges only.

## 12.2 Unit tests by module

| Module | Tests |
|---|---|
| `timeparse` | Every row of case 27/28/29; `to_us` exactness; `iso_utc` round trip; duration grammar and bounds |
| `keys` | Cases 31–33; every IP form from case 24; integer and over-long input; non-ASCII digits; idempotence of `username_key` over **all** Unicode code points (the first version failed for 26) |
| `reader` | Every row of cases 1–15; peak read-chunk ≤ 64 KiB + 1 on a 10 MB line; the hash equals SHA-256 of the whole file including drained lines |
| `models` | Cases 19–26; the counter invariant (Section 6.8) over mixed valid/invalid files |
| `events` | Sort key (cases 36–37); `dedupe` (48–50); `select` reason accounting (30, 32, 46, 47) |
| `window` | Section 12.3 |
| `rules` | `Params.validate` bounds (45); alert fields; severity ordering; ATT&CK tags; caveats incl. the dynamic uncorrelatable note |
| `coverage` | All five rows of the status table; every reason code; `no_events` |
| `redact` | Token stability, key length, ids built from tokens |
| `reporter` | Valid JSON; envelope present; counts equal findings; provenance populated; deterministic apart from `run_id` / envelope times |
| `outputs` | Cases 55–58 |
| `render` | Case 59; no ESC byte in output; consoles configured with `emoji=False, highlight=False` |
| `exporters` | Case 60; header and row count |
| `adapters/openssh` | Cases 66–73 against authored fixtures **and** sanitized real samples (Phase S3) |

## 12.3 Window-engine oracle tests

These are the most important tests in the project because they prove the window logic independently of the implementation.

**Oracle.** A brute-force function that, for every event `i` of a key, recomputes the window `(t_i − W, t_i]` from scratch and applies the episode definition of Section 6.6. It is O(n²) and obviously correct.

| Test | Method |
|---|---|
| Count metric | ≥ 3 000 seeded random streams (1–3 keys, 0–60 events, timestamps with deliberate ties, random threshold 2–6 and window from {10, 60, 300}); assert identical episodes (first line, last line, total count, peak). **Executed for the count metric during planning with 0 mismatches** `[VERIFIED]` |
| Distinct metric | Same harness with an oracle that counts distinct auxiliary values `[UNVERIFIED]` |
| Sweep equivalence | Re-run both with sweep interval 1 and with sweeping disabled; results must be identical `[UNVERIFIED]` |
| AW-004 | Oracle that, for each success, recounts failures in `(t − L, t]` with the consume-on-alert rule `[UNVERIFIED]` |
| Shuffle invariance | Shuffling input records must not change any alert (ids included) |
| Key-spelling invariance | Replacing a username with a case/fullwidth/zero-width variant in some records must not change the alerts |
| Boundaries | Section 6.6 table; flood → one alert; burst–quiet–burst |

## 12.4 Integration tests and acceptance matrix

1. `analyze samples/clean.jsonl` → exit `0`, `status: clean`.
2. `analyze samples/attacks.jsonl --report r.json` → exit `1`; report matches the expected alerts of Section 15.2; line numbers verify against the file and its hash.
3. `analyze samples/broken.jsonl` → exit `4`; the six alerts are still reported; six errors with the codes listed in Section 15.2.
4. Empty file → exit `4` (`no_events`).
5. UTF-16 file → exit `3`.
6. `--format json | python -m json.tool` → valid, nothing else on stdout.
7. Report path equals input / hard link / foreign file → exit `2` and the original byte-identical.
8. Out-of-range threshold or bad duration → exit `2`.
9. Same input run twice → identical reports apart from `run_id` and envelope times.
10. `--redact-usernames` → no username appears anywhere in stdout or the report.

| Scenario | status | result | Exit |
|---|---|---|---|
| Benign file, complete | `clean` | `clean` | 0 |
| Brute-force fixture | `alerts_detected` | `alerts_detected` | 1 |
| Benign + one invalid line | `incomplete` | `clean` | 4 |
| Brute-force + invalid lines | `incomplete` | `alerts_detected` | 4 |
| Empty file | `incomplete` | `clean` | 4 |
| Events with no usable IP, AW-001 enabled | `incomplete` | `clean` | 4 |
| UTF-16 input | (no report) | — | 3 |
| Bad option / output collision | (no report) | — | 2 |
| Ctrl+C | (no report) | — | 130 |
| Injected crash | (no report) | — | 4 |

## 12.5 Performance (to be measured)

No performance figure has been measured; the "≈ 1 million events" design target is a target, not a result. Phase P4 measures and records in the README, on the development machine: (a) one million events across many keys; (b) one million failures for a single key (flood); (c) one million distinct IPs; reporting wall time and peak memory (`tracemalloc` on a smaller sample plus process peak RSS on the full run). The tests assert only that none crashes and that memory does not grow with the length of an episode.

## 12.6 Results of checks already run

The checks executed while planning — what passed, what exposed bugs in proposed patches — are recorded in Appendix B.

---

# 13. Implementation Plan

**Budget:** Must tier ≈ 3 h 35 min. Should tier ≈ 1 h 45 min more. The Should tier is a deliberate second sitting.

| Phase | Time | Work | Deliverable | Commit message |
|---|---|---|---|---|
| **P0 — Setup** | 10 min | Repo, venv, `pyproject.toml`, package skeleton, `errors.py` with exit codes, `python -m authwatch --help` | Installs and runs | `chore: initialize AuthWatch project` |
| **P1 — Time, keys, reader, schema** | 50 min | `timeparse`, `keys`, `reader`, `models`, JSONL adapter, their unit tests | Hostile-input-proof path from file to validated events with exact counters | `feat: add strict reader, schema, timestamp and key handling` |
| **P2 — Engine** | 60 min | `events` (sort, dedupe, select), `window` (count metric, episodes, bounded evidence, sweep, cap), AW-001 and AW-002, `coverage.derive`, oracle tests | Tested, deterministic detections with honest coverage | `feat: add sliding-window engine, AW-001/002 and coverage model` |
| **P3 — CLI and reporting** | 45 min | `reporter`, `outputs`, `render`, `cli` with `guarded`, options and bounds | Working CLI with correct exit codes and report | `feat: add CLI, report envelope and terminal summary` |
| **P4 — Integration and review** | 30 min | Fixtures and generator, integration tests, acceptance matrix, performance measurement, security checklist | Verified Must tier | `test: add fixtures, integration tests and security review` |
| **P5 — Docs and release (Must)** | 20 min | README, sample report from a real run, demo, tag `v1.0.0` | Releasable Must tier | `docs: add usage, architecture and security guide` |
| **S1 — AW-003 and AW-004** | 40 min | Distinct metric, fail-then-success detector, oracle tests for both | Four rules | `feat: add spray and failure-then-success rules` |
| **S2 — Controls** | 25 min | `--rules`, redaction, `timeline`, ATT&CK tags | Privacy and visibility | `feat: add rule selection, redaction and timeline` |
| **S3 — Normalization** | 40 min | OpenSSH adapter, real sanitized samples, `normalize` command, adapter tests | Normalization thesis demonstrated | `feat: add OpenSSH adapter and normalize command` |

If the Should tier is built, re-run P4's acceptance matrix and update the README before tagging.

## 13.1 Security review checklist (end of P4)

- [ ] No code path returns exit `0` or `clean` when `coverage.complete` is false or `events_analyzed` is 0.
- [ ] No place groups on a raw username or IP string (only `ip_key` / `username_key` outputs).
- [ ] No timestamp is compared as a string or constructed without an explicit offset.
- [ ] `grep` shows `splitlines`, `json.load(` on text mode, and `model_validate_json` are not used on input (they bypass the byte reader or the duplicate-key hook).
- [ ] Every Rich print of untrusted data goes through `safe_display`; both consoles have `emoji=False, highlight=False`.
- [ ] No error message includes a record value.
- [ ] An injected exception in the engine exits `4`, never `1`.
- [ ] Report writes are atomic and refuse the input, a directory, a symlink and a foreign file; a hard-link test passes.
- [ ] Evidence is bounded: a one-million-failure single-key flood produces an alert with ≤ 50 line numbers.
- [ ] No `eval`, `exec`, `subprocess` or `os.system` anywhere in `src/`.
- [ ] `src/` contains no real log data; samples use documentation address ranges.

## 13.2 Cut rule

Cut in this order if time runs out; never cut a Must item: CSV export → Rich styling → `timeline` and ATT&CK tags → `--rules` → OpenSSH adapter and `normalize` → AW-003 → redaction → AW-004. Ship a smaller tool that cannot report a false clean rather than a larger one that can.

---

# 14. Repository and Packaging

## 14.1 Layout

```text
AuthWatch/
├── src/
│   └── authwatch/
│       ├── __init__.py            # __version__
│       ├── __main__.py            # python -m authwatch → cli.main()
│       ├── cli.py
│       ├── errors.py
│       ├── timeparse.py
│       ├── keys.py
│       ├── reader.py
│       ├── models.py
│       ├── events.py
│       ├── window.py
│       ├── rules.py
│       ├── coverage.py
│       ├── redact.py              # Should
│       ├── reporter.py
│       ├── exporters.py           # CSV (Could) · normalized JSONL (Should)
│       ├── outputs.py
│       ├── render.py
│       └── adapters/
│           ├── __init__.py
│           ├── jsonl.py
│           └── openssh.py         # Should — do not create empty adapters
├── tests/
│   ├── conftest.py                # tree/file helpers, platform skip markers
│   ├── test_timeparse.py   test_keys.py   test_reader.py   test_models.py
│   ├── test_events.py      test_window_oracle.py   test_rules.py   test_coverage.py
│   ├── test_reporter.py    test_outputs.py   test_render.py   test_redact.py
│   ├── test_openssh.py     # Should
│   └── test_cli.py         # subprocess integration
├── samples/
│   ├── make_samples.py            # deterministic generator
│   ├── clean.jsonl   attacks.jsonl   broken.jsonl
├── docs/
│   └── master-build.md            # this document
├── examples/
│   ├── demo.ps1   demo.sh
│   └── sample-report.json         # from a real run, demo data only
├── .gitignore   LICENSE   README.md   pyproject.toml
```

## 14.2 `pyproject.toml`

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "authwatch"
version = "1.0.0"
description = "Authentication-log analyzer with sliding-window detection and honest coverage reporting"
readme = "README.md"
requires-python = ">=3.11"
license = { text = "MIT" }
dependencies = ["typer>=0.12", "rich>=13", "pydantic>=2.6"]

[project.optional-dependencies]
dev = ["pytest>=8"]

[project.scripts]
authwatch = "authwatch.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["src/authwatch"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

Python 3.11 is the floor because the strict timestamp profile relies on the extended `datetime.fromisoformat` (accepts `Z`) introduced in 3.11. The name `authwatch` returned HTTP 404 on PyPI (both `authwatch` and `AuthWatch`) on 2026-10-26, i.e. it was unclaimed at that moment; check GitHub and re-check PyPI immediately before publishing. A test asserts `__version__` equals `importlib.metadata.version("authwatch")`.

## 14.3 `.gitignore` essentials

```text
.venv/
__pycache__/
*.egg-info/
.pytest_cache/
dist/
build/
out/
reports/
*.report.json
*.log
```

`samples/*.jsonl` and `examples/sample-report.json` are committed deliberately and contain only synthetic data.

## 14.4 Windows notes (the primary development platform)

| Topic | Rule |
|---|---|
| Text encoding | Read inputs in **binary**. Write every text file with `encoding="utf-8", newline="\n"` — the Windows default code page (often cp1252) would corrupt non-ASCII output |
| PowerShell | Windows PowerShell 5.1 `>` and `Out-File` write UTF-16 (→ exit `3`); use `-Encoding utf8`, which adds a BOM that the reader accepts. Recommend `$env:PYTHONUTF8 = "1"` |
| Timezones | Only fixed offsets are accepted; the IANA database is not shipped with Windows and would need an extra dependency |
| Atomic writes | `os.replace` onto a file open in another program raises `PermissionError` → exit `4`, original intact |
| Hard links / symlinks | `os.path.samefile` works on NTFS for hard links; symlink tests need Developer Mode or admin and are skipped otherwise |
| Permissions | The `0600` creation mode has no Windows equivalent; the README says to store reports in a user-only directory |
| Entry point | Always runnable as `python -m authwatch` even if the console script is not on `PATH` |

---

# 15. Expected Build Result

## 15.1 What the finished tool does

At the end of the Must tier, AuthWatch v1.0.0 installs with `pip install .`, exposes the `authwatch` command, and: reads hostile JSONL without crashing or mis-splitting records; validates every event strictly; groups on canonical keys; detects failure bursts per source IP and per account with a sliding window and one alert per sustained burst; reports every invalid or uncorrelatable record in a coverage block; never exits `0` on partial coverage or empty input; emits a JSON report in the series envelope with the input's SHA-256, parameters and line-number evidence; and refuses to overwrite its input. The Should tier adds spraying and failure-then-success rules, redaction, rule selection, the timeline block, and an OpenSSH adapter with a `normalize` command.

## 15.2 Fixtures and expected results

`samples/make_samples.py` writes three deterministic files (documentation address ranges only). Base time `2026-10-26T10:00:00Z`; offsets in seconds. Scenarios appear in this order, so line numbers in alerts are stable.

**`attacks.jsonl` — 39 events**

| Lines | Scenario | Events |
|---|---|---|
| 1–9 | S1 brute force | `alice` fails from `203.0.113.50` at offsets 1800 + 15·i, i = 0…8 (10:30:00–10:32:00) |
| 10 | S2 success after failures | `alice` succeeds from `198.51.100.7` at 1980 (10:33:00) |
| 11–22 | S3 spray | `192.0.2.99` fails once each for `user00`…`user11` at 2400 + 10·i (10:40:00–10:41:50) |
| 23–28 | S4 distributed on one account | `admin` fails once each from `203.0.113.1`…`.6` at 3000 + 30·i (10:50:00–10:52:30) |
| 29–31 | S5 benign | `bob` fails at 100 and 130, succeeds at 160, all from `198.51.100.20` |
| 32–34 | S5 benign | `carol` succeeds from `198.51.100.30` at 500, 900, 1300 |
| 35–39 | S6 boundary negative | `dave` fails from `198.51.100.200` at 4200, 4260, 4320, 4380, 4500 |

**Expected result with default parameters — derived by hand from the rule definitions, to be confirmed by the tests:** `alerts_detected`, exit `1`, coverage complete, six alerts.

| Rule | Subject | First → last seen | Count | Peak | Note |
|---|---|---|---|---|---|
| AW-004 | `user:alice` | 10:30:00 → 10:33:00 | 9 | 9 | HIGH; `ip_changed: true` |
| AW-001 | `ip:203.0.113.50` | 10:30:00 → 10:32:00 | 9 | 9 | |
| AW-002 | `user:alice` | 10:30:00 → 10:32:00 | 9 | 9 | one source IP |
| AW-001 | `ip:192.0.2.99` | 10:40:00 → 10:41:50 | 12 | 12 | fires by volume |
| AW-003 | `ip:192.0.2.99` | 10:40:00 → 10:41:50 | 12 | 12 | peak = distinct accounts |
| AW-002 | `user:admin` | 10:50:00 → 10:52:30 | 6 | 6 | six source IPs |

Deliberately **no** alert for `bob`/`carol` (below threshold or successes only) and **none** for `dave`: five failures spanning exactly 300 s leave four inside `(t − 300 s, t]` at the last event, which is the boundary rule of Section 6.6. A test must pin this.

**`clean.jsonl`** — the `bob` and `carol` events only (6 events): `clean`, exit `0`.

**`broken.jsonl`** — `attacks.jsonl` with six defective lines appended (lines 40–45), so alert line numbers do not change. Expected: `incomplete`, `result: alerts_detected`, exit `4`, the same six alerts, and these errors:

| Line | Defect | Reason code |
|---|---|---|
| 40 | duplicate `outcome` key | `duplicate_key` |
| 41 | `"source_port":NaN` | `invalid_value` |
| 42 | `"source_ip":"203.0.113.999"` | `schema_invalid: source_ip` |
| 43 | `source_ip` key missing | `schema_invalid: source_ip` |
| 44 | `sourceip` typo instead of `source_ip` | `schema_invalid: source_ip,unknown_field` |
| 45 | truncated JSON | `invalid_json` |

## 15.3 Demonstration

PowerShell (primary):

```powershell
python -m pip install -e ".[dev]"
python samples/make_samples.py
mkdir out | Out-Null
authwatch analyze samples/clean.jsonl;   "exit $LASTEXITCODE"      # 0
authwatch analyze samples/attacks.jsonl --report out/report.json; "exit $LASTEXITCODE"   # 1
authwatch analyze samples/broken.jsonl;  "exit $LASTEXITCODE"      # 4
authwatch analyze samples/attacks.jsonl --format json | python -m json.tool | more
```

Bash equivalent: the same commands with `mkdir -p out` and `echo "exit $?"`.

## 15.4 Expected terminal output (illustrative — derived by hand, layout indicative)

```text
AuthWatch 1.0.0 · analyze attacks.jsonl (jsonl) · sha256 3f9a…
Records    39 read · 39 events · 0 invalid · 0 unsupported · 0 duplicates dropped
Coverage   complete · 2026-10-26T10:01:40Z → 2026-10-26T11:15:00Z

  Sev     Rule    Subject             Count  Window  Reason
  HIGH    AW-004  user:alice              9   900s   success from a new IP after 9 failures
  MEDIUM  AW-001  ip:203.0.113.50         9   300s   9 failures from one IP
  MEDIUM  AW-002  user:alice              9   300s   9 failures, 1 source IP
  MEDIUM  AW-001  ip:192.0.2.99          12   300s   12 failures from one IP
  MEDIUM  AW-003  ip:192.0.2.99          12   600s   12 distinct accounts failed from one IP
  MEDIUM  AW-002  user:admin              6   300s   6 failures, 6 source IPs

Result     ALERTS DETECTED · 6 alerts · alerts are investigation leads, not proof of compromise
```

An incomplete run must look unmistakably different:

```text
Records    45 read · 39 events · 6 invalid · 0 unsupported
Coverage   PARTIAL · invalid_records
  line 40  duplicate_key
  line 41  invalid_value
  line 42  schema_invalid: source_ip
  …
Result     INCOMPLETE · 6 alerts found, but 6 records could not be analyzed — activity may be unseen (exit 4)
```

## 15.5 Behaviour guarantees

| You can rely on | Because |
|---|---|
| Exit `0` means every record was accounted for, at least one event was analyzed, and no rule fired | Coverage model + `derive()` + `guarded()` |
| An alert's line numbers point at the records that caused it | Evidence by line number + recorded input SHA-256 |
| A burst is not missed because of clock edges | Sliding window, oracle-tested |
| Spelling or address-form tricks do not split a count | Canonical keys |
| Junk lines cannot silently hide failures | Invalid records make coverage partial |
| The input was not modified and cannot be overwritten by the report | Read-only access; `same_file` check |
| The same input and parameters give the same alerts and ids | No wall-clock dependence; deterministic sort and ids |

---

# 16. Definition of Done

**Must tier:**

- [ ] Installs in a clean virtual environment; `authwatch --help` and `python -m authwatch --version` work.
- [ ] Reader passes every row of edge cases 1–18, including the 10 MB line with bounded memory.
- [ ] Schema rejects every row of cases 19–30; the counter invariant holds.
- [ ] Keys: cases 31–34 pass; `username_key` is idempotent over all Unicode code points.
- [ ] Window engine matches the brute-force oracle on ≥ 3 000 seeded streams, with and without sweeping; shuffle and key-spelling invariance hold.
- [ ] AW-001 and AW-002 fire on the brute-force and distributed-account fixtures and **not** on the boundary-negative fixture (`dave`).
- [ ] Coverage model: all five status rows and every reason code tested; empty input exits `4`.
- [ ] Exit codes follow Section 9.2 including precedence, `3` for UTF-16, and crash → `4`.
- [ ] Report is valid JSON in the shared envelope, with input SHA-256, parameters, per-rule coverage and bounded line-number evidence; identical across repeated runs apart from `run_id` and envelope times.
- [ ] Untrusted strings are escaped in the terminal; consoles have `emoji=False, highlight=False`.
- [ ] Output-path rules pass, including the hard-link case and atomic-write failure.
- [ ] Performance figures from Section 12.5 recorded in the README.
- [ ] All automated tests pass on Windows; POSIX-only tests are skipped there with a reason.
- [ ] README instructions verified in a clean environment; the repository contains no real logs.
- [ ] Demo shows a clean run, an alerts run and an incomplete run.

**Should / Could (when built):** AW-003 and AW-004 pass their oracle tests; redaction leaves no username in any output; `--rules` recorded in provenance; the OpenSSH adapter passes authored **and** real sanitized samples; CSV passes the injection test.

---

# 17. GitHub and Release Strategy

## 17.1 Repository setup

Repository `AuthWatch`, package `authwatch`. Before publishing: install in a clean venv, run every documented command and the full suite, inspect `git status` for generated reports, and re-check the package name (Section 14.2).

## 17.2 README outline

1. Title and one-line description
2. Problem, aim and core principle
3. Features, tiers and non-goals
4. Architecture and pipeline
5. Event schema and version policy
6. Installation and supported Python
7. Quick start (`samples/` and the demo)
8. Detection rules, keys, windows and defaults, with the Poisson guidance
9. Coverage model — how to read `status`, `result` and `reasons`
10. Example terminal output (clean, alerts, incomplete) copied from real runs
11. Report format and the shared envelope
12. Exit codes
13. Privacy: usernames can contain passwords; redaction; report storage
14. Windows notes
15. Tests, the oracle approach, and measured performance
16. Security considerations and limitations
17. Roadmap and license

## 17.3 Release

Tag `v1.0.0` with notes listing features, tested platform and Python version, measured performance, and known limitations. Attach `examples/sample-report.json`. The demo recording must show real output and must not imply that AuthWatch identifies attackers or proves compromise.

---

# 18. Future Roadmap

Deferred until the Must tier is tested; driven by observed limitations.

### V1.1 — more sources and rules

- **Windows Security adapter.** Read exported XML (`wevtutil qe Security /f:xml`, standard-library XML) rather than binary EVTX. Map Event ID `4625` (failed logon) and `4624` (successful logon); handle `-`, `::1` and `127.0.0.1` in the address field without rejecting the record; fill `logon_type`; map sub-status values such as "user name does not exist" to `unknown_account` after checking Microsoft's documentation. A Windows logon is not an SSH authentication: preserve actual semantics.
- Linux journald JSON export; gzip and rotated files; `--since` / `--until`.
- **Low-and-slow rule:** cumulative failures per key over long windows.
- Allow-lists for known scanners, NAT gateways and monitoring probes; severity escalation by count.

### V1.2 — scale and interop

- Multi-file input with `record_id` deduplication across overlaps.
- OCSF / Elastic Common Schema exporter.
- Baseline failure rates per key to calibrate thresholds automatically (replacing the manual Poisson exercise).

### V2

- Streaming/tail mode; incident-response ingestion of the envelope; optional signed reports.

---

# 19. Frozen Decision Register

## 19.1 Closure of the baseline's 19 open decisions

| # | Baseline open decision | Frozen value |
|---|---|---|
| 1 | Name and conflicts | AuthWatch / `authwatch`; PyPI unclaimed on 2026-10-26 (HTTP 404); GitHub check pending before publishing |
| 2 | Schema fields and `raw_event` | Section 8.1 fields; `raw_event` removed; evidence = line numbers + input hash |
| 3 | Version and compatibility | `"1.0"`; minor = additive optional fields; major = breaking; the 1.0 tool accepts exactly `"1.0"` |
| 4 | Timestamp policy | Strict ASCII RFC 3339, mandatory offset, naive invalid, UTC internally, microsecond truncation |
| 5 | JSONL contract and unknown fields | Every non-blank line must validate; `extra="forbid"`; nullable fields are required keys |
| 6 | Grouping keys | AW-001 `ip_key`; AW-002 `username_key`; AW-003 `ip_key` + distinct `username_key`; AW-004 `username_key` |
| 7 | Threshold and window defaults | 5 failures / 300 s; spray 10 accounts / 600 s; bounds in Section 9.1 |
| 8 | Correlation lookback | 900 s |
| 9 | Duplicate handling | `record_id` only (scoped by product and host); never content |
| 10 | Alert structure, severity, ids | Section 6.9; MEDIUM for AW-001/002/003, HIGH for AW-004; deterministic ids over the displayed subject |
| 11 | Typer vs stdlib | Typer |
| 12 | Rich vs plain | Rich, escaped, `emoji=False`, `highlight=False` |
| 13 | Dataclasses vs Pydantic | Pydantic v2 strict for the schema; plain dataclass for internal `Event` |
| 14 | pytest vs unittest | pytest |
| 15 | JSON only or JSON + CSV | JSON in Must; CSV in Could, escaped |
| 16 | Exit codes | `0`, `1`, `2`, `3`, `4`, `130` with precedence `2,3 > 4 > 1 > 0` |
| 17 | Partial-parse behaviour | Any invalid or unsupported record → `incomplete`, exit `4`; alerts still reported |
| 18 | First real-source adapter | OpenSSH text (Should, phase S3); Windows Security deferred to V1.1 |
| 19 | License, Python, packaging | MIT; Python 3.11+; hatchling; `src/` layout |

## 19.2 Further frozen decisions

| Decision | Frozen value |
|---|---|
| Series | Day 4 of 7 Days – 7 Builds; Python-first local CLI; read-only; no response actions |
| Cross-platform core | No OS-specific logic in the schema, keys or rules; Windows-first development |
| Reader | Bytes-level; split on `\n`; 64 KiB line cap including terminator; UTF-8 strict; BOM line 1 only; UTF-16/32 → exit `3` |
| Record errors | Reason codes only; values never echoed; `errors[]` capped at 1 000 |
| Window | Sliding `(t − W, t]`; integer microseconds; event exactly `W` old is outside |
| Episodes | One alert per sustained episode; `count` and `peak_in_window` |
| Sort key | `(timestamp, outcome rank failure<unknown<success, input order)` for every rule |
| Memory | Sweep every 4 096 events; evidence ≤ 50 line numbers and ≤ 1 000 tracked keys; ≤ 10 000 alerts per rule |
| Outcome `unknown` | Always uncorrelatable (partial coverage) |
| Empty input | `no_events` → `incomplete` |
| Dedup conflicts | Partial coverage |
| AW-004 | Per account; failures consumed on alert; `ip_changed` recorded |
| Determinism | No wall-clock use in validation or detection |
| Adapters | Sanitize attacker-controlled fields with warnings; reject only structurally |
| Syslog time | `--assume-year` and fixed-offset `--assume-tz` required; no IANA names; no guessing |
| Redaction | HMAC-SHA256 of the username key, 12 hex characters, `u:` prefix; key ≥ 32 bytes from `AUTHWATCH_REDACT_KEY` or ephemeral |
| Report | Shared `7d7b-report` envelope; `status` ∈ `clean`, `alerts_detected`, `incomplete`; fatal runs write no report |
| Output safety | `same_file` (resolve + samefile), directory/symlink refusal, foreign-file guard, atomic write |
| Terminal | All untrusted strings through `safe_display`; consoles without emoji or highlighting |
| Dependencies | Runtime: `typer`, `rich`, `pydantic`; dev: `pytest`; nothing else without approval |
| Not in V1 | ML, LLM interpretation, live SIEM, tailing, blocking, geo-IP, EVTX reader, dashboard, rules DSL |

---

# 20. Final Build Principle

AuthWatch is a small, dependable security tool — not a SIEM.

> **An analysis that could not cover all of its input must never be presented as proof that no suspicious activity occurred.**

Build the smallest system that honours this principle, prove the window logic against an oracle, document what it cannot see, and publish the result.

**Day 4 success criterion:** a user can feed AuthWatch hostile, messy, real-world-shaped authentication records and receive an accurate, machine-readable report that clearly separates alerts from uncertainty and from operational failure — with an exit code automation can trust.

---

# Appendix A — Findings Traceability

Findings from the pre-implementation review (C critical, H high, M medium, L low) and the ones found while drafting (N). "Test" cites the edge-case register (Section 11) or the oracle tests (Section 12.3).

| ID | Finding | Resolution | Test |
|---|---|---|---|
| C1 | No coverage model; "0 alerts" ambiguous | 5.4, 6.8 | 1, 30, 46, 47, 54, matrix |
| C2 | Window type open; fixed buckets miss bursts; per-event alert flood | 6.6 | 38–41, oracle |
| C3 | One grouping key cannot catch every attack | 6.7 | 51, fixture S1–S4 |
| C4 | Non-canonical keys split counts | 6.4 | 31–33, key-spelling invariance |
| C5 | Duplicate JSON keys flip outcomes | 6.1 | 11 |
| H1 | Loose timestamp contract | 6.3 | 27–30 |
| H2 | Unknown fields permitted → silent null | 6.2 | 19–20 |
| H3 | Terminal injection | 10.5 | 59 |
| H4 | CSV formula injection | 8.6 | 60 |
| H5 | Export can overwrite input | 9.4 | 55–58 |
| H6 | Fragile reader | 6.1 | 1–15 |
| H7 | Usernames may hold passwords; `raw_event` | 6.11 | 61–62 |
| H8 | Loose types | 6.2 | 22–25 |
| M1 | Series contract not adopted | 8.5, 9.2, 9.5 | 63–64, matrix |
| M2 | No provenance | 8.3 | integration 2, 9 |
| M3 | Alert ids not deterministic | 6.9 | integration 9 |
| M4 | Duplicate policy undecided | 6.5 | 48–50 |
| M5 | Rule C linkage and tie order | 6.5, 6.7 | 37, 52–53 |
| M6 | Unbounded configuration | 9.1 | 45 |
| M7 | Unbounded state | 6.6 | 42–44 |
| M8 | Tampering invisible | 8.3 `timeline` | 36 |
| M9 | Normalization never exercised | 6.10.3, phase S3 | 66–73 |
| L1–L3 | Hygiene decisions | 19 | — |
| N1 | Evasion by invalidity | 6.10.1 | 73 |
| N2 | Empty input read as clean | 6.8 | 1 |
| N3 | Alert id as username oracle | 6.9 | 61 |
| N4 | Repeat-suppressed syslog | 6.10.3 | 70 |
| N5 | Timestamp overflow after conversion | 6.3 | 28 |
| N6 | Wall-clock determinism | 6.3 | integration 9 |
| N7 | Windows encoding and timezone pitfalls | 14.4 | 75–77 |
| N8 | Syslog username spoofing; double counting | 6.10.3 | 68–69 |
| N9 | AW-001 / AW-003 overlap; overstated claim | 0.3, 6.7 | 51 |
| N10 | Decoy alert flooding | 6.6 | 43 |

---

# Appendix B — Verification Record

This appendix states exactly what was executed during planning, what the result was, and what was **not** executed. Nothing in the repository exists yet; no AuthWatch code has been run. The checks below exercised individual snippets and Python behaviours.

## B.1 Environment

| Item | Value |
|---|---|
| Python | 3.13.17 (the project floor is 3.11) |
| Platform | Linux container — **not Windows** |
| Libraries | pydantic 2.13.5, rich 15.0.0, typer 0.27.3, pytest 9.1.1 |
| Date | 2026-10-26 |

## B.2 Run 1 — what Python does by default (Python behaviours the design depends on)

| Probe | Observed | Consequence in the design |
|---|---|---|
| `datetime.fromisoformat` | Accepted naive timestamps, date-only values, ISO week dates (`2026-W44-1`) and basic format; truncated 9-digit fractions to 6; rejected `:60` | A strict regex precedes parsing (6.3) |
| Ordering by string across offsets | `"…10:30+05:30" < "…05:30Z"` printed `False`, although as instants 05:00Z precedes 05:30Z (the script printed instant equality `False`; the ordering contradiction follows by arithmetic) | Compare only aware datetimes / integers |
| Duplicate JSON keys | `{"outcome":"failure","outcome":"success"}` → `success` | Duplicate-key rejection (6.1) |
| `NaN`; top-level array | Both accepted by `json.loads` | `parse_constant`; object check |
| UTF-8 BOM | `JSONDecodeError` on line 1 | BOM handling |
| 5 000-digit integer | `ValueError`, not `JSONDecodeError` | Broader `except` |
| 100 000-deep nesting | `RecursionError` | Caught |
| Lone surrogate `\ud800` | Parsed, then `UnicodeEncodeError` on UTF-8 export | Rejected at validation |
| U+2028 inside a string | `splitlines()` → 2 pieces; split on `\n` → 1 | Bytes-level `\n` splitting |
| `ipaddress.ip_address` | Accepted integer `3232235801`, IPv4-mapped IPv6, and `fe80::1%eth0`; lower-cased `2001:DB8::1`; rejected `192.168.001.025` and `-` | String-only input; canonical `ip_key` |
| `isinstance(True, int)` | `True` | Strict type mode |
| `NFKC + casefold` | Merged `Alice` and fullwidth `ａｌｉｃｅ`; did **not** merge `alice​`; left `CORP\alice` and `alice@corp.local` distinct | Format-character stripping; documented non-merges |
| Window methods | Failures at 180, 200, 240, 310, 330 s: fixed buckets → no alert; sliding → alert | Sliding window (5.7) |

All probes behaved as the design assumed.

## B.3 Run 2 — the proposed patch snippets, executed as first written

| Patch | Result | Defect found |
|---|---|---|
| C5 duplicate-key hook | Held (top-level, nested, escaped-equal keys all rejected) | — |
| C2 sliding window + episodes (count metric) | Held: **0 mismatches against a brute-force oracle on 3 000 random streams**; boundary cases correct; 500-failure flood → 1 alert | — |
| H8 Pydantic strict model | Held: `True`, `22.0`, `NaN`, `70000` as port, integer IP, lone surrogate, NUL, unknown field, missing required key and `"FAILURE"` were all rejected; the valid record passed | — |
| H3 `safe_display` + Rich consoles | Held (markup, `:smile:`, ESC, RTL override rendered literally) | — |
| H7 HMAC redaction | Held (`Alice` and fullwidth variant → same token) | — |
| H1 timestamp regex (`\d`, `$`) | **Defective** | Accepted a trailing newline and `-00:00`; only `fromisoformat` happened to reject some bad forms |
| C4 `ip_key` (manual `%` split) | **Defective** | Accepted `1.2.3.4%eth0` and `1.2.3.4%`; an integer raised `AttributeError` |
| C4 `username_key` | **Defective** | 26 code points left non-normalized; a zero-width-only name became the empty key `""` |
| H4 `csv_safe` | **Defective** | Left ` =1+1`, `\n=1+1` and fullwidth `＝1+1` unescaped |
| M3 alert id | **Defective** | `sha256(str)` raised `TypeError`; the `\|` delimiter allowed collisions |
| H6 reader | **Defective** | `1e999` became `inf`; UTF-16 without BOM was reported as JSON errors; the over-long-line skip used an unbounded `readline()` (found by inspection) |
| H5 export ≠ input via `resolve()` | **Defective** | Missed a hard link (`resolve` equal: `False`; `samefile`: `True`) |
| C2/M5 sort key | **Defective** | `(ts, input order)` puts a success first at equal time; Rule C needs failure first |
| M7 key eviction | Weakness found by design review | Evicting a key with an open episode would drop its alert (verified fixed in Run 3) |
| AW-003 draft (distinct accounts) | Detected correctly, did not alert on one account | Emitted one hit per event (no episode merging) |

## B.4 Run 3 — the corrected versions, executed

| Fix | Result |
|---|---|
| `parse_ts` with ASCII `[0-9]`, `fullmatch`, `-00:00` rejection | Trailing newline, fullwidth digits, `-00:00` and hour 24 rejected; `Z` and `+05:30` parsed to the correct UTC instants |
| `ip_key` using native scope parsing | `::ffff:1.2.3.4` → `1.2.3.4`; `fe80::1%eth0` → scope `eth0`; `1.2.3.4%eth0`, `fe80::1%` and the integer rejected |
| `username_key` (NFKC→casefold→NFKC, strip `Cf`) | **0 non-normalized keys across all Unicode code points**; zero-width-only → `None` |
| `csv_safe` | All six test strings handled correctly, including leading space, newline and fullwidth `＝` |
| `alert_id` over canonical JSON | Stable; the two delimiter-collision inputs gave different ids |
| Reader with bounded drain | A 10 MB line was rejected with a peak read chunk of **65,537 bytes** and the next line read correctly; 32 000-deep nesting → `RecursionError` caught; `1e999` rejected; BOM + CRLF accepted; UTF-16 without BOM gave per-line `NUL byte` errors (the whole-input heuristic of 6.1 is **not** executed) |
| `same_file` | Hard link and symlink → `True`; a non-existent path → `False` |
| Sweep that closes open episodes first | Open episode kept (`['b']` remained; the episode for `a` was emitted) |
| `guarded()` exit mapping under Typer 0.27.3 | exit `0`, `1`, `2` (config error), `4` (crash), `130` (interrupt) and `2` for an unknown option — all as designed |

## B.5 Other checks

| Check | Result |
|---|---|
| Poisson tail table (Section 5.8) | Computed with Python's `math`; values as printed |
| PyPI name availability | `https://pypi.org/pypi/authwatch/json` and `…/AuthWatch/json` returned HTTP 404 on 2026-10-26 |

## B.6 Not executed — treat as unproven

- The distinct-metric detector, its oracle, the AW-004 detector and its oracle, sweep equivalence under the oracle, evidence bounding, the alert cap, `derive()` and the counter invariant.
- The full `AuthEvent` model with the timestamp, IP and cross-field validators wired together (only the constraints listed in B.3 were executed).
- The `OverflowError` guard in `parse_ts`, the UTF-16/NUL-heavy heuristic, SHA-256 hashing inside the reader, `write_atomic`, redaction wiring, `normalize`, the CLI, the report builder.
- **All OpenSSH patterns.** They have not been run against a single real or authored line.
- Performance of any kind; behaviour on Windows; whether spreadsheet software treats fullwidth `＝` as a formula.
- The expected alerts in Section 15.2, the report example in Section 8.3 and the terminal output in Section 15.4 were derived by hand from the rule definitions, not generated by running anything.

## B.7 Note on unrun reference code

During planning a larger reference implementation (reader, keys, window engine, rules, OpenSSH adapter, fixtures, pipeline) was begun and then abandoned at the owner's request before any of it was run. **None of it is used, relied on or claimed here.** The builder starts from this document, not from that draft.

---

# Appendix C — Instructions for Future Coding Assistants

This appendix is part of the project's source-of-truth contract.

1. Read this entire document before planning or editing code. Re-read the sections a module depends on before implementing it.
2. Inspect the actual repository, branch and tests before stating what is implemented. This document is the design; the repository and its tests are the current state. If they diverge, report and reconcile explicitly.
3. Treat Section 19 as frozen. Change a frozen decision only with the owner's explicit approval, and update this document in the same change.
4. Respect the status tags (Section 0.4). `[UNVERIFIED]` and `[PARTIAL]` snippets are specifications to be proven by tests, not evidence that something works. Never describe them as tested.
5. Snippets are reference designs. Where a snippet and the prose disagree, the prose and the tests win.
6. Do not invent features, flags, fields, events or files. If the document is silent, pick the simplest behaviour consistent with the core principle, and record it.
7. Never guess missing timestamps, usernames, IP addresses or outcomes; never assume a timezone.
8. Hard invariants (any violation is a defect):
   - Exit `0` / `clean` only when coverage is complete **and** at least one event was analyzed **and** no rule fired.
   - Group only on canonical keys; compare only aware UTC integers; sort with the global sort key.
   - Read input as bytes and split on `\n` only; reject duplicate JSON keys; never echo record values in errors.
   - Never execute or interpolate input content; no `eval`, `exec`, shell or `subprocess`.
   - Unexpected exceptions exit `4`, never `1`.
   - Every untrusted string is escaped before reaching the terminal; consoles have `emoji=False, highlight=False`.
   - Never write over the input, a directory, a symlink or a foreign file; write atomically.
   - Keep the engine free of `typer` and `rich`. Do not import `click` directly.
9. Adapters sanitize attacker-controlled fields with a warning; they do not reject recognised authentication lines because of their content. Do not call an adapter supported without tests against representative sanitized real samples.
10. Do not add ML, LLM interpretation, cloud dependencies, live SIEM integration, or automatic response without explicit approval. Runtime dependencies are exactly `typer`, `rich`, `pydantic`; development adds `pytest`.
11. Add positive, negative, malformed-input and time-boundary tests for every parser or rule change, and keep the oracle tests. Never weaken an assertion, delete a test or add `xfail` to get green; only platform skips are allowed.
12. No `TODO`, `pass` or `NotImplementedError` stubs in shipped code; no bare `except:`; no swallowed exceptions; do not add empty adapter files.
13. Keep repository samples synthetic (documentation address ranges only) and exclude real logs.
14. Distinguish owner decisions from assistant recommendations. If a major decision is ambiguous, state it as open and present options rather than silently changing the architecture.
15. When a task ends, report: changed files, tests run, tests not run, deviations from this document, and known limitations.

**Required handoff summary for a new session:** current repository and branch; implemented modules and actual CLI behaviour; current schema version; implemented rules; test status (counts, skips and reasons); differences between code and this document; the next smallest testable task.

---

# Appendix D — Glossary

| Term | Meaning in AuthWatch |
|---|---|
| **Adapter** | Component that reads one source format and emits validated events plus classified problems |
| **Alert** | A report that a rule fired, with reason, key, counts, window and evidence; an investigation lead, not proof |
| **Authentication event** | A record describing an authentication attempt and its outcome |
| **Canonical key** | The normalized form of an IP or username used for grouping; raw values are kept for display |
| **Coverage** | Whether the analysis could see all of the input; complete or partial |
| **Correlation** | Connecting several events into one pattern (as AW-004 does for failures and a success) |
| **Episode** | A sustained run of windows at or above threshold for one key, reported as one alert |
| **Evidence** | Line numbers, counts and top values that support an alert; verifiable against the recorded input hash |
| **JSONL** | JSON Lines: one JSON object per line |
| **Normalization** | Mapping parsed, interpreted source data into the common schema |
| **Oracle** | A slow, obviously correct reference used to check a fast implementation |
| **Parsing / semantic mapping** | Parsing extracts fields; semantic mapping decides what they mean |
| **Provenance** | Where the data came from and how it was processed (hash, parameters, versions) |
| **Redaction** | Replacing usernames with keyed-hash tokens in outputs |
| **Result vs status** | `result` says whether alerts were found; `status` also accounts for coverage |
| **Sliding window** | The interval `(t − W, t]` ending at each event |
| **Spraying** | One source trying a few passwords against many accounts |
| **Synthetic data** | Artificial records used for testing and demonstration |
| **Triage** | First review and prioritisation of activity that may need investigation |
| **Uncorrelatable** | A relevant event a rule cannot use (missing time, key or outcome); counted, never dropped silently |

---

**Document status:** Planning specification, version 2.0.0. It does not claim AuthWatch has been implemented or tested; Appendix B records exactly what was run during planning.
