# Rust Context Engine V1 — Benchmark & Security Evaluation Report

- **Generated (UTC):** `2026-11-22T12:56:38Z`
- **Evaluated Release Binary:** `context-engine.exe` (`6,394,368` bytes)
- **Overall V1 Gate Verdict:** **PASS (7/7 Gates Met)**

## 1. V1 Acceptance Gates (Section 11)

| Gate | Proposed V1 Bar | Measured Result | Status |
| --- | --- | --- | --- |
| `exact_recovery_100_pct` | 100% exact SHA-256 byte recovery on authorized fixtures | `22/22 (100.0%)` | **PASS** |
| `failure_retention_100_pct` | 100% distinct failure identifiers & exit codes retained | `24/24 IDs (100.0%), 13/13 exit codes` | **PASS** |
| `median_noisy_output_reduction_gte_40_pct` | >= 40.0% median tool-output byte reduction on noisy fixtures | `77.69%` | **PASS** |
| `median_paired_token_reduction_gte_25_pct` | >= 25.0% median paired end-to-end token reduction (including retrieval overhead) | `58.91%` | **PASS** |
| `non_inferior_task_effectiveness` | Zero task regressions vs uncached baseline (20/20) | `Engine 20/20 vs Baseline 20/20` | **PASS** |
| `zero_cross_scope_leaks_and_zero_egress` | 0 unauthorized cross-workspace retrievals and 0 network sockets | `leaks=0, sockets=0` | **PASS** |
| `safety_fail_closed` | Destructive/shell actions blocked and doctor healthy | `destructive_blocked=True, doctor_healthy=True` | **PASS** |

## 2. Latency, Resource & Offline Security Telemetry

| Metric | Value |
| --- | --- |
| CLI `doctor --json` Startup (`p50` / `p95`) | `112.48 ms` / `220.0 ms` |
| MCP In-Engine Tools (`index`/`search`/`get`/`resume`/`stats`/`doctor`) `p50` / `p95` | `5.34 ms` / `36.04 ms` |
| MCP All Tools (including child process spawn in `context_run`) `p50` / `p95` | `6.3 ms` / `219.3 ms` |
| Peak Server Working Set Memory | `20.93 MiB` |
| Workspace `.context-engine/` Disk Footprint (20 tasks + WAL index + zstd blobs) | `1,311,288 bytes` (`1280.6 KiB`) |
| Unauthorized Cross-Scope Retrievals (`SCOPE_VIOLATION` probe) | `0` |
| Observed TCP/UDP Network Sockets (`Get-NetTCPConnection`) | `0` |

## 3. Paired 20-Task End-to-End Evaluation (`evals/tasks.jsonl`)

- **Task Effectiveness:** `20/20` Engine vs `20/20` Baseline (`100%` decision-evidence parity)
- **Median Paired Net Token Reduction (including retrieval calls):** **`58.91%`** (mean `52.42%`, aggregate `93.84%` across `145,528` baseline tokens vs `8,964` engine tokens)

| Task | Category | Baseline Tokens | Compact View Tokens | Follow-Up Calls (`Tokens`) | Engine Total Tokens | Net Token Reduction | Evidence Parity |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| `T01` Diagnose multi-suite Cargo test failures and recover scope assertion diff | `cargo_test` | 1,201 | 556 | 2 (`298`) | 854 | `28.89%` | **PASS** |
| `T02` Verify 5,000-line noisy passing Cargo test suite outcome | `cargo_test` | 123,323 | 63 | 0 (`0`) | 63 | `99.95%` | **PASS** |
| `T03` Triage CRLF cargo-nextest failures and inspect zstd CRC mismatch trace | `cargo_test` | 1,069 | 108 | 1 (`146`) | 254 | `76.24%` | **PASS** |
| `T04` Diagnose ANSI + OSC-8 hyperlink + spinner torture test failure | `cargo_test` | 1,684 | 134 | 0 (`0`) | 134 | `92.04%` | **PASS** |
| `T05` Deduplicate multi-target rustc E0308/E0425/E0599 errors from cargo check | `compiler_diag` | 979 | 434 | 0 (`0`) | 434 | `55.67%` | **PASS** |
| `T06` Locate TypeScript strict type errors from tsc --noEmit | `compiler_diag` | 142 | 178 | 0 (`0`) | 178 | `-25.35%` | **PASS** |
| `T07` Triage pytest failures, fixture setup RuntimeError, and strict XPASS | `pytest` | 1,089 | 237 | 1 (`199`) | 436 | `59.96%` | **PASS** |
| `T08` Inspect Jest/Vitest Windows path and JSON array test failures | `jest_vitest` | 339 | 303 | 0 (`0`) | 303 | `10.62%` | **PASS** |
| `T09` Review multi-file Git diff summary and retrieve specific ansi.rs hunk | `git` | 1,043 | 174 | 1 (`257`) | 431 | `58.68%` | **PASS** |
| `T10` Audit dirty Git working tree and identify unmerged conflict path | `git` | 257 | 217 | 0 (`0`) | 217 | `15.56%` | **PASS** |
| `T11` Inspect 15-commit Git log history and retrieve TOCTOU confinement commit details | `git` | 1,929 | 574 | 2 (`198`) | 772 | `59.98%` | **PASS** |
| `T12` Group multi-crate ripgrep ScopeViolation and PathEscape hits and inspect store.rs span | `search` | 1,529 | 988 | 1 (`254`) | 1,242 | `18.77%` | **PASS** |
| `T13` Summarize SecretGuard ripgrep matches across Windows and relative paths | `search` | 425 | 303 | 0 (`0`) | 303 | `28.71%` | **PASS** |
| `T14` Identify failed batch records inside 40-item JSON API payload | `json_ndjson` | 1,693 | 432 | 1 (`122`) | 554 | `67.28%` | **PASS** |
| `T15` Pinpoint error events inside 80-line NDJSON worker telemetry stream | `json_ndjson` | 2,505 | 342 | 1 (`50`) | 392 | `84.35%` | **PASS** |
| `T16` Deduplicate noisy service log templates while retaining FATAL/ERROR causes | `logs` | 1,522 | 305 | 0 (`0`) | 305 | `79.96%` | **PASS** |
| `T17` Inspect binary PNG stream metadata and recover exact IHDR header bytes | `binary` | 1,024 | 96 | 1 (`16`) | 112 | `89.06%` | **PASS** |
| `T18` Locate Zstandard Integrity Repair and Emergency Prune steps in large runbook | `docs_source` | 1,526 | 313 | 2 (`636`) | 949 | `37.81%` | **PASS** |
| `T19` Locate verify_frame_window_bounds implementation inside large Rust module | `docs_source` | 1,400 | 313 | 2 (`371`) | 684 | `51.14%` | **PASS** |
| `T20` Analyze secret-bearing & prompt-injection incident logs safely without credential leakage | `security_adversarial` | 849 | 305 | 1 (`42`) | 347 | `59.13%` | **PASS** |

## 4. 23-Fixture Compression & Byte-Exact Recovery Matrix

- **Median Tool-Output Reduction (Noisy Target Fixtures):** **`77.69%`** (mean `71.98%`)
- **Exact SHA-256 Byte Recovery:** `22/22` (`100.0%` — `F22` intentionally stores `SecretGuard`-redacted text per `RedactBeforeIndex` policy)
- **Distinct Failure Identifier Retention:** `24/24` (`100.0%`)

| ID | Fixture | Reducer Transformations | Raw Bytes | View Bytes | Output Reduction | SHA-256 Recovery | Failures Retained |
| --- | --- | --- | ---: | ---: | ---: | --- | --- |
| `F01` | `cargo_test_failing_multiline` | `strip_ansi@1, cargo_test@1` | 4,802 | 2,223 | `53.71%` | `100% MATCH` | `4/4` |
| `F02` | `cargo_test_passing_noisy_5k` | `strip_ansi@1, cargo_test@1` | 493,290 | 252 | `99.95%` | `100% MATCH` | `0/0` |
| `F03` | `cargo_nextest_failing_crlf` | `strip_ansi@1, cargo_test@1` | 4,274 | 432 | `89.89%` | `100% MATCH` | `2/2` |
| `F04` | `ansi_crlf_spinner_torture` | `strip_ansi@1, cargo_test@1` | 6,735 | 536 | `92.04%` | `100% MATCH` | `1/1` |
| `F05` | `pytest_failing_suite` | `strip_ansi@1, pytest_jest@1` | 4,355 | 948 | `78.23%` | `100% MATCH` | `4/4` |
| `F06` | `vitest_jest_failing` | `strip_ansi@1, pytest_jest@1` | 1,354 | 1,211 | `10.56%` | `100% MATCH` | `2/2` |
| `F07` | `rustc_cargo_check_errors` | `strip_ansi@1, compiler_diag@1` | 3,916 | 1,733 | `55.75%` | `100% MATCH` | `3/3` |
| `F08` | `tsc_diagnostics` | `strip_ansi@1, compiler_diag@1` | 565 | 711 | `-25.84%` | `100% MATCH` | `3/3` |
| `F09` | `git_diff_large` | `strip_ansi@1, git_reducer@1` | 4,169 | 694 | `83.35%` | `100% MATCH` | `0/0` |
| `F10` | `git_status_dirty` | `strip_ansi@1, git_reducer@1` | 1,025 | 867 | `15.41%` | `100% MATCH` | `1/1` |
| `F11` | `git_log_graph_history` | `strip_ansi@1, git_reducer@1` | 7,715 | 2,295 | `70.25%` | `100% MATCH` | `0/0` |
| `F12` | `ripgrep_hits` | `strip_ansi@1, search_hits@1` | 1,700 | 1,210 | `28.82%` | `100% MATCH` | `0/0` |
| `F13` | `ripgrep_large_codebase` | `strip_ansi@1, search_hits@1` | 6,116 | 3,949 | `35.43%` | `100% MATCH` | `0/0` |
| `F14` | `binary_non_utf8_stream` | `unknown_safe@1` | 4,096 | 383 | `90.65%` | `100% MATCH` | `0/0` |
| `F15` | `large_api_records.json` | `strip_ansi@1, structured_json@1` | 6,771 | 1,727 | `74.49%` | `100% MATCH` | `2/2` |
| `F16` | `event_stream_telemetry.ndjson` | `strip_ansi@1, structured_json@1` | 10,019 | 1,368 | `86.35%` | `100% MATCH` | `2/2` |
| `F17` | `noisy_service.log` | `strip_ansi@1, log_dedup@1` | 6,085 | 1,219 | `79.97%` | `100% MATCH` | `0/0` |
| `F18` | `large_runbook_guide.md` | `strip_ansi@1, unknown_safe@1` | 6,104 | 1,249 | `79.54%` | `100% MATCH` | `0/0` |
| `F19` | `large_rust_module_source.rs` | `strip_ansi@1, unknown_safe@1` | 5,599 | 1,249 | `77.69%` | `100% MATCH` | `0/0` |
| `F20` | `architecture_notes.md` | `strip_ansi@1, unknown_safe@1` | 634 | 755 | `-19.09%` | `100% MATCH` | `0/0` |
| `F21` | `prompt_injection_tool_output.log` | `strip_ansi@1, log_dedup@1` | 4,933 | 1,251 | `74.64%` | `100% MATCH` | `0/0` |
| `F22` | `secret_bearing_incident.log` | `strip_ansi@1, secret_redact@1, log_dedup@1` | 3,394 | 1,218 | `64.11%` | `REDACT_POLICY` | `0/0` |
| `F23` | `malformed_nested_json_torture.json` | `strip_ansi@1, unknown_safe@1` | 2,644 | 1,250 | `52.72%` | `100% MATCH` | `0/0` |

