# Observed Behavior & Reducer Invariants (Phase 0 Reference Audit)

**Date:** 2026-11-22  
**Step:** `phase0-mcp-ref-porting` (Wave 1B)  
**Evidence Artifacts:** [`research/evidence/REPORT.md`](evidence/REPORT.md), [`research/evidence/port.rs`](evidence/port.rs), [`research/evidence/rust-anything.json`](evidence/rust-anything.json), [`research/evidence/verification-metrics.json`](evidence/verification-metrics.json)

---

## 1. Pinned Upstream Revisions & Subdirectory License Audit

Every cloned repository in the gitignored `research/refs/` sandbox was audited immediately upon shallow clone (`git clone --depth 1`) before inspecting implementation files:

| Reference | Repository URL | Pinned Commit SHA | Verified License Boundary | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Headroom** | `https://github.com/chopratejas/headroom.git` | `ce0460cfa8598dc939243dbc7aec4b2d35f4e44a` | **`Apache-2.0`** across root `LICENSE`, `NOTICE`, `headroom/**`, `crates/**`, and `plugins/headroom-oauth2/LICENSE`. | Cleared; isolated unit ported & gated via `user-rust-anything`. |
| **RTK** | `https://github.com/rtk-ai/rtk.git` | `b8cb15167268b7a27519b84f79e53c4cb742bafe` | **SPLIT LICENSE:** Root `LICENSE`, `src/**`, `tests/**`, and `text/**` (`rtk-text`) are **`Apache-2.0`**. Subdirectories **`engine/`**, **`proxy/`**, and **`plugin/`** carry **`BUSL-1.1`** (`Business Source License 1.1`). | Only `Apache-2.0` crates (`src/**`, `text/**`) were inspected. **`engine/`, `proxy/`, and `plugin/` were strictly excluded from reading or reuse.** |
| **Caveman** | `https://github.com/JuliusBrussee/caveman.git` | `70f4f34e834893ea9af9f4fc6022266bd56d18b1` | **`Apache-2.0`** repo-wide starting v3.0.0 (`LICENSE`, `LICENSING.md`, `NOTICE`), with pre-3.0.0 MIT notice retained in `LICENSE-MIT`. (Note: `engine/pixel/assets/` contains GNU Unifont with font exception — untouched.) | Cleared for hook, recovery-verification, and coexistence invariants. |
| **Caveman-Code** | `https://github.com/JuliusBrussee/caveman-code.git` | `6b20bc978102504c809965f93b4ebd99f0f67e97` | **`MIT`** (`LICENSE`, Copyright 2025 Mario Zechner, Copyright 2026 Julius Brussee). | Cleared for deterministic tool-budget, ANSI, and read-dedup analysis. |
| **Context Mode** | `https://github.com/mksglu/context-mode` | *(not cloned)* | **`Elastic-2.0`** (non-permissive source-available). | **BLOCKED** — never cloned, read, or copied. |

### Tooling Note on `user-rea` MCP vs Static Source Inspection
During pre-flight probing, `user-rea` returned `"Do not repeat this startup. Tell the user REA could not start and ask them to restart the MCP client, then run rea doctor."` Per Phase 0 protocol, `user-rea` was not re-invoked; all upstream invariants below were extracted directly from pinned `Apache-2.0` / `MIT` source trees via `Read`/`Grep`, and behavioral equivalence on the ported unit was proven dynamically via `user-rust-anything` (`diff` + `fuzz` + `gate`). Before Phase 6 release-binary PE hardening audit (`inspect_rust_binary`, `inspect_binary_hardening`, `audit_release_exposure`), restart the host MCP client and run `npx rea-agents@6.10.1 doctor`.

---

## 2. Verified `user-rust-anything` Port (`classifier-json-reducer-rs`)

Because `headroom`'s full Python package imports compiled `headroom._core` extensions and optional ML libraries (`sentence-transformers`, `numpy`), we isolated the pure-stdlib deterministic content-detection and JSON-structure logic from `headroom/transforms/content_detector.py`, `headroom/transforms/lossless_compaction.py`, and `headroom/transforms/recursive_json.py` (`ce0460cfa8598dc939243dbc7aec4b2d35f4e44a`, `Apache-2.0`) into `research/refs/port-unit/headroom_port/classifier_json_reducer.py` and executed the full `user-rust-anything` v3.1.0 workflow:

1. **`analyze`:** Mapped `headroom-port-unit` (`wave: 0`, `bridge: pyo3`, leaf unit with zero external dependencies) and flagged 5 cross-language hazard classes (`string-offsets`, `unordered-iteration`, `dynamic-regex`, `dynamic-typing`, `number-semantics`).
2. **`bridge` & `refresh`:** Generated PyO3 crate `classifier-json-reducer-rs` exporting `scan_json_spans`, `normalize_concatenated_json`, `carries_record_array`, `classify_content`, and `reduce_json_structure`.
3. **`record`:** Captured **1,180 deterministic cases** (`0` errors), combining 200 generated edge-case inputs per function, **138 semantic traps** (Unicode case-folding `"İstanbul"` / `"straße"` / `"ΣΊΣΥΦΟΣ"`, combining marks `"e\u0301"`, emoji `"🦀"` / `"👍🏽"`, UTF-8 BOM `\ufeff`, `None` optional args, integer extremes `i64::MIN`/`i64::MAX`), unit-test calls, and realistic Context Engine fixtures.
4. **`build` & `diff`:** Built cleanly (`#![forbid(unsafe_code)]`) and matched **1,180 / 1,180** recorded cases (`0` mismatches).
5. **`fuzz`:** Generated **2,748 fresh unseen cases** across 2 rounds (`seed = 20261122`), achieving **2,748 / 2,748** exact parity (`0` mismatches).
6. **`bench` & `report`:** Measured **6.94x – 7.19x** geometric mean speedup *including Python-to-Rust FFI call overhead* (`carries_record_array`: **15.39x–17.05x**, `classify_content`: **9.24x–9.83x**, `reduce_json_structure`: **8.77x–10.75x**, `scan_json_spans`: **4.47x–4.58x**, `normalize_concatenated_json`: **2.46x–2.75x**).
7. **`gate`:** **PASSED (`12 / 12` checks):** `fmt`, `clippy -D warnings`, `cargo test`, `unsafe` (0 unsafe), `lockfile`, `ported`, `size`, `error cases`, `panics`, `build`, `api`, and `behavior`.

### Cross-Language Traps Uncovered During Differential Porting
Wave 2 (`crates/context-reducers`) should keep these four invariants when integrating [`research/evidence/port.rs`](evidence/port.rs):
- **Unicode case-folding trap (`"İstanbul"`):** Rust's `regex` `(?i)` folds ASCII `'i'`/`'I'` with Turkish `'İ'` (`U+0130`) and `'ı'` (`U+0131`) under default Unicode mode, whereas ASCII log/HTML keywords (`INFO`, `<!DOCTYPE html>`) expect strict ASCII case-insensitivity (`(?i-u:...)`) and ASCII word boundaries (`(?-u:\b)`).
- **UTF-8 byte offsets vs Unicode scalar (`char`) offsets:** Embedded JSON span scanners (`scan_json_spans`) that slice around multi-byte UTF-8 text (emoji, CJK, box-drawing chars in CLI output) must maintain a `char_indices` offset table or operate consistently in byte offsets end-to-end; mixing `str::find` byte indices with `chars().count()` panics or corrupts slices.
- **RFC 8259 strictness & arbitrary-precision integers:** `serde_json` rejects `NaN`/`Infinity` per RFC 8259 and fails on integers `> u64::MAX` unless `arbitrary_precision` is enabled or non-JSON fallback is triggered cleanly.
- **Optional parameter `None` traps:** Tool callers over JSON-RPC frequently send explicit `null` for optional `max_depth` / `max_items` fields (`{"max_depth": null}`); Rust signatures must accept `Option<usize>` / `Option<i64>` and `.unwrap_or(default).clamp(min, max)`.

---

## 3. Reducer Edge Cases & Behavioral Invariants for Wave 2 (`crates/context-reducers`)

### 3.1 Single-Pass Idempotency & Never-Worse Benefit Gate
- **Re-compression prevention (`headroom/transforms/recursive_json.py`, `caveman/packages/pi-extension/src/tool-output.ts`):** Any payload or embedded JSON span already containing a retrieval/compression marker (`<<ccr:`, `context-engine:`, or a non-empty `ArtifactEnvelope.view.transformations` ledger) MUST be skipped by downstream reducers/hooks so outputs are never double-compressed or re-hashed.
- **Never-worse token/byte guard (`rtk/src/core/guard.rs`, `headroom/transforms/lossless_compaction.py`):** On tiny inputs (e.g., `"{}"` or a 2-line log), structured summary headers can exceed raw byte/token length. Reducers should compare reduced vs sanitized-raw size and keep the smaller representation—**except** when (a) `SecretGuard` redacted sensitive material (never fall back to unredacted raw!) or (b) the caller explicitly requested a structural view.

### 3.2 Stream Decoding, ANSI Stripping, and Binary/Encoding Safety (`strip_ansi@1` & `unknown_safe@1`)
- **Fatal `BufRead::lines().map_while(Result::ok)` bug (`rtk/src/core/stream.rs:10-40`):** A single non-UTF-8 byte in child output (common in localized Windows OEM/ANSI tool messages or binary test fixtures) causes `BufRead::lines()` to return `Err`, and `.map_while(Result::ok)` **silently drops every subsequent line in the stream**, hiding test failures at the end of the run.
  - **Required invariant:** `context-capture` / `context-store` must capture and hash exact raw `Vec<u8>` bytes. Derived text reducers must split on `b'\n'`, strip trailing `b'\r'`, and decode non-UTF-8 lines lossily (`String::from_utf8_lossy`) per line while setting `encoding: "lossy-utf8"` / `binary` metadata when invalid UTF-8 or NUL bytes appear.
- **Incomplete ANSI regex in naive strippers (`rtk/text/src/lib.rs:18` vs `caveman-code/.../cave-tool-compression.ts:109`):**
  - `rtk-text` uses `\x1b\[[0-9;]*[a-zA-Z]`, which **misses** CSI private-mode prefixes (`\x1b[?25l`, `\x1b[?2004h` bracketed paste), CSI intermediate bytes (`0x20..=0x2F`), 8-bit CSI (`\u{009b}`), and OSC sequences (`\x1b]8;;url\x07` clickable hyperlinks emitted by modern `rustc`, `cargo`, and `pytest`!).
  - **Carriage-return progress spinners (`\r` without `\n`):** Cargo/npm/pip progress bars emit `Downloading foo...\rDownloading bar...\rFinished\r\n`. Normalizing `\r\n` -> `\n` first and then resolving bare `\r` line overwrites (keeping text after the final bare `\r` on each line) prevents thousands of spinner frames from polluting `cargo_test@1` or `log_dedup@1` views, while `context-store` preserves the untouched raw bytes.

### 3.3 Content Classification & Search Hit Parsing (`Classifier` & `search_hits@1`)
- **Windows drive-letter colon bug (`headroom/crates/headroom-core/src/transforms/search_compressor.rs:44-50`):** Naive grep regexes `^([^:]+):(\d+):(.*)$` capture `"C"` on `C:\Users\dev\src\main.rs:42:fn main()`, fail `\d+` on `\`, and silently drop 100% of Windows `rg`/`grep` results!
  - **Required invariant:** Detect `[A-Za-z]:[\\/]` at byte 0..3 and begin scanning for the `<sep><digits><sep>` line-number marker at index `2`.
- **Dashed filenames & `rg -C` context markers (`headroom/.../search_compressor.rs:50-56`, `content_detector.py:55-63`):** `rg -C` / `grep -C` uses `-` instead of `:` around context line numbers (`src/pre-commit-config.yaml-42-context`). Excluding `-` from path character classes breaks dashed filenames; instead, scan left-to-right for the first `:\d+:` / `:\d+-` (match) or `-\d+-` (context, requiring `/`, `\`, or `.` in prefix so ISO dates `2026-11-22` and prose `version-2-release` are rejected).
- **Timestamped log lines masquerading as grep rows (`headroom/transforms/lossless_compaction.py:69-90`, `content_detector.py:580-596`):** `2026-11-22 14:30:00 [FATAL] db down` matches `^[^:]+:\d+:` (`path="2026-11-22 14"`, `line=30`)! Always test `_TIMESTAMP_ROW_RE` *before* search-line classification and require `>= 2` search lines comprising `>= 1/3` of non-empty lines (`matching * 3 >= non_empty`) plus path-shape guards (reject `<`, `>`, `=` in prefix).

### 3.4 Cargo, Compiler Diagnostics, and Pytest Reducers (`cargo_test@1`, `compiler_diag@1`, `pytest_jest@1`)
- **Cargo prefix grammar & summary noise (`rtk/src/cmds/rust/cargo_cmd.rs:42-200`):**
  - `cargo +nightly test` places `+toolchain` at `argv[1]`; `-C <dir>`, `--color <when>`, `--config <kv>`, and `-Z <flag>` consume a value token before the subcommand (`test`, `check`, `clippy`, `build`).
  - Skip `Compiling ...`, `Checking ...`, `Downloading ...`, `Downloaded ...`, `warning: crate generated N warnings`, and `error: could not compile ... due to N previous errors` boilerplate lines while counting compiled crates, unique `error[E....]:` / `error:` blocks, and `warning:` blocks.
  - Multi-crate workspaces run multiple test binaries (`Running unittests src/lib.rs`, `Running tests/integration.rs`, `Doc-tests ...`), each emitting its own `test result: ok/FAILED. X passed; Y failed; Z ignored` line! `cargo_test@1` MUST aggregate counts across **all** `test result:` sections in the run and retain **100%** of failing test names + panic locations (`thread '...' panicked at file:line:col:`).
- **Pytest exit code `5` vs pre-collection crash (`rtk/src/cmds/python/pytest_cmd.rs:55-65, 116-160`):**
  - Pytest exit code `5` legitimately means `"no tests collected"`. Any *other* nonzero exit code (`1`, `2`, `3`, `4`) with zero parsed test results means collection/import crashed (`SyntaxError`, `ImportError`, bad CLI flag) — never report `"0 failed / no tests collected"` on nonzero exit `!= 5`; surface the raw/sanitized error output!
  - Pytest emits setup/fixture/collection failures under `=== ERRORS ===` (distinct from `=== FAILURES ===`) and unexpected passes as `XPASS` — both must be preserved alongside `FAILED` identifiers.
- **Zero-result false-positive error indicators (`headroom/transforms/error_detection.py:230-283`):**
  - Clean toolchain summaries routinely pair `"error"` and `"fail"` at count zero (`"Found 0 errors"`, `"0 failed"`, `"0 errors, 0 warnings"`, `"Failures: 0"`, `"failed=0"`). Strip `\b(?:0|no)\s+(?:errors?|fail(?:ed|ing|ures?)?)\b` and `\b(?:errors?|fail(?:ed|ing|ures?)?)\s*[:=]\s*0\b` before heuristic error-presence triage!
  - Never put bare `"token"` in security/secret keyword heuristics (`headroom/transforms/error_detection.py:33`): it false-positives on every LLM usage log (`input_tokens`, `tokens_saved`). Use structured prefix/entropy patterns in `SecretGuard`.

### 3.5 Git Status & Diff Reducers (`git_reducer@1`)
- **Invisible line-ending / EOF-newline diffs (`rtk/src/cmds/git/diff_cmd.rs:106-149`):** Checking `str::lines()` equality without checking raw byte equality first misreports CRLF-vs-LF or missing-trailing-newline changes as `"identical"`. Always check byte equality first; if bytes differ while normalized lines match, explicitly report line-ending / trailing-newline difference.
- **Long commit preambles & combined merge diffs (`headroom/transforms/content_detector.py:69-83, 433-446`):** `git log -p` and `git format-patch` preambles often exceed 50 lines before `diff --git` appears (scan `>= 500` lines), and merge commits emit `diff --combined` / `diff --cc` and `@@@ -a,b -c,d +e,f @@@` headers.
- **Diff index lines (`headroom/transforms/lossless_compaction.py:92-94`):** `index <sha>..<sha> <mode>` lines carry git blob bookkeeping unneeded for code understanding in compact summaries (while remaining recoverable from `context-store`).

### 3.6 Log Deduplication & Stack-Trace Preservation (`log_dedup@1`)
- **Chained-exception blank-line trap (`headroom/crates/headroom-core/src/transforms/log_compressor.rs:24-31`):** Python chained tracebacks (`During handling of the above exception, another exception occurred:`) and Rust panic backtraces embed blank lines mid-trace. Terminating stack-trace capture on the first blank line amputates the root exception! Track language-specific trace continuations (`Traceback` -> indented `  File ...` frames -> exception line).
- **Over-aggressive template normalization (`headroom/.../log_compressor.rs:32-38`):** Normalizing digits, hex, and paths across the *entire* line collapses distinct error codes/types into one template. Preserve the prefix up to the first `:` or `=` intact and parameterize (`<UUID>`, `<HEX>`, `<NUM>`, `<TIMESTAMP>`) only in the trailing variable region.
- **High-severity labels (`rtk/src/cmds/system/log_cmd.rs:83-94`):** Route `FATAL`, `PANIC`, `CRITICAL`, `ALERT`, `EMERGENCY`, and `SEVERE` into the primary error bucket (never drop them because they lack the literal substring `"error"`).

### 3.7 JSON Structure Reducer (`structured_json@1`)
- **Leading UTF-8 BOM (`rtk/src/core/utils.rs:48-65`):** PowerShell 5.1 (`Out-File -Encoding utf8`), Windows Notepad, and Windows IDE hooks frequently prepend one or more `\u{feff}` (`EF BB BF`) BOMs that cause `serde_json::from_str` to fail at column 1. Always strip leading `\u{feff}` before JSON detection and parsing (implemented in [`research/evidence/port.rs`](evidence/port.rs)).
- **Concatenated & wrapped JSON (`headroom/transforms/content_detector.py:321-415`):** CLI/MCP tools frequently emit whitespace-separated JSON objects (`{...} {...}`) or wrap JSON with a short header (`Exit code: 0\n{...}`). Normalize concatenated objects and extract bulk wrapped JSON (`>= 60%` of payload).
- **Schema homogeneity vs inline sentinels (`headroom/transforms/smart_crusher.py:72-109`):** Injecting `{"_ccr_dropped": ...}` inside a JSON array mutates array schema; in Context Engine V1, keep `ArtifactEnvelope` metadata (`omitted: true`, `recovery.artifact_id`) in the envelope and render compact structural previews clearly as `structured_json@1` summaries so downstream consumers never mistake a summary marker for a real data record.

### 3.8 Hook, MCP Transport, and Recovery Integrity (`caveman` & `caveman-code`)
- **Persist-and-verify BEFORE publishing compact output (`caveman/packages/pi-extension/src/tool-output.ts:49-62`, `recovery.ts:101-120`, `shrink/shrink.go:112-139`):** Never emit a compact view claiming `originals_available: true` until the raw blob write + `zstd` flush + SHA-256 verification has committed to durable storage. If blob persistence fails, set `originals_available: false` explicitly.
- **Content-addressed SHA-256 vs prefix fingerprinting (`caveman-code/.../cave-tool-compression.ts:214-216`):** `caveman-code`'s `ReadDeduplicationCache` hashes only `length + text.slice(0, 256)`, which suffers silent false-unchanged collisions on same-length edits past byte 256. Context Engine's SHA-256 content-addressed store avoids this completely.
- **Preserve non-text MCP content blocks (`caveman/packages/pi-extension/src/tool-output.ts:66-69`, `caveman-code/.../cave-tool-compression.ts:176-197`):** Any adapter or MCP wrapper processing multi-block results must leave non-text blocks (`image`, `audio`, binary resources) untouched byte-for-byte.
- **Windows child-process & pipe hygiene (`caveman/packages/pi-extension/src/recovery.ts:176-226`, `packages/cli/src/native-hook-fast.ts:138-156`):**
  - Spawn background/child processes on Windows with `CREATE_NO_WINDOW` / `windowsHide` where appropriate so GUI IDE hosts (Cursor) do not flash console windows.
  - Handle broken-pipe (`EPIPE` / `ErrorKind::BrokenPipe`) cleanly on stdio JSON-RPC writes without panicking.
  - Concurrent hook executions occur within the same millisecond (`rtk/src/core/tee.rs:119-146`); temp files in `context-store` must include PID + atomic counter / cryptographic randomness (`tempfile::NamedTempFile`) before atomic rename to `<sha256>.zst`.
