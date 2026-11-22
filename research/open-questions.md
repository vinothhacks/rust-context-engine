# Phase 0 Open Questions & Recommended V1 Resolutions

**Date:** 2026-11-22  
**Step:** `phase0-mcp-ref-porting` (Wave 1B)  
**Target Consumers:** Wave 2 (`context-reducers`, `context-capture`, `context-store`), Wave 3 (`context-search`, `context-journal`, `context-mcp`, `context-cli`, `adapters`)

---

## OQ-01: Source-Hint vs Content-Shape Precedence in `context-reducers` Classifier
- **Context:** When `context_run` executes a known argv vector (e.g., `["cargo", "test"]`, `["git", "diff"]`, `["pytest"]`), we know the command's argv *and* we observe its `stdout`/`stderr` bytes. Conversely, `context_index` may receive raw text or a `.log` file with no argv metadata.
- **Edge Case Observed (RTK `cargo_cmd.rs` & `pytest_cmd.rs`):** If `cargo test` fails inside `build.rs` or fails to compile before running any test binary, its output is **compiler diagnostics** (`error[E0308]`), not `test result:` summaries. Similarly, if `pytest` fails with exit code `2` or `4` due to an `ImportError` or bad CLI flag, its output has no `=== FAILURES ===` header.
- **Recommended V1 Resolution for Wave 2:**
  1. Check the transformation ledger first; if already reduced, pass through untouched.
  2. Use `argv` as a **candidate prior**, but require structural anchor confirmation before emitting a specialized parser summary (`cargo_test@1` requires at least one `Running ` / `test result:` / `thread '...' panicked` anchor; otherwise cascade to `compiler_diag@1` -> [`classify_content`](evidence/port.rs) -> `unknown_safe@1`).
  3. On nonzero exit code when zero test failures/errors were extracted by a specialized test reducer, **never** emit an empty/clean test summary; fall back to `compiler_diag@1` / `log_dedup@1` / bounded `unknown_safe@1` head+tail excerpt with exit code prominently surfaced.

## OQ-02: Handling Combined vs Separate `stdout` and `stderr` in Reducers
- **Context:** `Cargo` writes `Compiling`/`Finished`/`error[E...]` diagnostics to `stderr` and `running N tests` / `test ... ok/FAILED` to `stdout` (while panic messages inside tests may land in captured `stdout` or `stderr` depending on `--nocapture`). `context-store` persists `stdout` and `stderr` as separate content-addressed blobs.
- **Question:** Should `context_run`'s compact `ArtifactEnvelope.view` reduce `stdout` and `stderr` together into one unified diagnostic summary while preserving exact per-stream pointers (`stream: "stdout"` vs `stream: "stderr"`) for `context_get`?
- **Recommended V1 Resolution for Wave 2:**
  - Persist `stdout` and `stderr` as **separate** SHA-256 blobs (`stdout_sha256`, `stderr_sha256`) so `context_get --stream stdout|stderr` is 100% exact.
  - Feed `(argv, exit_code, stdout_bytes, stderr_bytes)` to `context-reducers` so `cargo_test@1` and `compiler_diag@1` can synthesize a single coherent `view.safe_excerpt` (e.g., compiler errors from `stderr` + failing test blocks from `stdout`), tagging each recovery hint with its exact stream (`--stream stderr --lines A:B` or `--stream stdout --lines C:D`).

## OQ-03: Embedded JSON Spans Inside Hybrid Build/CLI Logs
- **Context:** Headroom's `recursive_json.py` (ported in [`scan_json_spans`](evidence/port.rs)) detects balanced JSON arrays/objects embedded inside mixed text (e.g., `Exit code: 0\n[{"id": 1}, ...]`, `curl -i` headers + JSON body, or structured JSON log lines).
- **Question:** In V1, should `structured_json@1` run only when JSON is the primary payload (pure JSON, concatenated `{...} {...}`, or `>= 60%` bulk wrapper as implemented in `classify_content`), or also splice-crush embedded JSON spans inside arbitrary prose/logs?
- **Recommended V1 Resolution for Wave 2:**
  - Route pure JSON, BOM-prefixed JSON, concatenated JSON objects (`{...} {...}`), and bulk-wrapped JSON (`>= 60%` of payload) to `structured_json@1` using [`reduce_json_structure`](evidence/port.rs).
  - Keep `scan_json_spans` available in `context-reducers` as a helper, but **avoid** mutating small inline JSON snippets inside compiler errors or assertion diffs (where mutating an expected-vs-actual JSON assertion in a failing test would hide the bug!).

## OQ-04: RTK Split-License (`Apache-2.0` vs `BUSL-1.1`) Enforcement Boundary
- **Context:** Inspection of `rtk` (`b8cb15167268b7a27519b84f79e53c4cb742bafe`) revealed that while root `Cargo.toml`, `src/**`, `tests/**`, and `text/**` are licensed under **`Apache-2.0`**, the workspace subcrates `rtk/engine/`, `rtk/proxy/`, and `rtk/plugin/` are licensed under **`BUSL-1.1`**.
- **Resolution (Enforced Immediately in Phase 0):**
  - Zero files from `rtk/engine/`, `rtk/proxy/`, or `rtk/plugin/` were read, copied, or analyzed.
  - All future subagents MUST restrict any reference lookup in `research/refs/rtk/` strictly to `rtk/src/**` and `rtk/text/**` (`Apache-2.0`), and preserve Apache-2.0 attribution in root `NOTICE` if any pattern is adapted.

## OQ-05: `user-rea` MCP Post-Build Hardening Audit Fallback Plan
- **Context:** `user-rea` failed startup in the current IDE host session (`REA could not start` — requires host MCP client restart and `npx rea-agents@6.10.1 doctor`).
- **Recommended Resolution for Phase 6 (`phase6-harden-audit-dist`):**
  - If the user has restarted the MCP client before Phase 6, run `user-rea` (`inspect_rust_binary`, `inspect_binary_hardening`, `audit_release_exposure`) against `dist/context-engine.exe`.
  - If the session remains continuous without an MCP host restart, execute deterministic Windows PE header & security verification via PowerShell/`dumpbin`/`llvm-readobj` + `icacls` DACL checks (verifying High-Entropy 64-bit ASLR `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA`, Dynamic Base, NX/DEP `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`, Control Flow Guard `IMAGE_DLLCHARACTERISTICS_GUARD_CF`, symbol stripping, and zero secret strings) and document that `npx rea-agents@6.10.1 doctor` + `user-rea` audit can be run post-restart.

## OQ-06: Coexistence of Opt-In Hooks with Installed Headroom / Caveman Plugins
- **Context:** The developer workstation already hosts `user-headroom` MCP and `caveman` skills/plugins. If an opt-in Claude Code or Cursor `PostToolUse` hook is enabled alongside Caveman or Headroom, both tools might inspect tool outputs.
- **Recommended Resolution for Phase 5 (`phase5-agent-adapters`):**
  - Prefer explicit MCP calls (`context_run`, `context_get`, `context_search`) + lightweight agent rules (`.cursor/rules/context-engine.mdc`, `CLAUDE.md` snippet) as the default conflict-free integration.
  - Ensure opt-in hook templates check for `<<ccr:`, `ccr_`, and `context-engine:` markers before transforming any payload, and emit `transformations: [...]` in `ArtifactEnvelope` so coexisting tools remain single-pass and idempotent.
