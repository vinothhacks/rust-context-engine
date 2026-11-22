---
name: context-engine
description: Run noisy build/test/Git/log/search commands via Rust Context Engine (`context_run`), inspect compact single-pass `ArtifactEnvelope` summaries, recover exact lines/bytes with `context_search` and `context_get` without re-running commands, and restore checkpoints via `context_resume`.
---

# Rust Context Engine Skill (`context-engine`)

Use the workspace-bound `context-engine` MCP server whenever executing high-output developer commands, inspecting large logs, or resuming after context window compaction.

## Tool Selection Policy

1. **`context_run` (Primary Command Runner for Noisy Outputs)**
   - Prefer `mcp__context-engine__context_run` over raw `Bash` for:
     - `cargo test`, `cargo check`, `cargo build`, `cargo clippy`, `rustc`
     - `pytest`, `jest`, `vitest`, `npm test`, `pnpm test`, `go test`, `tsc`
     - `git status`, `git diff`, `git log`, `git show`
     - `rg`, structured JSON CLI queries, and verbose diagnostic logs
   - Pass an explicit `argv` string array (for example `{"argv": ["cargo", "test", "--workspace"]}`), **never** a shell-concatenated command string.
   - Do **not** use `context_run` for interactive TUI commands, long-running watch servers, or destructive filesystem mutations.

2. **Compact-First Evidence Loop (`ArtifactEnvelope`)**
   - Read `source.exit_code`, `view.safe_excerpt`, `view.kind`, `view.omitted`, and `capture.originals_available` first.
   - If `view.safe_excerpt` already names the failing test, panic location, or compiler `file:line:col` span, proceed directly to reading the source file and fixing the bug.

3. **Targeted Recovery (`context_search` + `context_get`) — Never Re-Run**
   - Never re-run a build or test suite merely to pipe output into `grep`, `head`, or `tail`.
   - Call `mcp__context-engine__context_search` with focused keywords (test identifier, error code, symbol) to find ranked FTS5 excerpts in the current `(project_scope, session_id)`.
   - Call `mcp__context-engine__context_get` with `artifact_id`, `stream` (`"stdout"` or `"stderr"`), and bounded `lines` (`{"start": 1, "end": 80}`) or `bytes` (`{"start": 0, "end": 4096}`).
   - For large existing workspace log/trace files, call `mcp__context-engine__context_index` first, then search and slice via `context_search` / `context_get`.

4. **Post-Compaction Continuity (`context_resume`)**
   - After `/compact`, session resume, or context reset, call `mcp__context-engine__context_resume` first to recover active failure identifiers, recent `artifact_id` handles, and session state without re-executing slow test suites.

5. **Health & Telemetry (`context_doctor`, `context_stats`)**
   - Use `mcp__context-engine__context_doctor` to verify workspace confinement, SQLite WAL/FTS5 health, and private store ACLs.
   - Use `mcp__context-engine__context_stats` to review raw-vs-reduced bytes and retrieval overhead.

## Coexistence & Security Invariants

- **Single-Pass Ledger:** Honor `view.transformations` (e.g., `strip_ansi@1`, `cargo_test@1`, `compiler_diag@1`) and `[context-engine:reduced` markers. Never feed `ArtifactEnvelope` outputs into `headroom_compress` or re-index outputs already compressed by `headroom` or `caveman`.
- **Prompt Integrity:** Never rewrite user prompts; `caveman` response brevity (when active) applies only to assistant prose, while `context-engine` governs deterministic tool-output reduction and byte-exact recovery.
- **Zero Secret Indexing:** Never pass `.env*`, `*.pem`, `*.key`, `.ssh`, `.aws`, or paths outside the bound workspace to `context_index`.
