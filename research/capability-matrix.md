# Rust Context Engine V1 — Capability Matrix

**Date:** 2026-11-22  
**Status:** Phase 0 Gate — Approved Specification Mapping

## 1. Core Capability-to-Crate Matrix

| Capability Domain | V1 Requirement | Inspiration / Evidence Basis | Owning Crate(s) | Verification Gate |
| :--- | :--- | :--- | :--- | :--- |
| **Artifact Contract & Identity** | Versioned `ArtifactEnvelope` (`schema_version: 1`), opaque server-minted `a_<sha256>` IDs bound to canonical `(workspace_scope_id, session_id)`, explicit `complete` / `originals_available` / `reduction_error` flags. | Clean-room design ([ADR 0001](../docs/adrs/0001-artifact-identity-and-scope.md)) | `context-core` | Unit tests, cross-scope forgery tests, JSON round-trip golden tests |
| **Pre-Index Secret Protection** | Deterministic `SecretGuard` detecting PEM, AWS, GCP, GitHub, GitLab, OpenAI, Anthropic, Slack, JWT, Bearer, connection URIs, `.env` secrets, and high-entropy tokens; policy modes `RedactBeforeIndex`, `Quarantine`, `Deny`. | Clean-room design ([ADR 0002](../docs/adrs/0002-storage-and-secret-policy.md)) | `context-core` | Unit tests per token family, false-positive safe-token tests, adversarial FTS5 leakage suite |
| **Confined Process Execution** | Direct `argv` execution (`shell = false`), `dunce` canonical path + symlink/junction containment, sensitive file/dir denylist, safe dev-tool allowlist, destructive flag blocklist, env scrubbing, timeouts + `kill_on_drop`. | Clean-room design ([ADR 0003](../docs/adrs/0003-execution-confinement.md)) | `context-execution` | Traversal/symlink escape tests, shell-injection argv tests, timeout kill tests |
| **Bounded Stream Capture** | Concurrent `stdout` and `stderr` async capture with hard byte caps, backpressure, exact non-UTF-8 byte preservation, exit code, duration, and truncation markers. | Clean-room design | `context-capture` | 50 MiB flood test, binary/non-UTF-8 round-trip test, exit-code fidelity tests |
| **Content-Addressed Private Store** | Atomic temp-write -> `zstd` frame -> `sync_all` -> SHA-256 verify -> rename under `.context-engine/store/`; Windows owner-only DACL; byte-offset (`start:end`) and UTF-8 line-range (`start:end`) retrieval; TTL/quota pruning. | Clean-room design ([ADR 0002](../docs/adrs/0002-storage-and-secret-policy.md)) | `context-store` | SHA-256 byte-exact round-trip, `proptest` slice/line indexing, torn-write recovery, Windows ACL check |
| **Single-Pass Deterministic Reducers** | Single-pass classifier + transformation ledger (`transformations: Vec<String>`) across `strip_ansi@1`, `cargo_test@1`, `pytest_jest@1`, `compiler_diag@1`, `git_reducer@1`, `structured_json@1`, `log_dedup@1`, `search_hits@1`, `unknown_safe@1`. | `Headroom` (Apache-2.0 via `rust-anything` gate), `RTK` (Apache-2.0 study), `Caveman` (Apache-2.0 invariants), [ADR 0004](../docs/adrs/0004-single-pass-reduction-and-retention.md) | `context-reducers` | Golden fixture suite, `proptest` ANSI/UTF-8 safety, `rust-anything` diff/fuzz gate, double-reduction idempotency test |
| **Scoped Lexical Search** | SQLite WAL + FTS5 (`bm25()`) over *sanitized* chunks strictly filtered by `(workspace_scope_id, session_id)` with exact artifact provenance pointers. | Clean-room design (zero Context Mode code) | `context-search` | Scoped ranking tests, cross-workspace isolation tests, secret-absence FTS5 audit |
| **Session Continuity & Telemetry** | Append-only non-sensitive event journal, raw-vs-reduced byte/token telemetry, deterministic checkpointing, and `context_resume` state recovery after context resets. | Clean-room design | `context-journal` | Checkpoint/resume round-trip tests, token/byte accounting invariants |
| **Stdio MCP Server** | JSON-RPC 2.0 over stdio (`initialize`, `tools/list`, `tools/call`), strict argument schema validation, bounded output guard, structured `isError` responses, server-pinned `--workspace`. | MCP specification + clean-room Rust server | `context-mcp` | Schema validation unit tests, live stdio child-process E2E harness |
| **Unified CLI & Opt-In Adapters** | `context-engine` binary (`run`, `index`, `search`, `get`, `resume`, `stats`, `prune`, `doctor`, `mcp`, `setup`) + opt-in integration bundles in `dist/integrations/` without touching global user configs. | `Caveman` coexistence rules + host adapter specs | `context-cli`, `adapters/*` | CLI integration tests, `--dry-run` / `--output-dir` adapter config validation, REA binary audit |

## 2. MCP & CLI Surface Mapping

| MCP Tool | CLI Equivalent | Input Guardrails | Output Contract |
| :--- | :--- | :--- | :--- |
| `context_run` | `context-engine run -- <argv...>` | Server-bound workspace, `argv` allowlist, canonical `cwd` inside workspace, bounded timeout & capture cap | `ArtifactEnvelope` with compact reducer view, exit status, SHA-256 digests, and `context_get` handle |
| `context_index` | `context-engine index <path>` | Canonical workspace file check, sensitive-path denylist (`.env*`, `*.pem`, `*.key`, `.ssh`, `.aws`), `SecretGuard` scan | `ArtifactEnvelope` + sanitized FTS5 chunk count + recovery handle |
| `context_search` | `context-engine search <query>` | Safe FTS5 query tokenization, mandatory `(workspace_scope_id, session_id)` filter, bounded `limit` | Ranked sanitized snippets (`bm25`), `artifact_id`, stream kind, and exact line/byte range pointers |
| `context_get` | `context-engine get <artifact_id>` | Scope authorization check on `artifact_id`, max page bytes/lines cap, `SecretGuard` policy enforcement | Paginated exact UTF-8 line range or base64/hex-safe byte slice + continuation cursor |
| `context_resume` | `context-engine resume [--session <id>]` | Same `(workspace_scope_id, session_id)` authorization | Latest checkpoint summary, active failing tests/diagnostics, recent `artifact_id` handles, cumulative savings |
| `context_stats` | `context-engine stats [--session <id>]` | Read-only aggregate telemetry | Raw bytes, reduced bytes, estimated tokens saved, retrieval overhead bytes, secret redaction counts |
| `context_doctor` | `context-engine doctor` | Read-only environment & storage health check | Workspace path, store ACL status, SQLite WAL/FTS5 health, policy mode, quota usage |

## 3. Host Agent Integration & Coexistence Matrix

| Host / Client | Primary Transport | Optional Native Interception | Coexistence with Headroom & Caveman |
| :--- | :--- | :--- | :--- |
| **Cursor IDE** | `.cursor/mcp.json` (`--workspace`) | `.cursor/rules/context-engine.mdc` + opt-in hook | Checks `transformations` ledger; never modifies `~/.cursor` globally (emits to `--output-dir` or `dist/integrations/cursor/`) |
| **Claude Code** | `.mcp.json` (`--workspace`) | Opt-in `PreToolUse` / `PostToolUse` hook + `SKILL.md` | Skips outputs already tagged by `context-engine` or upstream reducers; coexists with Caveman terse-response rules |
| **OpenCode** | OpenCode MCP config | Validated tool-output plugin/hook template | Explicit MCP fallback when hooks are disabled |
| **Codex CLI** | `config.toml` `[mcp_servers.context_engine]` | `ce-run` wrapper script | Server-scoped workspace isolation |
| **Generic Shell / MCP Agent** | Stdio JSON-RPC 2.0 or `ce-run` CLI | POSIX `sh` / PowerShell `ce-run.ps1` wrapper | Works in air-gapped / offline environments with zero network egress |
