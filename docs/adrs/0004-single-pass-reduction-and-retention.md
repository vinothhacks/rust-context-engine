# ADR 0004: Single-Pass Deterministic Reduction, Transformation Ledger, and Retention

- **Status:** Accepted
- **Date:** 2026-11-22
- **Deciders:** Rust Context Engine Architecture

## Context

In multi-tool developer environments, a coding agent may simultaneously run host hooks (such as Claude Code `PostToolUse`, Caveman, or Headroom) alongside `context-engine` MCP/CLI tools. If an output is reduced more than once, failure identifiers (`file:line:col`, test names, exit codes) or recovery handles (`artifact_id`) can be stripped, producing misleading summaries. Conversely, if a reducer panics or fails on malformed/binary input, dumping the raw multi-megabyte stream into the agent response defeats both token savings and safety.

## Decision

1. **Single-Pass Classifier & Versioned Deterministic Reducers:**
   - `context-reducers` classifies each stream once using `(CommandSource metadata, UTF-8 validity, structural headers)` and applies at most one pre-normalization step (`strip_ansi@1` on a derived UTF-8 buffer) followed by **one** domain reducer:
     - `cargo_test@1`
     - `pytest_jest@1`
     - `compiler_diag@1`
     - `git_reducer@1`
     - `structured_json@1`
     - `log_dedup@1`
     - `search_hits@1`
     - `unknown_safe@1`
   - Stored raw bytes in `context-store` are **never** mutated by `strip_ansi@1` or any reducer.

2. **Immutable Transformation Ledger (`transformations: Vec<String>`):**
   - Every `ArtifactEnvelope` carries `view.transformations` (e.g., `["strip_ansi@1", "cargo_test@1"]`) and a canonical header/marker when rendered as text (`[context-engine:v1 artifact=a_... transforms=strip_ansi@1,cargo_test@1]`).
   - Before reducing any payload, `context-reducers` and opt-in host hooks check for an existing `context-engine` transformation ledger or envelope; if present, reduction is skipped (`already_reduced` short-circuit) so outputs are never double-compressed.

3. **Non-Inferiority Evidence Preservation Rules:**
   - Reducers must preserve **100%** of command exit codes, pass/fail/ignore counts, failing test names, compiler error codes, and primary `file:line:col` spans within `ReductionBudget`.
   - Whenever bytes or lines are elided, `view.omitted = true` is set and an explicit `context_get` pointer (`artifact_id`, stream, suggested line/byte window) is attached.

4. **Fail-Safe Degradation (`unknown_safe@1`):**
   - Any binary stream, invalid UTF-8 payload, or internal reducer error degrades cleanly to `unknown_safe@1` with `view.reduction_error` populated (on error), reporting byte count, SHA-256 digest, UTF-8 validity, a strictly bounded sanitized preview (`<= ReductionBudget::max_preview_bytes`), and the `context_get` handle.

5. **Tiered Retention & Consistent Pruning:**
   - Workspaces enforce configurable storage quotas (default `512 MiB` max store size, `14 days` TTL) via `context-engine prune`.
   - Pruning deletes expired/over-quota artifacts transactionally across SQLite metadata, FTS5 chunks, journal references, and unreferenced content-addressed `.zst` blobs.

## Consequences

- **Positive:** Guarantees idempotent single-pass reduction, preserves 100% of actionable debugging anchors, coexists cleanly with Caveman/Headroom, and bounds worst-case output tokens even on binary/hostile streams.
- **Trade-off:** Deterministic parsers intentionally avoid semantic LLM paraphrasing in V1; prose-heavy documents rely on `unknown_safe@1` preview + `context_search` FTS5 retrieval rather than generative summarization.
