## Context Engine (`context-engine` MCP)

- Prefer `mcp__context-engine__context_run` (passing an explicit `argv` array, never `sh -c`) over `Bash` for noisy `cargo`, `rustc`, `pytest`, `jest`, `tsc`, `git diff/log/status`, `rg`, and JSON/log commands.
- Read the compact `ArtifactEnvelope` (`source.exit_code` + `view.safe_excerpt`) first. Do **not** re-run builds or tests to grep/slice output; query `mcp__context-engine__context_search` or `mcp__context-engine__context_get` with bounded `lines` or `bytes` ranges instead.
- Index large workspace log files with `mcp__context-engine__context_index` rather than reading multi-megabyte logs directly into context.
- Call `mcp__context-engine__context_resume` after context compaction or session resume to restore active failures and `artifact_id` handles.
- Coexistence: never double-compress outputs carrying `view.transformations`, `[context-engine:reduced`, `[headroom`, or `[caveman` markers, and never pass `.env*` or private keys to `context_index`.
