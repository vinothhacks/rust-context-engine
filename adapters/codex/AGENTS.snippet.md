## Rust Context Engine (`context_engine` MCP)

When the `context_engine` MCP server is active in this repository:

1. **Prefer `context_run` for High-Volume Commands:** Use `context_run` (passing an explicit `argv` string array such as `["cargo", "test", "--workspace"]`, never `sh -c` or `powershell -Command`) instead of raw shell execution for `cargo`, `rustc`, `pytest`, `jest`, `tsc`, `go test`, `git status/diff/log`, `rg`, and verbose JSON/log commands.
2. **Read Compact `ArtifactEnvelope` Views First:** Inspect `source.exit_code`, `view.safe_excerpt`, `view.omitted`, and `capture.originals_available` before requesting raw output.
3. **Search & Slice Instead of Re-Running:** Never re-execute builds or test suites just to filter output with `head`, `tail`, or `grep`. Query `context_search` for ranked FTS5 excerpts or call `context_get` with bounded `lines` (`{"start": 1, "end": 80}`) or `bytes` (`{"start": 0, "end": 4096}`). Use `context_index` for large workspace log files.
4. **Session Continuity:** Call `context_resume` after context compaction or session resume to recover active failure identifiers and `artifact_id` handles.
5. **Single-Pass & Secret Safety:** Never re-index outputs carrying `view.transformations` or `[context-engine:reduced` markers, and never submit `.env*`, `*.pem`, `*.key`, `.ssh`, or `.aws` files to `context_index`.
