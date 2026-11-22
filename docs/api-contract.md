# Rust Context Engine V1 — API Contract (`CLI` & `MCP`)

**Version:** `0.1.0` (`schema_version: 1`)  
**Binary:** `context-engine` (`context-engine.exe` on Windows)  
**Transport:** Native CLI (`stdout`/`stderr` + exit codes) and Workspace-Scoped MCP JSON-RPC 2.0 over `stdio`

---

## 1. Core Architectural Invariants

1. **Server-Bound Workspace Authority (`WorkspaceScopeId`):**
   Every CLI invocation and `context-engine mcp --workspace <path>` server process canonicalizes its workspace root at startup via `dunce::canonicalize` and derives a deterministic `WorkspaceScopeId` (`ws_<32-lowercase-hex>`). Client-supplied arguments can narrow `session_id` within that workspace, but **never** override the bound workspace or read foreign artifacts.
2. **Opaque Server-Minted Artifact Identifiers (`ArtifactId`):**
   Captured command runs and indexed documents receive an opaque `a_<64-lowercase-hex>` identifier minted with domain-separated SHA-256 inputs bound to `(workspace_scope_id, session_id)`. Every manifest, SQLite FTS5 chunk, and journal lookup verifies `(workspace_scope_id, session_id)` before returning data.
3. **Exact Stream Separation & Integrity:**
   `stdout` and `stderr` are captured concurrently in bounded chunks, hashed with SHA-256 prior to compression, protected through `SecretGuard`, and persisted independently as content-addressed `zstd` frames under `.context-engine/store/blobs/`. Original non-UTF-8/binary bytes remain recoverable via half-open `--bytes start:end` ranges; UTF-8 line pagination (`--lines start:end`) is a separate derived view.
4. **Single-Pass Deterministic Reduction (`TransformationLedger`):**
   Each capture passes through at most one domain reducer (`cargo_test@1`, `pytest_jest@1`, `compiler_diag@1`, `git_reducer@1`, `structured_json@1`, `log_dedup@1`, `search_hits@1`, or `unknown_safe@1`) after optional `strip_ansi@1` / `secret_redact@1` preprocessing. Payloads already carrying `[context-engine:v1 ...]` banners or `ArtifactEnvelope` ledgers are never double-compressed.
5. **Pure `stdout` Discipline:**
   Optional `RUST_LOG` diagnostics default to `off` and write exclusively to `stderr` without ANSI codes, keeping `stdout` 100% pure for JSON-RPC 2.0 frames and `--json` CLI pipelines.

### Identifier & Budget Summary

| Parameter / Type | Pattern / Default | Ceiling / Constraint |
| :--- | :--- | :--- |
| `WorkspaceScopeId` | `^ws_[0-9a-f]{32}$` | Derived server-side from canonical workspace root |
| `SessionId` | `^[A-Za-z0-9._-]{1,128}$` | Default `"default"`; rejects `"."`, `".."`, leading `"-"` |
| `ArtifactId` | `^a_[0-9a-f]{64}$` | Minted server-side; verified against `(workspace, session)` |
| `CheckpointId` | `^cp_[0-9a-f]{32}$` | Deterministic continuity checkpoint identifier |
| `max_view_bytes` / `max_view_lines` | `4,096` bytes / `80` lines | Immediate `ArtifactView.safe_excerpt` ceiling |
| `max_failure_items` | `25` items (`12` trace lines each) | Inline failure cap before elision pointer |
| `max_preview_bytes` | `1,024` bytes | `unknown_safe@1` bounded head/tail preview |
| `max_get_lines` / `max_get_bytes` | `200` lines / `32,768` bytes (`32 KiB`) | Per-call `context_get` / `get` pagination cap |
| `max_search_results` / `snippet` | `20` hits (default `10`) / `512` bytes | Per-call `context_search` / `search` ceiling |
| `max_capture_stream_bytes` | `16,777,216` bytes (`16 MiB`) | Per-stream (`stdout` / `stderr` / `document`) capture cap |
| `max_workspace_store_bytes` | `536,870,912` bytes (`512 MiB`) | Per-workspace `.context-engine/store` quota |
| `retention_ttl_secs` | `1,209,600` s (`14` days) | Default artifact, FTS5, and journal retention TTL |

---

## 2. Canonical `ArtifactEnvelope` Specification (`v1`)

`context_run` / `context-engine run --json` and `context_index` / `context-engine index --json` return a validated `ArtifactEnvelope` (`schema_version: 1`).

### Field Reference

| Field | JSON Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `schema_version` | `integer` | Yes | Always `1` in V1 (`ARTIFACT_SCHEMA_VERSION`). |
| `artifact_id` | `string` | Yes | Opaque server-minted ID (`a_<64-hex>`). |
| `project_scope` | `string` | Yes | Server-bound workspace ID (`ws_<32-hex>`). |
| `session_id` | `string` | Yes | Validated session slug (`"default"` unless specified). |
| `source` | `object` | Yes | Tagged union (`"kind": "command"` or `"kind": "document"`). |
| `source.kind` | `string` | Yes | `"command"` or `"document"`. |
| `source.argv` | `string[]` | Command | Direct `argv` vector executed without shell interpolation. |
| `source.cwd_relative` | `string` | Command | Forward-slash path relative to workspace root (`"."` for root). |
| `source.exit_code` | `integer \| null` | Command | Child exit code (`null` if terminated by signal/timeout/cancel). |
| `source.duration_ms` | `integer` | Optional | Elapsed wall-clock execution duration in milliseconds. |
| `source.timed_out` | `boolean` | Optional | `true` when terminated due to timeout deadline. |
| `source.path_relative` | `string` | Optional | Workspace-relative path for file-backed `document` captures. |
| `source.label` | `string` | Optional | Sanitized provenance label (e.g., `"stdin"` or custom label). |
| `source.media_type` | `string` | Optional | Optional MIME hint (e.g., `"application/json"`). |
| `source.captured_at` | `string` | Yes | UTC timestamp in RFC 3339 millisecond format (`YYYY-MM-DDTHH:MM:SS.sssZ`). |
| `capture.stdout_sha256` | `string` | Yes | Raw `stdout` (or `document`) SHA-256 hex (`e3b0c442...` when `0` bytes). |
| `capture.stderr_sha256` | `string` | Yes | Raw `stderr` SHA-256 hex (`e3b0c442...` when `0` bytes or document). |
| `capture.stdout_bytes` | `integer` | Yes | Captured `stdout` (or `document`) byte count. |
| `capture.stderr_bytes` | `integer` | Yes | Captured `stderr` byte count (`0` for documents). |
| `capture.stdout_truncated` | `boolean` | When `true` | Present and `true` if `stdout` exceeded `max_capture_stream_bytes`. |
| `capture.stderr_truncated` | `boolean` | When `true` | Present and `true` if `stderr` exceeded `max_capture_stream_bytes`. |
| `capture.complete` | `boolean` | Yes | `true` iff no stream truncated and command was neither timed out nor cancelled. |
| `capture.encoding` | `string` | Yes | `"utf-8"`, `"utf-8-lossy"`, or `"binary"`. |
| `capture.originals_available` | `boolean` | Yes | `true` when `context_get` can serve stored content; `false` if quarantined. |
| `capture.secrets_redacted` | `integer` | When `> 0` | Count of secret spans redacted by `SecretGuard`. |
| `capture.secret_rule_ids` | `string[]` | When non-empty | Sorted distinct `SecretGuard` rule IDs triggered (never raw secret values). |
| `view.kind` | `string` | Yes | One of `test_summary`, `compiler_diagnostics`, `git_summary`, `structured_json`, `log_summary`, `search_hits`, `document_index`, `unknown_safe`, `passthrough`. |
| `view.reducer_version` | `string` | Yes | Reducer contract version (`"1"`). |
| `view.omitted` | `boolean` | Yes | `true` when raw content was compressed/elided relative to full stream bytes. |
| `view.safe_excerpt` | `string` | Yes | Bounded (`<= 4096` bytes, `<= 80` lines), secret-redacted summary text. |
| `view.transformations` | `string[]` | Yes | Ordered transformation ledger (e.g., `["strip_ansi@1", "cargo_test@1"]`). |
| `view.reduction_error` | `string` | Optional | Populated if a domain reducer degraded safely to `unknown_safe@1`. |
| `view.failure_identifiers` | `string[]` | When non-empty | Extracted failing test names or compiler diagnostic codes/locations. |
| `recovery.tool` | `string` | Yes | Always `"context_get"`. |
| `recovery.artifact_id` | `string` | Yes | Matches top-level `artifact_id`. |
| `recovery.bounded` | `boolean` | Yes | Always `true`. |
| `recovery.max_bytes_per_call` | `integer` | Optional | Byte ceiling per `context_get` call (`32768` when available). |
| `recovery.unavailable_reason` | `string` | Optional | Reason raw recovery is disabled (e.g., `"quarantined by workspace secret policy"`). |

### Example A: Command Capture (`cargo test` Failure)

```json
{
  "schema_version": 1,
  "artifact_id": "a_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "project_scope": "ws_4b227777d4dd1fc61c6f884f48641d02",
  "session_id": "default",
  "source": {
    "kind": "command",
    "argv": ["cargo", "test", "--workspace"],
    "cwd_relative": ".",
    "exit_code": 101,
    "duration_ms": 842,
    "captured_at": "2026-11-22T12:00:05.120Z"
  },
  "capture": {
    "stdout_sha256": "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
    "stderr_sha256": "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
    "stdout_bytes": 48210,
    "stderr_bytes": 612,
    "complete": true,
    "encoding": "utf-8",
    "originals_available": true
  },
  "view": {
    "kind": "test_summary",
    "reducer_version": "1",
    "omitted": true,
    "safe_excerpt": "cargo test: FAILED (exit 101) — 41 passed, 1 failed, 0 ignored\nFAIL auth::tests::verifies_token_signature @ crates/auth/src/lib.rs:88:9\n  assertion `left == right` failed: signature mismatch",
    "transformations": ["strip_ansi@1", "cargo_test@1"],
    "failure_identifiers": ["auth::tests::verifies_token_signature"]
  },
  "recovery": {
    "tool": "context_get",
    "artifact_id": "a_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "bounded": true,
    "max_bytes_per_call": 32768
  }
}
```

### Example B: Document Ingestion with `SecretGuard` Redaction

```json
{
  "schema_version": 1,
  "artifact_id": "a_3c59dc048e8850243be8079a5c74d07959a2feaa0c55ad015a3bf4f1b2b0b822",
  "project_scope": "ws_4b227777d4dd1fc61c6f884f48641d02",
  "session_id": "debug-prod-log",
  "source": {
    "kind": "document",
    "path_relative": "logs/worker.log",
    "label": "logs/worker.log",
    "captured_at": "2026-11-22T12:04:19.004Z"
  },
  "capture": {
    "stdout_sha256": "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
    "stderr_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "stdout_bytes": 19450,
    "stderr_bytes": 0,
    "complete": true,
    "encoding": "utf-8",
    "originals_available": true,
    "secrets_redacted": 1,
    "secret_rule_ids": ["GITHUB_TOKEN"]
  },
  "view": {
    "kind": "log_summary",
    "reducer_version": "1",
    "omitted": true,
    "safe_excerpt": "log_dedup: 312 lines -> 4 templates (INFO: 310, ERROR: 2)\nERROR 2026-11-22T12:00:01Z Upstream auth rejected token=[REDACTED:GITHUB_TOKEN] code=DB_POOL_99",
    "transformations": ["secret_redact@1", "log_dedup@1"]
  },
  "recovery": {
    "tool": "context_get",
    "artifact_id": "a_3c59dc048e8850243be8079a5c74d07959a2feaa0c55ad015a3bf4f1b2b0b822",
    "bounded": true,
    "max_bytes_per_call": 32768
  }
}
```

---

## 3. CLI Reference (`context-engine`)

### Global Resolution & Environment Variables

| Variable | Effect |
| :--- | :--- |
| `CONTEXT_ENGINE_WORKSPACE` | Fallback workspace directory when `--workspace <PATH>` is omitted (otherwise `std::env::current_dir()`). |
| `CONTEXT_ENGINE_SESSION` | Fallback session slug when `--session <ID>` is omitted (otherwise `"default"`). |
| `RUST_LOG` | Optional `tracing` filter (`off` by default); emitted strictly to `stderr` without ANSI escapes. |

### Subcommands & Flags

#### 1. `context-engine run`
Execute an allowlisted command directly via `argv` (zero shell interpolation), store exact `stdout`/`stderr` streams, index sanitized chunks in SQLite FTS5, and print either a compact banner+excerpt view or full `ArtifactEnvelope` JSON.

```text
context-engine run [OPTIONS] -- <ARGV>...
```

- `--workspace <PATH>`: Target workspace root.
- `--session <ID>`: Session identifier (`[A-Za-z0-9._-]{1,128}`).
- `--cwd <REL_PATH>`: Confined working directory inside `--workspace`.
- `--timeout-ms <MS>`: Wall-clock deadline (`1..=600000`, default `120000`).
- `--json`: Emit pretty-printed `ArtifactEnvelope` JSON instead of compact text banner.
- `--no-exit-code-passthrough`: Exit `0` after capturing even if the child process exits non-zero.
- `-- <ARGV>...`: Required direct executable name and arguments (e.g., `-- cargo test --workspace`).

#### 2. `context-engine index`
Ingest a confined workspace file or bounded `--stdin` stream through `SecretGuard` into `.context-engine/store` and SQLite FTS5.

```text
context-engine index [OPTIONS] [FILE_PATH]
```

- `<FILE_PATH>`: Workspace-confined file path (mutually exclusive with `--stdin`).
- `--stdin`: Read up to `max_capture_stream_bytes` from standard input (defaults `--label` to `"stdin"`).
- `--label <LABEL>`: Provenance label stored with the artifact.
- `--media-type <MIME>`: Optional MIME media type hint (e.g., `application/json`, `text/plain`).
- `--workspace <PATH>` / `--session <ID>` / `--json`.

#### 3. `context-engine search`
Run a `bm25()`-ranked SQLite FTS5 (`porter unicode61`) lexical query over sanitized chunks in the bound workspace.

```text
context-engine search [OPTIONS] <QUERY>
```

- `<QUERY>`: Lexical search keywords, symbol, test name, or error code.
- `--all-sessions`: Search across every session in the bound workspace (default searches active session only).
- `--limit <N>`: Maximum hits (`1..=20`, default `10`).
- `--workspace <PATH>` / `--session <ID>` / `--json`.

#### 4. `context-engine get`
Recover an exact byte range or derived 1-indexed line slice from `.context-engine/store` without re-executing commands.

```text
context-engine get [OPTIONS] <ARTIFACT_ID>
```

- `<ARTIFACT_ID>`: Opaque `a_<64-hex>` handle.
- `--stream <STREAM>`: `stdout`, `stderr`, `combined`, or `document` (auto-selected when omitted: `document` for indexed files, `stderr` if `stdout` is empty and `stderr` is non-empty, else `stdout`).
- `--lines <START:END>`: 1-indexed inclusive line window (max `200` lines; mutually exclusive with `--bytes`).
- `--bytes <START:END>`: Half-open byte range `[start, end)` (max `32768` bytes; mutually exclusive with `--lines`). Defaults to `1:80` lines for UTF-8 streams or `0:4096` bytes for binary streams when both are omitted.
- `--workspace <PATH>` / `--session <ID>` / `--json`.

#### 5. `context-engine resume`
Restore deterministic session continuity state (`ResumePack`) and optionally persist a new `SessionCheckpoint`.

```text
context-engine resume [OPTIONS]
```

- `--checkpoint`: Persist a new `cp_<32-hex>` checkpoint before returning the `ResumePack`.
- `--note <TEXT>`: Optional sanitized note attached to the checkpoint.
- `--workspace <PATH>` / `--session <ID>` / `--json`.

#### 6. `context-engine stats`
Report non-sensitive session or workspace telemetry (raw vs compact view vs retrieved bytes/tokens, net savings ratios, cache deduplication hits, secrets redacted, security denials, and blob-store footprint).

```text
context-engine stats [OPTIONS]
```

- `--all-sessions`: Aggregate telemetry across all sessions in the bound workspace.
- `--workspace <PATH>` / `--session <ID>` / `--json`.

#### 7. `context-engine prune`
Enforce TTL expiry and LRU byte-quota eviction consistently across `BlobStore`, `SearchIndex`, and `SessionJournal` (manifests removed before unreferenced `.zst` blobs).

```text
context-engine prune [OPTIONS]
```

- `--ttl-secs <SECS>`: Retention TTL override in seconds (defaults to `1209600` [14 days] when neither flag is given).
- `--max-bytes <BYTES>`: Workspace store byte ceiling override (defaults to `536870912` [512 MiB] when neither flag is given).
- `--workspace <PATH>` / `--json`.

#### 8. `context-engine doctor`
Run read-only health verification over workspace confinement, private `.context-engine/store` ACLs (`icacls` DACL on Windows / `0700` on Unix), SQLite WAL + `PRAGMA quick_check(1)` + FTS5 `'integrity-check'`, execution policy, and `SecretGuard` policy.

```text
context-engine doctor [--workspace <PATH>] [--json]
```

#### 9. `context-engine mcp`
Start the workspace-bound JSON-RPC 2.0 MCP server over `stdin`/`stdout`.

```text
context-engine mcp --workspace <PATH> [--session <ID>]
```

#### 10. `context-engine setup`
Render or install opt-in, project-scoped integration kits from embedded `adapters/` templates. Unconditionally refuses global user config directories (`~/.cursor`, `~/.claude`, `~/.codex`, `~/.config/opencode`, `%APPDATA%`, `$HOME`).

```text
context-engine setup --client <TARGET> [OPTIONS]
```

- `--client <TARGET>`: `cursor`, `claude-code` (alias `claude`), `opencode`, `codex`, `generic-mcp` (aliases `generic`, `windsurf`, `cline`, `continue`, `zed`, `roo-code`), or `all`.
- `--workspace <PATH>`: Project workspace path bound into `{{WORKSPACE_PATH}}`.
- `--binary <PATH>`: Explicit binary path bound into `{{BINARY_PATH}}` (defaults to `std::env::current_exe()`).
- `--output-dir <DIR>`: Write rendered files into `<DIR>` instead of `<workspace>`.
- `--write-project`: Opt in to writing/merging rendered files into `<workspace>` (preserves existing unrelated `mcpServers` entries).
- `--dry-run`: Preview rendered files without touching disk (default whenever neither `--output-dir` nor `--write-project` is passed).
- `--json`: Emit `SetupReport` JSON.

### CLI Exit Codes

| Exit Code | Symbolic Name | Condition |
| :--- | :--- | :--- |
| `0` | `EX_OK` | Command succeeded (`doctor` healthy, or `run --no-exit-code-passthrough`). |
| `<N>` | Child Exit Status | `context-engine run` forwards the child process exit code (e.g., `101` on `cargo test` failure). |
| `1` | General Error | Storage/SQLite/I/O error, `doctor` reported `healthy: false`, or child terminated without code. |
| `64` | `EX_USAGE` | `INVALID_CONFIG`, `INVALID_RANGE`, `INVALID_SESSION_ID`, or `INVALID_ARTIFACT_ID`. |
| `66` | `EX_NOINPUT` | `INVALID_WORKSPACE_PATH` or `ARTIFACT_NOT_FOUND`. |
| `77` | `EX_NOPERM` | Security boundary denial (`SCOPE_VIOLATION`, `SESSION_MISMATCH`, `PATH_ESCAPE`, `SENSITIVE_PATH_BLOCKED`, `EXECUTION_DENIED`, `SECRET_POLICY_DENIED`, `SECRET_QUARANTINED`). |
| `124` | Timeout | `EXECUTION_TIMEOUT` or child process exceeded `--timeout-ms`. |
| `130` | Cancelled | Cooperative cancellation (`SIGINT` / cancel token). |

---

## 4. MCP Stdio Protocol & Framing Modes (`context-mcp`)

### Wire Framing Auto-Detection (`FramingMode`)

`context-mcp` inspects each inbound frame on `stdin` and echoes its response using the exact same framing mode:

1. **Newline-Delimited JSON-RPC (`FramingMode::NewlineDelimited` — Official MCP Stdio Default):**
   One UTF-8 JSON object (or non-empty batch array) terminated by `\n` (`\r\n` accepted on input; `\n` emitted on `stdout`). Blank whitespace-only lines between messages are ignored.
2. **LSP `Content-Length` Framing (`FramingMode::ContentLength`):**
   Auto-detected whenever an inbound header line begins (case-insensitively) with `Content-Length: <bytes>\r\n`, followed by up to 16 optional HTTP-style header lines and `\r\n\r\n<utf8-json-body>`. Replies are framed identically as:
   ```http
   Content-Length: 214\r\n\r\n{"jsonrpc":"2.0","id":1,"result":{...}}
   ```

### Protocol Limits & Methods

- **Protocol Version Negotiation:** Supports `"2024-11-05"` (default fallback), `"2025-03-26"`, and `"2025-06-18"`.
- **Frame & Output Ceilings:** `MAX_RPC_FRAME_BYTES = 18,874,368` (`18 MiB`); `MAX_MCP_TOOL_OUTPUT_BYTES = 98,304` (`96 KiB` per `CallToolResult`).
- **Supported JSON-RPC Methods:**
  - `initialize` -> returns negotiated `protocolVersion`, `capabilities: { "tools": { "listChanged": false } }`, `serverInfo`, and compact-first `instructions`.
  - `notifications/initialized` (or `initialized`) -> acknowledged silently (no response frame).
  - `ping` -> returns `{}`.
  - `tools/list` -> returns the 7 tool descriptors, every one enforcing `"additionalProperties": false`.
  - `tools/call` -> spawned asynchronously onto a Tokio `JoinSet` so long-running `context_run` calls can be aborted mid-flight via `notifications/cancelled` (or `$/cancelRequest`) carrying `{ "requestId": <id> }`.

### Error Semantics: Protocol Errors vs Domain `isError: true`

1. **JSON-RPC Protocol / Schema Errors (`error` envelope):**
   Malformed JSON (`-32700`), invalid JSON-RPC envelopes (`-32600`), unknown methods (`-32601`), and unknown tools, missing required arguments, wrong JSON types, or unknown properties violating `additionalProperties: false` (`-32602`) return a standard JSON-RPC error response:
   ```json
   {
     "jsonrpc": "2.0",
     "id": 9,
     "error": {
       "code": -32602,
       "message": "Invalid params for 'context_run': unknown property 'shell' (additionalProperties: false)",
       "data": {
         "error_code": "INVALID_PARAMS",
         "tool": "context_run",
         "reason": "unknown property 'shell' (additionalProperties: false)"
       }
     }
   }
   ```
2. **Domain, Policy & Security Denials (`CallToolResult` with `isError: true`):**
   Command policy denials, path escapes, blocked `.env` reads, forged cross-workspace `artifact_id` lookups, timeouts, and storage errors return a valid `CallToolResult` (`isError: true`) containing a `SecretGuard`-redacted `ToolErrorPayload` JSON string (max `2048` UTF-8 bytes) without dropping the stdio transport:
   ```json
   {
     "jsonrpc": "2.0",
     "id": 10,
     "result": {
       "content": [
         {
           "type": "text",
           "text": "{\"error_code\":\"EXECUTION_DENIED\",\"message\":\"command execution denied for 'cmd': shell interpreters are disabled by execution policy\",\"security_denial\":true}"
         }
       ],
       "isError": true
     }
   }
   ```

### Machine-Readable `error_code` Catalog

| `error_code` | `security_denial` | Meaning |
| :--- | :--- | :--- |
| `SCOPE_VIOLATION` | `true` | Cross-workspace `artifact_id` access, client `project_scope` override, or forbidden global `setup` target. |
| `SESSION_MISMATCH` | `true` | `artifact_id` belongs to a different `session_id` than the caller's active session. |
| `PATH_ESCAPE` | `true` | `..` traversal, symlink, Windows NTFS junction, or TOCTOU swap escaping `workspace_root`. |
| `SENSITIVE_PATH_BLOCKED` | `true` | Attempted access to `.env*`, `*.pem`, `*.key`, `*.pfx`, `.ssh/`, `.aws/`, `.git/credentials`, `id_rsa*`, etc. |
| `EXECUTION_DENIED` | `true` | Shell interpreter (`cmd`, `powershell`, `sh`, `bash`), non-allowlisted binary, path in `argv[0]`, or destructive flags (`git reset --hard`, `git clean -fdx`, `-Recurse -Force`, network uploads). |
| `SECRET_POLICY_DENIED` | `true` | Secret detected while workspace operates in fail-closed `SecretPolicyMode::Deny`. |
| `SECRET_QUARANTINED` | `true` | `context_get` requested raw bytes from a stream quarantined by `SecretPolicy`. |
| `EXECUTION_TIMEOUT` | `false` | Child process exceeded `timeout_ms` and was terminated. |
| `INVALID_WORKSPACE_PATH` | `false` | Non-existent or non-directory workspace/`cwd` path, or non-regular file for `index`. |
| `INVALID_SESSION_ID` | `false` | Session ID failed `[A-Za-z0-9._-]{1,128}` validation. |
| `INVALID_ARTIFACT_ID` | `false` | Artifact ID failed `^a_[0-9a-f]{64}$` syntax validation. |
| `ARTIFACT_NOT_FOUND` | `false` | Valid `a_<64-hex>` ID is not present in `.context-engine/store/manifests/`. |
| `INVALID_RANGE` | `false` | Malformed `lines` (`0`-indexed or `end < start`) or `bytes` (`end < start`) range. |
| `BUDGET_EXCEEDED` | `false` | Requested `lines` (`> 200`), `bytes` (`> 32768`), `limit` (`> 20`), `timeout_ms` (`> 600000`), or MCP `96 KiB` ceiling exceeded. |
| `INTEGRITY_MISMATCH` | `false` | Stored `zstd` blob SHA-256 or manifest scope-binding hash failed verification. |
| `INVALID_CONFIG` | `false` | Conflicting CLI/config flags or invalid stream selector. |
| `STORAGE_ERROR` / `SEARCH_ERROR` / `JOURNAL_ERROR` / `REDUCTION_ERROR` / `PROTOCOL_ERROR` / `SERIALIZATION_ERROR` / `IO_ERROR` | `false` | Subsystem runtime failure; fails safely without exposing raw unredacted payloads. |

---

## 5. Complete MCP Tool Specifications (All 7 Tools)

Every MCP tool returns its structured payload serialized as JSON inside `result.content[0].text` (`"type": "text"`).

### 5.1 `context_run`

Execute an allowlisted command directly via `argv` inside the server-bound workspace, persist exact `stdout`/`stderr` blobs, index sanitized text in FTS5, and return a v1 `ArtifactEnvelope`.

- **Input Schema (`additionalProperties: false`):**
  - `argv` (`string[]`, **required**, `1..=256` items, each `1..=16384` bytes): Direct `argv` array (`argv[0]` bare program name on allowlist).
  - `cwd` (`string`, optional, `1..=4096` bytes): Confined relative subdirectory inside bound workspace.
  - `timeout_ms` (`integer`, optional, `1..=600000`, default `120000`): Wall-clock timeout in milliseconds.
  - `session_id` (`string`, optional, `^[A-Za-z0-9._-]{1,128}$`): Session override within bound workspace.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "context_run",
    "arguments": {
      "argv": ["cargo", "check", "--all-targets"],
      "timeout_ms": 120000,
      "session_id": "refactor-auth"
    }
  }
}
```

**Response (`result.content[0].text` decoded):** Returns `ArtifactEnvelope` (see [Section 2](#2-canonical-artifactenvelope-specification-v1)). Note that a non-zero child `exit_code` (such as `101` from `cargo test`) is a **successful capture** (`isError: false`) with `source.exit_code: 101` and `view.failure_identifiers` populated.

---

### 5.2 `context_index`

Ingest either a workspace-confined file (`path`) or inline UTF-8 text (`content` + `label`) into `.context-engine/store` and SQLite FTS5, returning an `ArtifactEnvelope`.

- **Input Schema (`additionalProperties: false`):**
  - `path` (`string`, optional, `1..=4096` bytes): Confined workspace file path (mutually exclusive with `content`).
  - `content` (`string`, optional, `0..=16777216` bytes): Inline UTF-8 payload (mutually exclusive with `path`; requires `label`).
  - `label` (`string`, optional for `path`, **required** for `content`, `1..=256` bytes): Provenance label.
  - `media_type` (`string`, optional, `1..=128` bytes): Optional MIME hint (e.g., `"application/json"`).
  - `session_id` (`string`, optional): Session slug.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "context_index",
    "arguments": {
      "path": "docs/threat-model.md",
      "session_id": "refactor-auth"
    }
  }
}
```

**Response (`result.content[0].text` decoded):** Returns `ArtifactEnvelope` (`source.kind == "document"`).

---

### 5.3 `context_search`

Search sanitized SQLite FTS5 chunks (`porter unicode61` tokenizer, `bm25()` ranked) within the bound workspace, returning bounded snippets, 1-indexed line spans, and `context_get` handles. Untrusted punctuation, FTS operators, and column prefixes are safely tokenized so arbitrary error strings never trigger SQL/FTS syntax errors.

- **Input Schema (`additionalProperties: false`):**
  - `query` (`string`, **required**, `1..=2048` bytes): Lexical search terms, symbol, or diagnostic code.
  - `session_only` (`boolean`, optional, default `true`): Restrict search to `session_id` (`false` searches all sessions in bound workspace).
  - `limit` (`integer`, optional, `1..=20`, default `10`): Maximum hits returned.
  - `session_id` (`string`, optional): Session slug.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "context_search",
    "arguments": {
      "query": "verifies_token_signature signature mismatch",
      "session_only": true,
      "limit": 5,
      "session_id": "refactor-auth"
    }
  }
}
```

**Response (`result.content[0].text` decoded — `SearchQueryOutcome`):**
```json
{
  "workspace_scope_id": "ws_4b227777d4dd1fc61c6f884f48641d02",
  "session_id": "refactor-auth",
  "session_only": true,
  "query": "verifies_token_signature signature mismatch",
  "hit_count": 1,
  "hits": [
    {
      "rank": 1,
      "score": 4.812,
      "raw_bm25": -4.812,
      "artifact_id": "a_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "session_id": "refactor-auth",
      "stream": "stdout",
      "source_label": "cargo test --workspace",
      "line_start": 41,
      "line_end": 72,
      "line_range": {
        "start_line": 41,
        "end_line": 72
      },
      "snippet": "---- auth::tests::verifies_token_signature stdout ----\nthread 'auth::tests::verifies_token_signature' panicked at crates/auth/src/lib.rs:88:9:\nassertion `left == right` failed: signature mismatch",
      "recovery": {
        "tool": "context_get",
        "artifact_id": "a_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "bounded": true,
        "max_bytes_per_call": 32768
      }
    }
  ]
}
```

---

### 5.4 `context_get`

Recover a bounded original slice from `.context-engine/store` (verifying `zstd` frame integrity and SHA-256) by 1-indexed inclusive `lines` range or half-open `bytes` range without re-running commands.

- **Input Schema (`additionalProperties: false`):**
  - `artifact_id` (`string`, **required**, `^a_[0-9a-f]{64}$`): Target artifact identifier.
  - `stream` (`string`, optional, enum `["stdout", "stderr", "combined", "document"]`): Target stream (auto-selected when omitted).
  - `lines` (optional, mutually exclusive with `bytes`): Either `"start:end"` (e.g., `"41:72"`) or `{"start": 41, "end": 72}` (1-indexed inclusive, max `200` lines).
  - `bytes` (optional, mutually exclusive with `lines`): Either `"start:end"` (e.g., `"0:4096"`) or `{"start": 0, "end": 4096}` (0-indexed half-open `[start, end)`, max `32768` bytes).
  - `session_id` (`string`, optional): Must match the session that owns `artifact_id`.

**Line-Mode Request & Response (`mode: "lines"`):**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "context_get",
    "arguments": {
      "artifact_id": "a_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "stream": "stdout",
      "lines": { "start": 41, "end": 45 },
      "session_id": "refactor-auth"
    }
  }
}
```
```json
{
  "mode": "lines",
  "artifact_id": "a_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "stream": "stdout",
  "sha256": "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
  "encoding": "utf-8",
  "exact_raw_preserved": true,
  "total_bytes": 48210,
  "total_lines": 914,
  "returned_range": { "start_line": 41, "end_line": 45 },
  "has_more": true,
  "byte_budget_truncated": false,
  "lines": [
    { "line_number": 41, "content": "---- auth::tests::verifies_token_signature stdout ----" },
    { "line_number": 42, "content": "thread 'auth::tests::verifies_token_signature' panicked at crates/auth/src/lib.rs:88:9:" },
    { "line_number": 43, "content": "assertion `left == right` failed: signature mismatch" },
    { "line_number": 44, "content": "  left: \"hmac_v1_bad\"" },
    { "line_number": 45, "content": " right: \"hmac_v1_ok\"" }
  ],
  "text": "---- auth::tests::verifies_token_signature stdout ----\nthread 'auth::tests::verifies_token_signature' panicked at crates/auth/src/lib.rs:88:9:\nassertion `left == right` failed: signature mismatch\n  left: \"hmac_v1_bad\"\n right: \"hmac_v1_ok\""
}
```

**Byte-Mode Request & Response (`mode: "bytes"` — Binary & Exact Offset Safe):**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "context_get",
    "arguments": {
      "artifact_id": "a_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "stream": "stderr",
      "bytes": "0:64",
      "session_id": "refactor-auth"
    }
  }
}
```
```json
{
  "mode": "bytes",
  "artifact_id": "a_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "stream": "stderr",
  "sha256": "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
  "encoding": "utf-8",
  "exact_raw_preserved": true,
  "total_bytes": 40,
  "total_lines": 1,
  "returned_range": { "start": 0, "end": 40 },
  "byte_length": 40,
  "has_more": false,
  "utf8_text": "error: test failed, to rerun pass `--lib`\n",
  "base64_bytes": "ZXJyb3I6IHRlc3QgZmFpbGVkLCB0byByZXJ1biBwYXNzIGAtLWxpYmAK"
}
```

---

### 5.5 `context_resume`

Restore deterministic session continuity (`ResumePack`) after context window compaction or agent restart, optionally persisting a new `SessionCheckpoint` first. Tracks unresolved failure identifiers (clearing them automatically once a subsequent run of the same check family succeeds).

- **Input Schema (`additionalProperties: false`):**
  - `session_id` (`string`, optional): Session slug.
  - `create_checkpoint` (`boolean`, optional, default `false`): Persist a new `cp_<32-hex>` checkpoint before returning.
  - `note` (`string`, optional, `0..=1024` bytes): Sanitized checkpoint note.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "context_resume",
    "arguments": {
      "session_id": "refactor-auth",
      "create_checkpoint": true,
      "note": "Isolated HMAC mismatch in crates/auth/src/lib.rs:88"
    }
  }
}
```

**Response (`result.content[0].text` decoded — `ResumePack`):**
```json
{
  "workspace_scope_id": "ws_4b227777d4dd1fc61c6f884f48641d02",
  "session_id": "refactor-auth",
  "resumed_at": "2026-11-22T12:06:00.250Z",
  "latest_checkpoint": {
    "checkpoint_id": "cp_81e9b2f04d7c11aa9023cc418802ef91",
    "workspace_scope_id": "ws_4b227777d4dd1fc61c6f884f48641d02",
    "session_id": "refactor-auth",
    "up_to_event_seq": 4,
    "created_at": "2026-11-22T12:06:00.248Z",
    "note": "Isolated HMAC mismatch in crates/auth/src/lib.rs:88",
    "recent_commands": [
      {
        "event_seq": 1,
        "recorded_at": "2026-11-22T12:00:05.125Z",
        "command_summary": "cargo test --workspace",
        "exit_code": 101,
        "reducer_id": "cargo_test@1",
        "artifact_id": "a_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "failure_count": 1,
        "latency_ms": 845
      }
    ],
    "unresolved_failures": ["auth::tests::verifies_token_signature"],
    "active_artifacts": [
      {
        "artifact_id": "a_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "event_kind": "command_captured",
        "label": "cargo test --workspace",
        "reducer_id": "cargo_test@1",
        "exit_code": 101,
        "recorded_at": "2026-11-22T12:00:05.125Z",
        "has_failures": true,
        "recovery": {
          "tool": "context_get",
          "artifact_id": "a_9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
          "bounded": true,
          "max_bytes_per_call": 32768
        }
      }
    ],
    "stats": { "...": "SessionStats snapshot" }
  },
  "events_since_checkpoint": 0,
  "recent_commands": [ /* RecentCommandRecord[] */ ],
  "unresolved_failures": ["auth::tests::verifies_token_signature"],
  "active_artifacts": [ /* ActiveArtifactHandle[] */ ],
  "stats": { /* live SessionStats */ }
}
```

---

### 5.6 `context_stats`

Return honest session or workspace accounting metrics, explicitly charging follow-up `context_search` snippet bytes and `context_get` retrieved bytes against raw captured bytes (`exposed_bytes = view_bytes + retrieved_bytes`, signed `net_saved_bytes = raw_bytes - exposed_bytes`).

- **Input Schema (`additionalProperties: false`):**
  - `session_id` (`string`, optional): Session slug.
  - `all_sessions` (`boolean`, optional, default `false`): Aggregate across all sessions in the bound workspace.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "context_stats",
    "arguments": {
      "all_sessions": false,
      "session_id": "refactor-auth"
    }
  }
}
```

**Response (`result.content[0].text` decoded — `EngineStatsReport`):**
```json
{
  "workspace_scope_id": "ws_4b227777d4dd1fc61c6f884f48641d02",
  "session_id": "refactor-auth",
  "distinct_sessions": 1,
  "total_events": 4,
  "total_captures": 2,
  "command_captures": 1,
  "document_indexes": 1,
  "search_queries": 1,
  "retrieval_calls": 1,
  "checkpoints_created": 1,
  "cache_dedup_hits": 0,
  "security_denials": 0,
  "secrets_redacted_total": 1,
  "raw_bytes": 68272,
  "view_bytes": 384,
  "retrieved_bytes": 462,
  "exposed_bytes": 846,
  "net_saved_bytes": 67426,
  "estimated_raw_tokens": 17068,
  "estimated_view_tokens": 96,
  "estimated_retrieved_tokens": 116,
  "estimated_exposed_tokens": 212,
  "estimated_net_saved_tokens": 16856,
  "view_reduction_ratio": 0.9943754394,
  "net_byte_savings_ratio": 0.9876083899,
  "net_token_savings_ratio": 0.9875790954,
  "retrieval_overhead_ratio": 0.0067670494,
  "token_retrieval_overhead_ratio": 0.0067963440,
  "store": {
    "artifact_count": 2,
    "blob_count": 3,
    "manifest_bytes": 3412,
    "compressed_blob_bytes": 9840,
    "total_store_bytes": 13252
  }
}
```

---

### 5.7 `context_doctor`

Run a read-only health audit over the bound workspace, private `.context-engine/store` ACLs, SQLite WAL + FTS5 integrity, session journal integrity, command allowlist policy, and `SecretGuard` policy.

- **Input Schema (`additionalProperties: false`):** `{}` (accepts zero properties).

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "tools/call",
  "params": {
    "name": "context_doctor",
    "arguments": {}
  }
}
```

**Response (`result.content[0].text` decoded — `DoctorReport`):**
```json
{
  "healthy": true,
  "engine_version": "0.1.0",
  "schema_version": 1,
  "workspace_root": "D:\\projects\\my-app",
  "workspace_scope_id": "ws_4b227777d4dd1fc61c6f884f48641d02",
  "session_id": "default",
  "store_permissions": {
    "store_dir": "D:\\projects\\my-app\\.context-engine\\store",
    "exists": true,
    "private_only": true,
    "platform_mechanism": "windows_icacls_dacl",
    "principal": "sm2063",
    "details": "DOMAIN\\sm2063:(OI)(CI)(F)"
  },
  "store_stats": {
    "artifact_count": 0,
    "blob_count": 0,
    "manifest_bytes": 0,
    "compressed_blob_bytes": 0,
    "total_store_bytes": 0
  },
  "search_health": {
    "healthy": true,
    "journal_mode": "wal",
    "foreign_keys_enabled": true,
    "schema_version": 1,
    "quick_check_ok": true,
    "fts_integrity_ok": true,
    "total_artifacts": 0,
    "total_chunks": 0,
    "db_size_bytes": 36864
  },
  "journal_health": {
    "healthy": true,
    "journal_mode": "wal",
    "foreign_keys_enabled": true,
    "schema_version": 1,
    "quick_check_ok": true,
    "total_events": 0,
    "total_checkpoints": 0,
    "db_size_bytes": 36864
  },
  "execution_policy": {
    "allow_shell": false,
    "allow_network_uploads": false,
    "allowed_programs": [
      "cargo", "rustc", "rustup", "git", "pytest", "python", "python3",
      "node", "npm", "npx", "pnpm", "yarn", "tsc", "go", "rg",
      "dotnet", "mvn", "gradle"
    ],
    "blocked_programs_count": 19,
    "preserved_env_keys_count": 29,
    "default_timeout_ms": 120000,
    "max_timeout_ms": 600000,
    "max_stream_bytes": 16777216
  },
  "secret_policy": {
    "mode": "redact_before_index",
    "enable_entropy_detection": true,
    "entropy_min_length": 28,
    "allow_raw_blob_when_redacted": false
  },
  "budget": {
    "max_view_bytes": 4096,
    "max_view_lines": 80,
    "max_failure_items": 25,
    "max_trace_lines_per_failure": 12,
    "max_preview_bytes": 1024,
    "max_get_bytes": 32768,
    "max_get_lines": 200,
    "max_search_results": 20,
    "max_search_snippet_bytes": 512,
    "max_capture_stream_bytes": 16777216,
    "max_workspace_store_bytes": 536870912,
    "retention_ttl_secs": 1209600
  }
}
```
