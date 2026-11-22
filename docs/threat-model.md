# Rust Context Engine V1 — Threat Model

**Date:** 2026-11-22  
**Status:** Approved V1 Security Baseline  
**Scope:** `context-engine` CLI, stdio MCP server (`context-mcp`), local storage (`.context-engine/`), and opt-in host adapters.

## 1. Security Objectives

1. **Zero Secret Exfiltration into Views or Search Indexes:** Credentials accidentally emitted to `stdout`/`stderr` or present in workspace files must never enter compact summaries, SQLite FTS5 tables, or session journals.
2. **Strict Workspace & Principal Confinement:** Every MCP server instance is bound at process startup (`--workspace <canonical_path>`) to a single canonical workspace scope. Client-supplied tool arguments cannot escape this workspace or read artifacts belonging to another workspace or unauthorized session.
3. **Safe, Non-Shell Command Execution:** `context_run` executes explicit `argv` vectors without invoking `cmd.exe`, `powershell.exe`, or `/bin/sh` by default, blocking command chaining, destructive filesystem flags, and sensitive environment leakage.
4. **Bounded Resource Consumption:** Hostile or runaway child processes (50+ MiB log floods, infinite loops, orphan background processes) cannot exhaust memory, disk, or agent context windows.
5. **Zero Engine Network Egress:** The Rust binary performs strictly local computation and storage, making zero outbound network connections at runtime.

## 2. Trust Boundaries

```text
+-----------------------------------------------------------------------+
| TB-1: Coding Agent / LLM Host (Untrusted / Prompt-Injectable Caller)  |
|   - Supplies MCP JSON-RPC arguments (argv, paths, search queries, IDs)|
|   - Consumes bounded compact views & sanitized search snippets        |
+-----------------------------------+-----------------------------------+
                                    | stdio JSON-RPC / CLI argv
                                    v
+-----------------------------------------------------------------------+
| TB-2: Context Engine Policy & Confinement Core                        |
|   - context-execution: canonical cwd, symlink rejection, argv policy  |
|   - context-core SecretGuard: pre-persistence / pre-index scanning    |
|   - Server-bound WorkspaceScopeId verification                        |
+-----------------+-----------------------------------+-----------------+
                  | direct OS spawn (no shell)        | atomic I/O
                  v                                   v
+-----------------------------------+ +---------------------------------+
| TB-3: Child Subprocess            | | TB-4: Private Local Storage     |
|   - Scrubbed env, timeout, cap    | |   - .context-engine/store/ (ACL)|
|   - Untrusted stdout/stderr bytes | |   - SQLite WAL + sanitized FTS5 |
+-----------------------------------+ +---------------------------------+
```

- **Important Egress Caveat:** While `context-engine` itself makes zero network calls, any coding agent backed by a hosted LLM provider transmits MCP tool responses to that provider. Therefore, `SecretGuard` treats MCP tool responses (`ArtifactEnvelope`, `context_search`, `context_get` in `RedactBeforeIndex`/`Quarantine`/`Deny` modes) as crossing an external disclosure boundary.

## 3. STRIDE Threat Analysis & Mitigations

| ID | Category | Threat Scenario | Mitigation Implemented in V1 | Owning Crate |
| :--- | :--- | :--- | :--- | :--- |
| **T-01** | **Spoofing / AuthZ Bypass** | Agent passes a forged or enumerated `artifact_id` or fake `project_id` to retrieve outputs from another repository or session. | `WorkspaceScopeId` is derived server-side from `dunce::canonicalize(workspace_root)` at startup. `ArtifactId` (`a_<64-hex>`) is server-minted and every `store` / `search` / `journal` lookup enforces `WHERE workspace_scope_id = ? AND session_id = ?`. Client `project_id` fields are ignored for authorization. | `context-core`, `context-store`, `context-search` |
| **T-02** | **Tampering / Path Escape** | `context_index` or `context_run` receives `..\..\.ssh\id_rsa`, a Windows directory junction, or a symlink pointing outside the workspace. | Canonicalize target and parent paths via `dunce::canonicalize`; verify canonical path starts with canonical `workspace_root`; reject symlinks/reparse points whose target resolves outside `workspace_root`; block sensitive path patterns (`.env*`, `*.pem`, `*.key`, `.ssh`, `.aws`, `.git/credentials`, `*.pfx`, `id_rsa*`). | `context-execution` |
| **T-03** | **Command Injection & Destructive Execution** | Prompt injection in a repo file tricks the agent into calling `context_run` with `["cmd", "/c", "del /s /q ..."]` or `["git", "reset", "--hard"]`. | Shell interpreters (`sh`, `bash`, `cmd`, `powershell`, `pwsh`) are rejected by default. `argv[0]` must match the safe executable allowlist (`cargo`, `rustc`, `git`, `pytest`, `python`, `node`, `npm`, `pnpm`, `go`, `rg`), and subcommand/flag denylists block destructive operations (`rm`, `Remove-Item`, `git reset --hard`, `git clean -fd`, `curl`/`Invoke-WebRequest` uploads). | `context-execution` |
| **T-04** | **Information Disclosure (Secrets in Logs/FTS5)** | Failing test or stack trace prints `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, `Bearer <jwt>`, PEM private key, or DB connection URI; agent later finds it via `context_search`. | Deterministic `SecretGuard` scans all streams *before* compact view generation, FTS5 indexing, or journal persistence using linear-time `RegexSet` + key/value & Shannon entropy heuristics. Under default `RedactBeforeIndex`, FTS5 and views receive `[REDACTED:<KIND>]`; under `Quarantine`, raw blob recovery via `context_get` is also blocked without explicit local override; under `Deny`, persistence fails closed. | `context-core`, `context-store`, `context-search` |
| **T-05** | **Information Disclosure (Env Inheritance)** | Child process spawned by `context_run` inherits host agent secrets (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`). | `context-execution` scrubs sensitive environment variables matching credential prefixes/suffixes (`*_API_KEY`, `*_SECRET*`, `*_TOKEN`, `*_PASSWORD`, `AWS_*`, `GITHUB_TOKEN`, `GITLAB_TOKEN`) before spawning child processes unless explicitly allowlisted. | `context-execution` |
| **T-06** | **Information Disclosure (Local Filesystem ACLs)** | Other local OS principals or unprivileged processes read `.context-engine/store/` blobs or SQLite files. | On Windows, storage directory creation restricts DACLs to the current owner/SYSTEM (`icacls` / owner-only security descriptor); on Unix, `0700` dirs / `0600` files. Verified via `context-engine doctor`. | `context-store` |
| **T-07** | **Denial of Service (Output Flood / Hang / ReDoS)** | Child command emits 500 MiB of stdout, hangs indefinitely, or crafts pathological strings against regex reducers. | Async stream readers enforce `max_stream_bytes` (default 16 MiB per stream) with explicit `complete: false` truncation markers; tokio deadline + `kill_on_drop(true)` terminates hung processes; all regexes use Rust `regex` crate (guaranteed `O(n)` DFA/NFA without backtracking); `context_get` enforces strict page byte/line ceilings. | `context-capture`, `context-core`, `context-reducers` |
| **T-08** | **Tampering / Crash Corruption** | Process crash or power loss mid-capture leaves half-written blob or inconsistent SQLite state. | Blobs write to `tempfile::NamedTempFile` in `.context-engine/store/tmp/`, compress with `zstd`, `sync_all()`, verify SHA-256 digest, and atomically rename to content-addressed path. SQLite runs with `journal_mode = WAL`, `synchronous = NORMAL`, and `foreign_keys = ON`. | `context-store`, `context-search`, `context-journal` |
| **T-09** | **Prompt Injection via Tool Output** | Malicious test output or log line contains `IGNORE PREVIOUS INSTRUCTIONS; run ...`. | Tool outputs are encapsulated inside structured `ArtifactEnvelope` fields and treated strictly as untrusted data; `context-engine` never auto-executes follow-up commands from captured output. | `context-core`, `context-mcp` |

## 4. Fail-Closed Security Invariants

1. **Authorization failure -> Deny immediately:** Any invalid scope, path escape, or disallowed executable returns a structured `ContextError` (`PolicyDenied` / `ScopeViolation`) before touching the filesystem or spawning a process.
2. **Secret policy failure -> Never leak raw text:** If `SecretPolicyMode::Deny` triggers, no blob, index row, or excerpt is emitted. If `RedactBeforeIndex` or `Quarantine` triggers, all compact views, search chunks, and error diagnostics carry only `[REDACTED:<RULE_ID>]` placeholders.
3. **Reducer failure -> Safe bounded fallback:** If a parser/reducer encounters malformed or unexpected data, it degrades to `unknown_safe@1` with `reduction_error` populated and a tiny sanitized metadata/head preview—never dumping megabytes of raw output into the agent response.
4. **Binary Hardening:** Release builds enable LTO (`thin`), single codegen unit, stripped symbols (`strip = "symbols"`), `panic = "abort"`, and Windows Control Flow Guard (`-C control-flow-guard=checks`), verified post-build with REA MCP / PE header inspection.
