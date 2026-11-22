# ADR 0001: Artifact Identity, Server-Bound Scope, and Envelope Contract

- **Status:** Accepted
- **Date:** 2026-11-22
- **Deciders:** Rust Context Engine Architecture

## Context

Coding agents invoke MCP tools (`context_run`, `context_index`, `context_search`, `context_get`, `context_resume`) with arguments influenced by model reasoning and untrusted repository text. If artifact identifiers are sequential integers (`1, 2, 3`), raw file paths, or scoped only by a client-supplied `project_id` parameter, a prompt-injected or misconfigured agent could enumerate or retrieve captured outputs from unrelated workspaces or sessions. Furthermore, agents need a stable, versioned envelope that distinguishes exact byte capture metadata from derived UTF-8 reduced views.

## Decision

1. **Server-Bound `WorkspaceScopeId`:**
   - Each `context-engine` execution (`mcp --workspace <path>` or CLI invocation in a workspace) canonicalizes the workspace root once via `dunce::canonicalize` and computes a deterministic scope identifier: `ws_<first-32-hex-of-sha256(canonical_utf8_path)>`.
   - Client-supplied `project_id` or `workspace` fields inside MCP tool call payloads are **never** used to switch or widen scope; if supplied and mismatched, the request fails closed with `ScopeViolation`.

2. **Validated `SessionId`:**
   - Session identifiers (`SessionId`) are restricted to safe ASCII slugs (`[A-Za-z0-9._-]{1,128}`) and paired with `WorkspaceScopeId` on every SQLite query (`WHERE workspace_scope_id = ?1 AND session_id = ?2`).

3. **Opaque Server-Minted `ArtifactId` (`a_<64-hex-sha256>`):**
   - `ArtifactId` values are minted exclusively by the engine using SHA-256 over domain-separated inputs:
     `SHA256("context-engine:artifact:v1" || workspace_scope_id || session_id || captured_at_rfc3339 || nonce_or_seq || stdout_sha256 || stderr_sha256)`.
   - Every `ArtifactId` carries the `a_` prefix followed by 64 lowercase hexadecimal characters.
   - Resolving an `ArtifactId` in `context_get` or `context_resume` requires both syntactic validation (`^a_[0-9a-f]{64}$`) and an authoritative scope match against the bound `WorkspaceScopeId` (and `SessionId` where session-scoped).

4. **`ArtifactEnvelope` (`schema_version = 1`):**
   - Separates `source` (`Command` argv/cwd/exit_code/duration or `Document` path/media_type), `capture` (independent `stdout` and `stderr` SHA-256 digests, byte lengths, `complete`, `encoding`, `originals_available`, secret-redaction metadata), `view` (`ViewKind`, `reducer_version`, `omitted`, `safe_excerpt`, `transformations`, optional `reduction_error`), and `recovery` (`tool: "context_get"`, `artifact_id`, `bounded: true`, `max_bytes_per_call`).
   - Non-UTF-8 raw bytes are preserved verbatim in `context-store` (when policy permits) and remain retrievable by byte range (`ByteRange`), while UTF-8 line-range (`LineRange`) views are explicitly modeled as a derived representation.

## Consequences

- **Positive:** Eliminates ID guessing, cross-project artifact leakage, and ambiguity between exact captured bytes and lossy/reduced display views.
- **Positive:** Downstream crates (`context-store`, `context-reducers`, `context-search`, `context-journal`, `context-mcp`, `context-cli`) share a single strongly typed `serde` contract in `context-core`.
- **Trade-off:** Moving a workspace directory to a new absolute path produces a new `WorkspaceScopeId`, intentionally isolating historical state unless re-indexed in the new workspace.
