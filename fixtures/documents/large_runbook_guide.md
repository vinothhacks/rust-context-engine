# Rust Context Engine Production Operations & Incident Runbook

## 1. Purpose and Isolation Model

The Rust Context Engine operates strictly inside a single bound local workspace root
(`--workspace <canonical_path>`). Every captured command stream (`stdout`, `stderr`) and
indexed document is bound to `(workspace_scope_id, session_id)` at ingest time.

Key operational invariants:
- No remote LLM calls, vector database uploads, or telemetry beacons are ever emitted.
- All MCP communication flows over standard input/output (`stdio`) using either official
  newline-delimited JSON-RPC 2.0 or auto-detected `Content-Length:` headers.
- Raw streams are compressed with Zstandard (`zstd` level 3) and stored under
  `<workspace>/.context-engine/store/blobs/<2-hex>/<sha256>.zst`.
- Derived lexical search chunks and continuity events live inside
  `<workspace>/.context-engine/index.db` under SQLite Write-Ahead Logging (`WAL`).

---

## 2. Routine Diagnostics (`context-engine doctor`)

Before escalating any workspace incident, run the read-only health check:

```powershell
context-engine doctor --workspace "D:\project" --json
```

Verify the following fields in the returned `DoctorReport`:
1. `healthy == true` — composite status across ACLs, SQLite WAL, FTS5, and journal tables.
2. `store_permissions.private_only == true` — confirms Windows DACL (`icacls`) restricts
   `.context-engine/store` exclusively to the current OS owner SID with inheritance removed.
3. `search_health.journal_mode == "wal"` and `search_health.fts_integrity_ok == true` —
   confirms FTS5 virtual table shadow indexes match `search_chunks` row-for-row.
4. `execution_policy.allow_shell == false` — ensures `cmd`, `powershell`, `pwsh`, and `bash`
   interpreters remain disabled.
5. `secret_policy.mode == "redact_before_index"` — confirms `SecretGuard` scrubs credentials
   prior to compact view rendering, SQLite FTS5 indexing, and journal persistence.

---

## 3. WAL Checkpoint Recovery

Under sustained parallel agent load (for example, multiple terminal hooks indexing outputs
concurrently while an MCP client runs `context_search`), SQLite WAL files (`index.db-wal`)
can grow between passive checkpoints.

Symptoms:
- `index.db-wal` exceeds `32 MiB` on disk.
- `SQLITE_BUSY` retry counters increase during burst writes (note: `busy_timeout = 5000ms`
  and immediate transaction retries handle transient contention automatically).

Resolution steps:
1. Ensure no hung external viewer holds a read transaction open on `index.db`.
2. Run `context-engine doctor --workspace <path>` to confirm `quick_check` passes.
3. Run `context-engine prune --workspace <path> --ttl-secs 604800` to sweep expired chunks
   and allow SQLite WAL to checkpoint cleanly on connection close.
4. Never delete `index.db-wal` or `index.db-shm` manually while `index.db` exists, as doing
   so discards uncommitted WAL frames and corrupts the database image.

---

## 4. Reparse Point & Junction Confinement

When `context_index` or `context_run` returns `PATH_ESCAPE`, inspect the requested path:
- `context-execution` walks path components incrementally from the canonical workspace root
  and invokes `dunce::canonicalize` at every existing directory prefix.
- Any NTFS directory junction (`FILE_ATTRIBUTE_REPARSE_POINT`) or symbolic link whose target
  resolves outside `<workspace>` is rejected immediately—even if the leaf filename does not
  exist yet.
- Post-open metadata verification (`verify_same_file_identity`) checks creation timestamps
  and reparse attributes while holding the file handle open to defeat TOCTOU swaps.

If a build system legitimately generates artifacts in an external cache directory, pass those
outputs via stdin (`context-engine index --stdin --label build-log`) rather than creating
cross-volume junctions out of the workspace.

---

## 5. Zstandard Integrity Repair

When `context_get` returns `INTEGRITY_MISMATCH`, the stored `.zst` frame failed either
Zstandard frame decompression or post-decompression SHA-256 verification against the
manifest's expected `stored_sha256`.

Diagnostic & Remediation Protocol (`RUNBOOK-ZSTD-704`):
1. Identify the affected `artifact_id` (`a_<64-hex>`) and `expected_sha256` from the error.
2. Inspect `<workspace>/.context-engine/store/manifests/<artifact_id>.json` to locate the
   referenced `stored_sha256` shard under `blobs/<first-2-hex>/<stored_sha256>.zst`.
3. Do NOT patch or edit `.zst` files in place; content-addressed blobs are immutable.
4. Remove the corrupted manifest via `context-engine prune --workspace <path> --ttl-secs 0`
   (or re-capture the command via `context_run` to mint a fresh verified blob and manifest).
5. Check underlying storage health (`chkdsk` / SMART telemetry) if bit-rot recurs.

---

## 6. Emergency Prune Procedure

If a workspace approaches the `512 MiB` default store quota (`E_QUOTA_EXCEEDED`), execute the
Emergency Prune Procedure (`RUNBOOK-PRUNE-911`):

1. Inspect current store footprint and session metrics:
   `context-engine stats --workspace <path> --all-sessions --json`
2. Evict artifacts older than 24 hours (`86400` seconds) while enforcing a `64 MiB` ceiling:
   `context-engine prune --workspace <path> --ttl-secs 86400 --max-bytes 67108864 --json`
3. Verify crash-safe deletion invariants in the returned `EnginePruneReport`:
   - Evicted manifests are deleted BEFORE unreferenced `.zst` blobs so no manifest ever
     points to a missing blob.
   - Leftover `.tmp` files in `.context-engine/store/tmp/` are swept automatically.
   - Corresponding `search_artifacts` and `search_chunks_fts` rows are removed in lockstep.
4. Re-run `context-engine doctor --workspace <path>` to confirm `healthy: true`.

---

## 7. Security Audit Checklist

- Confirm `security_denials` in `context_stats` after adversarial tests or unfamiliar scripts.
- Verify `.env`, `.env.*`, `*.pem`, `*.key`, `.ssh/`, `.aws/`, and `.git/credentials` remain
  blocked with `SENSITIVE_PATH_BLOCKED`.
- Confirm zero outbound TCP/UDP sockets exist for the `context-engine` PID via
  `Get-NetTCPConnection -OwningProcess <pid>`.
