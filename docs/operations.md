# Rust Context Engine V1 — Operations, Diagnostics & Maintenance Runbook

**Version:** `0.1.0`  
**Artifact Bundle:** `./dist/` (portable single-binary layout)  
**Target OS:** Windows 10/11 (`x86_64-pc-windows-msvc`) and POSIX (`Linux` / `macOS`)

---

## 1. Portable Deployment (`dist/`)

### 1.1 Building or Rebuilding the Release Bundle

Run the non-destructive packaging script from PowerShell 5.1 or PowerShell 7+:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\package-dist.ps1
```

`scripts/package-dist.ps1` performs six deterministic stages without using any recursive delete commands:
1. Audits all 162 resolved crates in `cargo metadata --format-version 1 --locked` + `Cargo.lock` for permissive SPDX compliance and writes `dist/sbom.cdx.json` (CycloneDX 1.5) and `dist/license-audit.json`.
2. Compiles `context-engine.exe` with `--release --locked --target-dir target/wave4-release` (automatically using `cargo auditable build` if `cargo-auditable` is installed on `PATH`).
3. Copies `context-engine.exe`, `NOTICE`, and `README.md` into `dist/` and renders all 5 client integration kits into `dist/integrations/` (`cursor`, `claude-code`, `opencode`, `codex`, `generic`).
4. Runs `dist\context-engine.exe doctor --workspace <repo> --json` -> `dist/doctor-report.json`.
5. Executes the PE32+ header, CFG/CET/ASLR/DEP, debug exposure, string, and `icacls` audit -> `dist/pe-hardening-audit.json`.
6. Generates `dist/SHA256SUMS.txt` across all 52 artifacts in `dist/`.

### 1.2 Verifying Artifact Checksums Before Rollout

```powershell
Push-Location .\dist
Get-Content .\SHA256SUMS.txt | ForEach-Object {
    $parts = $_ -split '  ', 2
    $actual = (Get-FileHash -LiteralPath $parts[1] -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $parts[0]) { throw "SHA-256 mismatch on $($parts[1])!" }
}
Write-Host "All dist/ SHA-256 checksums verified." -ForegroundColor Green
Pop-Location
```

### 1.3 Installing into a Target Project (Opt-In Only)

1. Place `dist/context-engine.exe` (and `dist/NOTICE`) in a stable local tools folder (e.g., `D:\tools\context-engine\context-engine.exe`) or use `dist\context-engine.exe` directly in place.
2. Always preview with `--dry-run` (default) before writing project files:
   ```powershell
   D:\tools\context-engine\context-engine.exe setup `
     --client cursor `
     --workspace "D:\projects\my-service" `
     --binary "D:\tools\context-engine\context-engine.exe" `
     --dry-run
   ```
3. Opt in for that workspace by passing `--write-project`:
   ```powershell
   D:\tools\context-engine\context-engine.exe setup `
     --client cursor `
     --workspace "D:\projects\my-service" `
     --binary "D:\tools\context-engine\context-engine.exe" `
     --write-project
   ```

---

## 2. Health Checks & `doctor` Diagnostics

Run `doctor` via CLI or invoke the `context_doctor` MCP tool inside your coding agent:

```powershell
.\dist\context-engine.exe doctor --workspace "D:\projects\my-service" --json
```

### Interpreting `DoctorReport`

| Field | Expected Value | Action if Degraded |
| :--- | :--- | :--- |
| `healthy` | `true` (CLI exit `0`) | Inspect sub-reports below; CLI exits `1` when `false`. |
| `store_permissions.private_only` | `true` | Another principal or inherited group (`Users` / `Everyone`) has access to `.context-engine/store`. Re-tighten ACLs (see [Section 4.2](#42-store-acl-drift-private_only--false)). |
| `search_health.journal_mode` | `"wal"` | Ensure workspace resides on a local filesystem supporting SQLite shared-memory WAL (avoid SMBv1/network shares without locking). |
| `search_health.quick_check_ok` | `true` | SQLite page integrity check (`PRAGMA quick_check(1)`). If `false`, restore or rebuild `.context-engine/index.db`. |
| `search_health.fts_integrity_ok` | `true` | FTS5 inverted index parity with `search_chunks`. |
| `journal_health.healthy` | `true` | Verifies `journal_events` / `journal_checkpoints` WAL state and schema version `1`. |
| `execution_policy.allow_shell` | `false` | Confirms direct `argv` spawning without shell interpolation. |
| `secret_policy.mode` | `"redact_before_index"` | Confirms pre-index / pre-view `SecretGuard` redaction is active. |

### Monitoring Token Savings & Security Denials

```powershell
.\dist\context-engine.exe stats --workspace "D:\projects\my-service" --all-sessions --json
```

Track:
- `net_token_savings_ratio` and `retrieval_overhead_ratio`: Verify compact views stay tight without forcing excessive `context_get` pagination.
- `security_denials`: Non-zero counts indicate blocked shell invocations, path traversal attempts, or sensitive file reads (`.env`, `.pem`) recorded in `journal_events`.
- `secrets_redacted_total`: Count of credential spans intercepted by `SecretGuard` before indexing.

---

## 3. Maintenance Runbook: `prune`, Backup & Upgrade

### 3.1 Routine Storage Pruning (`prune`)

Each workspace stores its own state inside `<workspace>/.context-engine/`:

```text
<workspace>/.context-engine/
  index.db              # SQLite WAL database (search_* + journal_* + schema_migrations)
  index.db-wal          # Write-Ahead Log
  index.db-shm          # Shared-memory WAL index
  store/
    .acl_v1             # Private DACL / 0700 initialization sentinel
    manifests/          # Scoped <artifact_id>.json envelopes & LRU timestamps
    blobs/<2-hex>/      # Content-addressed <sha256>.zst streams
    tmp/                # Atomic write staging files
```

Enforce default retention (`14` days TTL, `512 MiB` ceiling) or tighten limits on CI/laptop disks:

```powershell
# Enforce default 14-day TTL and 512 MiB store cap:
.\dist\context-engine.exe prune --workspace "D:\projects\my-service" --json

# Tighten to 48-hour TTL and 128 MiB store cap:
.\dist\context-engine.exe prune --workspace "D:\projects\my-service" --ttl-secs 172800 --max-bytes 134217728 --json
```

### 3.2 Safe Backup & Restore

1. **Quiesce or Copy Full WAL Triplet:** Stop active `context-engine mcp` processes for that workspace before copying `<workspace>/.context-engine/`, **or** ensure `index.db`, `index.db-wal`, and `index.db-shm` are snapshotted together alongside `store/manifests/` and `store/blobs/`. Never copy `index.db` alone while `index.db-wal` has uncheckpointed frames.
2. **Post-Restore Verification:** After restoring `.context-engine/` onto a new disk or user profile, re-apply owner ACLs on `.context-engine/store` and run `context-engine doctor --workspace <path>` before starting agents.

### 3.3 Binary Upgrades

1. Build or unpack the new `context-engine.exe` and verify `SHA256SUMS.txt`.
2. Stop running IDE MCP server instances (or reload MCP servers in Cursor / Claude Code / OpenCode / Codex).
3. Replace `context-engine.exe` atomically. On startup, `SearchIndex` and `SessionJournal` inspect the `schema_migrations (component, version)` table inside `index.db` and apply any forward schema migrations inside an `IMMEDIATE` transaction.
4. Run `context-engine doctor --workspace <path>` to confirm `healthy: true`.

---

## 4. Troubleshooting

### 4.1 CLI Exits `77` or MCP Tool Returns `isError: true` (`security_denial: true`)

- **`EXECUTION_DENIED`:**
  - *Cause:* Caller passed a shell (`["cmd", "/c", ...]`, `["powershell", "-Command", ...]`, `["sh", "-c", ...]`), a path in `argv[0]` (`["./script.sh"]`), a non-allowlisted binary, or destructive flags (`git reset --hard`, `git clean -fd`).
  - *Fix:* Pass the allowlisted tool directly as an `argv` array (e.g., `["cargo", "test", "--workspace"]` or `["python", "-m", "pytest"]`).
- **`SENSITIVE_PATH_BLOCKED` / `PATH_ESCAPE`:**
  - *Cause:* `context_index` or `cwd` targeted `.env*`, `*.pem`, `*.key`, `.ssh/`, `.aws/`, or a path/symlink/junction resolving outside `--workspace`.
  - *Fix:* Keep paths strictly inside the workspace root and never index secret files into `context-engine`.
- **`SESSION_MISMATCH` / `SCOPE_VIOLATION`:**
  - *Cause:* `context_get` requested an `artifact_id` created under a different `session_id` or different repository workspace.
  - *Fix:* Pass the matching `session_id` (visible in `context_search` with `session_only: false`) and query the MCP server bound to that repository.

### 4.2 Store ACL Drift (`private_only: false`)

If copying a workspace across filesystems restored inherited `BUILTIN\Users` ACEs on Windows:

```powershell
icacls "D:\projects\my-service\.context-engine\store" /inheritance:r /grant:r "$($env:USERNAME):(OI)(CI)F"
.\dist\context-engine.exe doctor --workspace "D:\projects\my-service"
```

### 4.3 `user-rea` Development MCP Reports `"REA could not start"`

During development-time binary hardening audits (never required for `context-engine` runtime operation), `user-rea` may return:
> `Do not repeat this startup. Tell the user REA could not start and ask them to restart the MCP client, then run rea doctor.`

**Resolution Steps:**
1. Do **not** loop retries against the failed `user-rea` session.
2. In a local terminal, run the pinned REA diagnostic check:
   ```powershell
   npx rea-agents@6.10.1 doctor
   ```
3. Verify Node.js (`v24+`) and `PATH` inheritance in your desktop IDE, then **restart the MCP client** (or reload the `user-rea` server in Cursor Settings -> MCP).
4. Once `user-rea` reports healthy, run read-only verification against `dist/context-engine.exe`:
   - `inspect_binary_hardening` (`path: "D:\\research 1\\mcp\\token reducer\\dist\\context-engine.exe"`)
   - `inspect_rust_binary` (`path: "D:\\research 1\\mcp\\token reducer\\dist\\context-engine.exe"`)
   - `audit_release_exposure` (`path: "D:\\research 1\\mcp\\token reducer\\dist\\context-engine.exe"`)
5. When `user-rea` is offline, `scripts/package-dist.ps1` provides deterministic offline verification via `dist/pe-hardening-audit.json`.

---

## 5. Instant Rollback & Bypass Switches

`context-engine` is engineered so operators can disable hooks or roll back per-project integrations in seconds with zero impact on global tooling:

| Scope | Rollback / Bypass Mechanism |
| :--- | :--- |
| **Bypass All Host Hooks Immediately** | Set `CONTEXT_ENGINE_DISABLE_HOOK=1` in your shell or IDE environment. Cursor (`post-command-capture.*`), Claude Code (`post-tool-reduce.mjs`), and OpenCode (`context-engine-plugin.mjs`) hooks exit `0` immediately as a pure pass-through. |
| **Silent Background Indexing Only** | Set `CONTEXT_ENGINE_HOOK_SILENT=1` (Claude Code hook indexes outputs into `.context-engine/` without injecting `additionalContext` notes). |
| **Raise Hook Capture Threshold** | Set `CONTEXT_ENGINE_MIN_CAPTURE_BYTES=16384` (defaults to `4096` bytes) to skip medium-sized command outputs. |
| **Disable Child Exit-Code Passthrough in Scripts** | Pass `--no-exit-code-passthrough` to `context-engine run` when a CI wrapper wants exit `0` even if tests failed. |
| **Full Per-Project Uninstall** | Remove `"context-engine"` from `<project>/.cursor/mcp.json`, `<project>/.mcp.json`, `<project>/opencode.json`, or `<project>/.codex/config.toml` (leaving other MCP servers intact). Existing global `~/.cursor`, `~/.claude`, `headroom`, and `caveman` installations remain untouched. |
