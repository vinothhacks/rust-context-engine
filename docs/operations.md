# Rust Context Engine operations

## 1. Installation and first use

The release workflow targets Linux x86-64 GNU on Ubuntu 22.04. PR CI tests the Linux archive and a Windows x64 release binary. An extracted local Windows x64 GNU candidate ZIP passed startup, stdio MCP, and byte recovery on Windows build 26300. Published clean-install evidence is pending for both platforms. macOS and ARM are outside the verified platform scope.

### 1.1 Verify a Linux release archive

Once a release is published, download the Linux `.tar.gz` and `SHA256SUMS` from that exact release and put both files in the same directory. Replace `v0.1.0` with the version you downloaded. Proceed to extraction only after the checksum command reports the archive as `OK`. [GitHub Releases](https://github.com/vinothhacks/rust-context-engine/releases)

```sh
name=context-engine-v0.1.0-x86_64-unknown-linux-gnu
sha256sum --check --strict SHA256SUMS &&
  tar -xzf "$name.tar.gz" &&
  "./$name/context-engine" --version
```

Keep the extracted binary in a stable tools directory. Point the MCP client at the absolute binary path and use a separate, existing workspace directory.

### 1.2 Build from source

Install the current stable Rust toolchain and a native C compiler. On Windows x64, use the MSVC toolchain and Visual Studio C++ Build Tools.

```sh
cargo build --locked --release -p context-cli
```

With the default Cargo target directory, the result is `target/release/context-engine` on Linux or `target\release\context-engine.exe` on Windows. For version `0.1.0`, `--version` should print `context-engine 0.1.0`.

Windows maintainers can run `scripts\package-dist.ps1` with PowerShell, Python 3.11 or later, and the MSVC toolchain to produce a local development bundle, SBOM, and PE diagnostics. The script emits a local `dist\SHA256SUMS.txt` file. The Linux release uses `SHA256SUMS` and checksums the compressed archive.

### 1.3 Check stdio and recover a fixture

Use a disposable workspace. An MCP client sends `initialize`, receives the negotiated protocol version and `serverInfo`, sends `notifications/initialized`, then requests `tools/list`. With a `2025-06-18` request, expect `2025-06-18` in the reply, `context-engine` and the binary version in `serverInfo`, and the seven `context_*` tools. The server exits successfully when the client closes stdin. [MCP client configuration](../README.md#connect-an-mcp-client-over-stdio)

From a source checkout, run `python3 scripts/verify-binary.py /absolute/path/to/context-engine` on Linux or `python scripts\verify-binary.py C:\tools\context-engine.exe` on Windows. The script starts the selected binary in a disposable workspace and checks startup, MCP negotiation, and byte recovery. Use the path to the extracted binary to exercise an archive.

The following Windows PowerShell example indexes a synthetic CRLF fixture and verifies the recovered bytes. Set `$engine` to the absolute path of the binary you want to check.

```powershell
$engine = 'C:\tools\context-engine.exe'
$workspace = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) "context-engine-$([guid]::NewGuid())")
$fixture = Join-Path $workspace.FullName 'fixture.log'
$recovered = Join-Path $workspace.FullName 'recovered.log'
$contents = [Text.Encoding]::UTF8.GetBytes("first line`r`nsecond line`r`n")
[IO.File]::WriteAllBytes($fixture, $contents)

$indexed = & $engine index $fixture --workspace $workspace.FullName --json
if ($LASTEXITCODE -ne 0) { throw 'Index failed' }
$artifact = $indexed | ConvertFrom-Json
$retrieved = & $engine get $artifact.artifact_id --workspace $workspace.FullName --stream document --bytes "0:$($contents.Length)" --json
if ($LASTEXITCODE -ne 0) { throw 'Recovery failed' }
$page = $retrieved | ConvertFrom-Json
[IO.File]::WriteAllBytes($recovered, [Convert]::FromBase64String($page.base64_bytes))

if ((Get-FileHash $fixture -Algorithm SHA256).Hash -ne (Get-FileHash $recovered -Algorithm SHA256).Hash) {
    throw 'Recovered SHA-256 does not match fixture'
}
'SHA-256 matched'
```

For larger artifacts, request half-open byte ranges in pages and concatenate the decoded `base64_bytes`. The default limit is 32,768 bytes per request. Check `exact_raw_preserved` and capture completion when comparing against the original. Redaction, truncation, and retention can change which bytes are available. [API contract](api-contract.md)

### 1.4 Configure a project

Preview with `--dry-run`. Use `--write-project` after approving the previewed changes.

```powershell
& $engine setup --client cursor --workspace 'D:\projects\my-service' --binary $engine --dry-run
```

### 1.5 Dependency checks

CI builds and tests against the committed lockfile. A pinned `cargo audit` or `cargo deny` CI check remains a follow-up.

---

## 2. Health Checks & `doctor` Diagnostics

Run `doctor` via CLI or invoke the `context_doctor` MCP tool inside your coding agent:

```powershell
& $engine doctor --workspace "D:\projects\my-service" --json
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
& $engine stats --workspace "D:\projects\my-service" --all-sessions --json
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
& $engine prune --workspace "D:\projects\my-service" --json

# Tighten to 48-hour TTL and 128 MiB store cap:
& $engine prune --workspace "D:\projects\my-service" --ttl-secs 172800 --max-bytes 134217728 --json
```

### 3.2 Safe Backup & Restore

1. **Quiesce or Copy Full WAL Triplet:** Stop active `context-engine mcp` processes for that workspace before copying `<workspace>/.context-engine/`, **or** ensure `index.db`, `index.db-wal`, and `index.db-shm` are snapshotted together alongside `store/manifests/` and `store/blobs/`. Never copy `index.db` alone while `index.db-wal` has uncheckpointed frames.
2. **Post-Restore Verification:** After restoring `.context-engine/` onto a new disk or user profile, re-apply owner ACLs on `.context-engine/store` and run `context-engine doctor --workspace <path>` before starting agents.

### 3.3 Binary Upgrades

1. Verify the release archive against its matching `SHA256SUMS` before unpacking it, or build the new binary from source.
2. Stop running IDE MCP server instances (or reload MCP servers in Cursor / Claude Code / OpenCode / Codex).
3. Replace the binary at the configured path. On startup, `SearchIndex` and `SessionJournal` inspect the `schema_migrations (component, version)` table inside `index.db` and apply any forward schema migrations inside an `IMMEDIATE` transaction.
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
& $engine doctor --workspace "D:\projects\my-service"
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
4. Once `user-rea` reports healthy, run read-only verification against the selected binary.
   - `inspect_binary_hardening` (`path: "C:\\tools\\context-engine.exe"`)
   - `inspect_rust_binary` (`path: "C:\\tools\\context-engine.exe"`)
   - `audit_release_exposure` (`path: "C:\\tools\\context-engine.exe"`)
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
