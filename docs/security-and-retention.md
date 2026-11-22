# Rust Context Engine V1 — Security Architecture, Retention & Binary Hardening Audit

**Date:** 2026-11-22  
**Status:** Verified Release Baseline (`v0.1.0`)  
**Companion Threat Model:** [`docs/threat-model.md`](threat-model.md)  
**Companion ADRs:** [`0001`](adrs/0001-artifact-identity-and-scope.md), [`0002`](adrs/0002-storage-and-secret-policy.md), [`0003`](adrs/0003-execution-confinement.md), [`0004`](adrs/0004-single-pass-reduction-and-retention.md)

---

## 1. Security Architecture & Defense-in-Depth Boundaries

`context-engine` enforces four nested security boundaries across every CLI command and MCP `stdio` request:

1. **Memory & Language Safety (`#![forbid(unsafe_code)]`):**
   Every workspace crate (`context-core`, `context-execution`, `context-capture`, `context-store`, `context-reducers`, `context-search`, `context-journal`, `context-mcp`, `context-cli`) enforces `[workspace.lints.rust] unsafe_code = "deny"` and `#![forbid(unsafe_code)]`. All regular expressions compile once via Rust `regex` (`LazyLock<RegexSet>` / `Regex`), guaranteeing linear-time `O(n)` automaton execution immune to catastrophic backtracking (ReDoS).
2. **Server-Bound Principal & Workspace Scope (`BoundScope`):**
   - `WorkspaceScopeId` (`ws_<32-hex>`) is derived server-side at process startup from `dunce::canonicalize(workspace_root)` hashed with domain separator `"context-engine:workspace-scope:v1\0"`.
   - `ArtifactId` (`a_<64-hex>`) is minted server-side from `(workspace_scope_id, session_id, captured_at, nonce, stdout_sha256, stderr_sha256)`.
   - Every stored manifest records a tamper-evident `scope_binding_sha256` covering `(workspace_scope_id, session_id, artifact_id, streams)`. Forged or transplanted manifests fail closed with `SCOPE_VIOLATION` (`exit 77` / MCP `isError: true`) before any blob pointer is dereferenced.
3. **Zero Engine Network Egress (with Hosted-LLM Disclosure Protection):**
   The `context-engine` binary links zero HTTP/TLS client libraries and opens zero network sockets at runtime. Because a coding agent connected over local `stdio` may forward MCP tool outputs to a hosted LLM API, `SecretGuard` treats compact views, FTS5 search snippets, error strings, and session journals as untrusted external disclosure surfaces.
4. **Global Host Configuration Isolation:**
   `context-engine setup` defaults to `--dry-run` and unconditionally rejects `~`, `~/.cursor`, `~/.claude`, `~/.codex`, `~/.config/opencode`, `%APPDATA%`, `$XDG_CONFIG_HOME/opencode`, and `$HOME`/`%USERPROFILE%` roots with `SCOPE_VIOLATION`.

---

## 2. `SecretGuard` Deterministic Redaction & Policy Engine

`SecretGuard` (`crates/context-core/src/secrets.rs`) scans all captured streams, document bodies, provenance metadata (`ArtifactSource::Command.argv` and `ArtifactSource::Document.label` via `sanitize_artifact_source`), echoed `SearchQueryOutcome.query` strings, journal fields, and error messages **before** compact view generation, manifest/blob persistence, or SQLite FTS5 indexing. In addition, `TransformationLedger::is_already_reduced_payload` requires a structurally verified `a_<64-hex>` `ArtifactId` inside `[context-engine:v1 ...]` banners so untrusted payloads cannot spoof already-reduced markers. Overlapping matches resolve deterministically by `(priority ASC, byte_start ASC, span_len DESC)`.

### 2.1 Complete `SecretGuard` Rule Catalog

| Priority | `SecretRuleKind` | `rule_id` | Placeholder Emitted | Pattern / Detection Scope |
| :---: | :--- | :--- | :--- | :--- |
| **1** | `PemPrivateKey` | `PEM_PRIVATE_KEY` | `[REDACTED:PEM_PRIVATE_KEY]` | Multi-line and truncated `-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----` blocks (RSA, EC, OPENSSH, PKCS#8). |
| **2** | `ConnectionUri` | `CONNECTION_URI` | `[REDACTED:CONNECTION_URI]` | `user:password@` authority credentials inside `postgres://`, `postgresql://`, `mysql://`, `mariadb://`, `mongodb(+srv)://`, `redis(s)://`, `amqp(s)://`, `mssql://`, `sqlserver://`, `clickhouse://` URIs. |
| **2** | `AuthHeader` | `AUTH_HEADER` | `[REDACTED:AUTH_HEADER]` | `Authorization: Bearer\|Basic\|Digest\|Token\|ApiKey <secret>` headers and standalone `Bearer <20+ char token>` strings. |
| **2** | `SlackWebhook` | `SLACK_WEBHOOK` | `[REDACTED:SLACK_WEBHOOK]` | `https://hooks.slack.com/services/T.../B.../...` incoming webhook URLs. |
| **3** | `AnthropicApiKey` | `ANTHROPIC_API_KEY` | `[REDACTED:ANTHROPIC_API_KEY]` | `sk-ant-[A-Za-z0-9\-_]{16,}` vendor API keys. |
| **3** | `OpenAiApiKey` | `OPENAI_API_KEY` | `[REDACTED:OPENAI_API_KEY]` | `sk-(proj-\|svcacct-\|live-\|test-)?[A-Za-z0-9\-_]{20,}` API keys. |
| **3** | `GitHubToken` | `GITHUB_TOKEN` | `[REDACTED:GITHUB_TOKEN]` | `gh[pousr]_[A-Za-z0-9]{24,}` classic tokens and `github_pat_[A-Za-z0-9_]{22,}` fine-grained PATs. |
| **3** | `GitLabToken` | `GITLAB_TOKEN` | `[REDACTED:GITLAB_TOKEN]` | `(glpat\|glptt\|gldt\|glrt\|gloas)-[A-Za-z0-9\-_]{20,}` tokens. |
| **3** | `AwsAccessKey` | `AWS_ACCESS_KEY` | `[REDACTED:AWS_ACCESS_KEY]` | `(AKIA\|ASIA\|ABIA\|ACCA)[0-9A-Z]{16}` IAM and STS access key IDs. |
| **3** | `AwsSecretKey` | `AWS_SECRET_KEY` | `[REDACTED:AWS_SECRET_KEY]` | `aws_secret_access_key` assignments with 40-char Base64 secret values. |
| **3** | `GcpApiKey` | `GCP_API_KEY` | `[REDACTED:GCP_API_KEY]` | `AIza[0-9A-Za-z\-_]{35}` Google Cloud API keys. |
| **3** | `GcpOAuthToken` | `GCP_OAUTH_TOKEN` | `[REDACTED:GCP_OAUTH_TOKEN]` | `ya29.[0-9A-Za-z\-_]{20,}` Google OAuth2 access tokens. |
| **3** | `SlackToken` | `SLACK_TOKEN` | `[REDACTED:SLACK_TOKEN]` | `xox[baprs]-[0-9A-Za-z\-]{10,}` bot/user/app tokens. |
| **3** | `JwtToken` | `JWT_TOKEN` | `[REDACTED:JWT_TOKEN]` | Three-segment `eyJ...` Base64URL-encoded JSON Web Tokens. |
| **4** | `EnvSecretAssignment` | `ENV_SECRET` | `[REDACTED:ENV_SECRET]` | `.env`, CLI, JSON, and YAML `KEY=VALUE` / `"key": "value"` assignments whose key contains `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`, `PWD`, `API_KEY`, `APIKEY`, `PRIVATE_KEY`, `ACCESS_KEY`, `AUTH_KEY`, `CLIENT_SECRET`, `WEBHOOK_SECRET`, `SIGNING_KEY`, or `ENCRYPTION_KEY` (excluding benign placeholders `true`/`null`/`${VAR}` and telemetry counters like `estimated_raw_tokens`). |
| **5** | `HighEntropyToken` | `HIGH_ENTROPY_TOKEN` | `[REDACTED:HIGH_ENTROPY_TOKEN]` | Unprefixed tokens (`>= 28` chars default, Shannon entropy `>= 4.15` bits/byte, `>= 3` character classes, `>= 2` digits). Automatically exempts SHA-256/Git hex digests, standard UUIDs, file paths, snake_case identifiers, `a_<64-hex>`, and `ws_<32-hex>`. |

### 2.2 `SecretPolicyMode` Dispositions

| Mode | Compact View & FTS5 Index | `.context-engine/store` Blob Persistence | `context_get` Behavior |
| :--- | :--- | :--- | :--- |
| **`RedactBeforeIndex`** *(Default)* | `[REDACTED:<RULE_ID>]` only | Persists **redacted** UTF-8 bytes by default (`allow_raw_blob_when_redacted = false`, `exact_raw_preserved = false`). For binary streams containing secrets, raw persistence is withheld (`originals_available = false`). | Serves redacted UTF-8 stream (or denies binary stream with `SECRET_QUARANTINED`). |
| **`Quarantine`** | `[REDACTED:<RULE_ID>]` only | Writes **zero** blob bytes (`stored_sha256 = None`, `quarantined = true`, `originals_available = false`). | Fails closed with `SECRET_QUARANTINED` (`exit 77`). |
| **`Deny`** | Rejected prior to view/index | Fails closed (`SECRET_POLICY_DENIED`, `exit 77`) in memory before writing any blob, manifest, index row, or journal payload. | Artifact never created. |

---

## 3. `ExecutionGate` Confinement & Subprocess Hardening

`ExecutionGate` (`crates/context-execution/`) validates every command and file path before OS execution or file open:

1. **Direct `argv` Spawning (Zero Shell Interpolation):**
   - Spawns `tokio::process::Command::new(&argv[0]).args(&argv[1..])` with `kill_on_drop(true)`.
   - Rejects empty `argv`, NUL bytes, and any path separator (`/`, `\`, `:`) in `argv[0]` so callers cannot invoke `./evil/cargo.exe` or `..\..\Windows\System32\cmd.exe`.
   - **Blocked Shell Interpreters (`allow_shell = false`):** `cmd`, `powershell`, `pwsh`, `sh`, `bash`, `zsh`, `fish`, `ksh`, `csh`, `wsl`.
2. **Default Executable Allowlist (18 Programs):**
   `cargo`, `rustc`, `rustup`, `git`, `pytest`, `python`, `python3`, `node`, `npm`, `npx`, `pnpm`, `yarn`, `tsc`, `go`, `rg`, `dotnet`, `mvn`, `gradle`.
3. **Explicit Destructive & Network Denylist (19 Programs + Subcommand Guards):**
   - **Blocked Binaries:** `rm`, `rmdir`, `del`, `erase`, `remove-item`, `format`, `diskpart`, `shred`, `curl`, `wget`, `invoke-webrequest`, `invoke-restmethod`, `ssh`, `scp`, `sftp`, `nc`, `ncat`, `netcat`, `telnet`.
   - **Blocked Destructive Flags:** `git reset --hard`, `git clean -d/-f/-x/--force`, `git push --force/-f/--force-with-lease`, `git checkout -- .`, PowerShell `-Recurse -Force` / `--recursive -Force`, and HTTP upload flags (`-d`, `--data*`, `--upload-file`, `-F`, `POST`/`PUT`/`DELETE`) even if `curl`/`wget` were manually policy-enabled.
4. **Environment Variable Scrubbing:**
   Preserves 28 safe build/toolchain keys (`PATH`, `PATHEXT`, `SYSTEMROOT`, `CARGO_HOME`, `RUSTUP_HOME`, `RUSTFLAGS`, `PYTHONPATH`, `VIRTUAL_ENV`, etc.) while stripping `AWS_*`, `AZURE_*`, `GCP_*`, `DATABASE_URL`, `REDIS_URL`, `MONGODB_URI`, `AMQP_URL`, `NPM_CONFIG_AUTHTOKEN`, and any variable containing `SECRET`, `TOKEN`, `PASSWORD`, `PASSWD`, `API_KEY`, `APIKEY`, `PRIVATE_KEY`, `ACCESS_KEY`, `AUTH_KEY`, `CREDENTIALS`, `CONN_STR`, or `CONNECTION_STRING`.
5. **Step-by-Step Canonical Confinement & Post-Open TOCTOU Verification:**
   - Walks every path component from `workspace_root`, dereferencing symlinks and Windows NTFS junctions (`FILE_ATTRIBUTE_REPARSE_POINT`) at each existing prefix via `dunce::canonicalize` and rejecting dangling links or escapes outside `workspace_root` (`PATH_ESCAPE`).
   - Blocks sensitive paths on **both** lexical input and canonical target: `.ssh/`, `.aws/`, `.gnupg/`, `.kube/`, `.azure/`, `.gcloud/`, `.git/credentials`, `.env`, `.env.*`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `credentials`, `id_rsa*`/`id_ed25519*`/`id_ecdsa*`/`id_dsa*` (excluding `.pub`), and extensions `.pem`, `.key`, `.pfx`, `.p12`, `.kdbx`, `.jks`, `.keystore` (`SENSITIVE_PATH_BLOCKED`).
   - `open_confined_file_sync` re-canonicalizes the path *while holding the OS file handle open* and verifies file identity (inode/device on Unix; creation timestamp + reparse-point check on Windows) to defeat TOCTOU file-swap attacks.

---

## 4. SQLite WAL + FTS5 Isolation & Private Store Permissions

- **Private Store ACLs (`.context-engine/store/`):**
  - **Windows:** `BlobStore::open_with_config` invokes `icacls <store_dir> /inheritance:r /grant:r "<PRINCIPAL>:(OI)(CI)F"` directly via `Command::new("icacls")`, stripping inherited ACEs (`Everyone`, `BUILTIN\Users`, `Authenticated Users`) so all subdirectories (`blobs/`, `manifests/`, `tmp/`) inherit owner-only Full Control.
  - **Unix:** Applies `0700` on directories and `0600` on files.
  - **Crash-Safe Atomic Writes:** Compressed `zstd` frames are decoded and SHA-256 verified in memory, written to `NamedTempFile` in `.context-engine/store/tmp/`, flushed via `sync_all()`, and atomically renamed into `blobs/<2-hex>/<sha256>.zst`.
- **SQLite WAL & FTS5 Defense-in-Depth (`.context-engine/index.db`):**
  - Connections enforce `PRAGMA journal_mode = WAL`, `PRAGMA foreign_keys = ON`, `PRAGMA synchronous = NORMAL`, `PRAGMA temp_store = MEMORY`, and `busy_timeout = 5000 ms` with automatic transient lock retry on NTFS.
  - `search_chunks_fts` uses `fts5(sanitized_body, source_label, content='search_chunks', content_rowid='chunk_id', tokenize='porter unicode61')` kept in 100% sync via `AFTER INSERT`, `AFTER DELETE`, and `AFTER UPDATE` triggers.
  - **Double Secret Gate:** `SearchIndex::index_artifact` runs `SecretGuard` across the entire stream prior to chunking (catching multi-line PEM keys) and then re-runs `SecretGuard` on every individual chunk + `source_label` as a post-redaction assertion before `INSERT`.
  - **Scoped Parameterized Queries:** Inbound `query` strings are stripped of FTS5 column/operator syntax and tokenized into quoted literals; SQL `SELECT` statements bind `WHERE c.workspace_scope_id = ?2 AND a.workspace_scope_id = ?2` (plus `session_id = ?3` when `session_only = true`), followed by post-query `BoundScope` verification in Rust.
  - **Append-Only Journal:** `journal_events` enforces `BEFORE UPDATE` trigger `trg_journal_events_immutable_update` (`RAISE(ABORT, ...)`), preventing historical event tampering.

---

## 5. Retention Lifecycle, TTL & Quota Pruning

| Parameter | Default | Override Flag |
| :--- | :--- | :--- |
| `retention_ttl_secs` | `1,209,600` s (`14` days) | `context-engine prune --ttl-secs <SECS>` |
| `max_workspace_store_bytes` | `536,870,912` bytes (`512 MiB`) | `context-engine prune --max-bytes <BYTES>` |

`ContextEngine::prune` executes a deterministic, crash-safe 4-stage sweep:

1. **Stale Temp Sweep:** Deletes orphaned temporary files inside `.context-engine/store/tmp/`.
2. **TTL + LRU Eviction Selection:** Marks manifests older than `ttl_secs`, then sorts remaining manifests by `(last_accessed_unix_ms ASC, created_at_unix_ms ASC, artifact_id ASC)` (`context_get` updates `last_accessed_unix_ms`) and marks oldest entries until live `(manifest_bytes + referenced_blob_bytes) <= max_store_bytes`.
3. **Manifests-Before-Blobs Deletion Order:** Removes evicted `manifests/<artifact_id>.json` files **before** sweeping unreferenced `blobs/<2-hex>/<sha256>.zst` files, guaranteeing no live manifest ever points to a deleted content-addressed blob even if interrupted mid-prune.
4. **Index & Journal Synchronization:** Deletes every evicted `artifact_id` from `search_artifacts` / `search_chunks` (cascading into `search_chunks_fts` via trigger) and prunes expired `journal_events` / `journal_checkpoints`.

---

## 6. Supply-Chain & CycloneDX 1.5 SBOM License Audit

Generated by `scripts/package-dist.ps1` into `dist/sbom.cdx.json` and `dist/license-audit.json` from `cargo metadata --format-version 1 --locked` + `Cargo.lock`:

- **`Cargo.lock` SHA-256:** `1637cee7c5ccf5ca2f7147c4303bbc9a9d1e02a1cfd689dffdeb338d461a486b`
- **Deterministic CycloneDX 1.5 Serial:** `urn:uuid:f899e93f-4b2c-574c-bfb5-92dd9fbb5e52` (`dist/sbom.cdx.json`)
- **Package Counts:** `162` total resolved packages (`9` workspace crates + `153` external crates; `101` crates in the `x86_64-pc-windows-msvc` normal runtime closure of `context-engine.exe`).
- **`cargo-auditable` Status:** `cargo-auditable` was not installed in the build host environment; standard `cargo build --release --locked` ran paired with deterministic CycloneDX 1.5 SBOM generation (`scripts/package-dist.ps1` automatically switches to `cargo auditable build --release --locked` whenever `cargo-auditable` is present on `PATH`).
- **Copyleft / Source-Available Audit Result:** **`PASSED` (`0` violations)** — `0` `GPL`, `0` `AGPL`, `0` `Elastic-2.0`, `0` `BUSL-1.1`, and `0` `SSPL` crates elected anywhere in the dependency graph.

| SPDX License Expression in `cargo metadata --locked` | Crate Count | Elected Permissive Path |
| :--- | ---: | :--- |
| `MIT OR Apache-2.0` | 96 | `MIT` |
| `MIT` | 21 | `MIT` |
| `Apache-2.0 OR MIT` | 17 | `Apache-2.0` |
| `MIT/Apache-2.0` | 8 | `MIT` |
| `Unlicense OR MIT` | 5 | `Unlicense` |
| `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 3 | `Apache-2.0 WITH LLVM-exception` |
| `BSD-2-Clause OR Apache-2.0 OR MIT` | 2 | `BSD-2-Clause` |
| `BSD-3-Clause` | 2 | `BSD-3-Clause` |
| `Unlicense/MIT` | 2 | `Unlicense` |
| `(MIT OR Apache-2.0) AND Unicode-3.0` | 1 | `MIT AND Unicode-3.0` |
| `Apache-2.0` | 1 | `Apache-2.0` |
| `Apache-2.0 / MIT` | 1 | `Apache-2.0` |
| `BSD-3-Clause AND BSD-2-Clause` | 1 | `BSD-3-Clause AND BSD-2-Clause` |
| `CC0-1.0 OR MIT-0 OR Apache-2.0` | 1 | `CC0-1.0` |
| `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | 1 | `MIT` (disjunctive `OR`; `LGPL` branch unused) |
| **Total Resolved Crates** | **162** | **100% Permissive** |

---

## 7. Release Binary Hardening & Exposure Audit (`dist/context-engine.exe`)

### 7.1 Audit Execution Provenance (`REA MCP` + Deterministic PE32+ Inspector)

1. **`user-rea` Probe:** Schema discovery (`GetDynamicTools`) succeeded for `inspect_binary_hardening`, `inspect_rust_binary`, and `audit_release_exposure`. A single `inspect_binary_hardening` call on `d:\research 1\mcp\token reducer\dist\context-engine.exe` returned:
   > `Do not repeat this startup. Tell the user REA could not start and ask them to restart the MCP client, then run rea doctor.`
   Per REA operational protocol, no retry was issued against the un-restarted host session (see [`docs/operations.md`](operations.md) for post-restart `npx rea-agents@6.10.1 doctor` verification steps).
2. **Deterministic Python 3.11 PE32+ Static Audit (`dist/pe-hardening-audit.json`):**
   `scripts/package-dist.ps1` executed a deterministic COFF / OptionalHeader / LoadConfig / DebugDirectory / String / `icacls` inspector directly over `dist/context-engine.exe` (`Python 3.11.15`).

### 7.2 Verified Artifact Identity & Compiler Flags

- **Artifact Path:** `dist/context-engine.exe`
- **Exact Size:** `6,394,368` bytes (`6.10 MiB`)
- **SHA-256 Digest:** `d8cb892e77e68013d6ad277660e82099c769479397c59dff97f6c511772b8a61`
- **Compiler & Linker Profile (`Cargo.toml` + `.cargo/config.toml`):** `rustc 1.99.1`, `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, `panic = "abort"`, `-C control-flow-guard=checks`, `/HIGHENTROPYVA`, `/DYNAMICBASE`, `/NXCOMPAT`, `/CETCOMPAT`.

### 7.3 Verified PE32+ Header, LoadConfig & Exposure Evidence

| Check Category | Header Field / Mechanism | Verified Value (Hex / Exact) | Status |
| :--- | :--- | :--- | :---: |
| **PE32+ Architecture** | DOS `e_magic` / `e_lfanew` / PE Signature | `0x5a4d` (`MZ`) / `0x00000100` / `0x00004550` (`PE\0\0`) | **PASS** |
| **Machine Type** | COFF `Machine` | `0x8664` (`IMAGE_FILE_MACHINE_AMD64`) | **PASS** |
| **Image Format** | OptionalHeader `Magic` / `Subsystem` | `0x020b` (`PE32+` 64-bit) / `3` (`WINDOWS_CUI`) | **PASS** |
| **64-Bit ASLR** | `DllCharacteristics` (`0xc160`) `& 0x0020` | `HIGH_ENTROPY_VA = true` (`0x0020`) | **PASS** |
| **Dynamic Base (ASLR)** | `DllCharacteristics` (`0xc160`) `& 0x0040` | `DYNAMIC_BASE = true` (`0x0040`) | **PASS** |
| **DEP / NX Stack & Heap** | `DllCharacteristics` (`0xc160`) `& 0x0100` | `NX_COMPAT = true` (`0x0100`) | **PASS** |
| **Control Flow Guard (CFG)** | `DllCharacteristics` (`0xc160`) `& 0x4000` | `GUARD_CF = true` (`0x4000`) | **PASS** |
| **CFG Function Table** | `LoadConfig` (`RVA 0x005d2a50`, `320` B) | `GuardFlags = 0x00017500` (`CF_INSTRUMENTED` + `CF_FUNCTION_TABLE_PRESENT`, `2,284` guarded targets) | **PASS** |
| **Stack Cookie (`/GS`)** | `LoadConfig.SecurityCookie` | `0x00000001405f9bc0` (`!= 0`, active) | **PASS** |
| **CET Shadow Stack** | `IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS` | `0x00000001` (`CET_COMPAT = true`) | **PASS** |
| **Symbol Stripping** | COFF Symbol Table & Sections | `PointerToSymbolTable = 0`, `NumberOfSymbols = 0`; sections `[.text, .rdata, .data, .pdata, .reloc]` (`0` `.debug_*`/`.symtab` sections) | **PASS** |
| **Debug Companion Exposure** | `.pdb` / `.map` / `.debug` files in `dist/` | `0` files shipped in `dist/` (RSDS header carries bare `"context_engine.pdb"` filename only, no host build path) | **PASS** |
| **Embedded Credential Scan** | `12,685` printable ASCII strings (`>= 8` B) | `0` leaked API keys, tokens, or private keys (`0` occurrences of workspace path `D:\research 1\mcp\token reducer`; `354` standard Cargo registry `.cargo\registry\src\...` panic location strings, stripped further if built with `--remap-path-prefix`) | **PASS** |
| **Windows Store DACL** | `icacls .context-engine\store` | `SOLVER\SM2063:(OI)(CI)(F)` — inheritance removed, `0` broad principal ACEs (`private_only = true`) | **PASS** |
