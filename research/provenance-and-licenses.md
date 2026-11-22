# Provenance and License Inventory

**Date:** 2026-11-22  
**Status:** Phase 0 Gate — Verified  
**Workspace Scope:** `d:\research 1\mcp\token reducer`

## 1. Governance Rules

1. **Permissive-Only Reference Gate:** Only permissively licensed (`Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `Unicode-3.0`) source code may be cloned into the gitignored `research/refs/` sandbox, analyzed with `user-rea`, or ported/verified via `user-rust-anything`.
2. **Source-Available / Copyleft Exclusion:** Repositories under non-OSI source-available licenses (`Elastic-2.0`, `SSPL`, `BUSL`) or strong copyleft (`GPL`, `AGPL`) are **strictly blocked** from cloning into `research/refs/`, code copying, translation, or automated porting.
3. **Attribution Preservation:** Any deterministic unit ported via `user-rust-anything` or pattern adapted from an `Apache-2.0` or `MIT` upstream must carry attribution in the root [`NOTICE`](../NOTICE) file and module-level provenance comments recording the upstream repository and license.
4. **Zero Runtime Coupling to Dev MCPs:** `user-rust-anything` and `user-rea` are development-time verification and static-audit tools only. The compiled `context-engine` binary has zero runtime dependencies on Node.js, Python, `rea-agents`, or `rust-anything`.

## 2. Reference Repository Inventory

| Repository | Upstream URL | Verified License | Primary Language | Permitted Role in V1 | Constraints & Obligations |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `chopratejas/headroom` | `https://github.com/chopratejas/headroom` | `Apache-2.0` | Python | **Permitted Reference & Unit Porting:** Shallow-clone pinned revision into gitignored `research/refs/headroom/`. Port/verify pure deterministic content-classification and structured JSON reduction units via `user-rust-anything` (`analyze` -> `bridge` -> `record` -> `diff` -> `fuzz` -> `gate`). | Preserve Apache-2.0 attribution in `NOTICE`; note intentional output-contract differences where `ArtifactEnvelope` supersedes upstream shapes. Do not port LLM/cloud summarizers. |
| `rtk-ai/rtk` | `https://github.com/rtk-ai/rtk` | `Apache-2.0` | Rust | **Permitted Architectural & Edge-Case Study:** Study deterministic CLI output reducer patterns (`cargo`, `git`, compiler diagnostics, ANSI stripping) directly in Rust. | Never invoke `rust-anything` to port Rust-to-Rust. Preserve Apache-2.0 attribution in `NOTICE` for any adapted patterns. |
| `JuliusBrussee/caveman` | `https://github.com/JuliusBrussee/caveman` | `Apache-2.0` | Markdown / Shell / JS | **Permitted Hook & Coexistence Study:** Inspect concise output-preservation rules and Claude Code / Cursor hook boundaries; ensure single-pass coexistence via transformation ledger. | Preserve Apache-2.0 attribution in `NOTICE`. Never rewrite raw user prompts or mutate stored originals. |
| `JuliusBrussee/caveman-code` | `https://github.com/JuliusBrussee/caveman-code` | `MIT` | TypeScript | **Permitted Inspection / Optional Unit Gate:** Inspect deterministic normalization and token-accounting helpers (`user-rea` / `user-rust-anything`). | Preserve MIT copyright notice in `NOTICE` if any code unit is ported. |
| `mksglu/context-mode` | `https://github.com/mksglu/context-mode` | `Elastic-2.0` | TypeScript | **BLOCKED / CLEAN-ROOM ONLY:** Excluded from cloning, source inspection for porting, translation, or code reuse due to Elastic License 2.0 managed/hosted restrictions. | Implement SQLite WAL + FTS5 lexical search, content-addressed `zstd` recovery, and session continuity 100% clean-room from our own ADRs (`docs/adrs/0001..0004`). |

## 3. Development Tooling Provenance

| Tool | Version Verified | License | Role | Runtime Dependency? |
| :--- | :--- | :--- | :--- | :--- |
| `erkamyaman/rust-anything` | `3.1.0` | `MIT` | Differential recording, fuzzing, benchmarking, and behavioral gating of selected Python/TS units into Rust (`src/port.rs`). | **No** (dev-only) |
| `morluto/rea` (`rea-agents`) | `6.10.1` | `MIT` | Static inspection of reference bundles and post-build PE/Rust binary hardening & symbol exposure audit (`inspect_rust_binary`, `inspect_binary_hardening`, `audit_release_exposure`). | **No** (dev-only) |

## 4. Rust Crate Dependency License Policy

All Cargo workspace dependencies must satisfy the permissive license allowlist (`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unicode-3.0`, `Zlib`):

| Crate | Purpose | License | Notes |
| :--- | :--- | :--- | :--- |
| `tokio` | Bounded async process capture, timeouts, cancellation | `MIT` | Scoped features (`rt-multi-thread`, `process`, `io-util`, `time`, `sync`, `macros`, `fs`) |
| `clap` | Unified CLI argument parser (`context-engine`) | `MIT OR Apache-2.0` | Derive-based subcommand validation |
| `serde`, `serde_json` | `ArtifactEnvelope`, JSON-RPC 2.0 MCP messages, structured JSON reducer | `MIT OR Apache-2.0` | Strict schema serialization |
| `rusqlite` (`bundled`) | Per-workspace SQLite WAL metadata, FTS5 search index, continuity journal | `MIT` (SQLite C core: Public Domain) | Bundled to guarantee FTS5 + deterministic SQLite version on Windows/Linux |
| `sha2`, `hex` | SHA-256 content addressing, `ArtifactId` minting, release checksums | `MIT OR Apache-2.0` | Cryptographic integrity checks |
| `zstd` | Fast lossless compression for private blob store | `MIT` (`libzstd`: `BSD-3-Clause OR GPL-2.0`, used under BSD) | Verified permissive BSD license path |
| `regex` | Pre-compiled `RegexSet` / `Regex` for `SecretGuard` and deterministic reducers | `MIT OR Apache-2.0` | Linear-time `O(n)` matching (immune to catastrophic backtracking ReDoS) |
| `dunce` | Canonical Windows paths without `\\?\` UNC verbatim prefix hazards | `CC0-1.0 OR MIT-0 OR Apache-2.0` | Critical for child-process `cwd` compatibility on Windows |
| `ignore` | Gitignore-aware workspace file traversal for `context_index` | `Unlicense OR MIT` | Respects workspace ignore boundaries |
| `tempfile` | Atomic temp-file write + sync + rename in `context-store` and isolated tests | `MIT OR Apache-2.0` | Crash-safe persistence |
| `thiserror` | Structured domain error contracts across workspace crates | `MIT OR Apache-2.0` | Zero-overhead `std::error::Error` impls |
| `tracing`, `tracing-subscriber` | Structured non-secret diagnostic telemetry | `MIT` | Never logs raw command payloads |
| `chrono` | ISO-8601 (`RFC 3339`) capture and journal timestamps | `MIT OR Apache-2.0` | UTC normalized timestamps |
| `proptest`, `criterion` | Property-based fuzz testing and micro-benchmarks (`dev-dependencies`) | `MIT OR Apache-2.0` | Test/bench only |
