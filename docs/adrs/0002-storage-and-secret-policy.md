# ADR 0002: Content-Addressed Storage and Pre-Index Secret Policy

- **Status:** Accepted
- **Date:** 2026-11-22
- **Deciders:** Rust Context Engine Architecture

## Context

Captured command outputs (`cargo test`, application logs, environment dumps, `git diff`) routinely contain accidental credentials (API keys, cloud tokens, JWTs, database URLs, PEM private keys, `.env` values). If secrets are redacted only in the compact summary while raw or unredacted text is inserted into SQLite FTS5, an agent can reconstruct secrets through lexical search (`context_search`) or range reads (`context_get`). At the same time, legitimate non-sensitive test outputs must support 100% byte-exact recovery with minimal disk footprint and crash safety on Windows and Linux.

## Decision

1. **Deterministic Pre-Storage / Pre-Index `SecretGuard` in `context-core`:**
   - Every captured stream and indexed document passes through `SecretGuard::inspect_bytes` / `SecretGuard::redact_text` **before** view reduction, FTS5 indexing, journal recording, or blob persistence decisions.
   - Detection rules use linear-time compiled `regex::RegexSet` and `regex::Regex` (zero backtracking ReDoS risk) plus deterministic Shannon-entropy token checks for secret assignments, covering:
     - PEM private keys (`-----BEGIN ... PRIVATE KEY-----`)
     - AWS access key IDs (`AKIA...`, `ASIA...`) and secret key assignments
     - Google Cloud (`AIza...`) and service-account private key fields
     - GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`)
     - GitLab tokens (`glpat-`, `glptt-`, `gldt-`)
     - OpenAI (`sk-proj-...`, `sk-...`) and Anthropic (`sk-ant-...`) API keys
     - Slack tokens (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`) and webhook URLs
     - HTTP `Authorization: Bearer ...`, `Basic ...`, and 3-part `eyJ...` JWTs
     - Credentialed connection URIs (`postgres://user:pass@`, `mysql://`, `mongodb+srv://`, `redis://`, `amqp://`)
     - `.env` / shell / YAML / JSON sensitive key assignments (`*_SECRET*`, `*_TOKEN*`, `*_PASSWORD*`, `*_API_KEY*`, `PRIVATE_KEY*`) including high-entropy secret values
   - Replacement tokens are deterministic and non-reversible: `[REDACTED:<RULE_ID>]`, recording rule counts and byte spans without storing raw secret substrings in metadata.

2. **Three Enforceable `SecretPolicyMode` Levels:**
   - `RedactBeforeIndex` (Default): Compact views, session journals, and SQLite FTS5 chunks **always** receive redacted text (`[REDACTED:<RULE_ID>]`). If no secrets were detected, exact raw bytes are stored in `context-store` and retrievable via `context_get`. If secrets were detected, `context_get` serves only sanitized/redacted content to agent callers unless raw secret storage was explicitly authorized by local policy; raw secret substrings **never** enter FTS5.
   - `Quarantine`: Secret-bearing streams are quarantined—compact views and FTS5 receive `[REDACTED:<RULE_ID>]`, `originals_available` for agent retrieval is marked `false` (quarantined), and `context_get` refuses unredacted recovery.
   - `Deny`: Any detected secret immediately aborts persistence and indexing (`ContextError::SecretPolicyDenied`), writing zero bytes to disk or SQLite.

3. **Crash-Safe Content-Addressed Store (`context-store`):**
   - Blobs are stored under `<workspace>/.context-engine/store/blobs/<2-hex-prefix>/<sha256>.zst`.
   - Write protocol: create temp file in `.context-engine/store/tmp/` -> compress with `zstd` -> flush & `sync_all()` -> verify decompressed/input SHA-256 -> atomic rename to final digest path.
   - Directory permissions are locked down at creation time (Windows owner-only DACL via `icacls` / Win32 security attributes; Unix `0700` / `0600`).

4. **SQLite WAL + Sanitized FTS5 (`context-search`):**
   - Per-workspace SQLite database (`.context-engine/index.db`) configured with `PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;`.
   - FTS5 virtual tables index exclusively `SecretGuard`-sanitized UTF-8 text chunks.

## Consequences

- **Positive:** Guarantees by construction that `context_search` (`bm25()`) and compact summaries cannot leak detected secrets, while preserving 100% byte-for-byte SHA-256 fidelity on clean build/test outputs.
- **Trade-off:** Overly aggressive entropy rules could redact long random hashes (such as git commit SHAs or SHA-256 digests); therefore `SecretGuard` explicitly exempts pure hex digests (`40`/`64` hex chars without secret key context) and `a_<64-hex>` artifact IDs to preserve debugging utility.
