# Rust Context Engine Architecture Notes

## Scope & Provenance Principles

Every artifact captured by `context-engine` is bound to a canonical server-resolved
workspace scope (`ws_<32-hex>`) and session identifier. Client requests cannot
escalate privileges by passing an alternate `project_scope` parameter.

## Storage Model

Raw `stdout` and `stderr` streams are compressed with Zstandard (`zstd`) and stored
atomically in `.context-engine/store/` keyed by their SHA-256 content digest.
Derived UTF-8 line indices allow fast bounded `context_get --lines start:end`
pagination without re-executing expensive test suites or builds.
