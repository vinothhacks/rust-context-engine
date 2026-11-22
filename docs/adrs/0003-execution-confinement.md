# ADR 0003: Subprocess Execution Confinement and Filesystem Containment

- **Status:** Accepted
- **Date:** 2026-11-22
- **Deciders:** Rust Context Engine Architecture

## Context

`context_run` and `context_index` execute local commands and read workspace files on behalf of coding agents. Without strict execution confinement, an LLM tricked by untrusted repository content could invoke shell pipelines (`cmd /c`, `powershell -Command`, `sh -c`), delete files (`rm -rf`, `Remove-Item -Recurse -Force`, `git clean -fdx`), traverse outside the workspace via `..` or junctions/symlinks, read `~/.ssh` or `.env`, or leak host API keys from inherited environment variables.

## Decision

1. **Direct `argv` Execution (`allow_shell = false` by default):**
   - `context-execution` spawns commands strictly via `tokio::process::Command::new(&argv[0]).args(&argv[1..])`.
   - Shell interpreters (`cmd`, `cmd.exe`, `powershell`, `powershell.exe`, `pwsh`, `pwsh.exe`, `sh`, `bash`, `zsh`, `wsl`) are rejected unless an operator explicitly enables an elevated policy override outside normal MCP usage.

2. **Executable Allowlist & Destructive Argument Denylist:**
   - Default allowed base executables: `cargo`, `rustc`, `rustup`, `git`, `pytest`, `python`, `python3`, `node`, `npm`, `npx`, `pnpm`, `yarn`, `tsc`, `go`, `rg`, `dotnet`, `mvn`, `gradle`.
   - Default blocked commands and flag combinations:
     - Filesystem deletion/formatting: `rm`, `rmdir`, `del`, `erase`, `Remove-Item`, `format`, `diskpart`, `shred`.
     - Destructive Git mutations: `git reset --hard`, `git clean` with `-f`/`-d`/`-x`, `git push --force`, `git checkout -- .`.
     - Arbitrary network uploaders / remote script execution: `curl`, `wget`, `Invoke-WebRequest`, `Invoke-RestMethod`, `ssh`, `scp`, `nc`, `ncat`.

3. **Canonical Workspace & Symlink Containment (`dunce`):**
   - Working directories (`cwd`) and indexed file paths are resolved relative to the server-bound canonical workspace root using `dunce::canonicalize` (avoiding broken `\\?\` verbatim path handling in Windows child tools).
   - Every resolved path must be lexically and canonically inside `workspace_root`. Symlinks or Windows junctions pointing outside `workspace_root` are rejected (`ContextError::PathEscape`).
   - Sensitive file/directory denylist blocks direct indexing or reading of `.env`, `.env.*`, `*.pem`, `*.key`, `*.pfx`, `*.p12`, `id_rsa*`, `id_ed25519*`, `.ssh/`, `.aws/`, `.gnupg/`, `.kube/`, and `.npmrc` / `.pypirc`.

4. **Environment Scrubbing, Timeouts, and Process Cleanup:**
   - Child processes receive a scrubbed environment removing variables matching sensitive credential names (`*_API_KEY`, `*_SECRET*`, `*_TOKEN`, `*_PASSWORD`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) while preserving `PATH`, `RUSTUP_HOME`, `CARGO_HOME`, `SYSTEMROOT`, `TEMP`, `TMP`, `HOME`, `USERPROFILE`, and `TERM=dumb` / `NO_COLOR=1` where configured.
   - Every command executes under a mandatory wall-clock timeout (default `120s`, configurable up to hard policy ceiling) with `kill_on_drop(true)` and bounded per-stream capture limits.

## Consequences

- **Positive:** Prevents shell-metacharacter injection, accidental destructive commands, credential leakage via inherited env vars, and workspace escape on both Windows and POSIX systems.
- **Trade-off:** Commands requiring shell pipes (`foo | bar`) cannot be passed directly to `context_run`; instead, agents run `foo` through `context_run` and search/filter its captured output via `context_search` and `context_get`, which aligns directly with the Context Engine workflow.
