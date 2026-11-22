# Claude Code Integration Kit (`context-engine`)

This directory contains **opt-in, project-scoped** integration files for Claude Code. It never modifies `~/.claude/settings.json`, `~/.claude/CLAUDE.md`, or existing global plugins (`caveman`, `headroom`).

## Included Files

- `.mcp.json.template` -> `<project-root>/.mcp.json`
  Registers the server-scoped stdio MCP server (`context-engine mcp --workspace <project-root>`).
- `SKILL.md` -> `<project-root>/.claude/skills/context-engine/SKILL.md`
  Project skill teaching Claude Code the compact-first loop (`context_run` -> `ArtifactEnvelope` -> `context_search` / bounded `context_get` -> `context_resume`).
- `CLAUDE.snippet.md` -> append to `<project-root>/CLAUDE.md` *(optional)*
  Concise repository-level instructions for `context-engine` tool routing.
- `hooks/settings.hooks.json.template` -> merge into `<project-root>/.claude/settings.local.json` *(optional)*
  Opt-in `PostToolUse` hook configuration matching `Bash|Read`.
- `hooks/post-tool-reduce.mjs` -> `<project-root>/.claude/hooks/post-tool-reduce.mjs` *(optional)*
  Cross-platform Node 24 zero-dependency `PostToolUse` hook script.

---

## Option A: One-Command Project Setup (Recommended)

Preview the rendered configuration without writing files:

```powershell
context-engine setup --client claude-code --workspace "D:\path\to\your-project" --dry-run
```

Install into `<project-root>/`:

```powershell
context-engine setup --client claude-code --workspace "D:\path\to\your-project"
```

---

## Option B: Manual Opt-In Setup

### 1. Register the Workspace-Scoped MCP Server

Copy `.mcp.json.template` to `<project-root>/.mcp.json` (or merge `"context-engine"` under `"mcpServers"`) and substitute:

- `{{BINARY_PATH}}`: Path to `context-engine.exe` / `context-engine` (JSON-escaped `\\` or `/` separators).
- `{{WORKSPACE_PATH}}`: Canonical `<project-root>` path without a trailing slash.

### 2. Install the Project Skill & `CLAUDE.md` Guidance

1. Copy `SKILL.md` to `<project-root>/.claude/skills/context-engine/SKILL.md`.
2. *(Optional)* Append `CLAUDE.snippet.md` to `<project-root>/CLAUDE.md`.

### 3. (Optional) Enable the Node 24 `PostToolUse` Hook

1. Copy `hooks/post-tool-reduce.mjs` to `<project-root>/.claude/hooks/post-tool-reduce.mjs`.
2. Merge `hooks/settings.hooks.json.template` (after replacing `{{BINARY_PATH}}` and `{{WORKSPACE_PATH}}`) into `<project-root>/.claude/settings.local.json`.

---

## Coexistence with `caveman` and `headroom`

`hooks/post-tool-reduce.mjs` and `SKILL.md` are explicitly engineered to run side-by-side with global `caveman` and `headroom` installations without conflicts:

1. **Never Rewrites User Prompts:** Only listens on `PostToolUse` for `Bash|Read`. It never registers on `UserPromptSubmit` or mutates user messages.
2. **Single-Pass Transformation Ledger:** Inspects both JSON envelopes and plain text for `transformations` arrays, `@1` reducer tags (`strip_ansi@1`, `cargo_test@1`, `compiler_diag@1`, etc.), and `[context-engine:reduced` headers before indexing.
3. **Headroom & Caveman Marker Detection:** Automatically skips outputs carrying `[headroom`, `"headroom_ref"`, `"smart_crusher"`, `"kompress"`, `CCR-` tokens, `[caveman`, `<!-- caveman`, or `caveman-compress` markers—preventing double-compression.
4. **Argv-Safe Subprocess Calls:** Uses `node:child_process` `execFileSync` with `shell: false`, scrubbed environment variables, canonical `fs.realpathSync` workspace confinement, and sensitive-path blocking (`.env*`, `*.pem`, `*.key`, `.ssh`, `.aws`).

## Runtime Environment Overrides

- `CONTEXT_ENGINE_DISABLE_HOOK=1`: Bypass `post-tool-reduce.mjs` immediately.
- `CONTEXT_ENGINE_MIN_CAPTURE_BYTES=4096`: Minimum UTF-8 payload size before indexing `Bash`/`Read` output (default `4096`).
- `CONTEXT_ENGINE_HOOK_SILENT=1`: Index eligible outputs into `.context-engine/` silently without emitting `additionalContext` notes.

## Verification & Uninstall

- Run `/mcp` inside Claude Code and invoke `mcp__context-engine__context_doctor`.
- To uninstall from a project, remove `"context-engine"` from `<project-root>/.mcp.json`, delete `<project-root>/.claude/skills/context-engine/`, and remove the hook entry from `<project-root>/.claude/settings.local.json`.
