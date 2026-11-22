# OpenCode Integration Kit (`context-engine`)

This directory provides **opt-in, project-scoped** integration templates for [OpenCode](https://opencode.ai). Nothing is installed globally into `~/.config/opencode/`; all configuration stays inside `<project-root>/`.

## Included Files

- `opencode.json.template` -> `<project-root>/opencode.json`
  Registers the local stdio MCP server (`["{{BINARY_PATH}}", "mcp", "--workspace", "{{WORKSPACE_PATH}}"]`), configures explicit tool permissions for the 7 `context-engine_context_*` tools, and wires the opt-in local plugin.
- `plugin/context-engine-plugin.mjs` -> `<project-root>/.opencode/plugin/context-engine-plugin.mjs`
  Verified OpenCode `tool.execute.after` adapter that captures large `bash`/`read` outputs (`>= 4096` bytes) via `context-engine index --stdin` and exposes `invokeContextEngineRun` for explicit `argv`-vector runs.

---

## Option A: One-Command Project Setup (Recommended)

Preview the generated files first:

```powershell
context-engine setup --client opencode --workspace "D:\path\to\your-project" --dry-run
```

Write `<project-root>/opencode.json` and `<project-root>/.opencode/plugin/context-engine-plugin.mjs`:

```powershell
context-engine setup --client opencode --workspace "D:\path\to\your-project"
```

---

## Option B: Manual Opt-In Setup

1. Copy `plugin/context-engine-plugin.mjs` verbatim to `<project-root>/.opencode/plugin/context-engine-plugin.mjs`.
2. Copy `opencode.json.template` to `<project-root>/opencode.json` (or merge `"mcp"`, `"plugin"`, and `"permission"` into your existing `opencode.json`) and substitute:
   - `{{BINARY_PATH}}`: Path to `context-engine.exe` / `context-engine` (JSON-escaped `\\` or `/`).
   - `{{WORKSPACE_PATH}}`: Canonical `<project-root>` path without a trailing slash.
3. *(MCP-only mode)* If you prefer explicit MCP tool calls without automatic `bash`/`read` post-capture, omit the `"plugin"` array entry in `opencode.json` and do not copy `context-engine-plugin.mjs`.
4. *(Stricter approval mode)* Change `"context-engine_context_run": "allow"` to `"ask"` in `opencode.json` if you want manual per-command confirmation on top of `context-engine`'s built-in executable allowlist.

---

## Security & Single-Pass Guarantees

- **Zero Shell Interpolation:** `context-engine-plugin.mjs` invokes `execFileSync(binaryPath, argvArray, { shell: false })` exclusively. Passing a non-array command string to `invokeContextEngineRun` throws a `TypeError` immediately.
- **Single-Pass Ledger Check:** Any output already carrying `view.transformations`, `[context-engine:reduced`, `[headroom`, or `[caveman` markers (or `metadata.contextEngine`) is passed through untouched.
- **Workspace & Secret Confinement:** Canonical `fs.realpathSync` checks prevent indexing files outside `<project-root>`, and `.env*`, `*.pem`, `*.key`, `.ssh`, and `.aws` paths are skipped before invocation.
- **Fail-Open Reliability:** Any missing binary or timeout leaves OpenCode's original tool output intact. Set `CONTEXT_ENGINE_DISABLE_HOOK=1` to temporarily disable plugin capture.
