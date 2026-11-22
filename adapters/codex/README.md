# Codex CLI Integration Kit (`context-engine`)

This directory provides **opt-in, project-scoped** integration files for OpenAI Codex CLI. It never touches `~/.codex/config.toml`; configuration is scoped strictly to `<project-root>/.codex/config.toml` and `<project-root>/AGENTS.md`.

## Included Files

- `config.toml.template` -> `<project-root>/.codex/config.toml`
  Registers `[mcp_servers.context_engine]` binding `command = "{{BINARY_PATH}}"` and `args = ["mcp", "--workspace", "{{WORKSPACE_PATH}}"]`.
- `AGENTS.snippet.md` -> append to `<project-root>/AGENTS.md`
  Project instructions guiding Codex to use `context_run`, `context_search`, bounded `context_get`, `context_index`, and `context_resume`.

---

## Option A: One-Command Project Setup (Recommended)

Preview the rendered TOML and instructions without writing to disk:

```powershell
context-engine setup --client codex --workspace "D:\path\to\your-project" --dry-run
```

Write `<project-root>/.codex/config.toml`:

```powershell
context-engine setup --client codex --workspace "D:\path\to\your-project"
```

---

## Option B: Manual Opt-In Setup

1. Copy `config.toml.template` into `<project-root>/.codex/config.toml` (or append the `[mcp_servers.context_engine]` table to your existing project `.codex/config.toml`) and replace:
   - `{{BINARY_PATH}}`: Absolute path to `context-engine.exe` / `context-engine`.
     *Note on TOML escaping:* Because `command` and `args` use double-quoted TOML basic strings, format Windows paths using forward slashes (`"D:/tools/context-engine.exe"`) or escaped backslashes (`"D:\\tools\\context-engine.exe"`), without a trailing slash on `{{WORKSPACE_PATH}}`.
   - `{{WORKSPACE_PATH}}`: Canonical path to `<project-root>`.
2. Append `AGENTS.snippet.md` to `<project-root>/AGENTS.md` so Codex routes noisy build/test/Git/log commands through `context_engine` tools automatically.

Example (`<project-root>/.codex/config.toml`):

```toml
[mcp_servers.context_engine]
command = "D:/tools/context-engine/context-engine.exe"
args = ["mcp", "--workspace", "D:/projects/my-app"]
startup_timeout_sec = 10
tool_timeout_sec = 120
enabled = true
```

## Verification & Uninstall

- Launch Codex inside `<project-root>` and ask it to run `context_doctor` to verify workspace binding and storage permissions.
- To remove, delete the `[mcp_servers.context_engine]` block from `<project-root>/.codex/config.toml` and remove the snippet from `<project-root>/AGENTS.md`.
