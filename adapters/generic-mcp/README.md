# Generic MCP & CLI Wrapper Kit (`context-engine`)

This directory provides **opt-in, project-scoped** integration assets for any coding agent that speaks standard MCP stdio JSON-RPC (Windsurf, Cline, Roo Code, Continue, Zed) as well as shell-only coding agents without MCP support (Aider, SWE-agent, custom terminal loops).

## Included Files

- `mcp-stdio.json.template` -> `<project-root>/.mcp.json` (or client-specific project MCP config)
  Standard `mcpServers` JSON stdio registration binding `["mcp", "--workspace", "{{WORKSPACE_PATH}}"]`.
- `wrappers/ce-run.ps1` -> `<project-root>/.context-engine/bin/ce-run.ps1`
  Safe PowerShell 5.1 / 7+ argv-forwarding wrapper for shell-only agents on Windows.
- `wrappers/ce-run.sh` -> `<project-root>/.context-engine/bin/ce-run.sh`
  Safe POSIX `sh` argv-forwarding wrapper (`exec`, zero `eval` / `sh -c`) for Linux, macOS, and WSL.

---

## Option A: One-Command Project Setup (Recommended)

Preview the generated bundle without writing files:

```powershell
context-engine setup --client generic-mcp --workspace "D:\path\to\your-project" --dry-run
```

Write the bundle into a project directory (or custom `--output-dir`):

```powershell
context-engine setup --client generic-mcp --workspace "D:\path\to\your-project"
```

---

## Option B: Host-Specific Project Setup

Substitute `{{BINARY_PATH}}` (JSON-escaped path to `context-engine.exe` / `context-engine`) and `{{WORKSPACE_PATH}}` (canonical `<project-root>` without trailing slash) in `mcp-stdio.json.template`, then place it in your client's project-scoped location:

- **Roo Code:** `<project-root>/.roo/mcp.json`
- **Continue:** `<project-root>/.continue/mcpServers/context-engine.json`
- **Cline / Windsurf:** Merge the `"context-engine"` object under `"mcpServers"` in your workspace MCP configuration.
- **Zed (`<project-root>/.zed/settings.json`):** Map the same binary and arguments under `"context_servers"`:
  ```json
  {
    "context_servers": {
      "context-engine": {
        "command": {
          "path": "D:/tools/context-engine/context-engine.exe",
          "args": ["mcp", "--workspace", "D:/projects/my-app"]
        }
      }
    }
  }
  ```

---

## Using `ce-run` with Shell-Only Agents (No MCP Required)

Coding agents that only execute shell commands can prefix noisy build/test/Git/search invocations with `ce-run.ps1` or `ce-run.sh`:

```powershell
# Windows PowerShell
.\.context-engine\bin\ce-run.ps1 cargo test --workspace
.\.context-engine\bin\ce-run.ps1 -- git diff --stat
```

```sh
# POSIX sh (Linux / macOS / WSL)
./.context-engine/bin/ce-run.sh cargo test --workspace
./.context-engine/bin/ce-run.sh -- pytest -q
```

Follow-up retrieval from the shell uses bounded ranges without re-running the test suite:

```powershell
context-engine search "assertion failed" --workspace "D:\projects\my-app"
context-engine get <artifact-id> --workspace "D:\projects\my-app" --stream stderr --lines 1:80
```

### Wrapper Safety Properties

1. **Pure `argv` Forwarding:** `ce-run.ps1` splats raw `$args` directly to `CreateProcess` (omitting `param()` so flags like `-p` or `--nocapture` are never intercepted by PowerShell), and `ce-run.sh` uses `exec "$CE_BIN" ... -- "$@"` with zero shell re-parsing.
2. **Exit Status Fidelity:** Returns the exact exit code reported by `context-engine run` (or `64` usage, `66` missing workspace, `127` missing binary).
3. **Recursion & Coexistence Guard:** Automatically unwraps direct nested calls to `context-engine`, `ce-run`, `headroom`, or `caveman` so outputs are never double-wrapped or double-reduced.
