# Cursor Integration Kit (`context-engine`)

This directory provides **strictly opt-in, project-scoped** integration templates for [Cursor IDE](https://cursor.com). Nothing is ever installed into `~/.cursor/` automatically; all files bind to a single target project workspace (`<project-root>/.cursor/`).

## Included Files

- `mcp.json.template` -> `<project-root>/.cursor/mcp.json`
  Registers the server-scoped stdio MCP server (`context-engine mcp --workspace <project-root>`).
- `rules/context-engine.mdc` -> `<project-root>/.cursor/rules/context-engine.mdc`
  Project rule instructing the Cursor agent to prefer `context_run`, inspect compact `ArtifactEnvelope` views first, use `context_search` / bounded `context_get` (`lines` or `bytes` ranges) instead of re-running commands, and call `context_resume` after context compaction.
- `hooks/hooks.json.template` -> `<project-root>/.cursor/hooks.json` *(optional)*
  Opt-in `afterShellExecution` hook configuration.
- `hooks/post-command-capture.ps1` & `hooks/post-command-capture.sh` -> `<project-root>/.cursor/hooks/` *(optional)*
  Non-invasive post-command capture wrappers for Windows PowerShell and POSIX `sh` that check `view.transformations` ledger markers so outputs are never double-compressed.

---

## Option A: One-Command Project Setup (Recommended)

Preview the generated files first without writing to disk:

```powershell
context-engine setup --client cursor --workspace "D:\path\to\your-project" --dry-run
```

Write the project-scoped configuration into `<project-root>/.cursor/`:

```powershell
context-engine setup --client cursor --workspace "D:\path\to\your-project"
```

---

## Option B: Manual Opt-In Setup

### 1. Register the Workspace-Scoped MCP Server

Copy `mcp.json.template` to `<project-root>/.cursor/mcp.json` (or merge the `"context-engine"` entry into your existing `.cursor/mcp.json`) and replace the two template placeholders:

- `{{BINARY_PATH}}`: Absolute path to `context-engine.exe` (Windows) or `context-engine` (macOS/Linux), using JSON-escaped backslashes (`\\`) or forward slashes (`/`).
- `{{WORKSPACE_PATH}}`: Canonical path to `<project-root>` without a trailing slash.

Example (`<project-root>/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "context-engine": {
      "command": "D:/tools/context-engine/context-engine.exe",
      "args": ["mcp", "--workspace", "D:/projects/my-app"]
    }
  }
}
```

### 2. Install the Compact-First Cursor Rule

Copy `rules/context-engine.mdc` verbatim to `<project-root>/.cursor/rules/context-engine.mdc` (no placeholder substitution required).

### 3. (Optional) Enable Post-Command Capture Hook

If you also want large native terminal runs in Cursor (`>= 4096` bytes) automatically indexed into `.context-engine/` for `context_search` and `context_get`:

1. Copy `hooks/post-command-capture.ps1` (Windows) or `hooks/post-command-capture.sh` (`chmod +x` on macOS/Linux) into `<project-root>/.cursor/hooks/`.
2. Copy `hooks/hooks.json.template` to `<project-root>/.cursor/hooks.json` and substitute `{{BINARY_PATH}}` and `{{WORKSPACE_PATH}}`.
   - **Windows (default in template):** invokes `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "<project-root>/.cursor/hooks/post-command-capture.ps1" -BinaryPath "<binary>" -WorkspacePath "<project-root>"`
   - **macOS / Linux:** replace the `"command"` value with:
     ```json
     "sh \"{{WORKSPACE_PATH}}/.cursor/hooks/post-command-capture.sh\" \"{{BINARY_PATH}}\" \"{{WORKSPACE_PATH}}\""
     ```

---

## Single-Pass & Coexistence Guarantees

- **Transformation Ledger Check:** Both hook scripts inspect outputs for `transformations` arrays, `@1` reducer tags (`strip_ansi@1`, `cargo_test@1`, `compiler_diag@1`, `git_reducer@1`, etc.), `[context-engine:reduced`, `[headroom`, and `[caveman` markers before indexing, preventing double-compression.
- **Zero Recursion:** Any command invoking `context-engine`, `ce-run`, `headroom`, or `caveman` is skipped automatically.
- **Secret & Path Protection:** Commands touching `.env*`, `*.pem`, `*.key`, `.ssh`, `.aws`, or running outside `{{WORKSPACE_PATH}}` are skipped; `SecretGuard` additionally redacts secrets prior to FTS5 indexing.
- **Fail-Open Terminal Safety:** Hook errors or missing binaries always return `{}` with exit status `0`. Set `CONTEXT_ENGINE_DISABLE_HOOK=1` to bypass the hook temporarily.

## Verification & Uninstall

- Reload Cursor's MCP servers for the project and call `context_doctor` to confirm workspace confinement, SQLite WAL + FTS5 health, and blob store permissions.
- To remove the integration from a project, delete the `"context-engine"` entry from `<project-root>/.cursor/mcp.json`, remove `<project-root>/.cursor/rules/context-engine.mdc`, and (if enabled) remove the hook entry from `<project-root>/.cursor/hooks.json`.
