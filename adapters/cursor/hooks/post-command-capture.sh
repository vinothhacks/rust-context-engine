#!/usr/bin/env sh
# Opt-in Cursor afterShellExecution hook for Rust Context Engine (POSIX sh).
# Captures large raw shell outputs into the workspace-scoped blob store + FTS5 index
# while checking transformation ledger markers so outputs are never double-compressed.
# Fails open ({} + exit 0) on any error so developer terminal workflows are never disrupted.

set -u

emit_noop() {
    printf '{}\n'
    exit 0
}

if [ "${CONTEXT_ENGINE_DISABLE_HOOK:-0}" = "1" ]; then
    emit_noop
fi

BINARY_PATH="${1:-${CONTEXT_ENGINE_BIN:-}}"
WORKSPACE_PATH="${2:-${CONTEXT_ENGINE_WORKSPACE:-}}"

RAW_STDIN="$(cat 2>/dev/null || true)"
if [ -z "$RAW_STDIN" ]; then
    emit_noop
fi

# Transformation ledger & coexistence guard — NEVER double-compress reduced artifacts
if printf '%s' "$RAW_STDIN" | grep -Eq '(\[context-engine:reduced|x-context-engine-transformations:|"transformations"[[:space:]]*:[[:space:]]*\[|(strip_ansi|cargo_test|pytest_jest|compiler_diag|git_reducer|structured_json|log_dedup|search_hits|unknown_safe)@1|\[headroom|"headroom_ref"|\[caveman|<!--[[:space:]]*caveman)'; then
    emit_noop
fi

if printf '%s' "$RAW_STDIN" | grep -Eq '"schema_version"[[:space:]]*:[[:space:]]*1' &&
   printf '%s' "$RAW_STDIN" | grep -Eq '"artifact_id"[[:space:]]*:[[:space:]]*"a_[A-Za-z0-9_-]+"'; then
    emit_noop
fi

MIN_BYTES="${CONTEXT_ENGINE_MIN_CAPTURE_BYTES:-4096}"
case "$MIN_BYTES" in
    ''|*[!0-9]*) MIN_BYTES=4096 ;;
esac

PAYLOAD_BYTES="$(printf '%s' "$RAW_STDIN" | wc -c | tr -d '[:space:]')"
if [ "${PAYLOAD_BYTES:-0}" -lt "$MIN_BYTES" ]; then
    emit_noop
fi

if [ -z "$WORKSPACE_PATH" ]; then
    WORKSPACE_PATH="$(pwd -P 2>/dev/null || pwd)"
fi
WORKSPACE_PATH="${WORKSPACE_PATH%/}"
if [ ! -d "$WORKSPACE_PATH" ]; then
    emit_noop
fi
WORKSPACE_PATH="$(cd "$WORKSPACE_PATH" 2>/dev/null && pwd -P)" || emit_noop

if [ -z "$BINARY_PATH" ]; then
    if [ -x "$WORKSPACE_PATH/dist/context-engine" ]; then
        BINARY_PATH="$WORKSPACE_PATH/dist/context-engine"
    elif command -v context-engine >/dev/null 2>&1; then
        BINARY_PATH="$(command -v context-engine)"
    fi
fi

if [ -z "$BINARY_PATH" ] || [ ! -x "$BINARY_PATH" ]; then
    emit_noop
fi

# Extract .output, .command, .cwd, and .conversation_id safely using node or python3 when available
EXTRACTED_OUTPUT=""
SESSION_ID=""

if command -v node >/dev/null 2>&1; then
    PARSED_META="$(printf '%s' "$RAW_STDIN" | WORKSPACE_BOUND="$WORKSPACE_PATH" node -e '
        const fs = require("node:fs");
        const path = require("node:path");
        try {
            const raw = fs.readFileSync(0, "utf8");
            const data = JSON.parse(raw);
            const cmd = String(data.command || "");
            if (/(^|[\\/\s"'\''&|;])(context-engine(\.exe)?|ce-run(\.ps1|\.sh)?|headroom|caveman)(\s|$|"|'\'')/i.test(cmd)) process.exit(2);
            if (/(^|[\s"'\''\\/])(\.env(\.[A-Za-z0-9_.-]+)?|id_rsa|id_ed25519|\.ssh|\.aws|\.npmrc|\.netrc)([\s"'\''\\/]|$)|\.(pem|key|pfx|p12)([\s"'\'']|$)/i.test(cmd)) process.exit(2);
            if (data.cwd && fs.existsSync(data.cwd)) {
                const ws = fs.realpathSync(process.env.WORKSPACE_BOUND);
                const cwd = fs.realpathSync(data.cwd);
                if (cwd !== ws && !cwd.startsWith(ws + path.sep)) process.exit(2);
            }
            const out = typeof data.output === "string" ? data.output : "";
            const sid = /^[A-Za-z0-9_.-]{1,128}$/.test(String(data.conversation_id || "")) ? String(data.conversation_id) : "";
            process.stdout.write(sid + "\n" + out);
        } catch {
            process.exit(2);
        }
    ' 2>/dev/null)" || emit_noop

    SESSION_ID="$(printf '%s' "$PARSED_META" | sed -n '1p')"
    EXTRACTED_OUTPUT="$(printf '%s' "$PARSED_META" | sed '1d')"
elif command -v python3 >/dev/null 2>&1; then
    PARSED_META="$(printf '%s' "$RAW_STDIN" | WORKSPACE_BOUND="$WORKSPACE_PATH" python3 -c '
import json, os, re, sys
try:
    data = json.loads(sys.stdin.read())
    cmd = str(data.get("command") or "")
    if re.search(r"(^|[\\/\s\"'\''&|;])(context-engine(\.exe)?|ce-run(\.ps1|\.sh)?|headroom|caveman)(\s|$|\"|'\'')", cmd, re.I):
        sys.exit(2)
    if re.search(r"(^|[\s\"'\''\\/])(\.env(\.[A-Za-z0-9_.-]+)?|id_rsa|id_ed25519|\.ssh|\.aws|\.npmrc|\.netrc)([\s\"'\''\\/]|$)|\.(pem|key|pfx|p12)([\s\"'\'']|$)", cmd, re.I):
        sys.exit(2)
    cwd = data.get("cwd")
    if cwd and os.path.isdir(cwd):
        ws = os.path.realpath(os.environ["WORKSPACE_BOUND"])
        rcwd = os.path.realpath(cwd)
        if rcwd != ws and not rcwd.startswith(ws + os.sep):
            sys.exit(2)
    out = data.get("output") if isinstance(data.get("output"), str) else ""
    sid_raw = str(data.get("conversation_id") or "")
    sid = sid_raw if re.match(r"^[A-Za-z0-9_.-]{1,128}$", sid_raw) else ""
    sys.stdout.write(sid + "\n" + out)
except Exception:
    sys.exit(2)
    ' 2>/dev/null)" || emit_noop

    SESSION_ID="$(printf '%s' "$PARSED_META" | sed -n '1p')"
    EXTRACTED_OUTPUT="$(printf '%s' "$PARSED_META" | sed '1d')"
else
    emit_noop
fi

OUT_BYTES="$(printf '%s' "$EXTRACTED_OUTPUT" | wc -c | tr -d '[:space:]')"
if [ "${OUT_BYTES:-0}" -lt "$MIN_BYTES" ]; then
    emit_noop
fi

# Invoke context-engine via explicit argv vector (never eval or sh -c)
if [ -n "$SESSION_ID" ]; then
    printf '%s' "$EXTRACTED_OUTPUT" | "$BINARY_PATH" index --stdin --workspace "$WORKSPACE_PATH" --label "cursor-afterShellExecution" --session "$SESSION_ID" >/dev/null 2>&1 || true
else
    printf '%s' "$EXTRACTED_OUTPUT" | "$BINARY_PATH" index --stdin --workspace "$WORKSPACE_PATH" --label "cursor-afterShellExecution" >/dev/null 2>&1 || true
fi

emit_noop
