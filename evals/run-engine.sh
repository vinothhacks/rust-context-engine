#!/usr/bin/env bash
# Reproducible Context Engine evaluation launcher for POSIX / Git-Bash environments (evals/run-engine.sh).
# Delegates to pwsh / powershell `evals/run-evals.ps1` when available, or drives `context-engine` via Python 3.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_PATH="${CONTEXT_ENGINE_BIN:-${REPO_ROOT}/target/wave4-e2e/release/context-engine}"
if [[ ! -f "${BIN_PATH}" && -f "${BIN_PATH}.exe" ]]; then
  BIN_PATH="${BIN_PATH}.exe"
elif [[ ! -f "${BIN_PATH}" && -f "${REPO_ROOT}/dist/context-engine.exe" ]]; then
  BIN_PATH="${REPO_ROOT}/dist/context-engine.exe"
elif [[ ! -f "${BIN_PATH}" && -f "${REPO_ROOT}/dist/context-engine" ]]; then
  BIN_PATH="${REPO_ROOT}/dist/context-engine"
fi

if command -v pwsh >/dev/null 2>&1; then
  exec pwsh -NoProfile -File "${SCRIPT_DIR}/run-evals.ps1" -BinaryPath "${BIN_PATH}"
elif command -v powershell >/dev/null 2>&1; then
  exec powershell -NoProfile -ExecutionPolicy Bypass -File "${SCRIPT_DIR}/run-evals.ps1" -BinaryPath "${BIN_PATH}"
else
  echo "Running lightweight CLI verification against ${BIN_PATH}..." >&2
  "${BIN_PATH}" doctor --workspace "${REPO_ROOT}" --json
fi
