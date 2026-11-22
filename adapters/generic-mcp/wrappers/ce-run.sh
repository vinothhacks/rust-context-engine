#!/usr/bin/env sh
# Safe argv-forwarding CLI wrapper for shell-only coding agents (POSIX sh).
# Forwards "$@" directly as an argv vector to `context-engine run -- ...` via `exec`
# without `eval` or `sh -c` string interpolation, preserving exact exit codes.

set -eu

usage() {
    printf 'Usage: ce-run.sh [--] <program> [args...]\n' >&2
    printf 'Environment overrides: CONTEXT_ENGINE_BIN, CONTEXT_ENGINE_WORKSPACE, CONTEXT_ENGINE_SESSION, CONTEXT_ENGINE_TIMEOUT_MS\n' >&2
}

if [ "$#" -eq 0 ]; then
    usage
    exit 64
fi

if [ "$#" -eq 1 ] && { [ "$1" = "--help" ] || [ "$1" = "-h" ]; }; then
    usage
    exit 0
fi

if [ "$1" = "--" ]; then
    shift
    if [ "$#" -eq 0 ]; then
        usage
        exit 64
    fi
fi

FIRST_PROG="$1"
if [ -z "$FIRST_PROG" ]; then
    usage
    exit 64
fi

# Recursion & coexistence guard: never double-wrap context-engine, ce-run, headroom, or caveman
BASE_PROG="${FIRST_PROG##*/}"
BASE_PROG="${BASE_PROG%.exe}"
BASE_PROG="${BASE_PROG%.sh}"
BASE_PROG="${BASE_PROG%.ps1}"

case "$BASE_PROG" in
    context-engine|ce-run|headroom|caveman)
        exec "$@"
        ;;
esac

CE_WORKSPACE="${CONTEXT_ENGINE_WORKSPACE:-}"
if [ -z "$CE_WORKSPACE" ]; then
    CE_WORKSPACE="$(pwd -P 2>/dev/null || pwd)"
fi
CE_WORKSPACE="${CE_WORKSPACE%/}"
if [ ! -d "$CE_WORKSPACE" ]; then
    printf 'ce-run.sh: workspace directory does not exist: %s\n' "$CE_WORKSPACE" >&2
    exit 66
fi
CE_WORKSPACE="$(cd "$CE_WORKSPACE" && pwd -P)"

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
CE_BIN="${CONTEXT_ENGINE_BIN:-}"

if [ -z "$CE_BIN" ] || [ ! -x "$CE_BIN" ]; then
    if [ -x "$CE_WORKSPACE/dist/context-engine" ]; then
        CE_BIN="$CE_WORKSPACE/dist/context-engine"
    elif [ -x "$CE_WORKSPACE/dist/context-engine.exe" ]; then
        CE_BIN="$CE_WORKSPACE/dist/context-engine.exe"
    elif [ -x "$SCRIPT_DIR/../../../dist/context-engine" ]; then
        CE_BIN="$SCRIPT_DIR/../../../dist/context-engine"
    elif command -v context-engine >/dev/null 2>&1; then
        CE_BIN="$(command -v context-engine)"
    fi
fi

if [ -z "$CE_BIN" ] || [ ! -x "$CE_BIN" ]; then
    printf 'ce-run.sh: context-engine binary not found. Set CONTEXT_ENGINE_BIN or build dist/context-engine.\n' >&2
    exit 127
fi

# Prepend context-engine flags safely onto "$@" without losing boundary quoting
if [ -n "${CONTEXT_ENGINE_TIMEOUT_MS:-}" ]; then
    case "$CONTEXT_ENGINE_TIMEOUT_MS" in
        *[!0-9]*|'') ;;
        *) set -- --timeout-ms "$CONTEXT_ENGINE_TIMEOUT_MS" "--" "$@" ;;
    esac
fi

if [ "$1" != "--" ] && [ "$1" != "--timeout-ms" ]; then
    set -- "--" "$@"
fi

if [ -n "${CONTEXT_ENGINE_SESSION:-}" ]; then
    case "$CONTEXT_ENGINE_SESSION" in
        *[!A-Za-z0-9_.-]*|'') ;;
        *) set -- --session "$CONTEXT_ENGINE_SESSION" "$@" ;;
    esac
fi

exec "$CE_BIN" run --workspace "$CE_WORKSPACE" "$@"
