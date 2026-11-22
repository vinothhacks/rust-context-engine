#!/usr/bin/env bash
# Reproducible uncached Baseline measurement script (evals/run-baseline.sh).
# Measures raw tool-output bytes and estimated tokens (ceil(bytes / 4)) across all 20 tasks in evals/tasks.jsonl.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TASKS_FILE="${SCRIPT_DIR}/tasks.jsonl"

python3 - "${REPO_ROOT}" "${TASKS_FILE}" <<'PY'
import json, math, pathlib, sys

repo_root = pathlib.Path(sys.argv[1])
tasks_file = pathlib.Path(sys.argv[2])

rows = []
for line in tasks_file.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    t = json.loads(line)
    raw_bytes = 0
    raw_text_parts = []
    for key in ("stdout_fixture", "stderr_fixture", "doc_fixture"):
        rel = t.get(key)
        if rel:
            data = (repo_root / rel).read_bytes()
            raw_bytes += len(data)
            raw_text_parts.append(data.decode("utf-8", errors="replace"))
    combined = "\n".join(raw_text_parts)
    tokens = math.ceil(raw_bytes / 4) if raw_bytes > 0 else 0
    rows.append({
        "task_id": t["task_id"],
        "category": t["category"],
        "baseline_bytes": raw_bytes,
        "baseline_tokens": tokens,
    })

print(json.dumps({"suite": "baseline", "task_count": len(rows), "tasks": rows}, indent=2))
PY
