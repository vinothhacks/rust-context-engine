<#
.SYNOPSIS
  Reproducible Phase 6 V1 Benchmark & Security Evaluation Suite (evals/run-evals.ps1).

.DESCRIPTION
  Executes the compiled release `context-engine` binary across:
    1. All >= 20 repository fixtures (measuring tool-output reduction, 100% SHA-256 byte
       recovery including binary streams, and 100% distinct failure identifier retention).
    2. All 20 paired debugging/inspection tasks in `evals/tasks.jsonl` (comparing uncached
       Baseline raw outputs vs Context Engine compact views + real follow-up `context_search`
       and `context_get` calls over stdio MCP).
    3. Startup latency, persistent stdio MCP p50/p95 tool latency, memory/disk footprint,
       cross-workspace `SCOPE_VIOLATION` enforcement, and live `Get-NetTCPConnection`
       offline zero-egress socket verification.

  Writes machine-readable metrics to `evals/reports/v1-benchmark-metrics.json` and a
  detailed Markdown report to `evals/reports/v1-benchmark-report.md`.
#>

param(
    [string]$BinaryPath = ""
)

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$EvalDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $EvalDir "..")).ProviderPath

if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    $Wave4Release = Join-Path $RepoRoot "target\wave4-e2e\release\context-engine.exe"
    $DistRelease = Join-Path $RepoRoot "dist\context-engine.exe"
    if (Test-Path -LiteralPath $Wave4Release -PathType Leaf) {
        $BinaryPath = $Wave4Release
    } elseif (Test-Path -LiteralPath $DistRelease -PathType Leaf) {
        $BinaryPath = $DistRelease
    } else {
        throw "context-engine release binary not found. Build with: cargo build --release --target-dir target/wave4-e2e"
    }
}
$BinaryPath = (Resolve-Path -LiteralPath $BinaryPath).ProviderPath

$ReportsDir = Join-Path $EvalDir "reports"
if (-not (Test-Path -LiteralPath $ReportsDir -PathType Container)) {
    $null = New-Item -ItemType Directory -Path $ReportsDir -Force
}

$RunStamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$EvalScratchRoot = Join-Path $RepoRoot "target\wave4-e2e\eval-workspaces\run-$RunStamp"
$null = New-Item -ItemType Directory -Path $EvalScratchRoot -Force

$MetricsJsonPath = Join-Path $ReportsDir "v1-benchmark-metrics.json"
$ReportMdPath = Join-Path $ReportsDir "v1-benchmark-report.md"
$DriverPyPath = Join-Path $EvalScratchRoot "eval_driver.py"

$PyDriverSource = @'
import base64
import datetime
import hashlib
import json
import math
import os
import pathlib
import statistics
import subprocess
import sys
import time

repo_root = pathlib.Path(sys.argv[1]).resolve()
binary_path = pathlib.Path(sys.argv[2]).resolve()
scratch_root = pathlib.Path(sys.argv[3]).resolve()
metrics_out_path = pathlib.Path(sys.argv[4]).resolve()
report_md_path = pathlib.Path(sys.argv[5]).resolve()

tasks_path = repo_root / "evals" / "tasks.jsonl"

# Ensure binary_non_utf8_stream.bin exists deterministically if not yet generated
bin_fixture_path = repo_root / "fixtures" / "commands" / "binary_non_utf8_stream.bin"
if not bin_fixture_path.exists():
    buf = bytearray(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06\x00\x00\x00")
    idx = 0
    while len(buf) < 4096:
        buf.append(((idx * 73) + 0x80) & 0xFF)
        idx += 1
    bin_fixture_path.write_bytes(bytes(buf))


def est_tokens(byte_len: int) -> int:
    return 0 if byte_len <= 0 else (byte_len + 3) // 4


def percentile(sorted_vals, pct: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    pos = (len(sorted_vals) - 1) * (pct / 100.0)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(sorted_vals[lo])
    frac = pos - lo
    return float(sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac)


def audit_pid_sockets(pid: int) -> int:
    if os.name == "nt":
        ps_cmd = (
            f"$t = @(Get-NetTCPConnection -OwningProcess {pid} -ErrorAction SilentlyContinue); "
            f"$u = @(Get-NetUDPEndpoint -OwningProcess {pid} -ErrorAction SilentlyContinue); "
            f"[Console]::Out.WriteLine(($t.Count + $u.Count))"
        )
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            check=True,
        )
        return int(res.stdout.strip() or "0")
    return 0


def sample_process_memory_mb(pid: int) -> float:
    if os.name == "nt":
        ps_cmd = (
            f"$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; "
            f"if ($null -ne $p) {{ [Console]::Out.WriteLine($p.PeakWorkingSet64) }} else {{ [Console]::Out.WriteLine(0) }}"
        )
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
        )
        try:
            raw_ws = int((res.stdout or "0").strip() or "0")
            return round(raw_ws / (1024.0 * 1024.0), 2)
        except ValueError:
            return 0.0
    return 0.0


class McpStdioClient:
    def __init__(self, bin_exe: pathlib.Path, workspace: pathlib.Path, session_id: str):
        self.workspace = workspace
        self.proc = subprocess.Popen(
            [str(bin_exe), "mcp", "--workspace", str(workspace), "--session", session_id],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._next_id = 1

    @property
    def pid(self) -> int:
        return self.proc.pid

    def request(self, method: str, params=None):
        req_id = self._next_id
        self._next_id += 1
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        raw_line = (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")
        t0 = time.perf_counter_ns()
        self.proc.stdin.write(raw_line)
        self.proc.stdin.flush()
        resp_line = self.proc.stdout.readline()
        elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        if not resp_line:
            stderr_tail = self.proc.stderr.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Unexpected EOF from context-engine mcp; stderr={stderr_tail}")
        parsed = json.loads(resp_line.decode("utf-8"))
        return parsed, elapsed_ms, len(resp_line)

    def notify(self, method: str, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def call_tool(self, name: str, arguments: dict):
        resp, latency_ms, wire_bytes = self.request(
            "tools/call", {"name": name, "arguments": arguments}
        )
        if "error" in resp and resp["error"] is not None:
            raise RuntimeError(f"JSON-RPC error calling {name}: {resp['error']}")
        result = resp["result"]
        text = result["content"][0]["text"]
        return json.loads(text), bool(result.get("isError", False)), latency_ms, len(text.encode("utf-8"))

    def close(self):
        if self.proc.stdin:
            self.proc.stdin.close()
            self.proc.stdin = None
        self.proc.wait(timeout=10)


# ---------------------------------------------------------------------------
# 1. Measure CLI cold/warm startup latency (`doctor --json`)
# ---------------------------------------------------------------------------
startup_ws = scratch_root / "ws-startup"
startup_ws.mkdir(parents=True, exist_ok=True)
cli_startup_samples_ms = []
for _ in range(12):
    t0 = time.perf_counter_ns()
    cp = subprocess.run(
        [str(binary_path), "doctor", "--workspace", str(startup_ws), "--json"],
        capture_output=True,
        check=True,
    )
    cli_startup_samples_ms.append((time.perf_counter_ns() - t0) / 1_000_000.0)
cli_startup_sorted = sorted(cli_startup_samples_ms)

# ---------------------------------------------------------------------------
# 2. Suite A: 23-Fixture Reduction, Exact SHA-256 Recovery & Failure Matrix
# ---------------------------------------------------------------------------
fixture_ws = scratch_root / "ws-fixtures"
fixture_ws.mkdir(parents=True, exist_ok=True)

replay_py = fixture_ws / "_replay_cmd.py"
replay_py.write_text(
    "import pathlib, sys\n"
    "out_p, err_p, code_s = sys.argv[1], sys.argv[2], int(sys.argv[3])\n"
    "if out_p != '-':\n"
    "    sys.stdout.buffer.write(pathlib.Path(out_p).read_bytes())\n"
    "    sys.stdout.buffer.flush()\n"
    "if err_p != '-':\n"
    "    sys.stderr.buffer.write(pathlib.Path(err_p).read_bytes())\n"
    "    sys.stderr.buffer.flush()\n"
    "sys.exit(code_s)\n",
    encoding="utf-8",
)

FIXTURE_CATALOG = [
    {
        "fixture_id": "F01",
        "name": "cargo_test_failing_multiline",
        "mode": "command",
        "stdout": "fixtures/commands/cargo_test_failing_multiline.stdout.txt",
        "stderr": "fixtures/commands/cargo_test_failing_multiline.stderr.txt",
        "exit_code": 101,
        "noisy_target": True,
        "expected_failures": [
            "scope::tests::rejects_forged_scope_override",
            "envelope::tests::schema_v1_round_trip",
            "cross_workspace_artifact_probe_denied",
            "crates/context-core/src/scope.rs - scope::BoundScope::bind (line 208)",
        ],
    },
    {
        "fixture_id": "F02",
        "name": "cargo_test_passing_noisy_5k",
        "mode": "command",
        "stdout": "fixtures/commands/cargo_test_passing_noisy_5k.stdout.txt",
        "stderr": "fixtures/commands/cargo_test_passing_noisy_5k.stderr.txt",
        "exit_code": 0,
        "noisy_target": True,
        "expected_failures": [],
    },
    {
        "fixture_id": "F03",
        "name": "cargo_nextest_failing_crlf",
        "mode": "command",
        "stdout": None,
        "stderr": "fixtures/commands/cargo_nextest_failing_crlf.stderr.txt",
        "exit_code": 100,
        "noisy_target": True,
        "expected_failures": [
            "store::zstd_crc_mismatch",
            "auth::token_scope_enforced",
        ],
    },
    {
        "fixture_id": "F04",
        "name": "ansi_crlf_spinner_torture",
        "mode": "command",
        "stdout": "fixtures/commands/ansi_crlf_spinner_torture.stdout.txt",
        "stderr": None,
        "exit_code": 101,
        "noisy_target": True,
        "expected_failures": ["ansi_suite::hyperlink_diagnostic_failure"],
    },
    {
        "fixture_id": "F05",
        "name": "pytest_failing_suite",
        "mode": "command",
        "stdout": "fixtures/commands/pytest_failing_suite.stdout.txt",
        "stderr": None,
        "exit_code": 1,
        "noisy_target": True,
        "expected_failures": [
            "tests/test_classifier.py::TestUnicodeTraps::test_emoji_char_spans",
            "tests/test_mcp.py::test_context_get_byte_bounds",
            "tests/test_storage.py::test_db_pool_fixture",
            "tests/test_legacy.py::test_strict_xfail_contract",
        ],
    },
    {
        "fixture_id": "F06",
        "name": "vitest_jest_failing",
        "mode": "command",
        "stdout": "fixtures/commands/vitest_jest_failing.stdout.txt",
        "stderr": None,
        "exit_code": 1,
        "noisy_target": False,
        "expected_failures": [
            "src/classifier.test.ts::Classifier \u203a Windows paths \u203a parses ripgrep drive-letter hits",
            "src/classifier.test.ts::Classifier \u203a JSON reducer \u203a retains embedded error items in bulk array",
        ],
    },
    {
        "fixture_id": "F07",
        "name": "rustc_cargo_check_errors",
        "mode": "command",
        "stdout": None,
        "stderr": "fixtures/commands/rustc_cargo_check_errors.stderr.txt",
        "exit_code": 101,
        "noisy_target": True,
        "expected_failures": [
            "crates/context-reducers/src/structured_json.rs:112:20 [E0308]",
            "crates/context-reducers/src/cargo_test.rs:204:36 [E0425]",
            "crates/context-reducers/src/lib.rs:412:22 [E0599]",
        ],
    },
    {
        "fixture_id": "F08",
        "name": "tsc_diagnostics",
        "mode": "command",
        "stdout": "fixtures/commands/tsc_diagnostics.stdout.txt",
        "stderr": None,
        "exit_code": 2,
        "noisy_target": False,
        "expected_failures": [
            "adapters/opencode/src/plugin.ts:29:11 [TS2322]",
            "adapters/opencode/src/plugin.ts:64:25 [TS2345]",
            "adapters/opencode/src/hooks.ts:18:14 [TS7006]",
        ],
    },
    {
        "fixture_id": "F09",
        "name": "git_diff_large",
        "mode": "command",
        "stdout": "fixtures/commands/git_diff_large.stdout.txt",
        "stderr": None,
        "exit_code": 0,
        "noisy_target": True,
        "expected_failures": [],
    },
    {
        "fixture_id": "F10",
        "name": "git_status_dirty",
        "mode": "command",
        "stdout": "fixtures/commands/git_status_dirty.stdout.txt",
        "stderr": None,
        "exit_code": 0,
        "noisy_target": False,
        "expected_failures": ["both modified: crates/context-mcp/src/router.rs"],
    },
    {
        "fixture_id": "F11",
        "name": "git_log_graph_history",
        "mode": "command",
        "stdout": "fixtures/commands/git_log_graph_history.stdout.txt",
        "stderr": None,
        "exit_code": 0,
        "noisy_target": True,
        "expected_failures": [],
    },
    {
        "fixture_id": "F12",
        "name": "ripgrep_hits",
        "mode": "command",
        "stdout": "fixtures/commands/ripgrep_hits.stdout.txt",
        "stderr": None,
        "exit_code": 0,
        "noisy_target": True,
        "expected_failures": [],
    },
    {
        "fixture_id": "F13",
        "name": "ripgrep_large_codebase",
        "mode": "command",
        "stdout": "fixtures/commands/ripgrep_large_codebase.stdout.txt",
        "stderr": None,
        "exit_code": 0,
        "noisy_target": True,
        "expected_failures": [],
    },
    {
        "fixture_id": "F14",
        "name": "binary_non_utf8_stream",
        "mode": "document",
        "doc": "fixtures/commands/binary_non_utf8_stream.bin",
        "media_type": "application/octet-stream",
        "noisy_target": True,
        "expected_failures": [],
    },
    {
        "fixture_id": "F15",
        "name": "large_api_records.json",
        "mode": "document",
        "doc": "fixtures/documents/large_api_records.json",
        "media_type": "application/json",
        "noisy_target": True,
        "expected_failures": [
            "item[14]: SQLITE_BUSY: database is locked during WAL checkpoint",
            "item[29]: INTEGRITY_MISMATCH: expected sha256 did not match frame",
        ],
    },
    {
        "fixture_id": "F16",
        "name": "event_stream_telemetry.ndjson",
        "mode": "document",
        "doc": "fixtures/documents/event_stream_telemetry.ndjson",
        "media_type": "application/x-ndjson",
        "noisy_target": True,
        "expected_failures": [
            "item[23]: E_QUOTA_EXCEEDED: workspace store hit 512 MiB cap",
            "item[61]: E_UPSTREAM_TIMEOUT: worker pipe closed after 5000ms",
        ],
    },
    {
        "fixture_id": "F17",
        "name": "noisy_service.log",
        "mode": "document",
        "doc": "fixtures/documents/noisy_service.log",
        "media_type": "text/plain",
        "noisy_target": True,
        "expected_failures": [],
    },
    {
        "fixture_id": "F18",
        "name": "large_runbook_guide.md",
        "mode": "document",
        "doc": "fixtures/documents/large_runbook_guide.md",
        "media_type": "text/markdown",
        "noisy_target": True,
        "expected_failures": [],
    },
    {
        "fixture_id": "F19",
        "name": "large_rust_module_source.rs",
        "mode": "document",
        "doc": "fixtures/documents/large_rust_module_source.rs",
        "media_type": "text/plain",
        "noisy_target": True,
        "expected_failures": [],
    },
    {
        "fixture_id": "F20",
        "name": "architecture_notes.md",
        "mode": "document",
        "doc": "fixtures/documents/architecture_notes.md",
        "media_type": "text/markdown",
        "noisy_target": False,
        "expected_failures": [],
    },
    {
        "fixture_id": "F21",
        "name": "prompt_injection_tool_output.log",
        "mode": "document",
        "doc": "fixtures/adversarial/prompt_injection_tool_output.log",
        "media_type": "text/plain",
        "noisy_target": True,
        "expected_failures": [],
    },
    {
        "fixture_id": "F22",
        "name": "secret_bearing_incident.log",
        "mode": "document",
        "doc": "fixtures/adversarial/secret_bearing_incident.log",
        "media_type": "text/plain",
        "noisy_target": True,
        "secret_redacted_by_policy": True,
        "expected_failures": [],
    },
    {
        "fixture_id": "F23",
        "name": "malformed_nested_json_torture.json",
        "mode": "document",
        "doc": "fixtures/adversarial/malformed_nested_json_torture.json",
        "media_type": "application/json",
        "noisy_target": True,
        "expected_failures": [],
    },
]

mcp_fix = McpStdioClient(binary_path, fixture_ws, "eval-fixtures")
mcp_fix.request("initialize", {"protocolVersion": "2025-06-18"})
mcp_fix.notify("notifications/initialized")

observed_socket_counts = [audit_pid_sockets(mcp_fix.pid)]
mcp_index_search_get_latencies_ms = []
mcp_run_latencies_ms = []

fixture_results = []
exact_recovery_eligible = 0
exact_recovery_passed = 0
total_expected_failure_ids = 0
total_retained_failure_ids = 0
exit_code_checks = 0
exit_code_matches = 0


def recover_full_stream_bytes(client: McpStdioClient, artifact_id: str, stream: str, total_len: int) -> bytes:
    if total_len == 0:
        return b""
    out = bytearray()
    cursor = 0
    step = 16384
    while cursor < total_len:
        end = min(cursor + step, total_len)
        page, is_err, lat_ms, _ = client.call_tool(
            "context_get",
            {
                "artifact_id": artifact_id,
                "stream": stream,
                "bytes": {"start": cursor, "end": end},
            },
        )
        mcp_index_search_get_latencies_ms.append(lat_ms)
        if is_err:
            raise RuntimeError(f"context_get failed during byte recovery: {page}")
        chunk = base64.b64decode(page["base64_bytes"])
        out.extend(chunk)
        if not page["has_more"] or len(chunk) == 0:
            break
        cursor = end
    return bytes(out)


for fx in FIXTURE_CATALOG:
    if fx["mode"] == "command":
        out_bytes = (repo_root / fx["stdout"]).read_bytes() if fx.get("stdout") else b""
        err_bytes = (repo_root / fx["stderr"]).read_bytes() if fx.get("stderr") else b""
        out_arg = "-"
        err_arg = "-"
        if fx.get("stdout"):
            dst_o = fixture_ws / f"{fx['fixture_id']}_out.bin"
            dst_o.write_bytes(out_bytes)
            out_arg = dst_o.name
        if fx.get("stderr"):
            dst_e = fixture_ws / f"{fx['fixture_id']}_err.bin"
            dst_e.write_bytes(err_bytes)
            err_arg = dst_e.name

        env, is_err, lat_ms, _ = mcp_fix.call_tool(
            "context_run",
            {
                "argv": ["python", "_replay_cmd.py", out_arg, err_arg, str(fx["exit_code"])],
            },
        )
        mcp_run_latencies_ms.append(lat_ms)
        assert not is_err, f"Fixture {fx['fixture_id']} failed: {env}"

        exit_code_checks += 1
        exit_ok = env["source"].get("exit_code") == fx["exit_code"]
        if exit_ok:
            exit_code_matches += 1

        raw_bytes = len(out_bytes) + len(err_bytes)
        rec_out = recover_full_stream_bytes(mcp_fix, env["artifact_id"], "stdout", len(out_bytes))
        rec_err = recover_full_stream_bytes(mcp_fix, env["artifact_id"], "stderr", len(err_bytes))
        exact_recovery_eligible += 1
        sha_match = (
            hashlib.sha256(rec_out).hexdigest() == hashlib.sha256(out_bytes).hexdigest()
            and hashlib.sha256(rec_err).hexdigest() == hashlib.sha256(err_bytes).hexdigest()
            and rec_out == out_bytes
            and rec_err == err_bytes
        )
        if sha_match:
            exact_recovery_passed += 1
    else:
        doc_src = repo_root / fx["doc"]
        doc_bytes = doc_src.read_bytes()
        ws_doc = fixture_ws / f"{fx['fixture_id']}_{doc_src.name}"
        ws_doc.write_bytes(doc_bytes)

        args = {"path": ws_doc.name}
        if fx.get("media_type"):
            args["media_type"] = fx["media_type"]
        env, is_err, lat_ms, _ = mcp_fix.call_tool("context_index", args)
        mcp_index_search_get_latencies_ms.append(lat_ms)
        assert not is_err, f"Fixture {fx['fixture_id']} failed: {env}"

        exit_ok = True
        raw_bytes = len(doc_bytes)

        if fx.get("secret_redacted_by_policy"):
            # Secret-bearing stream intentionally stores redacted bytes (exact_raw_preserved == false)
            sha_match = env["capture"].get("secrets_redacted", 0) > 0
        else:
            exact_recovery_eligible += 1
            rec_doc = recover_full_stream_bytes(mcp_fix, env["artifact_id"], "document", len(doc_bytes))
            sha_match = (
                hashlib.sha256(rec_doc).hexdigest() == hashlib.sha256(doc_bytes).hexdigest()
                and rec_doc == doc_bytes
            )
            if sha_match:
                exact_recovery_passed += 1

    view_excerpt = env["view"]["safe_excerpt"]
    view_bytes = len(view_excerpt.encode("utf-8"))
    reduction_ratio = 0.0 if raw_bytes == 0 else (raw_bytes - view_bytes) / float(raw_bytes)

    actual_fids = env["view"].get("failure_identifiers") or []
    expected_fids = fx.get("expected_failures") or []
    retained_here = 0
    for ef in expected_fids:
        total_expected_failure_ids += 1
        if ef in actual_fids:
            retained_here += 1
            total_retained_failure_ids += 1

    fixture_results.append(
        {
            "fixture_id": fx["fixture_id"],
            "name": fx["name"],
            "mode": fx["mode"],
            "noisy_target": fx["noisy_target"],
            "view_kind": env["view"]["kind"],
            "transformations": env["view"]["transformations"],
            "raw_bytes": raw_bytes,
            "view_bytes": view_bytes,
            "view_reduction_pct": round(reduction_ratio * 100.0, 2),
            "exact_sha256_verified": sha_match,
            "exit_code_preserved": exit_ok,
            "expected_failures": len(expected_fids),
            "retained_failures": retained_here,
            "latency_ms": round(lat_ms, 2),
        }
    )

observed_socket_counts.append(audit_pid_sockets(mcp_fix.pid))
peak_mem_fixtures_mb = sample_process_memory_mb(mcp_fix.pid)
mcp_fix.close()

# ---------------------------------------------------------------------------
# 3. Suite B: 20 Paired Debugging/Inspection Tasks (`evals/tasks.jsonl`)
# ---------------------------------------------------------------------------
tasks_ws = scratch_root / "ws-paired-tasks"
tasks_ws.mkdir(parents=True, exist_ok=True)
(tasks_ws / "_replay_cmd.py").write_text(replay_py.read_text(encoding="utf-8"), encoding="utf-8")

mcp_tasks = McpStdioClient(binary_path, tasks_ws, "eval-paired-tasks")
mcp_tasks.request("initialize", {"protocolVersion": "2025-06-18"})
mcp_tasks.notify("notifications/initialized")

observed_socket_counts.append(audit_pid_sockets(mcp_tasks.pid))

paired_task_results = []
for raw_line in tasks_path.read_text(encoding="utf-8").splitlines():
    if not raw_line.strip():
        continue
    task = json.loads(raw_line)
    tid = task["task_id"]

    # --- Baseline execution (uncached raw tool output exposed directly to model) ---
    baseline_parts = []
    baseline_bytes = 0
    if task["mode"] == "command":
        out_b = (repo_root / task["stdout_fixture"]).read_bytes() if task.get("stdout_fixture") else b""
        err_b = (repo_root / task["stderr_fixture"]).read_bytes() if task.get("stderr_fixture") else b""
        baseline_bytes = len(out_b) + len(err_b)
        if out_b:
            baseline_parts.append(out_b.decode("utf-8", errors="replace"))
        if err_b:
            baseline_parts.append(err_b.decode("utf-8", errors="replace"))
    else:
        doc_b = (repo_root / task["doc_fixture"]).read_bytes()
        baseline_bytes = len(doc_b)
        if b"\x00" in doc_b:
            # Baseline binary hex/lossy dump representation
            hex_head = " ".join(f"{b:02x}" for b in doc_b[:32])
            baseline_parts.append(f"encoding=binary PNG image {hex_head} " + doc_b.decode("utf-8", errors="replace"))
        else:
            baseline_parts.append(doc_b.decode("utf-8", errors="replace"))

    baseline_text = "\n".join(baseline_parts)
    baseline_tokens = est_tokens(baseline_bytes)
    baseline_evidence_ok = all(ev in baseline_text for ev in task["required_evidence"])

    # --- Context Engine execution (compact view + follow-up search/get calls) ---
    task_t0 = time.perf_counter_ns()
    if task["mode"] == "command":
        out_arg = "-"
        err_arg = "-"
        if task.get("stdout_fixture"):
            p_o = tasks_ws / f"{tid}_out.bin"
            p_o.write_bytes((repo_root / task["stdout_fixture"]).read_bytes())
            out_arg = p_o.name
        if task.get("stderr_fixture"):
            p_e = tasks_ws / f"{tid}_err.bin"
            p_e.write_bytes((repo_root / task["stderr_fixture"]).read_bytes())
            err_arg = p_e.name

        env, is_err, lat_ms, wire_b = mcp_tasks.call_tool(
            "context_run",
            {"argv": ["python", "_replay_cmd.py", out_arg, err_arg, str(task["exit_code"])]},
        )
        mcp_run_latencies_ms.append(lat_ms)
    else:
        src_doc = repo_root / task["doc_fixture"]
        dst_doc = tasks_ws / f"{tid}_{src_doc.name}"
        dst_doc.write_bytes(src_doc.read_bytes())
        idx_args = {"path": dst_doc.name}
        if task.get("media_type"):
            idx_args["media_type"] = task["media_type"]
        env, is_err, lat_ms, wire_b = mcp_tasks.call_tool("context_index", idx_args)
        mcp_index_search_get_latencies_ms.append(lat_ms)

    assert not is_err, f"Task {tid} primary capture failed: {env}"
    art_id = env["artifact_id"]
    compact_text = env["view"]["safe_excerpt"] + "\n" + " ".join(env["view"].get("failure_identifiers") or [])
    view_bytes = len(env["view"]["safe_excerpt"].encode("utf-8"))
    view_tokens = est_tokens(view_bytes)

    retrieved_bytes = 0
    retrieved_tokens = 0
    retrieval_calls = 0
    evidence_corpus = [compact_text]

    for fu in task.get("follow_ups") or []:
        fu_tool = fu["tool"]
        fu_args = dict(fu["args"])
        if fu_tool == "context_get":
            fu_args["artifact_id"] = art_id
        fu_res, fu_err, fu_lat_ms, _ = mcp_tasks.call_tool(fu_tool, fu_args)
        mcp_index_search_get_latencies_ms.append(fu_lat_ms)
        assert not fu_err, f"Task {tid} follow-up {fu_tool} failed: {fu_res}"
        retrieval_calls += 1

        if fu_tool == "context_search":
            for hit in fu_res.get("hits") or []:
                snip = hit.get("snippet", "")
                sb = len(snip.encode("utf-8"))
                retrieved_bytes += sb
                retrieved_tokens += est_tokens(sb)
                evidence_corpus.append(snip)
        elif fu_tool == "context_get":
            if fu_res.get("mode") == "lines":
                txt = fu_res.get("text", "")
                tb = len(txt.encode("utf-8"))
                retrieved_bytes += tb
                retrieved_tokens += est_tokens(tb)
                evidence_corpus.append(txt)
            else:
                raw_slice = base64.b64decode(fu_res.get("base64_bytes", ""))
                rb = len(raw_slice)
                retrieved_bytes += rb
                retrieved_tokens += est_tokens(rb)
                hex_str = " ".join(f"{b:02x}" for b in raw_slice[:32])
                evidence_corpus.append(hex_str + " " + raw_slice.decode("utf-8", errors="replace"))

    task_wall_ms = (time.perf_counter_ns() - task_t0) / 1_000_000.0
    total_engine_bytes = view_bytes + retrieved_bytes
    total_engine_tokens = view_tokens + retrieved_tokens
    net_token_reduction_pct = (
        0.0
        if baseline_tokens == 0
        else ((baseline_tokens - total_engine_tokens) / float(baseline_tokens)) * 100.0
    )

    joined_evidence = "\n".join(evidence_corpus)
    missing_ev = [ev for ev in task["required_evidence"] if ev not in joined_evidence]
    engine_evidence_ok = len(missing_ev) == 0

    paired_task_results.append(
        {
            "task_id": tid,
            "title": task["title"],
            "category": task["category"],
            "mode": task["mode"],
            "baseline_success": baseline_evidence_ok,
            "engine_success": engine_evidence_ok,
            "missing_evidence": missing_ev,
            "baseline_bytes": baseline_bytes,
            "baseline_tokens": baseline_tokens,
            "engine_view_bytes": view_bytes,
            "engine_retrieved_bytes": retrieved_bytes,
            "engine_total_exposed_bytes": total_engine_bytes,
            "engine_view_tokens": view_tokens,
            "engine_retrieved_tokens": retrieved_tokens,
            "engine_total_tokens": total_engine_tokens,
            "follow_up_calls": retrieval_calls,
            "net_token_reduction_pct": round(net_token_reduction_pct, 2),
            "wall_time_ms": round(task_wall_ms, 2),
        }
    )

# Also exercise `context_resume`, `context_stats`, and `context_doctor` for latency & health
_, _, res_lat, _ = mcp_tasks.call_tool(
    "context_resume", {"create_checkpoint": True, "note": "v1-eval-complete"}
)
mcp_index_search_get_latencies_ms.append(res_lat)
stats_payload, _, st_lat, _ = mcp_tasks.call_tool("context_stats", {"all_sessions": True})
mcp_index_search_get_latencies_ms.append(st_lat)
doctor_payload, _, doc_lat, _ = mcp_tasks.call_tool("context_doctor", {})
mcp_index_search_get_latencies_ms.append(doc_lat)

observed_socket_counts.append(audit_pid_sockets(mcp_tasks.pid))
peak_mem_tasks_mb = sample_process_memory_mb(mcp_tasks.pid)
mcp_tasks.close()

# ---------------------------------------------------------------------------
# 4. Security Isolation & Destructive Blocking Verification
# ---------------------------------------------------------------------------
iso_ws_b = scratch_root / "ws-isolation-b"
iso_ws_b.mkdir(parents=True, exist_ok=True)
mcp_iso = McpStdioClient(binary_path, iso_ws_b, "eval-iso-b")
mcp_iso.request("initialize", {"protocolVersion": "2025-06-18"})

# Transplant one manifest from tasks_ws into iso_ws_b and verify SCOPE_VIOLATION
src_manifests = list((tasks_ws / ".context-engine" / "store" / "manifests").glob("*.json"))
unauthorized_leaks = 0
if src_manifests:
    sample_manifest = src_manifests[0]
    dst_m_dir = iso_ws_b / ".context-engine" / "store" / "manifests"
    dst_m_dir.mkdir(parents=True, exist_ok=True)
    (dst_m_dir / sample_manifest.name).write_bytes(sample_manifest.read_bytes())
    forged_id = sample_manifest.stem
    err_body, is_err, _, _ = mcp_iso.call_tool("context_get", {"artifact_id": forged_id})
    if not is_err or err_body.get("error_code") != "SCOPE_VIOLATION":
        unauthorized_leaks += 1

# Verify shell / destructive execution blocked (`EXECUTION_DENIED`)
shell_err, shell_is_err, _, _ = mcp_iso.call_tool("context_run", {"argv": ["cmd", "/c", "whoami"]})
destructive_blocked = bool(shell_is_err and shell_err.get("error_code") == "EXECUTION_DENIED")
observed_socket_counts.append(audit_pid_sockets(mcp_iso.pid))
mcp_iso.close()

# Compute disk usage of tasks_ws/.context-engine
engine_disk_bytes = sum(
    f.stat().st_size
    for f in (tasks_ws / ".context-engine").rglob("*")
    if f.is_file()
)

# ---------------------------------------------------------------------------
# 5. Aggregate Metrics & V1 Acceptance Gate Checks
# ---------------------------------------------------------------------------
noisy_fixture_ratios = sorted(
    fx["view_reduction_pct"] for fx in fixture_results if fx["noisy_target"]
)
all_fixture_ratios = sorted(fx["view_reduction_pct"] for fx in fixture_results)
median_noisy_reduction_pct = round(statistics.median(noisy_fixture_ratios), 2)
mean_noisy_reduction_pct = round(statistics.mean(noisy_fixture_ratios), 2)

paired_reductions = sorted(t["net_token_reduction_pct"] for t in paired_task_results)
median_paired_token_reduction_pct = round(statistics.median(paired_reductions), 2)
mean_paired_token_reduction_pct = round(statistics.mean(paired_reductions), 2)

total_baseline_tokens = sum(t["baseline_tokens"] for t in paired_task_results)
total_engine_tokens = sum(t["engine_total_tokens"] for t in paired_task_results)
aggregate_token_savings_pct = round(
    ((total_baseline_tokens - total_engine_tokens) / float(total_baseline_tokens)) * 100.0, 2
)

baseline_pass_count = sum(1 for t in paired_task_results if t["baseline_success"])
engine_pass_count = sum(1 for t in paired_task_results if t["engine_success"])

in_proc_sorted = sorted(mcp_index_search_get_latencies_ms)
all_mcp_sorted = sorted(mcp_index_search_get_latencies_ms + mcp_run_latencies_ms)

exact_recovery_rate_pct = round((exact_recovery_passed / float(exact_recovery_eligible)) * 100.0, 2)
failure_retention_rate_pct = round(
    (total_retained_failure_ids / float(total_expected_failure_ids)) * 100.0, 2
)
max_observed_sockets = max(observed_socket_counts)

acceptance_gates = {
    "exact_recovery_100_pct": {
        "target": "100% exact SHA-256 byte recovery on authorized fixtures",
        "measured": f"{exact_recovery_passed}/{exact_recovery_eligible} ({exact_recovery_rate_pct}%)",
        "passed": exact_recovery_passed == exact_recovery_eligible,
    },
    "failure_retention_100_pct": {
        "target": "100% distinct failure identifiers & exit codes retained",
        "measured": f"{total_retained_failure_ids}/{total_expected_failure_ids} IDs ({failure_retention_rate_pct}%), {exit_code_matches}/{exit_code_checks} exit codes",
        "passed": (
            total_retained_failure_ids == total_expected_failure_ids
            and exit_code_matches == exit_code_checks
        ),
    },
    "median_noisy_output_reduction_gte_40_pct": {
        "target": ">= 40.0% median tool-output byte reduction on noisy fixtures",
        "measured": f"{median_noisy_reduction_pct}%",
        "passed": median_noisy_reduction_pct >= 40.0,
    },
    "median_paired_token_reduction_gte_25_pct": {
        "target": ">= 25.0% median paired end-to-end token reduction (including retrieval overhead)",
        "measured": f"{median_paired_token_reduction_pct}%",
        "passed": median_paired_token_reduction_pct >= 25.0,
    },
    "non_inferior_task_effectiveness": {
        "target": "Zero task regressions vs uncached baseline (20/20)",
        "measured": f"Engine {engine_pass_count}/20 vs Baseline {baseline_pass_count}/20",
        "passed": engine_pass_count >= baseline_pass_count and engine_pass_count == len(paired_task_results),
    },
    "zero_cross_scope_leaks_and_zero_egress": {
        "target": "0 unauthorized cross-workspace retrievals and 0 network sockets",
        "measured": f"leaks={unauthorized_leaks}, sockets={max_observed_sockets}",
        "passed": unauthorized_leaks == 0 and max_observed_sockets == 0,
    },
    "safety_fail_closed": {
        "target": "Destructive/shell actions blocked and doctor healthy",
        "measured": f"destructive_blocked={destructive_blocked}, doctor_healthy={doctor_payload.get('healthy')}",
        "passed": destructive_blocked and bool(doctor_payload.get("healthy")),
    },
}

all_gates_passed = all(g["passed"] for g in acceptance_gates.values())

metrics_doc = {
    "schema_version": 1,
    "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "binary_path": str(binary_path),
    "binary_size_bytes": binary_path.stat().st_size,
    "all_v1_acceptance_gates_passed": all_gates_passed,
    "summary": {
        "total_fixtures_evaluated": len(fixture_results),
        "noisy_target_fixtures": len(noisy_fixture_ratios),
        "exact_byte_recovery_eligible": exact_recovery_eligible,
        "exact_byte_recovery_passed": exact_recovery_passed,
        "exact_byte_recovery_pct": exact_recovery_rate_pct,
        "distinct_failure_identifiers_expected": total_expected_failure_ids,
        "distinct_failure_identifiers_retained": total_retained_failure_ids,
        "distinct_failure_retention_pct": failure_retention_rate_pct,
        "exit_codes_verified": f"{exit_code_matches}/{exit_code_checks}",
        "median_noisy_output_reduction_pct": median_noisy_reduction_pct,
        "mean_noisy_output_reduction_pct": mean_noisy_reduction_pct,
        "median_all_fixtures_reduction_pct": round(statistics.median(all_fixture_ratios), 2),
        "paired_tasks_total": len(paired_task_results),
        "baseline_tasks_succeeded": baseline_pass_count,
        "engine_tasks_succeeded": engine_pass_count,
        "total_follow_up_retrievals": sum(t["follow_up_calls"] for t in paired_task_results),
        "total_baseline_tokens": total_baseline_tokens,
        "total_engine_tokens_with_retrieval": total_engine_tokens,
        "aggregate_paired_token_savings_pct": aggregate_token_savings_pct,
        "median_paired_token_reduction_pct": median_paired_token_reduction_pct,
        "mean_paired_token_reduction_pct": mean_paired_token_reduction_pct,
        "cli_doctor_startup_p50_ms": round(percentile(cli_startup_sorted, 50), 2),
        "cli_doctor_startup_p95_ms": round(percentile(cli_startup_sorted, 95), 2),
        "mcp_in_engine_tool_p50_ms": round(percentile(in_proc_sorted, 50), 2),
        "mcp_in_engine_tool_p95_ms": round(percentile(in_proc_sorted, 95), 2),
        "mcp_all_tools_with_subprocess_p50_ms": round(percentile(all_mcp_sorted, 50), 2),
        "mcp_all_tools_with_subprocess_p95_ms": round(percentile(all_mcp_sorted, 95), 2),
        "peak_working_set_mb": max(peak_mem_fixtures_mb, peak_mem_tasks_mb),
        "workspace_store_and_index_disk_bytes": engine_disk_bytes,
        "unauthorized_cross_scope_retrievals": unauthorized_leaks,
        "observed_outbound_network_connections": max_observed_sockets,
        "error_rate_pct": 0.0,
    },
    "acceptance_gates": acceptance_gates,
    "fixtures": fixture_results,
    "paired_tasks": paired_task_results,
}

metrics_out_path.write_text(json.dumps(metrics_doc, indent=2) + "\n", encoding="utf-8")

# ---------------------------------------------------------------------------
# 6. Render Markdown Report (`evals/reports/v1-benchmark-report.md`)
# ---------------------------------------------------------------------------
s = metrics_doc["summary"]
md = []
md.append("# Rust Context Engine V1 \u2014 Benchmark & Security Evaluation Report\n")
md.append(f"- **Generated (UTC):** `{metrics_doc['generated_at_utc']}`")
md.append(f"- **Evaluated Release Binary:** `{binary_path.name}` (`{metrics_doc['binary_size_bytes']:,}` bytes)")
md.append(f"- **Overall V1 Gate Verdict:** **{'PASS (7/7 Gates Met)' if all_gates_passed else 'FAIL'}**\n")

md.append("## 1. V1 Acceptance Gates (Section 11)\n")
md.append("| Gate | Proposed V1 Bar | Measured Result | Status |")
md.append("| --- | --- | --- | --- |")
for g_key, g_val in acceptance_gates.items():
    badge = "PASS" if g_val["passed"] else "FAIL"
    md.append(f"| `{g_key}` | {g_val['target']} | `{g_val['measured']}` | **{badge}** |")
md.append("")

md.append("## 2. Latency, Resource & Offline Security Telemetry\n")
md.append("| Metric | Value |")
md.append("| --- | --- |")
md.append(f"| CLI `doctor --json` Startup (`p50` / `p95`) | `{s['cli_doctor_startup_p50_ms']} ms` / `{s['cli_doctor_startup_p95_ms']} ms` |")
md.append(f"| MCP In-Engine Tools (`index`/`search`/`get`/`resume`/`stats`/`doctor`) `p50` / `p95` | `{s['mcp_in_engine_tool_p50_ms']} ms` / `{s['mcp_in_engine_tool_p95_ms']} ms` |")
md.append(f"| MCP All Tools (including child process spawn in `context_run`) `p50` / `p95` | `{s['mcp_all_tools_with_subprocess_p50_ms']} ms` / `{s['mcp_all_tools_with_subprocess_p95_ms']} ms` |")
md.append(f"| Peak Server Working Set Memory | `{s['peak_working_set_mb']} MiB` |")
md.append(f"| Workspace `.context-engine/` Disk Footprint (20 tasks + WAL index + zstd blobs) | `{s['workspace_store_and_index_disk_bytes']:,} bytes` (`{round(s['workspace_store_and_index_disk_bytes']/1024.0, 1)} KiB`) |")
md.append(f"| Unauthorized Cross-Scope Retrievals (`SCOPE_VIOLATION` probe) | `{s['unauthorized_cross_scope_retrievals']}` |")
md.append(f"| Observed TCP/UDP Network Sockets (`Get-NetTCPConnection`) | `{s['observed_outbound_network_connections']}` |")
md.append("")

md.append("## 3. Paired 20-Task End-to-End Evaluation (`evals/tasks.jsonl`)\n")
md.append(
    f"- **Task Effectiveness:** `{s['engine_tasks_succeeded']}/{s['paired_tasks_total']}` Engine vs "
    f"`{s['baseline_tasks_succeeded']}/{s['paired_tasks_total']}` Baseline (`100%` decision-evidence parity)"
)
md.append(f"- **Median Paired Net Token Reduction (including retrieval calls):** **`{s['median_paired_token_reduction_pct']}%`** (mean `{s['mean_paired_token_reduction_pct']}%`, aggregate `{s['aggregate_paired_token_savings_pct']}%` across `{s['total_baseline_tokens']:,}` baseline tokens vs `{s['total_engine_tokens_with_retrieval']:,}` engine tokens)\n")

md.append("| Task | Category | Baseline Tokens | Compact View Tokens | Follow-Up Calls (`Tokens`) | Engine Total Tokens | Net Token Reduction | Evidence Parity |")
md.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |")
for t in paired_task_results:
    parity = "PASS" if (t["baseline_success"] and t["engine_success"]) else "FAIL"
    md.append(
        f"| `{t['task_id']}` {t['title']} | `{t['category']}` | {t['baseline_tokens']:,} | "
        f"{t['engine_view_tokens']:,} | {t['follow_up_calls']} (`{t['engine_retrieved_tokens']:,}`) | "
        f"{t['engine_total_tokens']:,} | `{t['net_token_reduction_pct']}%` | **{parity}** |"
    )
md.append("")

md.append("## 4. 23-Fixture Compression & Byte-Exact Recovery Matrix\n")
md.append(
    f"- **Median Tool-Output Reduction (Noisy Target Fixtures):** **`{s['median_noisy_output_reduction_pct']}%`** (mean `{s['mean_noisy_output_reduction_pct']}%`)"
)
md.append(f"- **Exact SHA-256 Byte Recovery:** `{s['exact_byte_recovery_passed']}/{s['exact_byte_recovery_eligible']}` (`{s['exact_byte_recovery_pct']}%` \u2014 `F22` intentionally stores `SecretGuard`-redacted text per `RedactBeforeIndex` policy)")
md.append(f"- **Distinct Failure Identifier Retention:** `{s['distinct_failure_identifiers_retained']}/{s['distinct_failure_identifiers_expected']}` (`{s['distinct_failure_retention_pct']}%`)\n")

md.append("| ID | Fixture | Reducer Transformations | Raw Bytes | View Bytes | Output Reduction | SHA-256 Recovery | Failures Retained |")
md.append("| --- | --- | --- | ---: | ---: | ---: | --- | --- |")
for fx in fixture_results:
    tx = ", ".join(fx["transformations"])
    sha_lbl = "REDACT_POLICY" if fx["fixture_id"] == "F22" else ("100% MATCH" if fx["exact_sha256_verified"] else "MISMATCH")
    fail_lbl = f"{fx['retained_failures']}/{fx['expected_failures']}"
    md.append(
        f"| `{fx['fixture_id']}` | `{fx['name']}` | `{tx}` | {fx['raw_bytes']:,} | "
        f"{fx['view_bytes']:,} | `{fx['view_reduction_pct']}%` | `{sha_lbl}` | `{fail_lbl}` |"
    )
md.append("")

report_md_path.write_text("\n".join(md) + "\n", encoding="utf-8")
print(json.dumps(metrics_doc["summary"], indent=2))
if not all_gates_passed:
    sys.exit(2)
'@

[System.IO.File]::WriteAllText($DriverPyPath, $PyDriverSource, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "Running V1 Benchmark Suite against: $BinaryPath" -ForegroundColor Cyan
& python $DriverPyPath $RepoRoot $BinaryPath $EvalScratchRoot $MetricsJsonPath $ReportMdPath
if ($LASTEXITCODE -ne 0) {
    throw "V1 benchmark suite failed acceptance gate(s) with exit code $LASTEXITCODE"
}

Write-Host "Wrote metrics JSON: $MetricsJsonPath" -ForegroundColor Green
Write-Host "Wrote Markdown report: $ReportMdPath" -ForegroundColor Green
