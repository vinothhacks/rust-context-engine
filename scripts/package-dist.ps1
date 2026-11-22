#Requires -Version 5.1
<#
.SYNOPSIS
    Repeatable supply-chain license audit, hardened release build, CycloneDX 1.5 SBOM
    generator, portable multi-agent bundle packager, PE32+ hardening verifier, and
    SHA-256 manifest builder for Rust Context Engine (`dist/`).

.DESCRIPTION
    Safety Guarantees:
    - Zero destructive filesystem commands (never invokes Remove-Item -Recurse -Force, rm, or rmdir).
    - Uses dedicated Cargo target directory (`target/wave4-release` by default) to avoid lock contention.
    - Never touches global user directories (`~/.cursor`, `~/.claude`, `~/.codex`, `%APPDATA%`).
    - Fails closed if any resolved Cargo dependency lacks a permissive SPDX license path or uses
      copyleft / source-available licenses (`GPL`, `AGPL`, `Elastic-2.0`, `BUSL-1.1`, `SSPL`).
#>

[CmdletBinding()]
param(
    [string]$Workspace = "",
    [string]$TargetDir = "target/wave4-release",
    [string]$DistSubdir = "dist"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Workspace)) {
    $Workspace = Join-Path $PSScriptRoot ".."
}
$RepoRoot = (Resolve-Path -LiteralPath $Workspace).Path
$CargoToml = Join-Path $RepoRoot "Cargo.toml"
$CargoLock = Join-Path $RepoRoot "Cargo.lock"
if (-not (Test-Path -LiteralPath $CargoToml)) {
    throw "Workspace Cargo.toml not found at '$CargoToml'."
}
if (-not (Test-Path -LiteralPath $CargoLock)) {
    throw "Workspace Cargo.lock not found at '$CargoLock'."
}

$ResolvedTargetDir = if ([System.IO.Path]::IsPathRooted($TargetDir)) {
    $TargetDir
} else {
    Join-Path $RepoRoot $TargetDir
}

$DistDir = if ([System.IO.Path]::IsPathRooted($DistSubdir)) {
    $DistSubdir
} else {
    Join-Path $RepoRoot $DistSubdir
}

# Create output directories non-destructively (no recursive delete).
foreach ($dir in @(
    $DistDir,
    (Join-Path $DistDir "integrations"),
    (Join-Path $DistDir "integrations\cursor"),
    (Join-Path $DistDir "integrations\claude-code"),
    (Join-Path $DistDir "integrations\opencode"),
    (Join-Path $DistDir "integrations\codex"),
    (Join-Path $DistDir "integrations\generic")
)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

Write-Host "==> [1/6] Auditing Cargo dependency licenses & generating deterministic CycloneDX 1.5 SBOM..." -ForegroundColor Cyan

$SbomPath = Join-Path $DistDir "sbom.cdx.json"
$LicenseAuditPath = Join-Path $DistDir "license-audit.json"

$SbomPyScript = @'
import hashlib
import json
import re
import subprocess
import sys
import tomllib
import uuid
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
sbom_out = Path(sys.argv[2]).resolve()
audit_out = Path(sys.argv[3]).resolve()

# 1. Load Cargo.lock SHA-256 checksums via Python 3.11 stdlib tomllib
lock_bytes = (repo_root / "Cargo.lock").read_bytes()
lock_sha256 = hashlib.sha256(lock_bytes).hexdigest()
lock_data = tomllib.loads(lock_bytes.decode("utf-8"))
checksum_by_key = {}
for pkg in lock_data.get("package", []):
    key = (pkg.get("name"), pkg.get("version"), pkg.get("source"))
    if pkg.get("checksum"):
        checksum_by_key[key] = pkg["checksum"]

# 2. Query full locked workspace metadata + Windows x86_64 runtime-filtered metadata
def run_cargo_metadata(extra_args):
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked", *extra_args]
    proc = subprocess.run(
        cmd,
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return json.loads(proc.stdout)

meta_all = run_cargo_metadata([])
meta_win = run_cargo_metadata(["--filter-platform", "x86_64-pc-windows-msvc"])

# Compute runtime (normal, non-dev) closure reachable from context-cli on x86_64-pc-windows-msvc
win_nodes = {n["id"]: n for n in meta_win["resolve"]["nodes"]}
cli_pkg_id = next(
    p["id"] for p in meta_win["packages"] if p["name"] == "context-cli" and p["source"] is None
)
runtime_ids = set()
stack = [cli_pkg_id]
while stack:
    curr = stack.pop()
    if curr in runtime_ids:
        continue
    runtime_ids.add(curr)
    node = win_nodes.get(curr)
    if not node:
        continue
    for dep in node.get("deps", []):
        kinds = [dk.get("kind") for dk in dep.get("dep_kinds", [])]
        # Normal dependencies have kind == None; build dependencies have kind == "build"
        if None in kinds or "build" in kinds:
            # Track strict normal runtime separately from build-script crates
            pass
        if None in kinds:
            stack.append(dep["pkg"])

# 3. Permissive SPDX boolean expression evaluator
PERMISSIVE_IDS = {
    "MIT",
    "MIT-0",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "0BSD",
    "ISC",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "Zlib",
    "CC0-1.0",
    "Unlicense",
    "MPL-2.0",
    "BSL-1.0",
}

FORBIDDEN_PREFIXES = (
    "GPL",
    "AGPL",
    "LGPL",
    "Elastic-2.0",
    "BUSL-1.1",
    "SSPL",
)

def tokenize_spdx(expr: str):
    # Normalize legacy '/' separator to ' OR '
    normalized = expr.replace("/", " OR ")
    # Collapse 'WITH <exception>' onto its preceding license identifier
    normalized = re.sub(
        r"([A-Za-z0-9.\-+]+)\s+WITH\s+([A-Za-z0-9.\-+]+)",
        r"\1__WITH__\2",
        normalized,
    )
    raw_tokens = re.findall(r"\(|\)|\bAND\b|\bOR\b|[^\s()]+", normalized)
    return [t.replace("__WITH__", " WITH ") for t in raw_tokens]

def eval_spdx_permissive(expr: str):
    tokens = tokenize_spdx(expr)
    pos = 0

    def parse_or():
        nonlocal pos
        left_ok, left_chosen = parse_and()
        choices = [left_chosen] if left_ok else []
        while pos < len(tokens) and tokens[pos] == "OR":
            pos += 1
            right_ok, right_chosen = parse_and()
            if right_ok and not choices:
                choices.append(right_chosen)
        if choices:
            return True, choices[0]
        return False, []

    def parse_and():
        nonlocal pos
        ok, chosen = parse_primary()
        all_ok = ok
        combined = list(chosen)
        while pos < len(tokens) and tokens[pos] == "AND":
            pos += 1
            r_ok, r_chosen = parse_primary()
            all_ok = all_ok and r_ok
            combined.extend(r_chosen)
        return (True, combined) if all_ok else (False, [])

    def parse_primary():
        nonlocal pos
        if pos >= len(tokens):
            return False, []
        tok = tokens[pos]
        if tok == "(":
            pos += 1
            res = parse_or()
            if pos < len(tokens) and tokens[pos] == ")":
                pos += 1
            return res
        pos += 1
        if tok in PERMISSIVE_IDS:
            return True, [tok]
        return False, []

    ok, elected = parse_or()
    if pos != len(tokens):
        return False, []
    return ok, elected

packages_sorted = sorted(
    meta_all["packages"], key=lambda p: (p["name"], p["version"], p["id"])
)

violations = []
license_histogram = {}
components = []
pkg_id_to_bom_ref = {}

for pkg in packages_sorted:
    name = pkg["name"]
    version = pkg["version"]
    source = pkg.get("source")
    lic_expr = (pkg.get("license") or "").strip()
    is_workspace_member = source is None

    if not lic_expr:
        violations.append({"crate": f"{name}@{version}", "reason": "missing SPDX license"})
        continue

    ok, elected = eval_spdx_permissive(lic_expr)
    if not ok:
        violations.append(
            {"crate": f"{name}@{version}", "license": lic_expr, "reason": "non-permissive SPDX"}
        )
    for e_lic in elected:
        if any(e_lic.upper().startswith(fp.upper()) for fp in FORBIDDEN_PREFIXES):
            violations.append(
                {
                    "crate": f"{name}@{version}",
                    "license": lic_expr,
                    "reason": f"forbidden license elected: {e_lic}",
                }
            )

    license_histogram[lic_expr] = license_histogram.get(lic_expr, 0) + 1

    purl = (
        f"pkg:cargo/{name}@{version}"
        if source is not None
        else f"pkg:cargo/{name}@{version}?vcs_url=local"
    )
    bom_ref = f"{name}@{version}" if source is not None else f"workspace:{name}@{version}"
    pkg_id_to_bom_ref[pkg["id"]] = bom_ref

    if pkg["id"] == cli_pkg_id:
        continue

    comp = {
        "type": "library",
        "bom-ref": bom_ref,
        "name": name,
        "version": version,
        "purl": purl,
        "scope": "required" if pkg["id"] in runtime_ids else "optional",
        "licenses": [{"expression": lic_expr}],
        "properties": [
            {
                "name": "context-engine:elected-permissive-path",
                "value": " AND ".join(elected),
            },
            {
                "name": "context-engine:workspace-member",
                "value": "true" if is_workspace_member else "false",
            },
        ],
    }

    sha = checksum_by_key.get((name, version, source))
    if sha:
        comp["hashes"] = [{"alg": "SHA-256", "content": sha}]
    if pkg.get("repository"):
        comp["externalReferences"] = [{"type": "vcs", "url": pkg["repository"]}]

    components.append(comp)

if violations:
    print("LICENSE AUDIT FAILED:", json.dumps(violations, indent=2), file=sys.stderr)
    sys.exit(1)

# 4. Deterministic dependency graph edges
all_nodes = sorted(meta_all["resolve"]["nodes"], key=lambda n: pkg_id_to_bom_ref[n["id"]])
dependencies = []
for node in all_nodes:
    ref = pkg_id_to_bom_ref[node["id"]]
    depends_on = sorted({pkg_id_to_bom_ref[d["pkg"]] for d in node.get("deps", [])})
    dependencies.append({"ref": ref, "dependsOn": depends_on})

cli_pkg = next(p for p in meta_all["packages"] if p["id"] == cli_pkg_id)
deterministic_uuid = uuid.uuid5(uuid.NAMESPACE_OID, f"context-engine-sbom-v1:{lock_sha256}")

sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:{deterministic_uuid}",
    "version": 1,
    "metadata": {
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "context-engine-package-dist",
                    "version": "1.0.0",
                }
            ]
        },
        "component": {
            "type": "application",
            "bom-ref": pkg_id_to_bom_ref[cli_pkg_id],
            "name": "context-engine",
            "version": cli_pkg["version"],
            "purl": f"pkg:cargo/{cli_pkg['name']}@{cli_pkg['version']}?vcs_url=local",
            "licenses": [{"expression": cli_pkg["license"]}],
        },
        "properties": [
            {"name": "cargo:lockfile-sha256", "value": lock_sha256},
            {"name": "cargo:total-resolved-packages", "value": str(len(packages_sorted))},
            {"name": "cargo:windows-x64-runtime-packages", "value": str(len(runtime_ids))},
        ],
    },
    "components": components,
    "dependencies": dependencies,
}

sbom_out.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8", newline="\n")

audit_summary = {
    "status": "PASSED",
    "cargo_lock_sha256": lock_sha256,
    "total_resolved_packages": len(packages_sorted),
    "workspace_member_crates": sum(1 for p in packages_sorted if p.get("source") is None),
    "external_crates_total": sum(1 for p in packages_sorted if p.get("source") is not None),
    "windows_x86_64_runtime_closure_crates": len(runtime_ids),
    "copyleft_or_source_available_violations": 0,
    "gpl_agpl_elastic_busl_count": 0,
    "distinct_spdx_expressions": dict(sorted(license_histogram.items())),
}
audit_out.write_text(json.dumps(audit_summary, indent=2) + "\n", encoding="utf-8", newline="\n")
print(
    f"  SBOM OK: {len(packages_sorted)} resolved packages "
    f"({len(runtime_ids)} Windows x86_64 runtime closure), 0 non-permissive crates."
)
'@

$SbomPyScript | python - $RepoRoot $SbomPath $LicenseAuditPath
if ($LASTEXITCODE -ne 0) {
    throw "Dependency license audit / CycloneDX 1.5 SBOM generation failed with exit code $LASTEXITCODE."
}

Write-Host "==> [2/6] Building hardened release binary (--target-dir $TargetDir)..." -ForegroundColor Cyan

$AuditableCmd = Get-Command cargo-auditable -ErrorAction SilentlyContinue
Push-Location $RepoRoot
try {
    if ($null -ne $AuditableCmd) {
        Write-Host "  Detected cargo-auditable: embedding dependency audit table in PE section..."
        & cargo auditable build --release --locked --target-dir $ResolvedTargetDir
    } else {
        Write-Host "  cargo-auditable not installed; building with standard 'cargo build --release --locked' + CycloneDX 1.5 SBOM..."
        & cargo build --release --locked --target-dir $ResolvedTargetDir
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Release cargo build failed with exit code $LASTEXITCODE."
    }
} finally {
    Pop-Location
}

$BuiltExe = Join-Path $ResolvedTargetDir "release\context-engine.exe"
if (-not (Test-Path -LiteralPath $BuiltExe)) {
    throw "Expected compiled binary not found at '$BuiltExe'."
}

Write-Host "==> [3/6] Staging release artifacts & portable integration bundles into dist/..." -ForegroundColor Cyan

$DistExe = Join-Path $DistDir "context-engine.exe"
Copy-Item -LiteralPath $BuiltExe -Destination $DistExe -Force
Copy-Item -LiteralPath (Join-Path $RepoRoot "NOTICE") -Destination (Join-Path $DistDir "NOTICE") -Force
if (Test-Path -LiteralPath (Join-Path $RepoRoot "README.md")) {
    Copy-Item -LiteralPath (Join-Path $RepoRoot "README.md") -Destination (Join-Path $DistDir "README.md") -Force
}

$IntegrationsRoot = Join-Path $DistDir "integrations"
$SetupJsonOut = & $DistExe setup --client all --workspace $RepoRoot --binary $DistExe --output-dir $IntegrationsRoot --json
if ($LASTEXITCODE -ne 0) {
    throw "'context-engine setup --client all' failed with exit code $LASTEXITCODE."
}
[System.IO.File]::WriteAllText(
    (Join-Path $DistDir "setup-report.json"),
    (($SetupJsonOut -join "`n") + "`n"),
    (New-Object System.Text.UTF8Encoding($false))
)

# Also populate isolated per-client subdirectories under dist/integrations/<client>/ for direct copy
$ClientTargets = @(
    @{ Client = "cursor";      Subdir = "cursor" },
    @{ Client = "claude-code"; Subdir = "claude-code" },
    @{ Client = "opencode";    Subdir = "opencode" },
    @{ Client = "codex";       Subdir = "codex" },
    @{ Client = "generic";     Subdir = "generic" }
)
foreach ($ct in $ClientTargets) {
    $subOut = Join-Path $IntegrationsRoot $ct.Subdir
    $null = & $DistExe setup --client $ct.Client --workspace $RepoRoot --binary $DistExe --output-dir $subOut --json
    if ($LASTEXITCODE -ne 0) {
        throw "'context-engine setup --client $($ct.Client)' failed with exit code $LASTEXITCODE."
    }
}

Write-Host "==> [4/6] Running 'context-engine doctor --json' health & ACL check..." -ForegroundColor Cyan

$DoctorJsonOut = & $DistExe doctor --workspace $RepoRoot --json
if ($LASTEXITCODE -ne 0) {
    throw "'context-engine doctor' reported unhealthy state (exit code $LASTEXITCODE)."
}
$DoctorText = ($DoctorJsonOut -join "`n") + "`n"
$DoctorObj = $DoctorText | ConvertFrom-Json
if (-not $DoctorObj.healthy) {
    throw "'context-engine doctor' returned healthy=false."
}
[System.IO.File]::WriteAllText(
    (Join-Path $DistDir "doctor-report.json"),
    $DoctorText,
    (New-Object System.Text.UTF8Encoding($false))
)

Write-Host "==> [5/6] Running deterministic PE32+ COFF/OptionalHeader/LoadConfig & exposure audit..." -ForegroundColor Cyan

$PeAuditPath = Join-Path $DistDir "pe-hardening-audit.json"

$PeAuditPyScript = @'
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

exe_path = Path(sys.argv[1]).resolve()
dist_dir = Path(sys.argv[2]).resolve()
repo_root = Path(sys.argv[3]).resolve()
audit_out = Path(sys.argv[4]).resolve()

data = exe_path.read_bytes()
exe_sha256 = hashlib.sha256(data).hexdigest()

# 1. DOS + PE Signature + COFF Header
e_magic = struct.unpack_from("<H", data, 0)[0]
if e_magic != 0x5A4D:
    raise RuntimeError(f"Invalid DOS e_magic: 0x{e_magic:04x}")
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
pe_sig = struct.unpack_from("<I", data, e_lfanew)[0]
if pe_sig != 0x00004550:
    raise RuntimeError(f"Invalid PE signature: 0x{pe_sig:08x}")

coff_off = e_lfanew + 4
(
    machine,
    num_sections,
    time_date_stamp,
    ptr_sym_table,
    num_symbols,
    size_opt_hdr,
    characteristics,
) = struct.unpack_from("<HHIIIHH", data, coff_off)

# 2. Optional Header (PE32+)
opt_off = coff_off + 20
opt_magic = struct.unpack_from("<H", data, opt_off)[0]
if opt_magic != 0x020B:
    raise RuntimeError(f"Expected PE32+ magic 0x020b, got 0x{opt_magic:04x}")

subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
dll_characteristics = struct.unpack_from("<H", data, opt_off + 70)[0]
num_rva_and_sizes = struct.unpack_from("<I", data, opt_off + 108)[0]

data_dirs_off = opt_off + 112
data_dirs = []
for i in range(min(num_rva_and_sizes, 16)):
    rva, sz = struct.unpack_from("<II", data, data_dirs_off + i * 8)
    data_dirs.append((rva, sz))

# 3. Section Table & RVA -> File Offset mapper
sec_off = opt_off + size_opt_hdr
sections = []
for i in range(num_sections):
    s_base = sec_off + i * 40
    raw_name = data[s_base : s_base + 8].rstrip(b"\x00").decode("ascii", errors="replace")
    vsize, vrva, raw_sz, raw_ptr = struct.unpack_from("<IIII", data, s_base + 8)
    sec_chars = struct.unpack_from("<I", data, s_base + 36)[0]
    sections.append(
        {
            "name": raw_name,
            "virtual_rva": f"0x{vrva:08x}",
            "virtual_size": vsize,
            "raw_size": raw_sz,
            "raw_ptr": raw_ptr,
            "characteristics": f"0x{sec_chars:08x}",
        }
    )

def rva_to_offset(rva: int):
    for s in sections:
        vrva = int(s["virtual_rva"], 16)
        span = max(s["virtual_size"], s["raw_size"])
        if vrva <= rva < vrva + span:
            off = s["raw_ptr"] + (rva - vrva)
            if off < len(data):
                return off
    return None

# 4. Debug Directory (DataDirectory[6]) & Extended DLL Characteristics (CETCOMPAT)
DEBUG_TYPES = {
    2: "IMAGE_DEBUG_TYPE_CODEVIEW",
    12: "IMAGE_DEBUG_TYPE_VC_FEATURE",
    13: "IMAGE_DEBUG_TYPE_POGO",
    14: "IMAGE_DEBUG_TYPE_ILTCG",
    16: "IMAGE_DEBUG_TYPE_REPRO",
    20: "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS",
}
debug_entries = []
cet_compat = False
codeview_pdb_paths = []

if len(data_dirs) > 6 and data_dirs[6][0] != 0 and data_dirs[6][1] >= 28:
    dbg_rva, dbg_sz = data_dirs[6]
    dbg_off = rva_to_offset(dbg_rva)
    if dbg_off is not None:
        count = dbg_sz // 28
        for idx in range(count):
            eb = dbg_off + idx * 28
            (
                _ch,
                _ts,
                _maj,
                _min,
                dtype,
                dsz,
                addr_raw,
                ptr_raw,
            ) = struct.unpack_from("<IIHHIIII", data, eb)
            tname = DEBUG_TYPES.get(dtype, f"TYPE_{dtype}")
            entry_info = {"type_id": dtype, "type_name": tname, "size": dsz}
            if dtype == 20 and ptr_raw and dsz >= 4 and ptr_raw + 4 <= len(data):
                ex_flags = struct.unpack_from("<I", data, ptr_raw)[0]
                entry_info["ex_dll_characteristics_hex"] = f"0x{ex_flags:08x}"
                cet_compat = bool(ex_flags & 0x0001)
            elif dtype == 2 and ptr_raw and dsz >= 24 and ptr_raw + dsz <= len(data):
                cv = data[ptr_raw : ptr_raw + dsz]
                if cv[:4] == b"RSDS":
                    pdb_raw = cv[24:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                    codeview_pdb_paths.append(pdb_raw)
                    entry_info["rsds_pdb_reference"] = pdb_raw
            debug_entries.append(entry_info)

# 5. Load Config Directory (DataDirectory[10]) -> SecurityCookie (/GS) & GuardFlags (CFG)
load_config = {}
if len(data_dirs) > 10 and data_dirs[10][0] != 0 and data_dirs[10][1] >= 0x94:
    lc_rva, lc_sz = data_dirs[10]
    lc_off = rva_to_offset(lc_rva)
    if lc_off is not None:
        lc_struct_size = struct.unpack_from("<I", data, lc_off)[0]
        security_cookie_va = struct.unpack_from("<Q", data, lc_off + 0x58)[0]
        guard_cf_check_fn_ptr = struct.unpack_from("<Q", data, lc_off + 0x70)[0]
        guard_cf_fn_table = struct.unpack_from("<Q", data, lc_off + 0x80)[0]
        guard_cf_fn_count = struct.unpack_from("<Q", data, lc_off + 0x88)[0]
        guard_flags = struct.unpack_from("<I", data, lc_off + 0x90)[0]
        load_config = {
            "rva": f"0x{lc_rva:08x}",
            "directory_size": lc_sz,
            "struct_size": lc_struct_size,
            "security_cookie_va": f"0x{security_cookie_va:016x}",
            "gs_stack_cookie_enabled": security_cookie_va != 0,
            "guard_cf_check_function_pointer_va": f"0x{guard_cf_check_fn_ptr:016x}",
            "guard_cf_function_table_va": f"0x{guard_cf_fn_table:016x}",
            "guard_cf_function_count": guard_cf_fn_count,
            "guard_flags_hex": f"0x{guard_flags:08x}",
            "cf_instrumented": bool(guard_flags & 0x00000100),
            "cf_function_table_present": bool(guard_flags & 0x00000400),
        }

# 6. Sibling .pdb / debug companion check in dist/
pdb_files_in_dist = [
    str(p.relative_to(dist_dir)).replace("\\", "/")
    for p in dist_dir.rglob("*")
    if p.is_file() and p.suffix.lower() in {".pdb", ".dwp", ".debug", ".map"}
]
has_debug_sections = any(s["name"].startswith(".debug") or s["name"] == ".symtab" for s in sections)
has_auditable_section = any(s["name"] == ".dep-v0" for s in sections)

# 7. Embedded printable string audit (leaked credentials vs workspace path occurrences)
ascii_strings = [m.group(0).decode("ascii") for m in re.finditer(rb"[\x20-\x7e]{8,}", data)]
cred_patterns = {
    "AWS_ACCESS_KEY": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "GITHUB_TOKEN": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{24,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    "OPENAI_API_KEY": re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9\-_]{24,}\b"),
    "ANTHROPIC_API_KEY": re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
    "GITLAB_TOKEN": re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),
    "SLACK_TOKEN": re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{12,}\b"),
    "GCP_API_KEY": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
}

leaked_credentials = []
for s in ascii_strings:
    # Skip SecretGuard's own compiled regex pattern literals (e.g. \bsk-ant-[A-Za-z0-9\-_]{16,}\b)
    if "[A-Za-z" in s or "[0-9" in s:
        continue
    for rule_name, pat in cred_patterns.items():
        if pat.search(s):
            leaked_credentials.append({"rule": rule_name, "sample_prefix": s[:12] + "..."})

user_path_hits = sum(1 for s in ascii_strings if "c:\\users\\" in s.lower())
workspace_path_hits = sum(1 for s in ascii_strings if str(repo_root).lower() in s.lower())

# 8. Windows icacls check on .context-engine/store
store_dir = repo_root / ".context-engine" / "store"
icacls_proc = subprocess.run(
    ["icacls", str(store_dir)],
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="replace",
    check=True,
)
icacls_lines = [
    ln.strip()
    for ln in icacls_proc.stdout.splitlines()
    if ln.strip() and not ln.strip().lower().startswith("successfully ")
]
icacls_summary = "; ".join(icacls_lines)
icacls_private = (
    "(I)" not in icacls_summary
    and "everyone:" not in icacls_summary.lower()
    and "builtin\\users:" not in icacls_summary.lower()
    and "(F)" in icacls_summary
)

flags = {
    "high_entropy_va_0x0020": bool(dll_characteristics & 0x0020),
    "dynamic_base_aslr_0x0040": bool(dll_characteristics & 0x0040),
    "nx_compat_dep_0x0100": bool(dll_characteristics & 0x0100),
    "guard_cf_0x4000": bool(dll_characteristics & 0x4000),
    "cet_compat_shadow_stack": cet_compat,
}

all_required_hardening = (
    machine == 0x8664
    and opt_magic == 0x020B
    and flags["high_entropy_va_0x0020"]
    and flags["dynamic_base_aslr_0x0040"]
    and flags["nx_compat_dep_0x0100"]
    and flags["guard_cf_0x4000"]
    and ptr_sym_table == 0
    and num_symbols == 0
    and not has_debug_sections
    and len(pdb_files_in_dist) == 0
    and len(leaked_credentials) == 0
    and icacls_private
)

report = {
    "status": "PASSED" if all_required_hardening else "FAILED",
    "binary_path": str(exe_path),
    "size_bytes": len(data),
    "sha256": exe_sha256,
    "pe_headers": {
        "dos_magic_hex": f"0x{e_magic:04x}",
        "e_lfanew_hex": f"0x{e_lfanew:08x}",
        "pe_signature_hex": f"0x{pe_sig:08x}",
        "machine_hex": f"0x{machine:04x}",
        "machine_arch": "x86_64 (IMAGE_FILE_MACHINE_AMD64)" if machine == 0x8664 else "other",
        "optional_header_magic_hex": f"0x{opt_magic:04x}",
        "format": "PE32+",
        "subsystem": subsystem,
        "coff_characteristics_hex": f"0x{characteristics:04x}",
        "dll_characteristics_hex": f"0x{dll_characteristics:04x}",
        "flags": flags,
    },
    "load_config": load_config,
    "symbol_and_debug_exposure": {
        "coff_pointer_to_symbol_table": ptr_sym_table,
        "coff_number_of_symbols": num_symbols,
        "has_dwarf_or_symtab_sections": has_debug_sections,
        "has_cargo_auditable_dep_v0_section": has_auditable_section,
        "pdb_files_shipped_in_dist": pdb_files_in_dist,
        "debug_directory_entries": debug_entries,
        "sections": [s["name"] for s in sections],
    },
    "embedded_strings_audit": {
        "total_ascii_strings_scanned": len(ascii_strings),
        "leaked_credentials_count": len(leaked_credentials),
        "leaked_credentials": leaked_credentials,
        "user_profile_path_occurrences": user_path_hits,
        "workspace_path_occurrences": workspace_path_hits,
    },
    "store_dacl_audit": {
        "store_dir": str(store_dir),
        "private_owner_only": icacls_private,
        "icacls_output": icacls_summary,
    },
}

audit_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")

if not all_required_hardening:
    print("PE32+ HARDENING AUDIT FAILED:", json.dumps(report, indent=2), file=sys.stderr)
    sys.exit(1)

print(
    f"  PE32+ OK: Machine=0x{machine:04x}, DllCharacteristics=0x{dll_characteristics:04x} "
    f"(HIGH_ENTROPY_VA={flags['high_entropy_va_0x0020']}, DYNAMIC_BASE={flags['dynamic_base_aslr_0x0040']}, "
    f"NX_COMPAT={flags['nx_compat_dep_0x0100']}, GUARD_CF={flags['guard_cf_0x4000']}, CETCOMPAT={cet_compat}), "
    f"0 .pdb in dist/, 0 leaked credentials, icacls private_only={icacls_private}."
)
'@

$PeAuditPyScript | python - $DistExe $DistDir $RepoRoot $PeAuditPath
if ($LASTEXITCODE -ne 0) {
    throw "PE32+ hardening / exposure audit failed with exit code $LASTEXITCODE."
}

Write-Host "==> [6/6] Computing dist/SHA256SUMS.txt across all packaged artifacts..." -ForegroundColor Cyan

$ShaSumsPath = Join-Path $DistDir "SHA256SUMS.txt"
$AllDistFiles = Get-ChildItem -LiteralPath $DistDir -Recurse -File |
    Where-Object { $_.FullName -ne $ShaSumsPath } |
    Sort-Object {
        $_.FullName.Substring($DistDir.Length).TrimStart('\', '/').Replace('\', '/')
    }

$ShaLines = New-Object System.Collections.Generic.List[string]
foreach ($file in $AllDistFiles) {
    $rel = $file.FullName.Substring($DistDir.Length).TrimStart('\', '/').Replace('\', '/')
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $ShaLines.Add("$hash  $rel")
}

[System.IO.File]::WriteAllText(
    $ShaSumsPath,
    (($ShaLines -join "`n") + "`n"),
    (New-Object System.Text.UTF8Encoding($false))
)

$ExeBytes = (Get-Item -LiteralPath $DistExe).Length
$ExeHash = (Get-FileHash -LiteralPath $DistExe -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host ""
Write-Host "Distribution bundle complete:" -ForegroundColor Green
Write-Host "  Binary:     $DistExe"
Write-Host "  Size:       $ExeBytes bytes"
Write-Host "  SHA-256:    $ExeHash"
Write-Host "  SBOM:       $SbomPath"
Write-Host "  Checksums:  $ShaSumsPath ($($ShaLines.Count) files)"
