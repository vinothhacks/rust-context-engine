# Opt-in Cursor afterShellExecution hook for Rust Context Engine.
# Captures large raw shell outputs into the workspace-scoped blob store + FTS5 index
# while strictly honoring transformation ledger markers so outputs are never double-compressed.
# Fails open ({} + exit 0) on any error so developer terminal workflows are never disrupted.

param(
    [string]$BinaryPath = "",
    [string]$WorkspacePath = ""
)

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}

function Write-HookNoOp {
    [Console]::Out.WriteLine("{}")
    exit 0
}

try {
    if ($env:CONTEXT_ENGINE_DISABLE_HOOK -eq "1") {
        Write-HookNoOp
    }

    $rawStdin = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($rawStdin)) {
        Write-HookNoOp
    }

    $payload = $null
    try {
        $payload = $rawStdin | ConvertFrom-Json
    } catch {
        Write-HookNoOp
    }

    if ($null -eq $payload) {
        Write-HookNoOp
    }

    $commandText = ""
    if ($null -ne $payload.PSObject.Properties["command"] -and $null -ne $payload.command) {
        $commandText = [string]$payload.command
    }

    # Skip recursive invocations of context-engine, ce-run, headroom, or caveman
    if ($commandText -match '(?i)(^|[\\/\s"''&|;])(context-engine(\.exe)?|ce-run(\.ps1|\.sh)?|headroom|caveman)(\s|$|"|'')') {
        Write-HookNoOp
    }

    # Skip commands referencing sensitive credential files by name
    if ($commandText -match '(?i)(^|[\s"''\\/])(\.env(\.[A-Za-z0-9_.-]+)?|id_rsa|id_ed25519|\.ssh|\.aws|\.npmrc|\.netrc)([\s"''\\/]|$)' -or
        $commandText -match '(?i)\.(pem|key|pfx|p12)([\s"'']|$)') {
        Write-HookNoOp
    }

    $outputText = ""
    if ($null -ne $payload.PSObject.Properties["output"] -and $null -ne $payload.output) {
        $outputText = [string]$payload.output
    }

    if ([string]::IsNullOrEmpty($outputText)) {
        Write-HookNoOp
    }

    # Transformation ledger & coexistence check — NEVER double-compress or re-index reduced artifacts
    $ledgerPattern = '(\[context-engine:reduced|x-context-engine-transformations:|"transformations"\s*:\s*\[|(strip_ansi|cargo_test|pytest_jest|compiler_diag|git_reducer|structured_json|log_dedup|search_hits|unknown_safe)@1|\[headroom|"headroom_ref"|\[caveman|<!--\s*caveman)'
    if ($outputText -match $ledgerPattern -or $rawStdin -match '"transformations"\s*:\s*\[\s*"') {
        Write-HookNoOp
    }

    # Also inspect structured JSON output for ArtifactEnvelope schema_version + artifact_id
    $trimmedOutput = $outputText.TrimStart()
    if ($trimmedOutput.StartsWith("{")) {
        try {
            $parsedOut = $trimmedOutput | ConvertFrom-Json
            if ($null -ne $parsedOut) {
                if (($null -ne $parsedOut.PSObject.Properties["view"] -and
                     $null -ne $parsedOut.view.PSObject.Properties["transformations"] -and
                     $parsedOut.view.transformations.Count -gt 0) -or
                    ($null -ne $parsedOut.PSObject.Properties["transformations"] -and
                     $parsedOut.transformations.Count -gt 0) -or
                    ($parsedOut.schema_version -eq 1 -and [string]$parsedOut.artifact_id -like "a_*")) {
                    Write-HookNoOp
                }
            }
        } catch {
            # Output is not pure JSON; continue normal threshold check
        }
    }

    $minBytes = 4096
    if (-not [string]::IsNullOrWhiteSpace($env:CONTEXT_ENGINE_MIN_CAPTURE_BYTES)) {
        $parsedMin = 0
        if ([int]::TryParse($env:CONTEXT_ENGINE_MIN_CAPTURE_BYTES, [ref]$parsedMin) -and $parsedMin -ge 0) {
            $minBytes = $parsedMin
        }
    }

    $utf8ByteCount = [System.Text.Encoding]::UTF8.GetByteCount($outputText)
    if ($utf8ByteCount -lt $minBytes) {
        Write-HookNoOp
    }

    # Resolve workspace path strictly without touching global directories
    if ([string]::IsNullOrWhiteSpace($WorkspacePath)) {
        $WorkspacePath = $env:CONTEXT_ENGINE_WORKSPACE
    }
    if ([string]::IsNullOrWhiteSpace($WorkspacePath)) {
        $WorkspacePath = (Get-Location).ProviderPath
    }
    $WorkspacePath = $WorkspacePath.Trim('"').TrimEnd('\', '/')
    if (-not (Test-Path -LiteralPath $WorkspacePath -PathType Container)) {
        Write-HookNoOp
    }
    $resolvedWorkspace = (Resolve-Path -LiteralPath $WorkspacePath).ProviderPath

    # Verify payload cwd (if present) stays inside the bound workspace
    if ($null -ne $payload.PSObject.Properties["cwd"] -and -not [string]::IsNullOrWhiteSpace([string]$payload.cwd)) {
        $payloadCwd = [string]$payload.cwd
        if (Test-Path -LiteralPath $payloadCwd -PathType Container) {
            $resolvedCwd = (Resolve-Path -LiteralPath $payloadCwd).ProviderPath
            $wsPrefix = $resolvedWorkspace.TrimEnd('\') + "\"
            if (-not ($resolvedCwd.Equals($resolvedWorkspace, [System.StringComparison]::OrdinalIgnoreCase) -or
                      $resolvedCwd.StartsWith($wsPrefix, [System.StringComparison]::OrdinalIgnoreCase))) {
                Write-HookNoOp
            }
        }
    }

    # Resolve binary path safely
    if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
        $BinaryPath = $env:CONTEXT_ENGINE_BIN
    }
    if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
        $candidate = Join-Path $resolvedWorkspace "dist\context-engine.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $BinaryPath = $candidate
        } else {
            $cmdInfo = Get-Command "context-engine" -ErrorAction SilentlyContinue
            if ($null -ne $cmdInfo) {
                $BinaryPath = $cmdInfo.Source
            }
        }
    }
    $BinaryPath = [string]$BinaryPath
    $BinaryPath = $BinaryPath.Trim('"')
    if ([string]::IsNullOrWhiteSpace($BinaryPath) -or -not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
        Write-HookNoOp
    }

    $indexArgs = @(
        "index",
        "--stdin",
        "--workspace", $resolvedWorkspace,
        "--label", "cursor-afterShellExecution"
    )

    if ($null -ne $payload.PSObject.Properties["conversation_id"] -and
        [string]$payload.conversation_id -match '^[A-Za-z0-9_.-]{1,128}$') {
        $indexArgs += @("--session", [string]$payload.conversation_id)
    }

    # Invoke context-engine via direct argv array (never Invoke-Expression or cmd /c)
    $null = $outputText | & $BinaryPath @indexArgs 2>$null

    Write-HookNoOp
} catch {
    Write-HookNoOp
}
