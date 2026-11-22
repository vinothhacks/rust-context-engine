# Safe argv-forwarding CLI wrapper for shell-only coding agents (PowerShell 5.1 & 7+).
# Intentionally omits [CmdletBinding()] / param() so PowerShell forwards all target flags
# (such as -p, -v, --nocapture, --workspace) verbatim in $args without parameter collisions.

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
}

function Show-CeRunUsage {
    [Console]::Error.WriteLine("Usage: ce-run.ps1 [--] <program> [args...]")
    [Console]::Error.WriteLine("Environment overrides: CONTEXT_ENGINE_BIN, CONTEXT_ENGINE_WORKSPACE, CONTEXT_ENGINE_SESSION, CONTEXT_ENGINE_TIMEOUT_MS")
}

if ($args.Count -eq 0) {
    Show-CeRunUsage
    exit 64
}

if ($args.Count -eq 1 -and ($args[0] -eq "--help" -or $args[0] -eq "-h")) {
    Show-CeRunUsage
    exit 0
}

$cmdArgs = @($args)
if ($cmdArgs[0] -eq "--") {
    if ($cmdArgs.Count -lt 2) {
        Show-CeRunUsage
        exit 64
    }
    $cmdArgs = @($cmdArgs | Select-Object -Skip 1)
}

$firstProgram = [string]$cmdArgs[0]
if ([string]::IsNullOrWhiteSpace($firstProgram)) {
    Show-CeRunUsage
    exit 64
}

# Recursion & coexistence guard: never double-wrap context-engine, ce-run, headroom, or caveman
$baseProgram = [System.IO.Path]::GetFileNameWithoutExtension($firstProgram)
if ($baseProgram -match '^(?i)(context-engine|ce-run|headroom|caveman)$') {
    $restArgs = @()
    if ($cmdArgs.Count -gt 1) {
        $restArgs = @($cmdArgs | Select-Object -Skip 1)
    }
    & $firstProgram @restArgs
    if ($null -ne $LASTEXITCODE) {
        exit $LASTEXITCODE
    }
    exit 0
}

# Resolve canonical workspace directory
$ceWorkspace = $env:CONTEXT_ENGINE_WORKSPACE
if ([string]::IsNullOrWhiteSpace($ceWorkspace)) {
    $ceWorkspace = (Get-Location).ProviderPath
}
$ceWorkspace = $ceWorkspace.Trim('"').TrimEnd('\', '/')
if (-not (Test-Path -LiteralPath $ceWorkspace -PathType Container)) {
    [Console]::Error.WriteLine("ce-run.ps1: workspace directory does not exist: $ceWorkspace")
    exit 66
}
$ceWorkspace = (Resolve-Path -LiteralPath $ceWorkspace).ProviderPath

# Resolve context-engine binary without touching global user config paths
$ceBin = $env:CONTEXT_ENGINE_BIN
if (-not [string]::IsNullOrWhiteSpace($ceBin)) {
    $ceBin = $ceBin.Trim('"')
}

if ([string]::IsNullOrWhiteSpace($ceBin) -or -not (Test-Path -LiteralPath $ceBin -PathType Leaf)) {
    $wsCandidate = Join-Path $ceWorkspace "dist\context-engine.exe"
    $repoCandidate = Join-Path $PSScriptRoot "..\..\..\dist\context-engine.exe"
    if (Test-Path -LiteralPath $wsCandidate -PathType Leaf) {
        $ceBin = $wsCandidate
    } elseif (Test-Path -LiteralPath $repoCandidate -PathType Leaf) {
        $ceBin = (Resolve-Path -LiteralPath $repoCandidate).ProviderPath
    } else {
        $foundCmd = Get-Command "context-engine" -ErrorAction SilentlyContinue
        if ($null -ne $foundCmd) {
            $ceBin = $foundCmd.Source
        }
    }
}

if ([string]::IsNullOrWhiteSpace($ceBin) -or -not (Test-Path -LiteralPath $ceBin -PathType Leaf)) {
    [Console]::Error.WriteLine("ce-run.ps1: context-engine binary not found. Set CONTEXT_ENGINE_BIN or build dist\context-engine.exe.")
    exit 127
}

$engineArgs = @("run", "--workspace", $ceWorkspace)

if (-not [string]::IsNullOrWhiteSpace($env:CONTEXT_ENGINE_SESSION) -and
    $env:CONTEXT_ENGINE_SESSION -match '^[A-Za-z0-9_.-]{1,128}$') {
    $engineArgs += @("--session", $env:CONTEXT_ENGINE_SESSION)
}

if (-not [string]::IsNullOrWhiteSpace($env:CONTEXT_ENGINE_TIMEOUT_MS) -and
    $env:CONTEXT_ENGINE_TIMEOUT_MS -match '^[0-9]+$') {
    $engineArgs += @("--timeout-ms", $env:CONTEXT_ENGINE_TIMEOUT_MS)
}

$engineArgs += "--"
$engineArgs += $cmdArgs

# Direct CreateProcess argv splat — never Invoke-Expression or cmd /c
& $ceBin @engineArgs
if ($null -ne $LASTEXITCODE) {
    exit $LASTEXITCODE
}
exit 0
