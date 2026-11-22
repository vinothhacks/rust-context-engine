#!/usr/bin/env node
/**
 * Opt-in Claude Code `PostToolUse` hook for Rust Context Engine (Node 24+, zero dependencies).
 *
 * Design invariants:
 * 1. Strictly `PostToolUse` for `Bash` and `Read` — NEVER intercepts `UserPromptSubmit` or rewrites user prompts.
 * 2. Single-pass ledger enforcement — detects `transformations` arrays, `ArtifactEnvelope` IDs, and
 *    `[context-engine:reduced` markers so outputs are never double-reduced.
 * 3. Clean coexistence with `caveman` and `headroom` — detects Headroom (`[headroom`, `headroom_ref`,
 *    `smart_crusher`, `kompress`, `CCR-`) and Caveman (`[caveman`, `<!-- caveman`, `caveman-compress`)
 *    markers and yields immediately without interference.
 * 4. Argv-safe execution — invokes `context-engine` exclusively via `execFileSync` with `shell: false`.
 * 5. Fail-open — exits 0 with empty stdout if the binary is absent, output is small, or any error occurs.
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const REDUCER_TAG_REGEX =
  /\b(strip_ansi|cargo_test|pytest_jest|compiler_diag|git_reducer|structured_json|log_dedup|search_hits|unknown_safe)@1\b/;

const TEXT_MARKER_REGEX =
  /(\[context-engine:reduced\b|x-context-engine-transformations:|\[headroom\b|"headroom_ref"\s*:|"headroom_compress"\b|"smart_crusher"\b|"kompress"\b|\bCCR-[A-Za-z0-9_-]{6,}\b|\[caveman\b|<!--\s*caveman\b|\bcaveman-compress\b)/i;

const RECURSIVE_COMMAND_REGEX =
  /(^|[\\/\s"'&|;])(context-engine(\.exe)?|ce-run(\.ps1|\.sh)?|headroom|caveman)(\s|$|"|')/i;

const SENSITIVE_BASENAME_REGEX =
  /^(\.env(\..+)?|id_rsa(\..+)?|id_ed25519(\..+)?|id_ecdsa(\..+)?|\.npmrc|\.netrc|\.pypirc|credentials\.json|service-account.*\.json)$/i;

const SENSITIVE_EXT_REGEX = /\.(pem|key|pfx|p12|kdbx|jks|keystore)$/i;

const SENSITIVE_SEGMENT_SET = new Set([".ssh", ".aws", ".gnupg", ".kube"]);

const SAFE_ENV_KEYS = [
  "PATH",
  "Path",
  "SYSTEMROOT",
  "SystemRoot",
  "WINDIR",
  "windir",
  "COMSPEC",
  "ComSpec",
  "HOME",
  "USERPROFILE",
  "APPDATA",
  "LOCALAPPDATA",
  "TEMP",
  "TMP",
  "TMPDIR",
  "LANG",
  "LC_ALL",
  "TERM",
  "NO_COLOR",
];

/**
 * Inspect raw text and structured tool responses for any existing reduction ledger or
 * coexisting optimizer (`headroom`, `caveman`) markers.
 */
export function hasTransformationMarkers(rawText, toolResponse = null) {
  if (
    process.env.HEADROOM_ALREADY_COMPRESSED === "1" ||
    process.env.CAVEMAN_ALREADY_COMPRESSED === "1"
  ) {
    return true;
  }

  if (toolResponse && typeof toolResponse === "object") {
    if (
      Array.isArray(toolResponse.transformations) &&
      toolResponse.transformations.length > 0
    ) {
      return true;
    }
    if (
      toolResponse.view &&
      typeof toolResponse.view === "object" &&
      Array.isArray(toolResponse.view.transformations) &&
      toolResponse.view.transformations.length > 0
    ) {
      return true;
    }
    if (
      toolResponse.schema_version === 1 &&
      typeof toolResponse.artifact_id === "string" &&
      toolResponse.artifact_id.startsWith("a_")
    ) {
      return true;
    }
    if (
      typeof toolResponse.headroom_ref === "string" ||
      toolResponse.caveman_compressed === true
    ) {
      return true;
    }
  }

  if (typeof rawText !== "string" || rawText.length === 0) {
    return false;
  }

  if (REDUCER_TAG_REGEX.test(rawText) || TEXT_MARKER_REGEX.test(rawText)) {
    return true;
  }

  const trimmed = rawText.trimStart();
  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object") {
        if (
          (Array.isArray(parsed.transformations) &&
            parsed.transformations.length > 0) ||
          (parsed.view &&
            Array.isArray(parsed.view.transformations) &&
            parsed.view.transformations.length > 0) ||
          (parsed.schema_version === 1 &&
            typeof parsed.artifact_id === "string" &&
            parsed.artifact_id.startsWith("a_")) ||
          typeof parsed.headroom_ref === "string"
        ) {
          return true;
        }
      }
    } catch {
      if (/"transformations"\s*:\s*\[\s*"/.test(rawText)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Check whether a candidate file path points to a credential or secret-bearing file.
 */
export function isSensitivePath(candidatePath) {
  if (typeof candidatePath !== "string" || candidatePath.trim().length === 0) {
    return false;
  }
  const normalized = candidatePath.replace(/\\/g, "/");
  const segments = normalized.split("/").filter(Boolean);
  for (const seg of segments) {
    if (SENSITIVE_SEGMENT_SET.has(seg.toLowerCase())) {
      return true;
    }
  }
  const base = segments.length > 0 ? segments[segments.length - 1] : normalized;
  return SENSITIVE_BASENAME_REGEX.test(base) || SENSITIVE_EXT_REGEX.test(base);
}

/**
 * Verify canonical path containment inside `workspaceRoot` (rejecting traversal and symlink escapes).
 */
export function isPathWithinWorkspace(targetPath, workspaceRoot) {
  try {
    const canonicalWorkspace = fs.realpathSync(workspaceRoot);
    const resolvedTarget = path.resolve(canonicalWorkspace, targetPath);
    const canonicalTarget = fs.existsSync(resolvedTarget)
      ? fs.realpathSync(resolvedTarget)
      : path.resolve(resolvedTarget);

    const compareWs =
      process.platform === "win32"
        ? canonicalWorkspace.toLowerCase()
        : canonicalWorkspace;
    const compareTarget =
      process.platform === "win32"
        ? canonicalTarget.toLowerCase()
        : canonicalTarget;

    if (compareTarget === compareWs) {
      return true;
    }
    const prefix = compareWs.endsWith(path.sep)
      ? compareWs
      : compareWs + path.sep;
    return compareTarget.startsWith(prefix);
  } catch {
    return false;
  }
}

/**
 * Extract plain UTF-8 tool output from Claude Code `PostToolUse` `tool_response` shapes.
 */
export function extractToolOutputText(toolName, toolResponse) {
  if (typeof toolResponse === "string") {
    return toolResponse;
  }
  if (!toolResponse || typeof toolResponse !== "object") {
    return "";
  }

  if (Array.isArray(toolResponse)) {
    return toolResponse
      .map((item) =>
        typeof item === "string"
          ? item
          : item && typeof item.text === "string"
            ? item.text
            : ""
      )
      .filter(Boolean)
      .join("\n");
  }

  if (toolName === "Bash") {
    const parts = [];
    if (typeof toolResponse.stdout === "string" && toolResponse.stdout.length > 0) {
      parts.push(toolResponse.stdout);
    }
    if (typeof toolResponse.stderr === "string" && toolResponse.stderr.length > 0) {
      parts.push(toolResponse.stderr);
    }
    if (parts.length > 0) {
      return parts.join("\n");
    }
  }

  if (
    toolResponse.file &&
    typeof toolResponse.file === "object" &&
    typeof toolResponse.file.content === "string"
  ) {
    return toolResponse.file.content;
  }

  if (typeof toolResponse.output === "string") {
    return toolResponse.output;
  }

  if (typeof toolResponse.content === "string") {
    return toolResponse.content;
  }

  if (Array.isArray(toolResponse.content)) {
    return extractToolOutputText(toolName, toolResponse.content);
  }

  return "";
}

function parseCliArgs(argv) {
  let binaryPath = process.env.CONTEXT_ENGINE_BIN || "";
  let workspacePath = process.env.CONTEXT_ENGINE_WORKSPACE || "";

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--binary" && i + 1 < argv.length) {
      binaryPath = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--binary=")) {
      binaryPath = arg.slice("--binary=".length);
    } else if (arg === "--workspace" && i + 1 < argv.length) {
      workspacePath = argv[i + 1];
      i += 1;
    } else if (arg.startsWith("--workspace=")) {
      workspacePath = arg.slice("--workspace=".length);
    }
  }

  return {
    binaryPath: binaryPath.trim().replace(/^"+|"+$/g, ""),
    workspacePath: workspacePath
      .trim()
      .replace(/^"+|"+$/g, "")
      .replace(/[\\/]+$/, ""),
  };
}

function buildScrubbedEnv() {
  const safeEnv = {};
  for (const key of SAFE_ENV_KEYS) {
    if (typeof process.env[key] === "string") {
      safeEnv[key] = process.env[key];
    }
  }
  return safeEnv;
}

function resolveBinary(explicitBinary, canonicalWorkspace) {
  if (explicitBinary && fs.existsSync(explicitBinary)) {
    return explicitBinary;
  }
  const exeName =
    process.platform === "win32" ? "context-engine.exe" : "context-engine";
  const localDist = path.join(canonicalWorkspace, "dist", exeName);
  if (fs.existsSync(localDist)) {
    return localDist;
  }
  return explicitBinary || exeName;
}

/**
 * Process a single Claude Code hook payload and optionally index large unreduced outputs.
 * Returns a JSON-serializable hook response object, or `null` for silent pass-through.
 */
export function processHookEvent(event, options = {}) {
  if (process.env.CONTEXT_ENGINE_DISABLE_HOOK === "1") {
    return null;
  }

  if (!event || typeof event !== "object") {
    return null;
  }

  // Strictly handle PostToolUse only — never touch UserPromptSubmit or user prompts.
  if (event.hook_event_name && event.hook_event_name !== "PostToolUse") {
    return null;
  }

  const toolName = String(event.tool_name || "");
  if (toolName !== "Bash" && toolName !== "Read") {
    return null;
  }

  const rawWorkspace =
    options.workspacePath || process.env.CONTEXT_ENGINE_WORKSPACE || process.cwd();
  if (!rawWorkspace || !fs.existsSync(rawWorkspace)) {
    return null;
  }
  const canonicalWorkspace = fs.realpathSync(rawWorkspace);

  if (
    typeof event.cwd === "string" &&
    event.cwd.length > 0 &&
    fs.existsSync(event.cwd) &&
    !isPathWithinWorkspace(event.cwd, canonicalWorkspace)
  ) {
    return null;
  }

  const toolInput =
    event.tool_input && typeof event.tool_input === "object"
      ? event.tool_input
      : {};

  if (toolName === "Bash") {
    const commandStr = String(toolInput.command || "");
    if (RECURSIVE_COMMAND_REGEX.test(commandStr)) {
      return null;
    }
    if (
      /(^|[\s"'\\/])(\.env(\.[A-Za-z0-9_.-]+)?|id_rsa|id_ed25519|\.ssh|\.aws|\.npmrc|\.netrc)([\s"'\\/]|$)|\.(pem|key|pfx|p12)([\s"']|$)/i.test(
        commandStr
      )
    ) {
      return null;
    }
  } else if (toolName === "Read") {
    const filePath = String(toolInput.file_path || toolInput.path || "");
    if (!filePath || isSensitivePath(filePath)) {
      return null;
    }
    if (!isPathWithinWorkspace(filePath, canonicalWorkspace)) {
      return null;
    }
  }

  const rawText = extractToolOutputText(toolName, event.tool_response);
  if (!rawText) {
    return null;
  }

  if (hasTransformationMarkers(rawText, event.tool_response)) {
    return null;
  }

  const parsedMin = Number.parseInt(
    process.env.CONTEXT_ENGINE_MIN_CAPTURE_BYTES || "4096",
    10
  );
  const minBytes = Number.isFinite(parsedMin) && parsedMin >= 0 ? parsedMin : 4096;
  const byteLength = Buffer.byteLength(rawText, "utf8");
  if (byteLength < minBytes) {
    return null;
  }

  const binaryToRun = resolveBinary(options.binaryPath || "", canonicalWorkspace);
  const label = `claude-PostToolUse-${toolName}`;
  const indexArgs = [
    "index",
    "--stdin",
    "--json",
    "--workspace",
    canonicalWorkspace,
    "--label",
    label,
  ];

  if (
    typeof event.session_id === "string" &&
    /^[A-Za-z0-9_.-]{1,128}$/.test(event.session_id)
  ) {
    indexArgs.push("--session", event.session_id);
  }

  const stdout = execFileSync(binaryToRun, indexArgs, {
    input: rawText,
    cwd: canonicalWorkspace,
    encoding: "utf8",
    timeout: 8000,
    maxBuffer: 8 * 1024 * 1024,
    shell: false,
    windowsHide: true,
    env: buildScrubbedEnv(),
    stdio: ["pipe", "pipe", "ignore"],
  });

  if (process.env.CONTEXT_ENGINE_HOOK_SILENT === "1") {
    return null;
  }

  const envelope = JSON.parse(stdout.trim());
  if (
    !envelope ||
    typeof envelope.artifact_id !== "string" ||
    !envelope.artifact_id.startsWith("a_")
  ) {
    return null;
  }

  const transformations = Array.isArray(envelope?.view?.transformations)
    ? envelope.view.transformations.join(",")
    : "unknown_safe@1";

  return {
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      additionalContext:
        `[context-engine:reduced artifact_id=${envelope.artifact_id} transformations=${transformations}] ` +
        `Captured ${byteLength} UTF-8 bytes from ${toolName} into workspace store. ` +
        `Query mcp__context-engine__context_search or mcp__context-engine__context_get ` +
        `(artifact_id="${envelope.artifact_id}", bounded lines/bytes) instead of re-running.`,
    },
  };
}

function main() {
  try {
    const cliOptions = parseCliArgs(process.argv.slice(2));
    const stdinText = fs.readFileSync(0, "utf8");
    if (!stdinText || stdinText.trim().length === 0) {
      process.exit(0);
    }

    const event = JSON.parse(stdinText);
    const result = processHookEvent(event, cliOptions);
    if (result) {
      process.stdout.write(`${JSON.stringify(result)}\n`);
    }
    process.exit(0);
  } catch {
    // Fail open on any hook error so Claude Code tool calls never fail.
    process.exit(0);
  }
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isMain) {
  main();
}
