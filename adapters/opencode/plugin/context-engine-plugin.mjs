/**
 * Opt-in OpenCode command-capture adapter for Rust Context Engine (Node 24+, zero dependencies).
 *
 * Security & correctness invariants:
 * - Invokes `context-engine index` and `context-engine run` strictly via `execFileSync` with an
 *   explicit `argv` string array and `shell: false` — NEVER shell string interpolation.
 * - Enforces single-pass reduction by checking `view.transformations`, `ArtifactEnvelope` metadata,
 *   and coexisting `headroom` / `caveman` markers before reducing or replacing output.
 * - Enforces canonical `fs.realpathSync` workspace confinement and skips `.env*`, private keys,
 *   and credential directories.
 * - Fails open cleanly on any subprocess or parsing error so OpenCode tool execution never breaks.
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const REDUCER_TAG_REGEX =
  /\b(strip_ansi|cargo_test|pytest_jest|compiler_diag|git_reducer|structured_json|log_dedup|search_hits|unknown_safe)@1\b/;

const TEXT_MARKER_REGEX =
  /(\[context-engine:reduced\b|x-context-engine-transformations:|\[headroom\b|"headroom_ref"\s*:|"smart_crusher"\b|"kompress"\b|\bCCR-[A-Za-z0-9_-]{6,}\b|\[caveman\b|<!--\s*caveman\b|\bcaveman-compress\b)/i;

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

function buildScrubbedEnv() {
  const safeEnv = {};
  for (const key of SAFE_ENV_KEYS) {
    if (typeof process.env[key] === "string") {
      safeEnv[key] = process.env[key];
    }
  }
  return safeEnv;
}

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

export function isPathWithinWorkspace(targetPath, canonicalWorkspace) {
  try {
    const resolvedTarget = path.resolve(canonicalWorkspace, targetPath);
    const canonicalTarget = fs.existsSync(resolvedTarget)
      ? fs.realpathSync(resolvedTarget)
      : path.resolve(resolvedTarget);

    const wsNorm =
      process.platform === "win32"
        ? canonicalWorkspace.toLowerCase()
        : canonicalWorkspace;
    const targetNorm =
      process.platform === "win32"
        ? canonicalTarget.toLowerCase()
        : canonicalTarget;

    if (targetNorm === wsNorm) {
      return true;
    }
    const prefix = wsNorm.endsWith(path.sep) ? wsNorm : wsNorm + path.sep;
    return targetNorm.startsWith(prefix);
  } catch {
    return false;
  }
}

export function hasTransformationMarker(outputText, metadata = null) {
  if (metadata && typeof metadata === "object") {
    if (metadata.contextEngine && metadata.contextEngine.artifactId) {
      return true;
    }
    if (
      Array.isArray(metadata.transformations) &&
      metadata.transformations.length > 0
    ) {
      return true;
    }
  }

  if (typeof outputText !== "string" || outputText.length === 0) {
    return false;
  }

  if (REDUCER_TAG_REGEX.test(outputText) || TEXT_MARKER_REGEX.test(outputText)) {
    return true;
  }

  const trimmed = outputText.trimStart();
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
            parsed.artifact_id.startsWith("a_"))
        ) {
          return true;
        }
      }
    } catch {
      if (/"transformations"\s*:\s*\[\s*"/.test(outputText)) {
        return true;
      }
    }
  }

  return false;
}

export function resolveBinaryPath(canonicalWorkspace, explicitBinary = "") {
  const candidate = (explicitBinary || process.env.CONTEXT_ENGINE_BIN || "")
    .trim()
    .replace(/^"+|"+$/g, "");
  if (candidate && fs.existsSync(candidate)) {
    return candidate;
  }

  const opencodeConfigPath = path.join(canonicalWorkspace, "opencode.json");
  if (fs.existsSync(opencodeConfigPath)) {
    try {
      const cfg = JSON.parse(fs.readFileSync(opencodeConfigPath, "utf8"));
      const cmdArr = cfg?.mcp?.["context-engine"]?.command;
      if (
        Array.isArray(cmdArr) &&
        typeof cmdArr[0] === "string" &&
        fs.existsSync(cmdArr[0])
      ) {
        return cmdArr[0];
      }
    } catch {
      // Fall back to workspace dist or PATH
    }
  }

  const exeName =
    process.platform === "win32" ? "context-engine.exe" : "context-engine";
  const distBin = path.join(canonicalWorkspace, "dist", exeName);
  if (fs.existsSync(distBin)) {
    return distBin;
  }

  return candidate || exeName;
}

/**
 * Safely execute `context-engine run` with a strict `argv` string vector (never shell interpolation).
 */
export function invokeContextEngineRun({
  binaryPath,
  workspacePath,
  argv,
  sessionId = "",
  timeoutMs = 60000,
}) {
  if (
    !Array.isArray(argv) ||
    argv.length === 0 ||
    !argv.every((item) => typeof item === "string" && item.length > 0)
  ) {
    throw new TypeError(
      "invokeContextEngineRun requires a non-empty string[] argv vector; shell command strings are forbidden."
    );
  }

  const canonicalWorkspace = fs.realpathSync(workspacePath);
  const resolvedBin = resolveBinaryPath(canonicalWorkspace, binaryPath);

  const engineArgs = [
    "run",
    "--json",
    "--no-exit-code-passthrough",
    "--workspace",
    canonicalWorkspace,
  ];
  if (sessionId && /^[A-Za-z0-9_.-]{1,128}$/.test(sessionId)) {
    engineArgs.push("--session", sessionId);
  }
  if (Number.isInteger(timeoutMs) && timeoutMs > 0) {
    engineArgs.push("--timeout-ms", String(timeoutMs));
  }
  engineArgs.push("--", ...argv);

  const stdout = execFileSync(resolvedBin, engineArgs, {
    cwd: canonicalWorkspace,
    encoding: "utf8",
    timeout: Math.max(timeoutMs + 2000, 5000),
    maxBuffer: 8 * 1024 * 1024,
    shell: false,
    windowsHide: true,
    env: buildScrubbedEnv(),
    stdio: ["ignore", "pipe", "pipe"],
  });

  return JSON.parse(stdout.trim());
}

/**
 * Safely pipe captured output to `context-engine index --stdin` via `execFileSync` (`shell: false`).
 */
export function invokeContextEngineIndex({
  binaryPath,
  workspacePath,
  content,
  label = "opencode-capture",
  sessionId = "",
}) {
  if (typeof content !== "string" || content.length === 0) {
    return null;
  }

  const canonicalWorkspace = fs.realpathSync(workspacePath);
  const resolvedBin = resolveBinaryPath(canonicalWorkspace, binaryPath);

  const engineArgs = [
    "index",
    "--stdin",
    "--json",
    "--workspace",
    canonicalWorkspace,
    "--label",
    String(label).slice(0, 128),
  ];
  if (sessionId && /^[A-Za-z0-9_.-]{1,128}$/.test(sessionId)) {
    engineArgs.push("--session", sessionId);
  }

  const stdout = execFileSync(resolvedBin, engineArgs, {
    input: content,
    cwd: canonicalWorkspace,
    encoding: "utf8",
    timeout: 10000,
    maxBuffer: 8 * 1024 * 1024,
    shell: false,
    windowsHide: true,
    env: buildScrubbedEnv(),
    stdio: ["pipe", "pipe", "ignore"],
  });

  return JSON.parse(stdout.trim());
}

export function formatCompactEnvelopeView(envelope, originalByteLength) {
  const transformations = Array.isArray(envelope?.view?.transformations)
    ? envelope.view.transformations.join(",")
    : "unknown_safe@1";
  const excerpt =
    typeof envelope?.view?.safe_excerpt === "string"
      ? envelope.view.safe_excerpt
      : "";
  const originalsAvailable = Boolean(envelope?.capture?.originals_available);

  const header =
    `[context-engine:reduced artifact_id=${envelope.artifact_id} ` +
    `kind=${envelope?.view?.kind || "summary"} ` +
    `raw_bytes=${originalByteLength} ` +
    `originals_available=${originalsAvailable} ` +
    `transformations=${transformations}]`;

  const footer =
    `[recovery] Call context-engine_context_search or context-engine_context_get ` +
    `{"artifact_id":"${envelope.artifact_id}","lines":{"start":1,"end":80}} ` +
    `to inspect exact original lines without re-running the command.`;

  return excerpt ? `${header}\n${excerpt}\n${footer}` : `${header}\n${footer}`;
}

/**
 * OpenCode plugin entrypoint (`tool.execute.after` hook).
 */
export const ContextEnginePlugin = async (ctx = {}) => {
  const rawRoot =
    ctx.worktree ||
    ctx.directory ||
    ctx.project?.worktree ||
    process.env.CONTEXT_ENGINE_WORKSPACE ||
    process.cwd();

  const canonicalWorkspace = fs.existsSync(rawRoot)
    ? fs.realpathSync(rawRoot)
    : path.resolve(rawRoot);

  return {
    "tool.execute.after": async (input, output) => {
      try {
        if (process.env.CONTEXT_ENGINE_DISABLE_HOOK === "1") {
          return;
        }
        if (!input || !output || typeof output.output !== "string") {
          return;
        }

        const toolName = String(input.tool || "").toLowerCase();
        if (
          toolName.startsWith("context-engine") ||
          toolName.startsWith("headroom") ||
          toolName.startsWith("caveman")
        ) {
          return;
        }

        const isShellTool = toolName === "bash" || toolName === "shell";
        const isReadTool = toolName === "read";
        if (!isShellTool && !isReadTool) {
          return;
        }

        if (hasTransformationMarker(output.output, output.metadata)) {
          return;
        }

        const toolArgs =
          input.args && typeof input.args === "object" ? input.args : {};

        if (isShellTool) {
          const cmdText = String(toolArgs.command || "");
          if (RECURSIVE_COMMAND_REGEX.test(cmdText)) {
            return;
          }
          if (
            /(^|[\s"'\\/])(\.env(\.[A-Za-z0-9_.-]+)?|id_rsa|id_ed25519|\.ssh|\.aws|\.npmrc|\.netrc)([\s"'\\/]|$)|\.(pem|key|pfx|p12)([\s"']|$)/i.test(
              cmdText
            )
          ) {
            return;
          }
        } else if (isReadTool) {
          const readPath = String(toolArgs.filePath || toolArgs.path || "");
          if (
            !readPath ||
            isSensitivePath(readPath) ||
            !isPathWithinWorkspace(readPath, canonicalWorkspace)
          ) {
            return;
          }
        }

        const parsedMin = Number.parseInt(
          process.env.CONTEXT_ENGINE_MIN_CAPTURE_BYTES || "4096",
          10
        );
        const minBytes =
          Number.isFinite(parsedMin) && parsedMin >= 0 ? parsedMin : 4096;
        const rawBytes = Buffer.byteLength(output.output, "utf8");
        if (rawBytes < minBytes) {
          return;
        }

        const envelope = invokeContextEngineIndex({
          workspacePath: canonicalWorkspace,
          content: output.output,
          label: `opencode-${toolName}`,
          sessionId: typeof input.sessionID === "string" ? input.sessionID : "",
        });

        if (
          !envelope ||
          typeof envelope.artifact_id !== "string" ||
          !envelope.artifact_id.startsWith("a_")
        ) {
          return;
        }

        output.metadata = {
          ...(output.metadata && typeof output.metadata === "object"
            ? output.metadata
            : {}),
          contextEngine: {
            artifactId: envelope.artifact_id,
            transformations: envelope?.view?.transformations || [],
            rawBytes,
          },
        };

        if (envelope?.view?.omitted === true) {
          const compactText = formatCompactEnvelopeView(envelope, rawBytes);
          if (Buffer.byteLength(compactText, "utf8") < rawBytes) {
            output.output = compactText;
          }
        }
      } catch {
        // Fail open: preserve untouched tool output if context-engine is unavailable or errors.
      }
    },
  };
};

export default ContextEnginePlugin;
