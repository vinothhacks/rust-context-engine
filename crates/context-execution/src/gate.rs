//! Command execution gate (`CommandRequest` -> `ApprovedCommand`) enforcing allowlists,
//! destructive-flag blocking, workspace `cwd` confinement, timeouts, and env scrubbing.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

use context_core::{BoundScope, ContextError, ExecutionPolicyConfig, Result};
use serde::{Deserialize, Serialize};

use crate::confinement::{
    open_confined_file, open_confined_file_sync, resolve_cwd_in_scope,
    resolve_existing_file_in_scope, resolve_path_in_scope, ConfinedPath,
};

/// Untrusted command execution request submitted by an MCP tool or CLI caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRequest {
    /// Direct `argv` vector (`argv[0]` is executable name, `argv[1..]` are arguments).
    pub argv: Vec<String>,
    /// Optional working directory (relative to `BoundScope::workspace_root` or canonical inside it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    /// Optional wall-clock timeout override in milliseconds (capped by `ExecutionPolicyConfig::max_timeout_ms`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Optional extra environment variables (subject to `ExecutionPolicyConfig::filter_safe_env`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_env: Vec<(String, String)>,
    /// Optional per-stream byte capture limit override (capped by `ExecutionPolicyConfig::max_stream_bytes`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_stream_bytes: Option<u64>,
}

impl CommandRequest {
    /// Constructs a [`CommandRequest`] for `argv` using default workspace `cwd` and policy limits.
    pub fn new<I, S>(argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            cwd: None,
            timeout_ms: None,
            extra_env: Vec::new(),
            max_stream_bytes: None,
        }
    }

    /// Sets the requested working directory.
    #[must_use]
    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Sets the requested wall-clock timeout in milliseconds.
    #[must_use]
    pub const fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }

    /// Appends extra environment variables (still scrubbed by policy before execution).
    #[must_use]
    pub fn with_extra_env<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.extra_env
            .extend(vars.into_iter().map(|(k, v)| (k.into(), v.into())));
        self
    }

    /// Overrides the per-stream byte capture ceiling (cannot exceed policy ceiling).
    #[must_use]
    pub const fn with_max_stream_bytes(mut self, max_stream_bytes: u64) -> Self {
        self.max_stream_bytes = Some(max_stream_bytes);
        self
    }
}

/// Sealed, policy-validated command specification ready to be spawned by `context-capture`.
///
/// Fields are intentionally private so an [`ApprovedCommand`] can only be minted by
/// [`ExecutionGate::authorize`] / [`ExecutionGate::authorize_with_env`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedCommand {
    scope: BoundScope,
    normalized_program: String,
    argv: Vec<String>,
    cwd: ConfinedPath,
    scrubbed_env: Vec<(String, String)>,
    timeout_ms: u64,
    max_stream_bytes: u64,
}

impl ApprovedCommand {
    /// Server-bound workspace and session scope under which this command was authorized.
    #[must_use]
    pub const fn scope(&self) -> &BoundScope {
        &self.scope
    }

    /// Normalized lowercase base executable name (e.g. `"cargo"`).
    #[must_use]
    pub fn normalized_program(&self) -> &str {
        &self.normalized_program
    }

    /// Raw validated `argv[0]` executable string passed to `Command::new`.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.argv[0]
    }

    /// Validated `argv[1..]` argument slice passed to `Command::args`.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.argv[1..]
    }

    /// Full validated `argv` slice.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// Confined working directory (canonical + workspace-relative).
    #[must_use]
    pub const fn cwd(&self) -> &ConfinedPath {
        &self.cwd
    }

    /// Canonical filesystem path of the working directory.
    #[must_use]
    pub fn cwd_canonical(&self) -> &Path {
        &self.cwd.canonical
    }

    /// Workspace-relative working directory string (`"."` for workspace root).
    #[must_use]
    pub fn cwd_relative(&self) -> &str {
        &self.cwd.relative
    }

    /// Scrubbed, non-sensitive environment variables passed to the child process.
    #[must_use]
    pub fn scrubbed_env(&self) -> &[(String, String)] {
        &self.scrubbed_env
    }

    /// Enforced wall-clock timeout in milliseconds.
    #[must_use]
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Enforced wall-clock timeout as [`Duration`].
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    /// Maximum captured bytes per child stream (`stdout` / `stderr`).
    #[must_use]
    pub const fn max_stream_bytes(&self) -> u64 {
        self.max_stream_bytes
    }
}

/// Stateful authorization gate combining [`ExecutionPolicyConfig`] with workspace confinement.
#[derive(Debug, Clone, Default)]
pub struct ExecutionGate {
    policy: ExecutionPolicyConfig,
    allow_network_uploads: bool,
}

impl ExecutionGate {
    /// Creates an [`ExecutionGate`] enforcing `policy` (with network upload flags disabled).
    #[must_use]
    pub const fn new(policy: ExecutionPolicyConfig) -> Self {
        Self {
            policy,
            allow_network_uploads: false,
        }
    }

    /// Explicitly permits or denies HTTP/file upload flags if `curl` or `wget` were policy-enabled.
    #[must_use]
    pub const fn with_allow_network_uploads(mut self, allow: bool) -> Self {
        self.allow_network_uploads = allow;
        self
    }

    /// Returns the active [`ExecutionPolicyConfig`].
    #[must_use]
    pub const fn policy(&self) -> &ExecutionPolicyConfig {
        &self.policy
    }

    /// Resolves an arbitrary path (existing or non-existent leaf) inside `scope`.
    pub fn resolve_path(&self, scope: &BoundScope, requested: &Path) -> Result<ConfinedPath> {
        resolve_path_in_scope(scope, &self.policy, requested)
    }

    /// Resolves and validates a working directory inside `scope`.
    pub fn resolve_cwd(
        &self,
        scope: &BoundScope,
        requested_cwd: Option<&Path>,
    ) -> Result<ConfinedPath> {
        resolve_cwd_in_scope(scope, &self.policy, requested_cwd)
    }

    /// Resolves and validates an existing regular file inside `scope`.
    pub fn resolve_file(&self, scope: &BoundScope, requested_file: &Path) -> Result<ConfinedPath> {
        resolve_existing_file_in_scope(scope, &self.policy, requested_file)
    }

    /// Opens a confined regular file synchronously with TOCTOU verification.
    pub fn open_file_sync(
        &self,
        scope: &BoundScope,
        requested_file: &Path,
    ) -> Result<(File, ConfinedPath)> {
        open_confined_file_sync(scope, &self.policy, requested_file)
    }

    /// Opens a confined regular file asynchronously with TOCTOU verification.
    pub async fn open_file(
        &self,
        scope: &BoundScope,
        requested_file: &Path,
    ) -> Result<(tokio::fs::File, ConfinedPath)> {
        open_confined_file(scope, &self.policy, requested_file).await
    }

    /// Validates `request` against `scope` and the process environment (`std::env::vars()`),
    /// returning a sealed [`ApprovedCommand`].
    pub fn authorize(
        &self,
        scope: &BoundScope,
        request: &CommandRequest,
    ) -> Result<ApprovedCommand> {
        self.authorize_with_env(scope, request, std::env::vars())
    }

    /// Validates `request` against `scope` using an explicit `base_env` iterator (useful for
    /// deterministic hermetic unit testing without mutating global `std::env`).
    pub fn authorize_with_env<I, K, V>(
        &self,
        scope: &BoundScope,
        request: &CommandRequest,
        base_env: I,
    ) -> Result<ApprovedCommand>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let normalized_program = self.policy.validate_argv(&request.argv)?;
        self.validate_extended_argument_safety(
            &normalized_program,
            &request.argv[1..],
            &request.argv[0],
        )?;

        let timeout_ms = self.policy.resolve_timeout_ms(request.timeout_ms)?;
        let max_stream_bytes = self.resolve_max_stream_bytes(request.max_stream_bytes)?;
        let cwd = self.resolve_cwd(scope, request.cwd.as_deref())?;

        let safe_base = self.policy.filter_safe_env(base_env);
        let safe_extra = self.policy.filter_safe_env(request.extra_env.iter().cloned());
        let scrubbed_env = merge_env_vars(safe_base, safe_extra);

        Ok(ApprovedCommand {
            scope: scope.clone(),
            normalized_program,
            argv: request.argv.clone(),
            cwd,
            scrubbed_env,
            timeout_ms,
            max_stream_bytes,
        })
    }

    fn resolve_max_stream_bytes(&self, requested: Option<u64>) -> Result<u64> {
        if self.policy.max_stream_bytes == 0 {
            return Err(ContextError::InvalidConfig {
                field: "max_stream_bytes",
                reason: "policy max_stream_bytes must be greater than 0".to_string(),
            });
        }
        let stream_bytes = requested.unwrap_or(self.policy.max_stream_bytes);
        if stream_bytes == 0 {
            return Err(ContextError::InvalidConfig {
                field: "max_stream_bytes",
                reason: "requested max_stream_bytes must be greater than 0".to_string(),
            });
        }
        if stream_bytes > self.policy.max_stream_bytes {
            return Err(ContextError::BudgetExceeded {
                resource: "execution.max_stream_bytes",
                requested: usize::try_from(stream_bytes).unwrap_or(usize::MAX),
                limit: usize::try_from(self.policy.max_stream_bytes).unwrap_or(usize::MAX),
            });
        }
        Ok(stream_bytes)
    }

    fn validate_extended_argument_safety(
        &self,
        base: &str,
        args: &[String],
        raw_program: &str,
    ) -> Result<()> {
        let lower_args: Vec<String> = args.iter().map(|a| a.to_ascii_lowercase()).collect();

        // Enforce ADR 0003: block `git clean` with `-d` as well as `-f`/`-x`.
        if base == "git" {
            let subcmd = lower_args
                .iter()
                .find(|a| !a.starts_with('-'))
                .map(String::as_str);
            if subcmd == Some("clean")
                && lower_args.iter().any(|a| {
                    a.starts_with('-')
                        && !a.starts_with("--")
                        && (a.contains('d') || a.contains('f') || a.contains('x'))
                })
            {
                return Err(ContextError::ExecutionDenied {
                    program: raw_program.to_string(),
                    reason: "'git clean -d/-f/-x' is blocked as a destructive operation"
                        .to_string(),
                });
            }
        }

        // Even if an operator explicitly enables `curl` or `wget` in `ExecutionPolicyConfig`,
        // block outbound data/file upload flags unless `allow_network_uploads` is also enabled.
        if !self.allow_network_uploads && matches!(base, "curl" | "wget") {
            let is_upload = lower_args.iter().any(|arg| {
                matches!(
                    arg.as_str(),
                    "-d" | "--data"
                        | "--data-raw"
                        | "--data-binary"
                        | "--data-urlencode"
                        | "--json"
                        | "-f"
                        | "--form"
                        | "--form-string"
                        | "-t"
                        | "--upload-file"
                        | "--post-data"
                        | "--post-file"
                ) || arg.starts_with("--data=")
                    || arg.starts_with("--form=")
                    || arg.starts_with("--upload-file=")
                    || arg.starts_with("--post-data=")
                    || arg.starts_with("--post-file=")
            }) || lower_args.windows(2).any(|w| {
                (w[0] == "-x" || w[0] == "--request" || w[0] == "--method")
                    && matches!(w[1].as_str(), "post" | "put" | "patch" | "delete")
            });

            if is_upload {
                return Err(ContextError::ExecutionDenied {
                    program: raw_program.to_string(),
                    reason: format!(
                        "network upload/mutation flags on '{base}' are blocked by execution policy"
                    ),
                });
            }
        }

        Ok(())
    }
}

/// Convenience helper authorizing `request` against `scope` and `policy`.
pub fn authorize_command(
    scope: &BoundScope,
    policy: &ExecutionPolicyConfig,
    request: &CommandRequest,
) -> Result<ApprovedCommand> {
    ExecutionGate::new(policy.clone()).authorize(scope, request)
}

fn merge_env_vars(
    base: Vec<(String, String)>,
    extra: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let mut merged: Vec<(String, String)> = Vec::with_capacity(base.len() + extra.len());
    for (k, v) in base.into_iter().chain(extra) {
        if let Some(existing) = merged.iter_mut().find(|(ek, _)| env_key_eq(ek, &k)) {
            existing.0 = k;
            existing.1 = v;
        } else {
            merged.push((k, v));
        }
    }
    merged
}

fn env_key_eq(a: &str, b: &str) -> bool {
    #[cfg(windows)]
    {
        a.eq_ignore_ascii_case(b)
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}
