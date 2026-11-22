//! Domain error contracts and machine-readable error codes for Rust Context Engine.

use thiserror::Error;

/// Crate-wide result alias using [`ContextError`].
pub type Result<T> = std::result::Result<T, ContextError>;

/// Structured failure contract shared across all Context Engine crates.
#[derive(Debug, Error)]
pub enum ContextError {
    #[error("invalid workspace path '{path}': {reason}")]
    InvalidWorkspacePath { path: String, reason: String },

    #[error("invalid session id '{session_id}': {reason}")]
    InvalidSessionId { session_id: String, reason: String },

    #[error("invalid artifact id '{artifact_id}': {reason}")]
    InvalidArtifactId { artifact_id: String, reason: String },

    #[error("workspace scope violation (expected '{expected_workspace}', got '{actual_workspace}'): {detail}")]
    ScopeViolation {
        expected_workspace: String,
        actual_workspace: String,
        detail: String,
    },

    #[error("session scope mismatch (expected '{expected_session}', got '{actual_session}')")]
    SessionMismatch {
        expected_session: String,
        actual_session: String,
    },

    #[error("path '{path}' escapes confined workspace '{workspace_root}': {reason}")]
    PathEscape {
        path: String,
        workspace_root: String,
        reason: String,
    },

    #[error("sensitive path '{path}' blocked by policy rule '{rule}'")]
    SensitivePathBlocked { path: String, rule: String },

    #[error("command execution denied for '{program}': {reason}")]
    ExecutionDenied { program: String, reason: String },

    #[error("command execution timed out after {timeout_ms} ms")]
    ExecutionTimeout { timeout_ms: u64 },

    #[error("secret policy denied persistence ({findings_count} finding(s): {rule_ids:?})")]
    SecretPolicyDenied {
        findings_count: usize,
        rule_ids: Vec<String>,
    },

    #[error("artifact '{artifact_id}' raw stream is quarantined by secret policy: {reason}")]
    SecretQuarantined { artifact_id: String, reason: String },

    #[error("artifact not found in bound scope: '{artifact_id}'")]
    ArtifactNotFound { artifact_id: String },

    #[error("invalid {kind} range {start}:{end}: {reason}")]
    InvalidRange {
        kind: &'static str,
        start: u64,
        end: u64,
        reason: String,
    },

    #[error("budget exceeded for {resource}: requested {requested}, limit {limit}")]
    BudgetExceeded {
        resource: &'static str,
        requested: usize,
        limit: usize,
    },

    #[error("SHA-256 integrity mismatch (expected {expected_sha256}, actual {actual_sha256})")]
    IntegrityMismatch {
        expected_sha256: String,
        actual_sha256: String,
    },

    #[error("invalid configuration for '{field}': {reason}")]
    InvalidConfig { field: &'static str, reason: String },

    #[error("storage error: {message}")]
    Storage { message: String },

    #[error("search index error: {message}")]
    Search { message: String },

    #[error("journal error: {message}")]
    Journal { message: String },

    #[error("reducer '{reducer}' failed: {message}")]
    Reduction { reducer: String, message: String },

    #[error("protocol error: {message}")]
    Protocol { message: String },

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl ContextError {
    /// Returns a stable uppercase error code suitable for MCP `isError` responses and telemetry.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidWorkspacePath { .. } => "INVALID_WORKSPACE_PATH",
            Self::InvalidSessionId { .. } => "INVALID_SESSION_ID",
            Self::InvalidArtifactId { .. } => "INVALID_ARTIFACT_ID",
            Self::ScopeViolation { .. } => "SCOPE_VIOLATION",
            Self::SessionMismatch { .. } => "SESSION_MISMATCH",
            Self::PathEscape { .. } => "PATH_ESCAPE",
            Self::SensitivePathBlocked { .. } => "SENSITIVE_PATH_BLOCKED",
            Self::ExecutionDenied { .. } => "EXECUTION_DENIED",
            Self::ExecutionTimeout { .. } => "EXECUTION_TIMEOUT",
            Self::SecretPolicyDenied { .. } => "SECRET_POLICY_DENIED",
            Self::SecretQuarantined { .. } => "SECRET_QUARANTINED",
            Self::ArtifactNotFound { .. } => "ARTIFACT_NOT_FOUND",
            Self::InvalidRange { .. } => "INVALID_RANGE",
            Self::BudgetExceeded { .. } => "BUDGET_EXCEEDED",
            Self::IntegrityMismatch { .. } => "INTEGRITY_MISMATCH",
            Self::InvalidConfig { .. } => "INVALID_CONFIG",
            Self::Storage { .. } => "STORAGE_ERROR",
            Self::Search { .. } => "SEARCH_ERROR",
            Self::Journal { .. } => "JOURNAL_ERROR",
            Self::Reduction { .. } => "REDUCTION_ERROR",
            Self::Protocol { .. } => "PROTOCOL_ERROR",
            Self::Serialization(_) => "SERIALIZATION_ERROR",
            Self::Io(_) => "IO_ERROR",
        }
    }

    /// Returns `true` when the error represents an enforced security or policy boundary denial.
    #[must_use]
    pub fn is_security_denial(&self) -> bool {
        matches!(
            self,
            Self::ScopeViolation { .. }
                | Self::SessionMismatch { .. }
                | Self::PathEscape { .. }
                | Self::SensitivePathBlocked { .. }
                | Self::ExecutionDenied { .. }
                | Self::SecretPolicyDenied { .. }
                | Self::SecretQuarantined { .. }
        )
    }
}
