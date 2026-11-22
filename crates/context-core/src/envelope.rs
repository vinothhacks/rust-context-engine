//! Versioned `ArtifactEnvelope` (v1), stream metadata, views, and bounded retrieval ranges.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::budget::estimate_tokens_from_bytes;
use crate::error::{ContextError, Result};
use crate::scope::{ArtifactId, BoundScope, SessionId, WorkspaceScopeId, EMPTY_SHA256_HEX};

/// Current `ArtifactEnvelope` schema version (`1`).
pub const ARTIFACT_SCHEMA_VERSION: u32 = 1;

/// Tool name advertised in [`RecoveryHandle::tool`].
pub const RECOVERY_TOOL_CONTEXT_GET: &str = "context_get";

/// Identifies which captured stream is being indexed, searched, or retrieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    Stdout,
    Stderr,
    Combined,
    Document,
}

impl StreamKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Combined => "combined",
            Self::Document => "document",
        }
    }
}

impl fmt::Display for StreamKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for StreamKind {
    type Err = ContextError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "stdout" => Ok(Self::Stdout),
            "stderr" => Ok(Self::Stderr),
            "combined" => Ok(Self::Combined),
            "document" | "doc" => Ok(Self::Document),
            other => Err(ContextError::InvalidConfig {
                field: "stream",
                reason: format!(
                    "unknown stream '{other}' (expected stdout, stderr, combined, or document)"
                ),
            }),
        }
    }
}

/// Detected byte-level character encoding of a captured stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamEncoding {
    #[serde(rename = "utf-8")]
    Utf8,
    #[serde(rename = "utf-8-lossy")]
    Utf8Lossy,
    #[serde(rename = "binary")]
    Binary,
}

impl StreamEncoding {
    /// Classifies `bytes` as strict UTF-8 text or binary (when invalid UTF-8 or NUL bytes appear).
    #[must_use]
    pub fn detect(bytes: &[u8]) -> Self {
        if bytes.contains(&0) {
            return Self::Binary;
        }
        match std::str::from_utf8(bytes) {
            Ok(_) => Self::Utf8,
            Err(_) => Self::Binary,
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Utf8Lossy => "utf-8-lossy",
            Self::Binary => "binary",
        }
    }
}

impl fmt::Display for StreamEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classification of the compact view produced by `context-reducers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKind {
    TestSummary,
    CompilerDiagnostics,
    GitSummary,
    StructuredJson,
    LogSummary,
    SearchHits,
    DocumentIndex,
    UnknownSafe,
    Passthrough,
}

impl ViewKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TestSummary => "test_summary",
            Self::CompilerDiagnostics => "compiler_diagnostics",
            Self::GitSummary => "git_summary",
            Self::StructuredJson => "structured_json",
            Self::LogSummary => "log_summary",
            Self::SearchHits => "search_hits",
            Self::DocumentIndex => "document_index",
            Self::UnknownSafe => "unknown_safe",
            Self::Passthrough => "passthrough",
        }
    }
}

impl fmt::Display for ViewKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Provenance describing how an artifact entered the Context Engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactSource {
    Command {
        argv: Vec<String>,
        cwd_relative: String,
        exit_code: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timed_out: Option<bool>,
        captured_at: String,
    },
    Document {
        #[serde(skip_serializing_if = "Option::is_none")]
        path_relative: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        media_type: Option<String>,
        captured_at: String,
    },
}

impl ArtifactSource {
    /// Returns the RFC 3339 capture timestamp of this source.
    #[must_use]
    pub fn captured_at(&self) -> &str {
        match self {
            Self::Command { captured_at, .. } | Self::Document { captured_at, .. } => captured_at,
        }
    }

    /// Returns the process exit code if this artifact originated from a command.
    #[must_use]
    pub const fn exit_code(&self) -> Option<i32> {
        match self {
            Self::Command { exit_code, .. } => *exit_code,
            Self::Document { .. } => None,
        }
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(flag: &bool) -> bool {
    !*flag
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero_usize(val: &usize) -> bool {
    *val == 0
}

/// Integrity, byte-count, completeness, and secret-protection summary of captured streams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureSummary {
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub stdout_truncated: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub stderr_truncated: bool,
    pub complete: bool,
    pub encoding: StreamEncoding,
    pub originals_available: bool,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub secrets_redacted: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_rule_ids: Vec<String>,
}

impl CaptureSummary {
    /// Convenience constructor for single-stream document captures (`stderr` set to empty SHA-256).
    #[must_use]
    pub fn for_document(
        sha256: String,
        byte_len: u64,
        complete: bool,
        encoding: StreamEncoding,
        originals_available: bool,
    ) -> Self {
        Self {
            stdout_sha256: sha256,
            stderr_sha256: EMPTY_SHA256_HEX.to_string(),
            stdout_bytes: byte_len,
            stderr_bytes: 0,
            stdout_truncated: !complete,
            stderr_truncated: false,
            complete,
            encoding,
            originals_available,
            secrets_redacted: 0,
            secret_rule_ids: Vec::new(),
        }
    }
}

/// Compact, sanitized view returned immediately to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactView {
    pub kind: ViewKind,
    pub reducer_version: String,
    pub omitted: bool,
    pub safe_excerpt: String,
    pub transformations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reduction_error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failure_identifiers: Vec<String>,
}

/// Handle instructing an agent how to recover bounded exact ranges on demand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryHandle {
    pub tool: String,
    pub artifact_id: ArtifactId,
    pub bounded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes_per_call: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

impl RecoveryHandle {
    /// Constructs a standard bounded `context_get` recovery handle for `artifact_id`.
    #[must_use]
    pub fn for_artifact(artifact_id: ArtifactId, max_bytes_per_call: Option<usize>) -> Self {
        Self {
            tool: RECOVERY_TOOL_CONTEXT_GET.to_string(),
            artifact_id,
            bounded: true,
            max_bytes_per_call,
            unavailable_reason: None,
        }
    }

    /// Constructs a handle indicating that raw recovery is unavailable (e.g. quarantined).
    #[must_use]
    pub fn unavailable(artifact_id: ArtifactId, reason: impl Into<String>) -> Self {
        Self {
            tool: RECOVERY_TOOL_CONTEXT_GET.to_string(),
            artifact_id,
            bounded: true,
            max_bytes_per_call: None,
            unavailable_reason: Some(reason.into()),
        }
    }
}

/// Canonical v1 envelope returned by `context_run` and `context_index` (ADR 0001).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEnvelope {
    pub schema_version: u32,
    pub artifact_id: ArtifactId,
    pub project_scope: WorkspaceScopeId,
    pub session_id: SessionId,
    pub source: ArtifactSource,
    pub capture: CaptureSummary,
    pub view: ArtifactView,
    pub recovery: RecoveryHandle,
}

impl ArtifactEnvelope {
    /// Constructs a v1 [`ArtifactEnvelope`] bound to `scope`.
    #[must_use]
    pub fn new_v1(
        scope: &BoundScope,
        artifact_id: ArtifactId,
        source: ArtifactSource,
        capture: CaptureSummary,
        view: ArtifactView,
        recovery: RecoveryHandle,
    ) -> Self {
        Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            artifact_id,
            project_scope: scope.workspace_scope_id.clone(),
            session_id: scope.session_id.clone(),
            source,
            capture,
            view,
            recovery,
        }
    }

    /// Validates envelope structural invariants and binding against `caller_scope`.
    pub fn validate(&self, caller_scope: &BoundScope) -> Result<()> {
        if self.schema_version != ARTIFACT_SCHEMA_VERSION {
            return Err(ContextError::Protocol {
                message: format!(
                    "unsupported schema_version {} (expected {ARTIFACT_SCHEMA_VERSION})",
                    self.schema_version
                ),
            });
        }
        ArtifactId::parse(self.artifact_id.as_str())?;
        WorkspaceScopeId::parse(self.project_scope.as_str())?;
        SessionId::parse(self.session_id.as_str())?;

        caller_scope.verify_exact_scope(&self.project_scope, &self.session_id)?;

        if self.recovery.artifact_id != self.artifact_id {
            return Err(ContextError::Protocol {
                message: format!(
                    "recovery.artifact_id '{}' does not match envelope artifact_id '{}'",
                    self.recovery.artifact_id, self.artifact_id
                ),
            });
        }
        Ok(())
    }

    /// Total raw captured bytes across `stdout` and `stderr`.
    #[must_use]
    pub const fn total_raw_bytes(&self) -> u64 {
        self.capture
            .stdout_bytes
            .saturating_add(self.capture.stderr_bytes)
    }

    /// UTF-8 byte length of the compact view excerpt.
    #[must_use]
    pub fn view_bytes(&self) -> u64 {
        self.view.safe_excerpt.len() as u64
    }

    /// Heuristic raw token count (`ceil(total_raw_bytes / 4)`).
    #[must_use]
    pub const fn estimated_raw_tokens(&self) -> u64 {
        estimate_tokens_from_bytes(self.total_raw_bytes())
    }

    /// Heuristic reduced view token count (`ceil(view_bytes / 4)`).
    #[must_use]
    pub fn estimated_view_tokens(&self) -> u64 {
        estimate_tokens_from_bytes(self.view_bytes())
    }
}

/// Half-open byte offset range `[start, end)` for exact binary/UTF-8 pagination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    /// Validates `[start, end)` against `max_bytes`.
    pub fn new(start: u64, end: u64, max_bytes: usize) -> Result<Self> {
        if end < start {
            return Err(ContextError::InvalidRange {
                kind: "byte",
                start,
                end,
                reason: "end offset must be >= start offset".to_string(),
            });
        }
        let span = end - start;
        if span > max_bytes as u64 {
            return Err(ContextError::BudgetExceeded {
                resource: "context_get.bytes",
                requested: usize::try_from(span).unwrap_or(usize::MAX),
                limit: max_bytes,
            });
        }
        Ok(Self { start, end })
    }

    /// Parses `"start:end"` (e.g. `"0:4096"`) and validates against `max_bytes`.
    pub fn parse(spec: &str, max_bytes: usize) -> Result<Self> {
        let (left, right) =
            spec.trim()
                .split_once(':')
                .ok_or_else(|| ContextError::InvalidRange {
                    kind: "byte",
                    start: 0,
                    end: 0,
                    reason: format!("expected 'start:end' byte range, got '{spec}'"),
                })?;
        let start: u64 = left.parse().map_err(|_| ContextError::InvalidRange {
            kind: "byte",
            start: 0,
            end: 0,
            reason: format!("invalid start byte offset '{left}'"),
        })?;
        let end: u64 = right.parse().map_err(|_| ContextError::InvalidRange {
            kind: "byte",
            start,
            end: 0,
            reason: format!("invalid end byte offset '{right}'"),
        })?;
        Self::new(start, end, max_bytes)
    }

    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end - self.start
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end == self.start
    }
}

/// 1-indexed inclusive line range `[start_line, end_line]` for derived UTF-8 pagination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineRange {
    pub start_line: usize,
    pub end_line: usize,
}

impl LineRange {
    /// Validates 1-indexed inclusive `[start_line, end_line]` against `max_lines`.
    pub fn new(start_line: usize, end_line: usize, max_lines: usize) -> Result<Self> {
        if start_line == 0 {
            return Err(ContextError::InvalidRange {
                kind: "line",
                start: 0,
                end: end_line as u64,
                reason: "line numbers are 1-indexed and must be >= 1".to_string(),
            });
        }
        if end_line < start_line {
            return Err(ContextError::InvalidRange {
                kind: "line",
                start: start_line as u64,
                end: end_line as u64,
                reason: "end_line must be >= start_line".to_string(),
            });
        }
        let count = end_line - start_line + 1;
        if count > max_lines {
            return Err(ContextError::BudgetExceeded {
                resource: "context_get.lines",
                requested: count,
                limit: max_lines,
            });
        }
        Ok(Self {
            start_line,
            end_line,
        })
    }

    /// Parses `"start:end"` (e.g. `"10:70"`) as a 1-indexed inclusive line range.
    pub fn parse(spec: &str, max_lines: usize) -> Result<Self> {
        let (left, right) =
            spec.trim()
                .split_once(':')
                .ok_or_else(|| ContextError::InvalidRange {
                    kind: "line",
                    start: 0,
                    end: 0,
                    reason: format!("expected 'start:end' line range, got '{spec}'"),
                })?;
        let start: usize = left.parse().map_err(|_| ContextError::InvalidRange {
            kind: "line",
            start: 0,
            end: 0,
            reason: format!("invalid start line '{left}'"),
        })?;
        let end: usize = right.parse().map_err(|_| ContextError::InvalidRange {
            kind: "line",
            start: start as u64,
            end: 0,
            reason: format!("invalid end line '{right}'"),
        })?;
        Self::new(start, end, max_lines)
    }

    /// Number of lines covered by this inclusive range.
    #[must_use]
    pub const fn line_count(&self) -> usize {
        self.end_line - self.start_line + 1
    }
}
