//! Structured event, telemetry, checkpoint, and `ResumePack` contracts for `context-journal`.

use std::fmt;
use std::str::FromStr;

use context_core::{
    estimate_tokens_from_bytes, ArtifactId, ContextError, RecoveryHandle, Result, SessionId,
    StreamKind, WorkspaceScopeId,
};
use serde::{Deserialize, Serialize};

/// Non-sensitive session event categories recorded in [`crate::SessionJournal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalEventKind {
    CommandCaptured,
    DocumentIndexed,
    ArtifactSearched,
    ArtifactRetrieved,
    SecurityDenied,
    CheckpointCreated,
}

impl JournalEventKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CommandCaptured => "command_captured",
            Self::DocumentIndexed => "document_indexed",
            Self::ArtifactSearched => "artifact_searched",
            Self::ArtifactRetrieved => "artifact_retrieved",
            Self::SecurityDenied => "security_denied",
            Self::CheckpointCreated => "checkpoint_created",
        }
    }
}

impl fmt::Display for JournalEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for JournalEventKind {
    type Err = ContextError;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "command_captured" => Ok(Self::CommandCaptured),
            "document_indexed" => Ok(Self::DocumentIndexed),
            "artifact_searched" => Ok(Self::ArtifactSearched),
            "artifact_retrieved" => Ok(Self::ArtifactRetrieved),
            "security_denied" => Ok(Self::SecurityDenied),
            "checkpoint_created" => Ok(Self::CheckpointCreated),
            other => Err(ContextError::Journal {
                message: format!("unknown journal event kind '{other}'"),
            }),
        }
    }
}

/// Structured input payload for appending a non-sensitive event to [`crate::SessionJournal`].
///
/// All string fields are passed through [`context_core::SecretGuard`] before SQLite persistence
/// so accidental credentials in command arguments, error reasons, or failure names are never logged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEventInput {
    pub kind: JournalEventKind,
    pub artifact_id: Option<ArtifactId>,
    pub command_summary: Option<String>,
    pub source_label: Option<String>,
    pub stream: Option<StreamKind>,
    pub reducer_id: Option<String>,
    pub exit_code: Option<i32>,
    pub raw_bytes: u64,
    pub view_bytes: u64,
    pub retrieved_bytes: u64,
    /// Optional override; defaults to `estimate_tokens_from_bytes(raw_bytes)` when `None`.
    pub estimated_raw_tokens: Option<u64>,
    /// Optional override; defaults to `estimate_tokens_from_bytes(view_bytes)` when `None`.
    pub estimated_view_tokens: Option<u64>,
    /// Optional override; defaults to `estimate_tokens_from_bytes(retrieved_bytes)` when `None`.
    pub estimated_retrieved_tokens: Option<u64>,
    /// Marks whether this capture hit an existing content-addressed blob or already-reduced ledger.
    pub deduplicated: bool,
    /// Whether raw recovery via `context_get` is permitted for `artifact_id`.
    pub originals_available: bool,
    /// Count of secrets redacted during stream protection (never the secret values).
    pub secrets_redacted: usize,
    /// Machine-readable denial code (e.g. `"SCOPE_VIOLATION"`, `"EXECUTION_DENIED"`).
    pub denial_code: Option<String>,
    /// Sanitized human-readable denial reason.
    pub denial_reason: Option<String>,
    /// Failing test names or compiler diagnostic identifiers (`file:line` / error codes).
    pub failure_identifiers: Vec<String>,
    /// Hit count returned by `context_search` when `kind == ArtifactSearched`.
    pub search_hit_count: Option<usize>,
    /// Wall-clock duration in milliseconds for the recorded operation.
    pub latency_ms: Option<u64>,
}

impl JournalEventInput {
    /// Creates a baseline event of `kind` with zeroed byte/token counters.
    #[must_use]
    pub fn new(kind: JournalEventKind) -> Self {
        Self {
            kind,
            artifact_id: None,
            command_summary: None,
            source_label: None,
            stream: None,
            reducer_id: None,
            exit_code: None,
            raw_bytes: 0,
            view_bytes: 0,
            retrieved_bytes: 0,
            estimated_raw_tokens: None,
            estimated_view_tokens: None,
            estimated_retrieved_tokens: None,
            deduplicated: false,
            originals_available: true,
            secrets_redacted: 0,
            denial_code: None,
            denial_reason: None,
            failure_identifiers: Vec::new(),
            search_hit_count: None,
            latency_ms: None,
        }
    }

    #[must_use]
    pub fn resolved_raw_tokens(&self) -> u64 {
        self.estimated_raw_tokens
            .unwrap_or_else(|| estimate_tokens_from_bytes(self.raw_bytes))
    }

    #[must_use]
    pub fn resolved_view_tokens(&self) -> u64 {
        self.estimated_view_tokens
            .unwrap_or_else(|| estimate_tokens_from_bytes(self.view_bytes))
    }

    #[must_use]
    pub fn resolved_retrieved_tokens(&self) -> u64 {
        self.estimated_retrieved_tokens
            .unwrap_or_else(|| estimate_tokens_from_bytes(self.retrieved_bytes))
    }
}

/// Persisted, sanitized journal event returned by [`crate::SessionJournal::record_event`] and
/// [`crate::SessionJournal::list_recent_events`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedEvent {
    pub event_seq: u64,
    pub workspace_scope_id: WorkspaceScopeId,
    pub session_id: SessionId,
    pub kind: JournalEventKind,
    pub recorded_at: String,
    pub artifact_id: Option<ArtifactId>,
    pub command_summary: Option<String>,
    pub source_label: Option<String>,
    pub stream: Option<StreamKind>,
    pub reducer_id: Option<String>,
    pub exit_code: Option<i32>,
    pub raw_bytes: u64,
    pub view_bytes: u64,
    pub retrieved_bytes: u64,
    pub estimated_raw_tokens: u64,
    pub estimated_view_tokens: u64,
    pub estimated_retrieved_tokens: u64,
    pub deduplicated: bool,
    pub originals_available: bool,
    pub secrets_redacted: usize,
    pub denial_code: Option<String>,
    pub denial_reason: Option<String>,
    pub failure_identifiers: Vec<String>,
    pub search_hit_count: Option<usize>,
    pub latency_ms: Option<u64>,
}

/// Compact summary of a recently executed command surfaced in checkpoints and `context_resume`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentCommandRecord {
    pub event_seq: u64,
    pub recorded_at: String,
    pub command_summary: String,
    pub exit_code: Option<i32>,
    pub reducer_id: Option<String>,
    pub artifact_id: Option<ArtifactId>,
    pub failure_count: usize,
    pub latency_ms: Option<u64>,
}

/// Active artifact pointer paired with its bounded `context_get` [`RecoveryHandle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveArtifactHandle {
    pub artifact_id: ArtifactId,
    pub event_kind: JournalEventKind,
    pub label: String,
    pub reducer_id: Option<String>,
    pub exit_code: Option<i32>,
    pub recorded_at: String,
    pub has_failures: bool,
    pub recovery: RecoveryHandle,
}

/// Aggregate session or workspace compression, retrieval-overhead, and safety telemetry.
///
/// ### Accounting Identities
/// - `exposed_bytes = view_bytes + retrieved_bytes`
/// - `net_saved_bytes = raw_bytes - exposed_bytes` (signed `i64`: negative if excess retrieval
///   exceeded raw capture size, never falsely clamped to positive savings)
/// - `net_byte_savings_ratio = (raw_bytes - exposed_bytes) / raw_bytes`
/// - `retrieval_overhead_ratio = retrieved_bytes / raw_bytes`
/// - `net_token_savings_ratio = (estimated_raw_tokens - estimated_exposed_tokens) / estimated_raw_tokens`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionStats {
    pub workspace_scope_id: WorkspaceScopeId,
    /// `Some(session_id)` for single-session queries; `None` when aggregated across all workspace sessions.
    pub session_id: Option<SessionId>,
    pub distinct_sessions: usize,
    pub total_events: u64,
    /// Total captured artifacts (`command_captures + document_indexes`).
    pub total_captures: u64,
    pub command_captures: u64,
    pub document_indexes: u64,
    pub search_queries: u64,
    pub retrieval_calls: u64,
    pub checkpoints_created: u64,
    pub cache_dedup_hits: u64,
    pub security_denials: u64,
    pub secrets_redacted_total: u64,
    pub raw_bytes: u64,
    pub view_bytes: u64,
    pub retrieved_bytes: u64,
    pub exposed_bytes: u64,
    pub net_saved_bytes: i64,
    pub estimated_raw_tokens: u64,
    pub estimated_view_tokens: u64,
    pub estimated_retrieved_tokens: u64,
    pub estimated_exposed_tokens: u64,
    pub estimated_net_saved_tokens: i64,
    /// Initial view compression ratio `(raw_bytes - view_bytes) / raw_bytes` (`0.0` when `raw_bytes == 0`).
    pub view_reduction_ratio: f64,
    /// Net byte savings ratio `(raw_bytes - (view_bytes + retrieved_bytes)) / raw_bytes`.
    pub net_byte_savings_ratio: f64,
    /// Net token savings ratio `(estimated_raw_tokens - estimated_exposed_tokens) / estimated_raw_tokens`.
    pub net_token_savings_ratio: f64,
    /// Follow-up byte retrieval overhead relative to raw bytes (`retrieved_bytes / raw_bytes`).
    pub retrieval_overhead_ratio: f64,
    /// Follow-up token retrieval overhead relative to raw tokens (`estimated_retrieved_tokens / estimated_raw_tokens`).
    pub token_retrieval_overhead_ratio: f64,
}

impl SessionStats {
    /// Constructs a zeroed [`SessionStats`] for an empty session or workspace.
    #[must_use]
    pub fn empty(workspace_scope_id: WorkspaceScopeId, session_id: Option<SessionId>) -> Self {
        Self {
            workspace_scope_id,
            session_id,
            distinct_sessions: 0,
            total_events: 0,
            total_captures: 0,
            command_captures: 0,
            document_indexes: 0,
            search_queries: 0,
            retrieval_calls: 0,
            checkpoints_created: 0,
            cache_dedup_hits: 0,
            security_denials: 0,
            secrets_redacted_total: 0,
            raw_bytes: 0,
            view_bytes: 0,
            retrieved_bytes: 0,
            exposed_bytes: 0,
            net_saved_bytes: 0,
            estimated_raw_tokens: 0,
            estimated_view_tokens: 0,
            estimated_retrieved_tokens: 0,
            estimated_exposed_tokens: 0,
            estimated_net_saved_tokens: 0,
            view_reduction_ratio: 0.0,
            net_byte_savings_ratio: 0.0,
            net_token_savings_ratio: 0.0,
            retrieval_overhead_ratio: 0.0,
            token_retrieval_overhead_ratio: 0.0,
        }
    }
}

/// Deterministic continuity checkpoint persisted by [`crate::SessionJournal::create_checkpoint`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionCheckpoint {
    /// Opaque server-minted checkpoint identifier (`cp_<32-lowercase-hex>`).
    pub checkpoint_id: String,
    pub workspace_scope_id: WorkspaceScopeId,
    pub session_id: SessionId,
    /// Highest `journal_events.event_seq` included in this checkpoint.
    pub up_to_event_seq: u64,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub recent_commands: Vec<RecentCommandRecord>,
    pub unresolved_failures: Vec<String>,
    pub active_artifacts: Vec<ActiveArtifactHandle>,
    pub stats: SessionStats,
}

/// Continuity recovery bundle returned by [`crate::SessionJournal::resume`] (`context_resume`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResumePack {
    pub workspace_scope_id: WorkspaceScopeId,
    pub session_id: SessionId,
    pub resumed_at: String,
    /// Most recent explicit checkpoint in this `(workspace_scope_id, session_id)`, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_checkpoint: Option<SessionCheckpoint>,
    /// Count of journal events recorded in this session after `latest_checkpoint` (or total events if `None`).
    pub events_since_checkpoint: u64,
    /// Bounded chronological window of recent commands in this session (oldest-to-newest within window).
    pub recent_commands: Vec<RecentCommandRecord>,
    /// Currently unresolved failing test/compiler identifiers across active check families.
    pub unresolved_failures: Vec<String>,
    /// Prioritized active `ArtifactId` entries paired with `context_get` [`RecoveryHandle`]s.
    pub active_artifacts: Vec<ActiveArtifactHandle>,
    /// Live session compression and retrieval-overhead telemetry.
    pub stats: SessionStats,
}

impl ResumePack {
    /// Extracts the ordered `context_get` [`RecoveryHandle`] list for active session artifacts.
    #[must_use]
    pub fn recovery_handles(&self) -> Vec<RecoveryHandle> {
        self.active_artifacts
            .iter()
            .map(|item| item.recovery.clone())
            .collect()
    }
}

/// Summary returned by [`crate::SessionJournal::prune_expired`] and
/// [`crate::SessionJournal::prune_before_unix_ms`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalPruneReport {
    pub pruned_events: usize,
    pub pruned_checkpoints: usize,
}
