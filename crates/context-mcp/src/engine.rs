//! Unified 9-step `ContextEngine` pipeline shared identically by `context-mcp` and `context-cli`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use context_capture::{
    capture_bytes, capture_command_with_cancel, capture_file, CaptureCancelToken,
};
use context_core::{
    ArtifactEnvelope, ArtifactId, BoundScope, ByteRange, ContextError, ExecutionPolicyConfig,
    LineRange, ReductionBudget, Result, SecretGuard, SecretPolicy, SecretPolicyMode, SessionId,
    StreamEncoding, StreamKind, WorkspaceScopeId, ARTIFACT_SCHEMA_VERSION,
};
use context_execution::{CommandRequest, ExecutionGate};
use context_journal::{
    JournalConfig, JournalHealthReport, JournalPruneReport, ResumePack, SessionJournal,
    SessionStats,
};
use context_reducers::{CommandReductionInput, DocumentReductionInput, ReducerEngine};
use context_search::{ChunkConfig, SearchConfig, SearchHealthReport, SearchHit, SearchIndex};
use context_store::{
    ArtifactStreamInput, BlobStore, LineSlicePage, PrunePolicy, PruneReport as StorePruneReport,
    PutArtifactRequest, StorePermissionReport, StoreStats,
};
use serde::{Deserialize, Serialize};

/// Configuration bundle for constructing a [`ContextEngine`].
#[derive(Debug, Clone, Default)]
pub struct EngineConfig {
    pub execution_policy: ExecutionPolicyConfig,
    pub secret_policy: SecretPolicy,
    pub budget: ReductionBudget,
    pub allow_network_uploads: bool,
}

/// Request payload for `context_run` / `context-engine run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunCommandRequest {
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_project_scope: Option<String>,
}

impl RunCommandRequest {
    /// Constructs a [`RunCommandRequest`] for `argv` using the bound workspace defaults.
    pub fn new<I, S>(argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            cwd: None,
            timeout_ms: None,
            session_id: None,
            client_project_scope: None,
        }
    }
}

/// Result returned by [`ContextEngine::run_command`] / [`ContextEngine::run_command_with_cancel`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunCommandOutcome {
    pub envelope: ArtifactEnvelope,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub deduplicated: bool,
}

/// Source payload for `context_index` / `context-engine index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexSource {
    /// Confined path inside the bound workspace.
    FilePath(PathBuf),
    /// Raw inline content bytes (e.g. MCP `content` field or CLI `--stdin`).
    InlineBytes(Vec<u8>),
}

/// Request payload for [`ContextEngine::index_document`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexDocumentRequest {
    pub source: IndexSource,
    pub label: Option<String>,
    pub media_type: Option<String>,
    pub session_id: Option<String>,
    pub client_project_scope: Option<String>,
}

/// Result returned by [`ContextEngine::index_document`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexDocumentOutcome {
    pub envelope: ArtifactEnvelope,
    pub chunks_indexed: usize,
    pub deduplicated: bool,
}

/// Request payload for [`ContextEngine::search`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchQueryRequest {
    pub query: String,
    pub session_only: bool,
    pub limit: Option<usize>,
    pub session_id: Option<String>,
    pub client_project_scope: Option<String>,
}

/// Ranked FTS5 search response returned by [`ContextEngine::search`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchQueryOutcome {
    pub workspace_scope_id: WorkspaceScopeId,
    pub session_id: SessionId,
    pub session_only: bool,
    pub query: String,
    pub hit_count: usize,
    pub hits: Vec<SearchHit>,
}

/// Range selector for [`ContextEngine::get_slice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetRangeSelector {
    /// Default bounded window (`1:80` lines for UTF-8 streams, `0:4096` bytes for binary streams).
    DefaultWindow,
    /// 1-indexed inclusive line range `[start_line, end_line]`.
    Lines(LineRange),
    /// Half-open byte range `[start, end)`.
    Bytes(ByteRange),
}

/// Request payload for [`ContextEngine::get_slice`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetSliceRequest {
    pub artifact_id: String,
    pub stream: Option<StreamKind>,
    pub range: GetRangeSelector,
    pub session_id: Option<String>,
    pub client_project_scope: Option<String>,
}

/// Binary-safe JSON-serializable byte-slice recovery page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSliceResponse {
    pub artifact_id: ArtifactId,
    pub stream: StreamKind,
    pub sha256: String,
    pub encoding: StreamEncoding,
    pub exact_raw_preserved: bool,
    pub total_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_lines: Option<usize>,
    pub returned_range: ByteRange,
    pub byte_length: usize,
    pub has_more: bool,
    /// Strict UTF-8 view when the returned slice is valid UTF-8 (`None` for binary/partial codepoints).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utf8_text: Option<String>,
    /// Lossless standard Base64 encoding of the exact returned byte slice.
    pub base64_bytes: String,
    /// Exact raw bytes kept in memory for native Rust/CLI callers without Base64 overhead.
    #[serde(skip)]
    pub raw_bytes: Vec<u8>,
}

/// Bounded recovery payload returned by [`ContextEngine::get_slice`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum GetSliceOutcome {
    Lines(LineSlicePage),
    Bytes(ByteSliceResponse),
}

/// Request payload for [`ContextEngine::resume`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeRequest {
    pub session_id: Option<String>,
    pub create_checkpoint: bool,
    pub note: Option<String>,
    pub client_project_scope: Option<String>,
}

/// Combined session/workspace telemetry and blob-store footprint returned by [`ContextEngine::stats`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineStatsReport {
    #[serde(flatten)]
    pub session: SessionStats,
    pub store: StoreStats,
}

/// Unified retention pruning report across `BlobStore`, `SearchIndex`, and `SessionJournal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnginePruneReport {
    pub workspace_scope_id: WorkspaceScopeId,
    pub store: StorePruneReport,
    pub search_pruned_artifacts: usize,
    pub search_pruned_chunks: usize,
    pub search_reclaimed_bytes: u64,
    pub journal: JournalPruneReport,
}

/// Non-sensitive summary of the active [`ExecutionPolicyConfig`] reported by `context_doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPolicySummary {
    pub allow_shell: bool,
    pub allow_network_uploads: bool,
    pub allowed_programs: Vec<String>,
    pub blocked_programs_count: usize,
    pub preserved_env_keys_count: usize,
    pub default_timeout_ms: u64,
    pub max_timeout_ms: u64,
    pub max_stream_bytes: u64,
}

/// Non-sensitive summary of the active [`SecretPolicy`] reported by `context_doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPolicySummary {
    pub mode: SecretPolicyMode,
    pub enable_entropy_detection: bool,
    pub entropy_min_length: usize,
    pub allow_raw_blob_when_redacted: bool,
}

/// Read-only workspace, storage ACL, SQLite WAL/FTS5, journal, and policy diagnostic report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub healthy: bool,
    pub engine_version: String,
    pub schema_version: u32,
    pub workspace_root: String,
    pub workspace_scope_id: WorkspaceScopeId,
    pub session_id: SessionId,
    pub store_permissions: StorePermissionReport,
    pub store_stats: StoreStats,
    pub search_health: SearchHealthReport,
    pub journal_health: JournalHealthReport,
    pub execution_policy: ExecutionPolicySummary,
    pub secret_policy: SecretPolicySummary,
    pub budget: ReductionBudget,
}

/// Reusable, thread-safe (`Send + Sync`) Rust Context Engine runtime bound to a single canonical workspace.
pub struct ContextEngine {
    bound_scope: BoundScope,
    execution_gate: ExecutionGate,
    allow_network_uploads: bool,
    secret_guard: SecretGuard,
    budget: ReductionBudget,
    reducer: ReducerEngine,
    store: BlobStore,
    search: SearchIndex,
    journal: SessionJournal,
}

impl std::fmt::Debug for ContextEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextEngine")
            .field("bound_scope", &self.bound_scope)
            .field("budget", &self.budget)
            .finish_non_exhaustive()
    }
}

impl ContextEngine {
    /// Opens a [`ContextEngine`] bound to `workspace_root` (and optional default `session_id`).
    pub fn open_workspace(
        workspace_root: impl AsRef<Path>,
        session_id: Option<&str>,
    ) -> Result<Self> {
        let scope = BoundScope::bind(workspace_root, session_id)?;
        Self::open(scope)
    }

    /// Opens a [`ContextEngine`] for an already-bound [`BoundScope`] using default policies.
    pub fn open(bound_scope: BoundScope) -> Result<Self> {
        Self::open_with_config(bound_scope, EngineConfig::default())
    }

    /// Opens a [`ContextEngine`] with explicit execution, secret, and budget policies.
    pub fn open_with_config(bound_scope: BoundScope, config: EngineConfig) -> Result<Self> {
        config.budget.validate()?;

        let secret_guard = SecretGuard::new(config.secret_policy);
        let execution_gate = ExecutionGate::new(config.execution_policy)
            .with_allow_network_uploads(config.allow_network_uploads);
        let reducer = ReducerEngine::new(config.budget.clone(), secret_guard.clone());

        let store = BlobStore::open_with_config(
            &bound_scope,
            secret_guard.clone(),
            config.budget.clone(),
        )?;
        let search = SearchIndex::open_for_scope_with_config(
            &bound_scope,
            SearchConfig {
                budget: config.budget.clone(),
                chunk_config: ChunkConfig::default(),
                secret_guard: secret_guard.clone(),
            },
        )?;
        let journal = SessionJournal::open_for_scope_with_config(
            &bound_scope,
            JournalConfig {
                budget: config.budget.clone(),
                secret_guard: secret_guard.clone(),
                ..JournalConfig::default()
            },
        )?;

        Ok(Self {
            bound_scope,
            execution_gate,
            allow_network_uploads: config.allow_network_uploads,
            secret_guard,
            budget: config.budget,
            reducer,
            store,
            search,
            journal,
        })
    }

    /// Server-bound `(workspace_root, workspace_scope_id, session_id)` context.
    #[must_use]
    pub const fn bound_scope(&self) -> &BoundScope {
        &self.bound_scope
    }

    /// Active [`ReductionBudget`].
    #[must_use]
    pub const fn budget(&self) -> &ReductionBudget {
        &self.budget
    }

    /// Active [`ExecutionGate`].
    #[must_use]
    pub const fn execution_gate(&self) -> &ExecutionGate {
        &self.execution_gate
    }

    /// Active [`SecretGuard`].
    #[must_use]
    pub const fn secret_guard(&self) -> &SecretGuard {
        &self.secret_guard
    }

    /// Underlying [`BlobStore`].
    #[must_use]
    pub const fn store(&self) -> &BlobStore {
        &self.store
    }

    /// Underlying [`SearchIndex`].
    #[must_use]
    pub const fn search_index(&self) -> &SearchIndex {
        &self.search
    }

    /// Underlying [`SessionJournal`].
    #[must_use]
    pub const fn journal(&self) -> &SessionJournal {
        &self.journal
    }

    /// Executes the full 9-step command pipeline (`Authorize -> Capture -> Protect -> Persist ->
    /// Classify -> Reduce once -> Index -> Respond -> Journal`).
    pub async fn run_command(&self, req: RunCommandRequest) -> Result<RunCommandOutcome> {
        let cancel_token = CaptureCancelToken::new();
        self.run_command_with_cancel(req, &cancel_token).await
    }

    /// Executes the full 9-step command pipeline with cooperative cancellation via `cancel_token`.
    pub async fn run_command_with_cancel(
        &self,
        req: RunCommandRequest,
        cancel_token: &CaptureCancelToken,
    ) -> Result<RunCommandOutcome> {
        let started = Instant::now();

        // Step 1: Authorize (`BoundScope` + `ExecutionGate`, journaling any security denial).
        let scope = self.resolve_scope(
            req.client_project_scope.as_deref(),
            req.session_id.as_deref(),
            started,
        )?;

        let stream_cap = self
            .budget
            .max_capture_stream_bytes
            .min(self.execution_gate.policy().max_stream_bytes);
        let mut cmd_req = CommandRequest::new(req.argv).with_max_stream_bytes(stream_cap);
        if let Some(cwd) = req.cwd {
            cmd_req = cmd_req.with_cwd(cwd);
        }
        if let Some(timeout_ms) = req.timeout_ms {
            cmd_req = cmd_req.with_timeout_ms(timeout_ms);
        }

        let approved = match self.execution_gate.authorize(&scope, &cmd_req) {
            Ok(cmd) => cmd,
            Err(err) => {
                self.record_if_security_denial(&scope, &err, started);
                return Err(err);
            }
        };

        // Step 2: Capture (`stdout` + `stderr` concurrently with bounded backpressure and timeout).
        let captured = match capture_command_with_cancel(&approved, cancel_token).await {
            Ok(cap) => cap,
            Err(err) => {
                self.record_if_security_denial(&scope, &err, started);
                return Err(err);
            }
        };

        let pre_existing_blobs =
            self.streams_already_cached(&[&captured.stdout.bytes, &captured.stderr.bytes]);

        // Step 3 & Step 4: Protect (`SecretGuard`) & Persist (`BlobStore` atomic zstd + SHA-256).
        let stored = match self.store.put_artifact_streams(
            &scope,
            PutArtifactRequest {
                artifact_id: None,
                source: captured.to_artifact_source(),
                streams: vec![
                    ArtifactStreamInput::new(
                        StreamKind::Stdout,
                        &captured.stdout.bytes,
                        captured.stdout.truncated,
                    ),
                    ArtifactStreamInput::new(
                        StreamKind::Stderr,
                        &captured.stderr.bytes,
                        captured.stderr.truncated,
                    ),
                ],
                capture_complete: captured.is_complete(),
                view: None,
            },
        ) {
            Ok(out) => out,
            Err(err) => {
                self.record_if_security_denial(&scope, &err, started);
                return Err(err);
            }
        };

        // Step 5 & Step 6: Classify & Reduce once across both `stdout` and `stderr`, then update manifest view.
        let reduction = self.reducer.reduce_command_with_input(&CommandReductionInput {
            argv: &captured.argv,
            exit_code: captured.exit_code,
            stdout: &captured.stdout.bytes,
            stderr: &captured.stderr.bytes,
            artifact_id: Some(&stored.envelope.artifact_id),
            originals_available: stored.envelope.capture.originals_available,
            timed_out: captured.timed_out,
            stdout_truncated: captured.stdout.truncated,
            stderr_truncated: captured.stderr.truncated,
            existing_transforms: &[],
        });

        let envelope = self.store.update_artifact_view(
            &scope,
            &stored.envelope.artifact_id,
            reduction.view,
        )?;

        // Step 7: Index sanitized UTF-8 streams into SQLite FTS5 (`None` for pure binary streams).
        let sanitized_stdout = find_sanitized_stream(&stored.sanitized_streams, StreamKind::Stdout);
        let sanitized_stderr = find_sanitized_stream(&stored.sanitized_streams, StreamKind::Stderr);

        if let Err(err) = self.search.index_envelope_streams(
            &scope,
            &envelope,
            sanitized_stdout,
            sanitized_stderr,
        ) {
            self.record_if_security_denial(&scope, &err, started);
            return Err(err);
        }

        // Step 8 & Step 9: Journal & Respond.
        let deduplicated = pre_existing_blobs || reduction.already_reduced;
        let latency_ms = elapsed_ms(started);
        self.journal
            .record_envelope(&scope, &envelope, deduplicated, Some(latency_ms))?;

        Ok(RunCommandOutcome {
            envelope,
            exit_code: captured.exit_code,
            timed_out: captured.timed_out,
            cancelled: captured.cancelled,
            deduplicated,
        })
    }

    /// Executes the 9-step ingestion pipeline for workspace files or supplied inline content.
    pub async fn index_document(&self, req: IndexDocumentRequest) -> Result<IndexDocumentOutcome> {
        let started = Instant::now();

        // Step 1: Authorize scope.
        let scope = self.resolve_scope(
            req.client_project_scope.as_deref(),
            req.session_id.as_deref(),
            started,
        )?;

        // Step 2: Capture confined file (with TOCTOU + sensitive-path enforcement) or bounded inline bytes.
        let doc = match req.source {
            IndexSource::FilePath(ref requested_path) => {
                let mut captured = match capture_file(
                    &scope,
                    &self.execution_gate,
                    requested_path,
                    self.budget.max_capture_stream_bytes,
                )
                .await
                {
                    Ok(d) => d,
                    Err(err) => {
                        self.record_if_security_denial(&scope, &err, started);
                        return Err(err);
                    }
                };
                if req.label.is_some() {
                    captured.label = req.label;
                }
                if req.media_type.is_some() {
                    captured.media_type = req.media_type;
                }
                captured
            }
            IndexSource::InlineBytes(ref bytes) => capture_bytes(
                bytes,
                req.label,
                req.media_type,
                self.budget.max_capture_stream_bytes,
            )?,
        };

        let pre_existing_blob = self.streams_already_cached(&[&doc.stream.bytes]);

        // Step 3 & Step 4: Protect (`SecretGuard`) & Persist (`BlobStore`).
        let stored = match self.store.put_artifact_streams(
            &scope,
            PutArtifactRequest {
                artifact_id: None,
                source: doc.to_artifact_source(),
                streams: vec![ArtifactStreamInput::new(
                    StreamKind::Document,
                    &doc.stream.bytes,
                    doc.stream.truncated,
                )],
                capture_complete: doc.is_complete(),
                view: None,
            },
        ) {
            Ok(out) => out,
            Err(err) => {
                self.record_if_security_denial(&scope, &err, started);
                return Err(err);
            }
        };

        // Step 5 & Step 6: Classify & Reduce once, then update manifest view.
        let reduction = self.reducer.reduce_document_with_input(&DocumentReductionInput {
            bytes: &doc.stream.bytes,
            path_relative: doc.path_relative.as_deref(),
            label: doc.label.as_deref(),
            media_type: doc.media_type.as_deref(),
            artifact_id: Some(&stored.envelope.artifact_id),
            originals_available: stored.envelope.capture.originals_available,
            truncated: doc.stream.truncated,
            existing_transforms: &[],
        });

        let envelope = self.store.update_artifact_view(
            &scope,
            &stored.envelope.artifact_id,
            reduction.view,
        )?;

        // Step 7: Index sanitized text into SQLite FTS5.
        let sanitized_doc =
            find_sanitized_stream(&stored.sanitized_streams, StreamKind::Document);
        let index_stats = match self
            .search
            .index_envelope_streams(&scope, &envelope, sanitized_doc, None)
        {
            Ok(st) => st,
            Err(err) => {
                self.record_if_security_denial(&scope, &err, started);
                return Err(err);
            }
        };

        // Step 8 & Step 9: Journal & Respond.
        let deduplicated = pre_existing_blob || reduction.already_reduced;
        let latency_ms = elapsed_ms(started);
        self.journal
            .record_envelope(&scope, &envelope, deduplicated, Some(latency_ms))?;

        Ok(IndexDocumentOutcome {
            envelope,
            chunks_indexed: index_stats.chunks_indexed,
            deduplicated,
        })
    }

    /// Executes a scoped SQLite FTS5 lexical query and records retrieval telemetry in `SessionJournal`.
    pub fn search(&self, req: SearchQueryRequest) -> Result<SearchQueryOutcome> {
        let started = Instant::now();
        let scope = self.resolve_scope(
            req.client_project_scope.as_deref(),
            req.session_id.as_deref(),
            started,
        )?;

        let requested_limit = req.limit.unwrap_or(10);
        if requested_limit == 0 {
            return Err(ContextError::InvalidConfig {
                field: "limit",
                reason: "search limit must be >= 1".to_string(),
            });
        }
        if requested_limit > self.budget.max_search_results {
            return Err(ContextError::BudgetExceeded {
                resource: "context_search.limit",
                requested: requested_limit,
                limit: self.budget.max_search_results,
            });
        }

        let hits = match self
            .search
            .search(&scope, &req.query, req.session_only, requested_limit)
        {
            Ok(h) => h,
            Err(err) => {
                self.record_if_security_denial(&scope, &err, started);
                return Err(err);
            }
        };

        let snippet_bytes: u64 = hits.iter().map(|h| h.snippet.len() as u64).sum();
        let latency_ms = elapsed_ms(started);
        self.journal
            .record_search(&scope, hits.len(), snippet_bytes, Some(latency_ms))?;

        Ok(SearchQueryOutcome {
            workspace_scope_id: scope.workspace_scope_id,
            session_id: scope.session_id,
            session_only: req.session_only,
            query: req.query,
            hit_count: hits.len(),
            hits,
        })
    }

    /// Recovers a bounded byte or line slice from `BlobStore` and records retrieval telemetry.
    pub fn get_slice(&self, req: GetSliceRequest) -> Result<GetSliceOutcome> {
        let started = Instant::now();
        let scope = self.resolve_scope(
            req.client_project_scope.as_deref(),
            req.session_id.as_deref(),
            started,
        )?;

        let artifact_id = match ArtifactId::parse(&req.artifact_id) {
            Ok(id) => id,
            Err(err) => {
                self.record_if_security_denial(&scope, &err, started);
                return Err(err);
            }
        };

        let manifest = match self.store.get_manifest(&scope, &artifact_id) {
            Ok(m) => m,
            Err(err) => {
                self.record_if_security_denial(&scope, &err, started);
                return Err(err);
            }
        };

        let stream = req
            .stream
            .unwrap_or_else(|| select_default_stream(&manifest.streams));

        let effective_selector = match req.range {
            GetRangeSelector::Lines(lr) => GetRangeSelector::Lines(lr),
            GetRangeSelector::Bytes(br) => GetRangeSelector::Bytes(br),
            GetRangeSelector::DefaultWindow => {
                let is_binary = manifest
                    .streams
                    .iter()
                    .find(|s| s.stream == stream)
                    .is_some_and(|s| s.encoding == StreamEncoding::Binary);
                if is_binary {
                    let default_end = 4_096usize.min(self.budget.max_get_bytes) as u64;
                    GetRangeSelector::Bytes(ByteRange::new(
                        0,
                        default_end,
                        self.budget.max_get_bytes,
                    )?)
                } else {
                    let default_end = 80usize.min(self.budget.max_get_lines);
                    GetRangeSelector::Lines(LineRange::new(
                        1,
                        default_end,
                        self.budget.max_get_lines,
                    )?)
                }
            }
        };

        match effective_selector {
            GetRangeSelector::Lines(line_range) => {
                let page = match self
                    .store
                    .get_lines(&scope, &artifact_id, stream, line_range)
                {
                    Ok(p) => p,
                    Err(err) => {
                        self.record_if_security_denial(&scope, &err, started);
                        return Err(err);
                    }
                };
                let retrieved_bytes = page.text.len() as u64;
                self.journal.record_retrieval(
                    &scope,
                    &artifact_id,
                    page.stream,
                    retrieved_bytes,
                    Some(elapsed_ms(started)),
                )?;
                Ok(GetSliceOutcome::Lines(page))
            }
            GetRangeSelector::Bytes(byte_range) => {
                let page = match self
                    .store
                    .get_bytes(&scope, &artifact_id, stream, byte_range)
                {
                    Ok(p) => p,
                    Err(err) => {
                        self.record_if_security_denial(&scope, &err, started);
                        return Err(err);
                    }
                };
                let retrieved_bytes = page.bytes.len() as u64;
                self.journal.record_retrieval(
                    &scope,
                    &artifact_id,
                    page.stream,
                    retrieved_bytes,
                    Some(elapsed_ms(started)),
                )?;
                let utf8_text = page.as_utf8().ok().map(str::to_string);
                let base64_bytes = page.to_base64();
                let byte_length = page.bytes.len();

                Ok(GetSliceOutcome::Bytes(ByteSliceResponse {
                    artifact_id: page.artifact_id,
                    stream: page.stream,
                    sha256: page.sha256,
                    encoding: page.encoding,
                    exact_raw_preserved: page.exact_raw_preserved,
                    total_bytes: page.total_bytes,
                    total_lines: page.total_lines,
                    returned_range: page.returned_range,
                    byte_length,
                    has_more: page.has_more,
                    utf8_text,
                    base64_bytes,
                    raw_bytes: page.bytes,
                }))
            }
            GetRangeSelector::DefaultWindow => unreachable!("DefaultWindow resolved above"),
        }
    }

    /// Optionally creates a session checkpoint and returns a deterministic [`ResumePack`].
    pub fn resume(&self, req: ResumeRequest) -> Result<ResumePack> {
        let started = Instant::now();
        let scope = self.resolve_scope(
            req.client_project_scope.as_deref(),
            req.session_id.as_deref(),
            started,
        )?;

        if req.create_checkpoint {
            self.journal.create_checkpoint(&scope, req.note.as_deref())?;
        }
        self.journal.resume(&scope)
    }

    /// Computes non-sensitive session or workspace telemetry paired with store footprint stats.
    pub fn stats(
        &self,
        session_id: Option<&str>,
        all_sessions: bool,
    ) -> Result<EngineStatsReport> {
        let started = Instant::now();
        let scope = self.resolve_scope(None, session_id, started)?;
        let session = self.journal.stats(&scope, all_sessions)?;
        let store = self.store.stats()?;
        Ok(EngineStatsReport { session, store })
    }

    /// Consistently prunes `BlobStore`, `SearchIndex`, and `SessionJournal` under workspace quotas/TTL.
    pub fn prune(
        &self,
        ttl_secs: Option<u64>,
        max_store_bytes: Option<u64>,
    ) -> Result<EnginePruneReport> {
        let (effective_ttl, effective_max_bytes) = if ttl_secs.is_none() && max_store_bytes.is_none()
        {
            (
                Some(self.budget.retention_ttl_secs),
                Some(self.budget.max_workspace_store_bytes),
            )
        } else {
            (ttl_secs, max_store_bytes)
        };

        // 1. Prune expired/LRU-evicted manifests and unreferenced blobs in `BlobStore`.
        let store_report = self.store.prune(PrunePolicy {
            ttl_secs: effective_ttl,
            max_store_bytes: effective_max_bytes,
            now_unix_ms: None,
        })?;

        // 2. Remove every store-evicted artifact from `SearchIndex` (handles both TTL and LRU quota evictions).
        let mut removed_ids: BTreeSet<String> = BTreeSet::new();
        for art_id in &store_report.evicted_artifact_ids {
            if self.search.remove_artifact(&self.bound_scope, art_id)? {
                removed_ids.insert(art_id.as_str().to_string());
            }
        }

        // 3. Also sweep any TTL-expired search rows & journal events when `effective_ttl` is set.
        let mut search_pruned_chunks = 0usize;
        let mut search_reclaimed_bytes = 0u64;
        let journal_report = if let Some(ttl) = effective_ttl {
            let sr = self.search.prune_expired(&self.bound_scope, ttl)?;
            for id in sr.pruned_artifacts {
                removed_ids.insert(id.as_str().to_string());
            }
            search_pruned_chunks = sr.pruned_chunks;
            search_reclaimed_bytes = sr.reclaimed_sanitized_bytes;
            self.journal.prune_expired(&self.bound_scope, ttl)?
        } else {
            JournalPruneReport {
                pruned_events: 0,
                pruned_checkpoints: 0,
            }
        };

        Ok(EnginePruneReport {
            workspace_scope_id: self.bound_scope.workspace_scope_id.clone(),
            store: store_report,
            search_pruned_artifacts: removed_ids.len(),
            search_pruned_chunks,
            search_reclaimed_bytes,
            journal: journal_report,
        })
    }

    /// Runs a read-only diagnostic check over bound scope, store ACLs, SQLite WAL + FTS5,
    /// journal health, command allowlist policy, and `SecretGuard` policy.
    pub fn doctor(&self) -> Result<DoctorReport> {
        let store_permissions = self.store.verify_store_permissions()?;
        let store_stats = self.store.stats()?;
        let search_health = self.search.health_check()?;
        let journal_health = self.journal.health_check()?;

        let exec_pol = self.execution_gate.policy();
        let execution_policy = ExecutionPolicySummary {
            allow_shell: exec_pol.allow_shell,
            allow_network_uploads: self.allow_network_uploads,
            allowed_programs: exec_pol.allowed_programs.clone(),
            blocked_programs_count: exec_pol.blocked_programs.len(),
            preserved_env_keys_count: exec_pol.preserved_env_keys.len(),
            default_timeout_ms: exec_pol.default_timeout_ms,
            max_timeout_ms: exec_pol.max_timeout_ms,
            max_stream_bytes: exec_pol.max_stream_bytes,
        };

        let sec_pol = self.secret_guard.policy();
        let secret_policy = SecretPolicySummary {
            mode: sec_pol.mode,
            enable_entropy_detection: sec_pol.enable_entropy_detection,
            entropy_min_length: sec_pol.entropy_min_length,
            allow_raw_blob_when_redacted: sec_pol.allow_raw_blob_when_redacted,
        };

        let healthy = store_permissions.exists
            && store_permissions.private_only
            && search_health.healthy
            && journal_health.healthy;

        Ok(DoctorReport {
            healthy,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            schema_version: ARTIFACT_SCHEMA_VERSION,
            workspace_root: self.bound_scope.workspace_root.display().to_string(),
            workspace_scope_id: self.bound_scope.workspace_scope_id.clone(),
            session_id: self.bound_scope.session_id.clone(),
            store_permissions,
            store_stats,
            search_health,
            journal_health,
            execution_policy,
            secret_policy,
            budget: self.budget.clone(),
        })
    }

    fn resolve_scope(
        &self,
        client_project_scope: Option<&str>,
        session_id: Option<&str>,
        started: Instant,
    ) -> Result<BoundScope> {
        match self
            .bound_scope
            .resolve_request_scope(client_project_scope, session_id)
        {
            Ok(scope) => Ok(scope),
            Err(err) => {
                self.record_if_security_denial(&self.bound_scope, &err, started);
                Err(err)
            }
        }
    }

    fn record_if_security_denial(&self, scope: &BoundScope, err: &ContextError, started: Instant) {
        if err.is_security_denial() {
            let _ = self
                .journal
                .record_security_denial(scope, err, Some(elapsed_ms(started)));
        }
    }

    fn streams_already_cached(&self, raw_slices: &[&[u8]]) -> bool {
        let mut saw_non_empty = false;
        for slice in raw_slices {
            if slice.is_empty() {
                continue;
            }
            saw_non_empty = true;
            let sha = context_core::sha256_hex(slice);
            let exists = self
                .store
                .blob_path_for_sha256(&sha)
                .is_ok_and(|p| p.exists());
            if !exists {
                return false;
            }
        }
        saw_non_empty
    }
}

fn find_sanitized_stream(
    streams: &[(StreamKind, Option<String>)],
    target: StreamKind,
) -> Option<&str> {
    streams
        .iter()
        .find(|(kind, _)| *kind == target)
        .and_then(|(_, text)| text.as_deref())
}

fn select_default_stream(streams: &[context_store::StoredStreamRef]) -> StreamKind {
    if streams.len() == 1 && streams[0].stream == StreamKind::Document {
        return StreamKind::Document;
    }
    let stdout_bytes = streams
        .iter()
        .find(|s| s.stream == StreamKind::Stdout)
        .map_or(0, |s| s.raw_bytes);
    let stderr_bytes = streams
        .iter()
        .find(|s| s.stream == StreamKind::Stderr)
        .map_or(0, |s| s.raw_bytes);

    if stdout_bytes == 0 && stderr_bytes > 0 {
        StreamKind::Stderr
    } else {
        StreamKind::Stdout
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
