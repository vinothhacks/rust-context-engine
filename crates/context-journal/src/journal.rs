//! Scoped `SessionJournal` implementation backed by SQLite WAL.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;
use context_core::{
    now_rfc3339_utc, sha256_hex, truncate_str_utf8_boundary, ArtifactEnvelope, ArtifactId,
    ArtifactSource, BoundScope, ContextError, RecoveryHandle, ReductionBudget, Result, SecretGuard,
    SessionId, StreamKind, WorkspaceScopeId, TRANSFORM_CARGO_TEST_V1, TRANSFORM_COMPILER_DIAG_V1,
    TRANSFORM_PYTEST_JEST_V1, TRANSFORM_SECRET_REDACT_V1, TRANSFORM_STRIP_ANSI_V1,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::model::{
    ActiveArtifactHandle, JournalEventInput, JournalEventKind, JournalPruneReport,
    RecentCommandRecord, RecordedEvent, ResumePack, SessionCheckpoint, SessionStats,
};
use crate::schema::{
    map_sql_err, open_and_configure_file, open_and_configure_in_memory, run_health_check,
    with_lock_retry, JournalHealthReport,
};

/// Configuration governing bounded continuity snapshots and defense-in-depth secret redaction
/// inside [`SessionJournal`].
#[derive(Debug, Clone)]
pub struct JournalConfig {
    pub budget: ReductionBudget,
    pub secret_guard: SecretGuard,
    /// Maximum recent commands included in [`SessionCheckpoint`] and [`ResumePack`] (`10` default).
    pub max_recent_commands: usize,
    /// Maximum active `ArtifactId` handles included in [`SessionCheckpoint`] and [`ResumePack`] (`15` default).
    pub max_active_artifacts: usize,
    /// Maximum unresolved failure identifiers included inline (`50` default).
    pub max_unresolved_failures: usize,
    /// Maximum UTF-8 byte length of an optional checkpoint `note` (`1_024` default).
    pub max_note_bytes: usize,
}

impl Default for JournalConfig {
    fn default() -> Self {
        Self {
            budget: ReductionBudget::default(),
            secret_guard: SecretGuard::default(),
            max_recent_commands: 10,
            max_active_artifacts: 15,
            max_unresolved_failures: 50,
            max_note_bytes: 1_024,
        }
    }
}

/// Thread-safe (`Send + Sync`) append-only session event log and checkpoint store.
///
/// ### Storage Coexistence with `context-search`
/// [`SessionJournal::open_for_scope`] opens `<workspace>/.context-engine/index.db`
/// ([`BoundScope::index_db_path`]) using namespaced `journal_*` tables (`journal_events`,
/// `journal_checkpoints`) and the shared `schema_migrations (component, version)` table.
/// Both `SearchIndex` and `SessionJournal` can safely open the same `.context-engine/index.db`
/// concurrently under SQLite WAL (`busy_timeout = 5000`), or standalone `.db` paths via
/// [`SessionJournal::open`].
pub struct SessionJournal {
    db_path: Option<PathBuf>,
    conn: Mutex<Connection>,
    config: JournalConfig,
}

impl std::fmt::Debug for SessionJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionJournal")
            .field("db_path", &self.db_path)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl SessionJournal {
    /// Opens (or initializes) the session journal inside `<workspace>/.context-engine/index.db`
    /// ([`BoundScope::index_db_path`]).
    pub fn open_for_scope(scope: &BoundScope) -> Result<Self> {
        Self::open_with_config(scope.index_db_path(), JournalConfig::default())
    }

    /// Opens (or initializes) the session journal at [`BoundScope::index_db_path`] with custom config.
    pub fn open_for_scope_with_config(scope: &BoundScope, config: JournalConfig) -> Result<Self> {
        Self::open_with_config(scope.index_db_path(), config)
    }

    /// Opens (or initializes) a SQLite WAL session journal at an explicit path.
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_config(db_path, JournalConfig::default())
    }

    /// Opens (or initializes) a SQLite WAL session journal at `db_path` with custom [`JournalConfig`].
    pub fn open_with_config(db_path: impl AsRef<Path>, config: JournalConfig) -> Result<Self> {
        config.budget.validate()?;
        let path = db_path.as_ref().to_path_buf();
        let conn = open_and_configure_file(&path)?;
        Ok(Self {
            db_path: Some(path),
            conn: Mutex::new(conn),
            config,
        })
    }

    /// Opens an ephemeral in-memory journal for unit testing.
    pub fn open_in_memory() -> Result<Self> {
        Self::open_in_memory_with_config(JournalConfig::default())
    }

    /// Opens an ephemeral in-memory journal with custom [`JournalConfig`].
    pub fn open_in_memory_with_config(config: JournalConfig) -> Result<Self> {
        config.budget.validate()?;
        let conn = open_and_configure_in_memory()?;
        Ok(Self {
            db_path: None,
            conn: Mutex::new(conn),
            config,
        })
    }

    /// Returns the backing SQLite database path (`None` for `:memory:`).
    #[must_use]
    pub fn db_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
    }

    #[must_use]
    pub const fn config(&self) -> &JournalConfig {
        &self.config
    }

    /// Appends a structured non-sensitive event under `scope`, redacting all text metadata via
    /// [`SecretGuard`] before SQLite persistence.
    pub fn record_event(
        &self,
        scope: &BoundScope,
        input: JournalEventInput,
    ) -> Result<RecordedEvent> {
        WorkspaceScopeId::parse(scope.workspace_scope_id.as_str())?;
        SessionId::parse(scope.session_id.as_str())?;
        if let Some(ref art) = input.artifact_id {
            ArtifactId::parse(art.as_str())?;
        }

        let sanitized = self.sanitize_input(input)?;
        let recorded_at = now_rfc3339_utc();
        let recorded_unix_ms = Utc::now().timestamp_millis();

        let mut conn = self.lock_conn()?;
        let event_seq = with_lock_retry("failed to append journal event", || {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let seq =
                insert_sanitized_event(&tx, scope, &sanitized, &recorded_at, recorded_unix_ms)?;
            tx.commit()?;
            Ok(seq)
        })?;

        Ok(sanitized.into_recorded(event_seq, scope, recorded_at))
    }

    /// Convenience helper recording an [`ArtifactEnvelope`] (`CommandCaptured` or `DocumentIndexed`).
    pub fn record_envelope(
        &self,
        scope: &BoundScope,
        envelope: &ArtifactEnvelope,
        deduplicated: bool,
        latency_ms: Option<u64>,
    ) -> Result<RecordedEvent> {
        envelope.validate(scope)?;

        let domain_reducer = envelope
            .view
            .transformations
            .iter()
            .find(|t| {
                t.as_str() != TRANSFORM_STRIP_ANSI_V1 && t.as_str() != TRANSFORM_SECRET_REDACT_V1
            })
            .or_else(|| envelope.view.transformations.last())
            .cloned();

        let originals_available =
            envelope.capture.originals_available && envelope.recovery.unavailable_reason.is_none();

        let mut input = match &envelope.source {
            ArtifactSource::Command {
                argv,
                exit_code,
                duration_ms,
                ..
            } => {
                let cmd = argv.join(" ");
                let mut ev = JournalEventInput::new(JournalEventKind::CommandCaptured);
                ev.command_summary = Some(cmd.clone());
                ev.source_label = Some(cmd);
                ev.exit_code = *exit_code;
                ev.latency_ms = latency_ms.or(*duration_ms);
                ev
            }
            ArtifactSource::Document {
                path_relative,
                label,
                ..
            } => {
                let doc_label = label
                    .clone()
                    .or_else(|| path_relative.clone())
                    .unwrap_or_else(|| "document".to_string());
                let mut ev = JournalEventInput::new(JournalEventKind::DocumentIndexed);
                ev.source_label = Some(doc_label);
                ev.latency_ms = latency_ms;
                ev
            }
        };

        input.artifact_id = Some(envelope.artifact_id.clone());
        input.reducer_id = domain_reducer;
        input.raw_bytes = envelope.total_raw_bytes();
        input.view_bytes = envelope.view_bytes();
        input.retrieved_bytes = 0;
        input.estimated_raw_tokens = Some(envelope.estimated_raw_tokens());
        input.estimated_view_tokens = Some(envelope.estimated_view_tokens());
        input.estimated_retrieved_tokens = Some(0);
        input.deduplicated = deduplicated;
        input.originals_available = originals_available;
        input.secrets_redacted = envelope.capture.secrets_redacted;
        input.failure_identifiers = envelope.view.failure_identifiers.clone();

        self.record_event(scope, input)
    }

    /// Convenience helper recording a `context_search` query event (`ArtifactSearched`).
    pub fn record_search(
        &self,
        scope: &BoundScope,
        hit_count: usize,
        response_bytes: u64,
        latency_ms: Option<u64>,
    ) -> Result<RecordedEvent> {
        let mut ev = JournalEventInput::new(JournalEventKind::ArtifactSearched);
        ev.retrieved_bytes = response_bytes;
        ev.search_hit_count = Some(hit_count);
        ev.latency_ms = latency_ms;
        self.record_event(scope, ev)
    }

    /// Convenience helper recording a `context_get` slice recovery event (`ArtifactRetrieved`).
    pub fn record_retrieval(
        &self,
        scope: &BoundScope,
        artifact_id: &ArtifactId,
        stream: StreamKind,
        retrieved_bytes: u64,
        latency_ms: Option<u64>,
    ) -> Result<RecordedEvent> {
        let mut ev = JournalEventInput::new(JournalEventKind::ArtifactRetrieved);
        ev.artifact_id = Some(artifact_id.clone());
        ev.stream = Some(stream);
        ev.retrieved_bytes = retrieved_bytes;
        ev.latency_ms = latency_ms;
        self.record_event(scope, ev)
    }

    /// Convenience helper recording a blocked security/policy boundary violation (`SecurityDenied`).
    ///
    /// Accepts `&ContextError` directly or custom `(code, reason)` via [`Self::record_security_denial_code`].
    pub fn record_security_denial(
        &self,
        scope: &BoundScope,
        err: &ContextError,
        latency_ms: Option<u64>,
    ) -> Result<RecordedEvent> {
        self.record_security_denial_code(scope, err.error_code(), &err.to_string(), latency_ms)
    }

    /// Records a `SecurityDenied` event from an explicit error code and sanitized description.
    pub fn record_security_denial_code(
        &self,
        scope: &BoundScope,
        denial_code: &str,
        denial_reason: &str,
        latency_ms: Option<u64>,
    ) -> Result<RecordedEvent> {
        let mut ev = JournalEventInput::new(JournalEventKind::SecurityDenied);
        ev.denial_code = Some(denial_code.to_string());
        ev.denial_reason = Some(denial_reason.to_string());
        ev.latency_ms = latency_ms;
        self.record_event(scope, ev)
    }

    /// Creates a deterministic continuity checkpoint for `scope`, appending a `CheckpointCreated`
    /// event and persisting the serialized [`SessionCheckpoint`] atomically.
    pub fn create_checkpoint(
        &self,
        scope: &BoundScope,
        note: Option<&str>,
    ) -> Result<SessionCheckpoint> {
        WorkspaceScopeId::parse(scope.workspace_scope_id.as_str())?;
        SessionId::parse(scope.session_id.as_str())?;

        let sanitized_note = note.and_then(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                let redacted = self.config.secret_guard.redact_str(trimmed);
                let (bounded, _) =
                    truncate_str_utf8_boundary(&redacted, self.config.max_note_bytes);
                Some(bounded.to_string())
            }
        });

        let created_at = now_rfc3339_utc();
        let created_unix_ms = Utc::now().timestamp_millis();

        let cp_event = self.sanitize_input(JournalEventInput {
            source_label: sanitized_note.clone(),
            ..JournalEventInput::new(JournalEventKind::CheckpointCreated)
        })?;

        let mut conn = self.lock_conn()?;
        let checkpoint = with_lock_retry("failed to create session checkpoint", || {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

            let up_to_seq =
                insert_sanitized_event(&tx, scope, &cp_event, &created_at, created_unix_ms)?;

            let events = load_session_events(&tx, scope)?;
            let stats = query_stats_on_conn(&tx, scope, false)?;
            let derived = derive_continuity_view(
                &events,
                self.config.max_recent_commands,
                self.config.max_active_artifacts,
                self.config.max_unresolved_failures,
                self.config.budget.max_get_bytes,
            );

            let seed = format!(
                "context-engine:checkpoint:v1:{}:{}:{}:{up_to_seq}",
                scope.workspace_scope_id.as_str(),
                scope.session_id.as_str(),
                created_at,
            );
            let digest = sha256_hex(seed.as_bytes());
            let checkpoint_id = format!("cp_{}", &digest[..32]);

            let checkpoint = SessionCheckpoint {
                checkpoint_id: checkpoint_id.clone(),
                workspace_scope_id: scope.workspace_scope_id.clone(),
                session_id: scope.session_id.clone(),
                up_to_event_seq: up_to_seq,
                created_at: created_at.clone(),
                note: sanitized_note.clone(),
                recent_commands: derived.recent_commands,
                unresolved_failures: derived.unresolved_failures,
                active_artifacts: derived.active_artifacts,
                stats,
            };

            let snapshot_json = serde_json::to_string(&checkpoint)
                .map_err(|ser_err| rusqlite::Error::ToSqlConversionFailure(Box::new(ser_err)))?;
            let persisted_checkpoint: SessionCheckpoint = serde_json::from_str(&snapshot_json)
                .map_err(|de_err| rusqlite::Error::ToSqlConversionFailure(Box::new(de_err)))?;

            tx.execute(
                "INSERT INTO journal_checkpoints (
                    checkpoint_id,
                    workspace_scope_id,
                    session_id,
                    up_to_event_seq,
                    created_at,
                    created_unix_ms,
                    note,
                    snapshot_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    checkpoint_id.as_str(),
                    scope.workspace_scope_id.as_str(),
                    scope.session_id.as_str(),
                    u64_to_sql(up_to_seq),
                    created_at.as_str(),
                    created_unix_ms,
                    sanitized_note.as_deref(),
                    snapshot_json.as_str(),
                ],
            )?;

            tx.commit()?;
            Ok(persisted_checkpoint)
        })?;

        Ok(checkpoint)
    }

    /// Reconstructs a full [`ResumePack`] (`context_resume`) for `(scope.workspace_scope_id, scope.session_id)`.
    ///
    /// Includes the latest persisted [`SessionCheckpoint`] (if any), events accrued since that
    /// checkpoint, chronological recent commands, currently unresolved failing test/compiler
    /// identifiers, prioritized `context_get` [`RecoveryHandle`]s, and live [`SessionStats`].
    pub fn resume(&self, scope: &BoundScope) -> Result<ResumePack> {
        WorkspaceScopeId::parse(scope.workspace_scope_id.as_str())?;
        SessionId::parse(scope.session_id.as_str())?;

        let conn = self.lock_conn()?;

        let latest_cp_json: Option<(String, String, i64, String)> = conn
            .query_row(
                "SELECT workspace_scope_id, session_id, up_to_event_seq, snapshot_json
                 FROM journal_checkpoints
                 WHERE workspace_scope_id = ?1 AND session_id = ?2
                 ORDER BY up_to_event_seq DESC, rowid DESC
                 LIMIT 1",
                params![scope.workspace_scope_id.as_str(), scope.session_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|err| map_sql_err("failed to query latest checkpoint", &err))?;

        let latest_checkpoint = match latest_cp_json {
            Some((stored_ws, stored_sess, _seq, json_str)) => {
                let parsed_ws = WorkspaceScopeId::parse(&stored_ws)?;
                let parsed_sess = SessionId::parse(&stored_sess)?;
                scope.verify_exact_scope(&parsed_ws, &parsed_sess)?;
                let cp: SessionCheckpoint = serde_json::from_str(&json_str)?;
                scope.verify_exact_scope(&cp.workspace_scope_id, &cp.session_id)?;
                Some(cp)
            }
            None => None,
        };

        let events = load_session_events(&conn, scope)
            .map_err(|err| map_sql_err("failed to load session events for resume", &err))?;
        let stats = query_stats_on_conn(&conn, scope, false)
            .map_err(|err| map_sql_err("failed to compute session stats for resume", &err))?;

        let events_since_checkpoint = match &latest_checkpoint {
            Some(cp) => events
                .iter()
                .filter(|ev| ev.event_seq > cp.up_to_event_seq)
                .count() as u64,
            None => events.len() as u64,
        };

        let derived = derive_continuity_view(
            &events,
            self.config.max_recent_commands,
            self.config.max_active_artifacts,
            self.config.max_unresolved_failures,
            self.config.budget.max_get_bytes,
        );

        Ok(ResumePack {
            workspace_scope_id: scope.workspace_scope_id.clone(),
            session_id: scope.session_id.clone(),
            resumed_at: now_rfc3339_utc(),
            latest_checkpoint,
            events_since_checkpoint,
            recent_commands: derived.recent_commands,
            unresolved_failures: derived.unresolved_failures,
            active_artifacts: derived.active_artifacts,
            stats,
        })
    }

    /// Computes aggregate [`SessionStats`] for `context_stats`, scoped either to `scope.session_id`
    /// (`all_sessions_in_workspace == false`) or across every session in `scope.workspace_scope_id`
    /// (`all_sessions_in_workspace == true`).
    pub fn stats(
        &self,
        scope: &BoundScope,
        all_sessions_in_workspace: bool,
    ) -> Result<SessionStats> {
        WorkspaceScopeId::parse(scope.workspace_scope_id.as_str())?;
        SessionId::parse(scope.session_id.as_str())?;

        let conn = self.lock_conn()?;
        query_stats_on_conn(&conn, scope, all_sessions_in_workspace)
            .map_err(|err| map_sql_err("failed to aggregate journal stats", &err))
    }

    /// Lists up to `limit` most recent events in `scope` ordered from oldest-to-newest within the window.
    pub fn list_recent_events(
        &self,
        scope: &BoundScope,
        limit: usize,
    ) -> Result<Vec<RecordedEvent>> {
        WorkspaceScopeId::parse(scope.workspace_scope_id.as_str())?;
        SessionId::parse(scope.session_id.as_str())?;
        if limit == 0 {
            return Ok(Vec::new());
        }

        let conn = self.lock_conn()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT
                    event_seq,
                    workspace_scope_id,
                    session_id,
                    event_kind,
                    recorded_at,
                    artifact_id,
                    command_summary,
                    source_label,
                    stream,
                    reducer_id,
                    exit_code,
                    raw_bytes,
                    view_bytes,
                    retrieved_bytes,
                    estimated_raw_tokens,
                    estimated_view_tokens,
                    estimated_retrieved_tokens,
                    deduplicated,
                    originals_available,
                    secrets_redacted,
                    denial_code,
                    denial_reason,
                    failure_identifiers_json,
                    search_hit_count,
                    latency_ms
                 FROM journal_events
                 WHERE workspace_scope_id = ?1 AND session_id = ?2
                 ORDER BY event_seq DESC
                 LIMIT ?3",
            )
            .map_err(|err| map_sql_err("failed to prepare list_recent_events", &err))?;

        let rows = stmt
            .query_map(
                params![
                    scope.workspace_scope_id.as_str(),
                    scope.session_id.as_str(),
                    u64_to_sql(limit as u64),
                ],
                decode_event_row,
            )
            .map_err(|err| map_sql_err("failed to query list_recent_events", &err))?;

        let mut events: Vec<RecordedEvent> = Vec::new();
        for row_res in rows {
            let raw_ev =
                row_res.map_err(|err| map_sql_err("failed to decode journal event row", &err))?;
            let ev = raw_ev?;
            scope.verify_exact_scope(&ev.workspace_scope_id, &ev.session_id)?;
            events.push(ev);
        }
        events.reverse();
        Ok(events)
    }

    /// Administrative TTL pruning for expired events and checkpoints inside `caller_scope.workspace_scope_id`.
    pub fn prune_expired(
        &self,
        caller_scope: &BoundScope,
        ttl_secs: u64,
    ) -> Result<JournalPruneReport> {
        let now_ms = Utc::now().timestamp_millis();
        let ttl_ms = i64::try_from(ttl_secs.saturating_mul(1_000)).unwrap_or(i64::MAX);
        let cutoff_unix_ms = now_ms.saturating_sub(ttl_ms);
        self.prune_before_unix_ms(caller_scope, cutoff_unix_ms)
    }

    /// Prunes journal events and checkpoints in `caller_scope.workspace_scope_id` older than or
    /// equal to `cutoff_unix_ms`.
    pub fn prune_before_unix_ms(
        &self,
        caller_scope: &BoundScope,
        cutoff_unix_ms: i64,
    ) -> Result<JournalPruneReport> {
        WorkspaceScopeId::parse(caller_scope.workspace_scope_id.as_str())?;
        SessionId::parse(caller_scope.session_id.as_str())?;

        let mut conn = self.lock_conn()?;
        let (pruned_events, pruned_checkpoints) =
            with_lock_retry("failed to prune expired journal records", || {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let del_cp = tx.execute(
                    "DELETE FROM journal_checkpoints
                     WHERE workspace_scope_id = ?1 AND created_unix_ms <= ?2",
                    params![caller_scope.workspace_scope_id.as_str(), cutoff_unix_ms],
                )?;
                let del_ev = tx.execute(
                    "DELETE FROM journal_events
                     WHERE workspace_scope_id = ?1 AND recorded_unix_ms <= ?2",
                    params![caller_scope.workspace_scope_id.as_str(), cutoff_unix_ms],
                )?;
                tx.commit()?;
                Ok((del_ev, del_cp))
            })?;

        Ok(JournalPruneReport {
            pruned_events,
            pruned_checkpoints,
        })
    }

    /// Runs SQLite WAL, foreign-key, schema-migration, and `quick_check` diagnostics for `context_doctor`.
    pub fn health_check(&self) -> Result<JournalHealthReport> {
        let conn = self.lock_conn()?;
        run_health_check(&conn, self.db_path.as_deref())
    }

    fn sanitize_input(&self, input: JournalEventInput) -> Result<SanitizedEvent> {
        let guard = &self.config.secret_guard;
        let redact_opt = |opt: Option<String>, max_len: usize| -> Option<String> {
            opt.map(|s| {
                let clean = guard.redact_str(&s);
                let (bounded, _) = truncate_str_utf8_boundary(&clean, max_len);
                bounded.to_string()
            })
        };

        let mut sanitized_failures = Vec::with_capacity(input.failure_identifiers.len());
        for ident in &input.failure_identifiers {
            let trimmed = ident.trim();
            if !trimmed.is_empty() {
                let clean = guard.redact_str(trimmed);
                let (bounded, _) = truncate_str_utf8_boundary(&clean, 256);
                sanitized_failures.push(bounded.to_string());
            }
        }

        let failure_identifiers_json = serde_json::to_string(&sanitized_failures)?;

        let raw_tokens = input.resolved_raw_tokens();
        let view_tokens = input.resolved_view_tokens();
        let retrieved_tokens = input.resolved_retrieved_tokens();

        Ok(SanitizedEvent {
            kind: input.kind,
            artifact_id: input.artifact_id,
            command_summary: redact_opt(input.command_summary, 512),
            source_label: redact_opt(input.source_label, 512),
            stream: input.stream,
            reducer_id: redact_opt(input.reducer_id, 128),
            exit_code: input.exit_code,
            raw_bytes: input.raw_bytes,
            view_bytes: input.view_bytes,
            retrieved_bytes: input.retrieved_bytes,
            estimated_raw_tokens: raw_tokens,
            estimated_view_tokens: view_tokens,
            estimated_retrieved_tokens: retrieved_tokens,
            deduplicated: input.deduplicated,
            originals_available: input.originals_available,
            secrets_redacted: input.secrets_redacted,
            denial_code: redact_opt(input.denial_code, 128),
            denial_reason: redact_opt(input.denial_reason, 512),
            failure_identifiers: sanitized_failures,
            failure_identifiers_json,
            search_hit_count: input.search_hit_count,
            latency_ms: input.latency_ms,
        })
    }

    fn lock_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|_| ContextError::Journal {
            message: "session journal connection mutex poisoned".to_string(),
        })
    }
}

struct SanitizedEvent {
    kind: JournalEventKind,
    artifact_id: Option<ArtifactId>,
    command_summary: Option<String>,
    source_label: Option<String>,
    stream: Option<StreamKind>,
    reducer_id: Option<String>,
    exit_code: Option<i32>,
    raw_bytes: u64,
    view_bytes: u64,
    retrieved_bytes: u64,
    estimated_raw_tokens: u64,
    estimated_view_tokens: u64,
    estimated_retrieved_tokens: u64,
    deduplicated: bool,
    originals_available: bool,
    secrets_redacted: usize,
    denial_code: Option<String>,
    denial_reason: Option<String>,
    failure_identifiers: Vec<String>,
    failure_identifiers_json: String,
    search_hit_count: Option<usize>,
    latency_ms: Option<u64>,
}

impl SanitizedEvent {
    fn into_recorded(
        self,
        event_seq: u64,
        scope: &BoundScope,
        recorded_at: String,
    ) -> RecordedEvent {
        RecordedEvent {
            event_seq,
            workspace_scope_id: scope.workspace_scope_id.clone(),
            session_id: scope.session_id.clone(),
            kind: self.kind,
            recorded_at,
            artifact_id: self.artifact_id,
            command_summary: self.command_summary,
            source_label: self.source_label,
            stream: self.stream,
            reducer_id: self.reducer_id,
            exit_code: self.exit_code,
            raw_bytes: self.raw_bytes,
            view_bytes: self.view_bytes,
            retrieved_bytes: self.retrieved_bytes,
            estimated_raw_tokens: self.estimated_raw_tokens,
            estimated_view_tokens: self.estimated_view_tokens,
            estimated_retrieved_tokens: self.estimated_retrieved_tokens,
            deduplicated: self.deduplicated,
            originals_available: self.originals_available,
            secrets_redacted: self.secrets_redacted,
            denial_code: self.denial_code,
            denial_reason: self.denial_reason,
            failure_identifiers: self.failure_identifiers,
            search_hit_count: self.search_hit_count,
            latency_ms: self.latency_ms,
        }
    }
}

fn insert_sanitized_event(
    conn: &Connection,
    scope: &BoundScope,
    ev: &SanitizedEvent,
    recorded_at: &str,
    recorded_unix_ms: i64,
) -> std::result::Result<u64, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO journal_events (
            workspace_scope_id,
            session_id,
            event_kind,
            recorded_at,
            recorded_unix_ms,
            artifact_id,
            command_summary,
            source_label,
            stream,
            reducer_id,
            exit_code,
            raw_bytes,
            view_bytes,
            retrieved_bytes,
            estimated_raw_tokens,
            estimated_view_tokens,
            estimated_retrieved_tokens,
            deduplicated,
            originals_available,
            secrets_redacted,
            denial_code,
            denial_reason,
            failure_identifiers_json,
            search_hit_count,
            latency_ms
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
            ?21, ?22, ?23, ?24, ?25
        )",
    )?;

    stmt.execute(params![
        scope.workspace_scope_id.as_str(),
        scope.session_id.as_str(),
        ev.kind.as_str(),
        recorded_at,
        recorded_unix_ms,
        ev.artifact_id.as_ref().map(ArtifactId::as_str),
        ev.command_summary.as_deref(),
        ev.source_label.as_deref(),
        ev.stream.as_ref().map(StreamKind::as_str),
        ev.reducer_id.as_deref(),
        ev.exit_code,
        u64_to_sql(ev.raw_bytes),
        u64_to_sql(ev.view_bytes),
        u64_to_sql(ev.retrieved_bytes),
        u64_to_sql(ev.estimated_raw_tokens),
        u64_to_sql(ev.estimated_view_tokens),
        u64_to_sql(ev.estimated_retrieved_tokens),
        i64::from(ev.deduplicated),
        i64::from(ev.originals_available),
        u64_to_sql(ev.secrets_redacted as u64),
        ev.denial_code.as_deref(),
        ev.denial_reason.as_deref(),
        ev.failure_identifiers_json.as_str(),
        ev.search_hit_count.map(|c| u64_to_sql(c as u64)),
        ev.latency_ms.map(u64_to_sql),
    ])?;

    let row_id = conn.last_insert_rowid();
    Ok(sql_to_u64(row_id))
}

fn decode_event_row(
    row: &rusqlite::Row<'_>,
) -> std::result::Result<Result<RecordedEvent>, rusqlite::Error> {
    let seq_raw: i64 = row.get(0)?;
    let ws_raw: String = row.get(1)?;
    let sess_raw: String = row.get(2)?;
    let kind_raw: String = row.get(3)?;
    let recorded_at: String = row.get(4)?;
    let artifact_raw: Option<String> = row.get(5)?;
    let command_summary: Option<String> = row.get(6)?;
    let source_label: Option<String> = row.get(7)?;
    let stream_raw: Option<String> = row.get(8)?;
    let reducer_id: Option<String> = row.get(9)?;
    let exit_code: Option<i32> = row.get(10)?;
    let raw_bytes: i64 = row.get(11)?;
    let view_bytes: i64 = row.get(12)?;
    let retrieved_bytes: i64 = row.get(13)?;
    let est_raw_tokens: i64 = row.get(14)?;
    let est_view_tokens: i64 = row.get(15)?;
    let est_retrieved_tokens: i64 = row.get(16)?;
    let deduplicated_raw: i64 = row.get(17)?;
    let originals_raw: i64 = row.get(18)?;
    let secrets_redacted_raw: i64 = row.get(19)?;
    let denial_code: Option<String> = row.get(20)?;
    let denial_reason: Option<String> = row.get(21)?;
    let failures_json: String = row.get(22)?;
    let search_hits_raw: Option<i64> = row.get(23)?;
    let latency_raw: Option<i64> = row.get(24)?;

    let parsed = (|| -> Result<RecordedEvent> {
        let workspace_scope_id = WorkspaceScopeId::parse(&ws_raw)?;
        let session_id = SessionId::parse(&sess_raw)?;
        let kind: JournalEventKind = kind_raw.parse()?;
        let artifact_id = match artifact_raw {
            Some(ref s) => Some(ArtifactId::parse(s)?),
            None => None,
        };
        let stream = match stream_raw {
            Some(ref s) => Some(s.parse::<StreamKind>()?),
            None => None,
        };
        let failure_identifiers: Vec<String> = serde_json::from_str(&failures_json)?;

        Ok(RecordedEvent {
            event_seq: sql_to_u64(seq_raw),
            workspace_scope_id,
            session_id,
            kind,
            recorded_at,
            artifact_id,
            command_summary,
            source_label,
            stream,
            reducer_id,
            exit_code,
            raw_bytes: sql_to_u64(raw_bytes),
            view_bytes: sql_to_u64(view_bytes),
            retrieved_bytes: sql_to_u64(retrieved_bytes),
            estimated_raw_tokens: sql_to_u64(est_raw_tokens),
            estimated_view_tokens: sql_to_u64(est_view_tokens),
            estimated_retrieved_tokens: sql_to_u64(est_retrieved_tokens),
            deduplicated: deduplicated_raw != 0,
            originals_available: originals_raw != 0,
            secrets_redacted: usize::try_from(secrets_redacted_raw.max(0)).unwrap_or(0),
            denial_code,
            denial_reason,
            failure_identifiers,
            search_hit_count: search_hits_raw.map(|c| usize::try_from(c.max(0)).unwrap_or(0)),
            latency_ms: latency_raw.map(sql_to_u64),
        })
    })();

    Ok(parsed)
}

fn load_session_events(
    conn: &Connection,
    scope: &BoundScope,
) -> std::result::Result<Vec<RecordedEvent>, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(
        "SELECT
            event_seq,
            workspace_scope_id,
            session_id,
            event_kind,
            recorded_at,
            artifact_id,
            command_summary,
            source_label,
            stream,
            reducer_id,
            exit_code,
            raw_bytes,
            view_bytes,
            retrieved_bytes,
            estimated_raw_tokens,
            estimated_view_tokens,
            estimated_retrieved_tokens,
            deduplicated,
            originals_available,
            secrets_redacted,
            denial_code,
            denial_reason,
            failure_identifiers_json,
            search_hit_count,
            latency_ms
         FROM journal_events
         WHERE workspace_scope_id = ?1 AND session_id = ?2
         ORDER BY event_seq ASC",
    )?;

    let mapped = stmt.query_map(
        params![scope.workspace_scope_id.as_str(), scope.session_id.as_str()],
        decode_event_row,
    )?;

    let mut out = Vec::new();
    for item in mapped {
        let ev_res = item?;
        let ev = ev_res.map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?;
        out.push(ev);
    }
    Ok(out)
}

fn query_stats_on_conn(
    conn: &Connection,
    scope: &BoundScope,
    all_sessions_in_workspace: bool,
) -> std::result::Result<SessionStats, rusqlite::Error> {
    const SELECT_COLS: &str = "
        COUNT(*),
        COUNT(DISTINCT session_id),
        COALESCE(SUM(CASE WHEN event_kind = 'command_captured' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN event_kind = 'document_indexed' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN event_kind = 'artifact_searched' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN event_kind = 'artifact_retrieved' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN event_kind = 'checkpoint_created' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN deduplicated != 0 AND event_kind IN ('command_captured', 'document_indexed') THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN event_kind = 'security_denied' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(secrets_redacted), 0),
        COALESCE(SUM(raw_bytes), 0),
        COALESCE(SUM(view_bytes), 0),
        COALESCE(SUM(retrieved_bytes), 0),
        COALESCE(SUM(estimated_raw_tokens), 0),
        COALESCE(SUM(estimated_view_tokens), 0),
        COALESCE(SUM(estimated_retrieved_tokens), 0)
    ";

    type AggTuple = (
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    );

    let read_tuple = |row: &rusqlite::Row<'_>| -> std::result::Result<AggTuple, rusqlite::Error> {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
            row.get(9)?,
            row.get(10)?,
            row.get(11)?,
            row.get(12)?,
            row.get(13)?,
            row.get(14)?,
            row.get(15)?,
        ))
    };

    let agg: AggTuple = if all_sessions_in_workspace {
        let sql = format!("SELECT {SELECT_COLS} FROM journal_events WHERE workspace_scope_id = ?1");
        conn.query_row(&sql, params![scope.workspace_scope_id.as_str()], read_tuple)?
    } else {
        let sql = format!(
            "SELECT {SELECT_COLS} FROM journal_events WHERE workspace_scope_id = ?1 AND session_id = ?2"
        );
        conn.query_row(
            &sql,
            params![scope.workspace_scope_id.as_str(), scope.session_id.as_str()],
            read_tuple,
        )?
    };

    let total_events = sql_to_u64(agg.0);
    let distinct_sessions = usize::try_from(agg.1.max(0)).unwrap_or(0);
    let command_captures = sql_to_u64(agg.2);
    let document_indexes = sql_to_u64(agg.3);
    let total_captures = command_captures.saturating_add(document_indexes);
    let search_queries = sql_to_u64(agg.4);
    let retrieval_calls = sql_to_u64(agg.5);
    let checkpoints_created = sql_to_u64(agg.6);
    let cache_dedup_hits = sql_to_u64(agg.7);
    let security_denials = sql_to_u64(agg.8);
    let secrets_redacted_total = sql_to_u64(agg.9);

    let raw_bytes = sql_to_u64(agg.10);
    let view_bytes = sql_to_u64(agg.11);
    let retrieved_bytes = sql_to_u64(agg.12);
    let exposed_bytes = view_bytes.saturating_add(retrieved_bytes);
    let net_saved_bytes = signed_diff(raw_bytes, exposed_bytes);

    let estimated_raw_tokens = sql_to_u64(agg.13);
    let estimated_view_tokens = sql_to_u64(agg.14);
    let estimated_retrieved_tokens = sql_to_u64(agg.15);
    let estimated_exposed_tokens = estimated_view_tokens.saturating_add(estimated_retrieved_tokens);
    let estimated_net_saved_tokens = signed_diff(estimated_raw_tokens, estimated_exposed_tokens);

    let view_reduction_ratio = finite_savings_ratio(raw_bytes, view_bytes);
    let net_byte_savings_ratio = finite_savings_ratio(raw_bytes, exposed_bytes);
    let net_token_savings_ratio =
        finite_savings_ratio(estimated_raw_tokens, estimated_exposed_tokens);
    let retrieval_overhead_ratio = finite_overhead_ratio(retrieved_bytes, raw_bytes);
    let token_retrieval_overhead_ratio =
        finite_overhead_ratio(estimated_retrieved_tokens, estimated_raw_tokens);

    let session_opt = if all_sessions_in_workspace {
        None
    } else {
        Some(scope.session_id.clone())
    };

    Ok(SessionStats {
        workspace_scope_id: scope.workspace_scope_id.clone(),
        session_id: session_opt,
        distinct_sessions,
        total_events,
        total_captures,
        command_captures,
        document_indexes,
        search_queries,
        retrieval_calls,
        checkpoints_created,
        cache_dedup_hits,
        security_denials,
        secrets_redacted_total,
        raw_bytes,
        view_bytes,
        retrieved_bytes,
        exposed_bytes,
        net_saved_bytes,
        estimated_raw_tokens,
        estimated_view_tokens,
        estimated_retrieved_tokens,
        estimated_exposed_tokens,
        estimated_net_saved_tokens,
        view_reduction_ratio,
        net_byte_savings_ratio,
        net_token_savings_ratio,
        retrieval_overhead_ratio,
        token_retrieval_overhead_ratio,
    })
}

struct DerivedContinuityView {
    recent_commands: Vec<RecentCommandRecord>,
    unresolved_failures: Vec<String>,
    active_artifacts: Vec<ActiveArtifactHandle>,
}

/// Deterministically folds chronological session events into recent commands, unresolved test/compiler
/// failures, and prioritized `context_get` recovery handles.
fn derive_continuity_view(
    events: &[RecordedEvent],
    max_recent_commands: usize,
    max_active_artifacts: usize,
    max_unresolved_failures: usize,
    max_get_bytes: usize,
) -> DerivedContinuityView {
    // 1. Chronological recent commands (oldest-to-newest within bounded window).
    let mut all_commands: Vec<RecentCommandRecord> = Vec::new();

    // 2. Family-keyed unresolved failure tracking:
    //    - A failing run in family `K` sets `unresolved_by_family[K] = failure_identifiers`.
    //    - A subsequent clean passing run (`exit_code == Some(0)` and `failure_identifiers.is_empty()`)
    //      in that SAME family `K` resolves and clears `unresolved_by_family[K]`, while unrelated
    //      commands (`git status`, `rg`) never wipe out test or compiler failures!
    let mut unresolved_by_family: BTreeMap<String, Vec<String>> = BTreeMap::new();

    // 3. Distinct artifact tracking (latest metadata wins; failed artifacts prioritized first).
    let mut artifact_map: BTreeMap<String, (u64, ActiveArtifactHandle)> = BTreeMap::new();

    for ev in events {
        if ev.kind == JournalEventKind::CommandCaptured {
            let cmd_summary = ev
                .command_summary
                .clone()
                .or_else(|| ev.source_label.clone())
                .unwrap_or_else(|| "command".to_string());

            all_commands.push(RecentCommandRecord {
                event_seq: ev.event_seq,
                recorded_at: ev.recorded_at.clone(),
                command_summary: cmd_summary.clone(),
                exit_code: ev.exit_code,
                reducer_id: ev.reducer_id.clone(),
                artifact_id: ev.artifact_id.clone(),
                failure_count: ev.failure_identifiers.len(),
                latency_ms: ev.latency_ms,
            });

            let family = classify_check_family(ev.reducer_id.as_deref(), &cmd_summary);
            let is_failed =
                ev.exit_code.is_some_and(|code| code != 0) || !ev.failure_identifiers.is_empty();
            let is_clean_pass = ev.exit_code == Some(0) && ev.failure_identifiers.is_empty();

            if is_failed {
                if !ev.failure_identifiers.is_empty() {
                    unresolved_by_family.insert(family, ev.failure_identifiers.clone());
                }
            } else if is_clean_pass {
                unresolved_by_family.remove(&family);
            }
        }

        if matches!(
            ev.kind,
            JournalEventKind::CommandCaptured | JournalEventKind::DocumentIndexed
        ) {
            if let Some(ref art_id) = ev.artifact_id {
                let label = ev
                    .command_summary
                    .clone()
                    .or_else(|| ev.source_label.clone())
                    .unwrap_or_else(|| ev.kind.as_str().to_string());
                let has_failures =
                    ev.exit_code.is_some_and(|c| c != 0) || !ev.failure_identifiers.is_empty();
                let recovery = if ev.originals_available {
                    RecoveryHandle::for_artifact(art_id.clone(), Some(max_get_bytes))
                } else {
                    RecoveryHandle::unavailable(art_id.clone(), "originals unavailable")
                };

                artifact_map.insert(
                    art_id.as_str().to_string(),
                    (
                        ev.event_seq,
                        ActiveArtifactHandle {
                            artifact_id: art_id.clone(),
                            event_kind: ev.kind,
                            label,
                            reducer_id: ev.reducer_id.clone(),
                            exit_code: ev.exit_code,
                            recorded_at: ev.recorded_at.clone(),
                            has_failures,
                            recovery,
                        },
                    ),
                );
            }
        }
    }

    let recent_commands = if all_commands.len() > max_recent_commands {
        all_commands[all_commands.len() - max_recent_commands..].to_vec()
    } else {
        all_commands
    };

    let mut seen_failures = BTreeSet::new();
    let mut unresolved_failures = Vec::new();
    for items in unresolved_by_family.values() {
        for ident in items {
            if seen_failures.insert(ident.clone()) {
                unresolved_failures.push(ident.clone());
                if unresolved_failures.len() >= max_unresolved_failures {
                    break;
                }
            }
        }
        if unresolved_failures.len() >= max_unresolved_failures {
            break;
        }
    }

    // Prioritize failure-bearing artifacts first, then most recent `event_seq` descending.
    let mut ranked_artifacts: Vec<(u64, ActiveArtifactHandle)> =
        artifact_map.into_values().collect();
    ranked_artifacts.sort_by(|(seq_a, art_a), (seq_b, art_b)| {
        art_b
            .has_failures
            .cmp(&art_a.has_failures)
            .then_with(|| seq_b.cmp(seq_a))
    });
    let active_artifacts = ranked_artifacts
        .into_iter()
        .take(max_active_artifacts)
        .map(|(_, handle)| handle)
        .collect();

    DerivedContinuityView {
        recent_commands,
        unresolved_failures,
        active_artifacts,
    }
}

fn classify_check_family(reducer_id: Option<&str>, command_summary: &str) -> String {
    if let Some(red) = reducer_id {
        if red == TRANSFORM_CARGO_TEST_V1 || red == TRANSFORM_PYTEST_JEST_V1 {
            return "test_suite".to_string();
        }
        if red == TRANSFORM_COMPILER_DIAG_V1 {
            return "compiler_diagnostics".to_string();
        }
    }

    let lower = command_summary.trim().to_ascii_lowercase();
    let parts: Vec<&str> = lower.split_whitespace().collect();
    match parts.as_slice() {
        ["cargo", "test" | "nextest", ..]
        | ["pytest", ..]
        | ["npm" | "pnpm" | "yarn", "test", ..] => "test_suite".to_string(),
        ["cargo", "check" | "build" | "clippy", ..] | ["rustc", ..] | ["tsc", ..] => {
            "compiler_diagnostics".to_string()
        }
        [prog, sub, ..] => format!("cmd:{prog}:{sub}"),
        [prog] => format!("cmd:{prog}"),
        [] => "cmd:unknown".to_string(),
    }
}

const fn u64_to_sql(val: u64) -> i64 {
    if val > i64::MAX as u64 {
        i64::MAX
    } else {
        val as i64
    }
}

const fn sql_to_u64(val: i64) -> u64 {
    if val <= 0 {
        0
    } else {
        val as u64
    }
}

fn signed_diff(raw: u64, exposed: u64) -> i64 {
    let diff = i128::from(raw) - i128::from(exposed);
    diff.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

#[allow(clippy::cast_precision_loss)]
fn finite_savings_ratio(raw: u64, exposed: u64) -> f64 {
    if raw == 0 {
        return 0.0;
    }
    let ratio = (raw as f64 - exposed as f64) / (raw as f64);
    if ratio.is_finite() {
        ratio
    } else {
        0.0
    }
}

#[allow(clippy::cast_precision_loss)]
fn finite_overhead_ratio(retrieved: u64, raw: u64) -> f64 {
    if raw == 0 {
        return 0.0;
    }
    let ratio = (retrieved as f64) / (raw as f64);
    if ratio.is_finite() {
        ratio
    } else {
        0.0
    }
}
