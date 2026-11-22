//! Scoped `SearchIndex` implementation over SQLite WAL + FTS5 (`porter unicode61`).

use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;
use context_core::{
    now_rfc3339_utc, truncate_str_utf8_boundary, ArtifactEnvelope, ArtifactId, ArtifactSource,
    BoundScope, ContextError, LineRange, RecoveryHandle, ReductionBudget, Result, SecretGuard,
    SecretPolicyMode, SessionId, StreamKind, WorkspaceScopeId,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::chunker::{chunk_sanitized_text, sanitize_fts5_query, ChunkConfig};
use crate::schema::{
    map_sql_err, open_and_configure_file, open_and_configure_in_memory, run_health_check,
    with_lock_retry, SearchHealthReport,
};

/// Configuration governing chunking, budgets, and defense-in-depth `SecretGuard` enforcement
/// inside [`SearchIndex`].
#[derive(Debug, Clone, Default)]
pub struct SearchConfig {
    pub budget: ReductionBudget,
    pub chunk_config: ChunkConfig,
    pub secret_guard: SecretGuard,
}

/// Single stream payload submitted to [`SearchIndex::index_artifact`].
#[derive(Debug, Clone, Copy)]
pub struct StreamInput<'a> {
    pub stream: StreamKind,
    pub text: &'a str,
}

/// Multi-stream artifact indexing request bound to a single [`ArtifactId`].
#[derive(Debug, Clone)]
pub struct IndexArtifactRequest<'a> {
    pub artifact_id: ArtifactId,
    pub source_label: &'a str,
    pub streams: Vec<StreamInput<'a>>,
    pub originals_available: bool,
    pub unavailable_reason: Option<&'a str>,
}

/// Convenience single-stream indexing request.
#[derive(Debug, Clone, Copy)]
pub struct IndexStreamRequest<'a> {
    pub artifact_id: &'a ArtifactId,
    pub stream: StreamKind,
    pub source_label: &'a str,
    pub text: &'a str,
    pub originals_available: bool,
}

/// Non-sensitive telemetry returned after indexing an artifact's stream(s).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexStats {
    pub artifact_id: ArtifactId,
    pub chunks_indexed: usize,
    pub sanitized_bytes: u64,
    pub secrets_redacted: usize,
    pub secret_rule_ids: Vec<String>,
    pub originals_available: bool,
}

/// Ranked lexical search match returned by [`SearchIndex::search`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchHit {
    /// 1-indexed position in the BM25-ranked result set (`1` = highest relevance).
    pub rank: usize,
    /// Non-negative BM25 relevance score (`>= 0.0`; larger means stronger match).
    pub score: f64,
    /// Raw SQLite FTS5 `bm25()` score (negative; lower means stronger match).
    pub raw_bm25: f64,
    /// Server-minted artifact identifier containing the matched chunk.
    pub artifact_id: ArtifactId,
    /// Session in which the artifact was captured.
    pub session_id: SessionId,
    /// Stream (`stdout`, `stderr`, `combined`, `document`) where the match occurred.
    pub stream: StreamKind,
    /// Sanitized provenance label (e.g. `"cargo test"` or `"docs/architecture.md"`).
    pub source_label: String,
    /// 1-indexed starting line number of the matched chunk (inclusive).
    pub line_start: usize,
    /// 1-indexed ending line number of the matched chunk (inclusive).
    pub line_end: usize,
    /// Validated `LineRange` (`line_start..=line_end`) ready for `context_get`.
    pub line_range: LineRange,
    /// Bounded, UTF-8 safe sanitized excerpt (`<= ReductionBudget::max_search_snippet_bytes`).
    pub snippet: String,
    /// Recovery handle pointing to `context_get` (or marked unavailable if quarantined).
    pub recovery: RecoveryHandle,
}

impl SearchHit {
    /// Returns the 1-indexed inclusive line span `line_start..=line_end`.
    #[must_use]
    pub const fn line_span(&self) -> RangeInclusive<usize> {
        self.line_start..=self.line_end
    }
}

/// Summary returned by [`SearchIndex::prune_expired`] and [`SearchIndex::prune_before_unix_ms`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneReport {
    /// Artifact IDs removed from the index (can be used to sweep unreferenced store blobs).
    pub pruned_artifacts: Vec<ArtifactId>,
    /// Number of line-addressed chunks deleted across relational and FTS5 tables.
    pub pruned_chunks: usize,
    /// Total sanitized text bytes reclaimed.
    pub reclaimed_sanitized_bytes: u64,
}

/// Thread-safe (`Send + Sync`) SQLite WAL + FTS5 lexical search manager.
///
/// ### Storage Layout
/// By default, [`SearchIndex::open_for_scope`] opens `<workspace>/.context-engine/index.db`
/// ([`BoundScope::index_db_path`]) using namespaced `search_*` tables and the shared
/// `schema_migrations (component, version)` ledger, allowing `context-search` and
/// `context-journal` to coexist cleanly in the same WAL database file without table collisions.
pub struct SearchIndex {
    db_path: Option<PathBuf>,
    conn: Mutex<Connection>,
    config: SearchConfig,
}

impl std::fmt::Debug for SearchIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchIndex")
            .field("db_path", &self.db_path)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl SearchIndex {
    /// Opens (or initializes) the per-workspace SQLite WAL index at [`BoundScope::index_db_path`].
    pub fn open_for_scope(scope: &BoundScope) -> Result<Self> {
        Self::open_with_config(scope.index_db_path(), SearchConfig::default())
    }

    /// Opens (or initializes) the per-workspace SQLite WAL index with custom [`SearchConfig`].
    pub fn open_for_scope_with_config(scope: &BoundScope, config: SearchConfig) -> Result<Self> {
        Self::open_with_config(scope.index_db_path(), config)
    }

    /// Opens (or initializes) a SQLite WAL index at an explicit path (useful for isolated tests).
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_config(db_path, SearchConfig::default())
    }

    /// Opens (or initializes) a SQLite WAL index at `db_path` with custom [`SearchConfig`].
    pub fn open_with_config(db_path: impl AsRef<Path>, config: SearchConfig) -> Result<Self> {
        config.budget.validate()?;
        let path = db_path.as_ref().to_path_buf();
        let conn = open_and_configure_file(&path)?;
        Ok(Self {
            db_path: Some(path),
            conn: Mutex::new(conn),
            config,
        })
    }

    /// Opens an ephemeral in-memory FTS5 search index for unit tests.
    pub fn open_in_memory() -> Result<Self> {
        Self::open_in_memory_with_config(SearchConfig::default())
    }

    /// Opens an ephemeral in-memory FTS5 search index with custom [`SearchConfig`].
    pub fn open_in_memory_with_config(config: SearchConfig) -> Result<Self> {
        config.budget.validate()?;
        let conn = open_and_configure_in_memory()?;
        Ok(Self {
            db_path: None,
            conn: Mutex::new(conn),
            config,
        })
    }

    /// Returns the backing SQLite file path (`None` for `:memory:`).
    #[must_use]
    pub fn db_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
    }

    #[must_use]
    pub const fn config(&self) -> &SearchConfig {
        &self.config
    }

    /// Convenience helper to index a single stream (`stdout`, `stderr`, `combined`, `document`).
    pub fn index_stream(&self, scope: &BoundScope, req: IndexStreamRequest<'_>) -> Result<IndexStats> {
        self.index_artifact(
            scope,
            IndexArtifactRequest {
                artifact_id: req.artifact_id.clone(),
                source_label: req.source_label,
                streams: vec![StreamInput {
                    stream: req.stream,
                    text: req.text,
                }],
                originals_available: req.originals_available,
                unavailable_reason: if req.originals_available {
                    None
                } else {
                    Some("originals unavailable")
                },
            },
        )
    }

    /// Convenience helper wiring an [`ArtifactEnvelope`] and its UTF-8 stream bodies directly into FTS5.
    pub fn index_envelope_streams(
        &self,
        scope: &BoundScope,
        envelope: &ArtifactEnvelope,
        stdout_text: Option<&str>,
        stderr_text: Option<&str>,
    ) -> Result<IndexStats> {
        envelope.validate(scope)?;

        let label = match &envelope.source {
            ArtifactSource::Command { argv, .. } => argv.join(" "),
            ArtifactSource::Document {
                path_relative,
                label,
                ..
            } => label
                .clone()
                .or_else(|| path_relative.clone())
                .unwrap_or_else(|| "document".to_string()),
        };

        let mut streams = Vec::new();
        let primary_stream = match &envelope.source {
            ArtifactSource::Command { .. } => StreamKind::Stdout,
            ArtifactSource::Document { .. } => StreamKind::Document,
        };
        if let Some(out) = stdout_text {
            streams.push(StreamInput {
                stream: primary_stream,
                text: out,
            });
        }
        if let Some(err) = stderr_text {
            streams.push(StreamInput {
                stream: StreamKind::Stderr,
                text: err,
            });
        }

        let originals_available =
            envelope.capture.originals_available && envelope.recovery.unavailable_reason.is_none();

        self.index_artifact(
            scope,
            IndexArtifactRequest {
                artifact_id: envelope.artifact_id.clone(),
                source_label: &label,
                streams,
                originals_available,
                unavailable_reason: envelope.recovery.unavailable_reason.as_deref(),
            },
        )
    }

    /// Sanitizes incoming text via [`SecretGuard`], chunks it into 1-indexed line spans, and
    /// atomically persists metadata + FTS5 entries under `scope`.
    ///
    /// ### Security Invariant
    /// Even if a caller accidentally passes unredacted text containing credentials, [`SecretGuard`]
    /// runs unconditionally on both `source_label` and every stream body before chunking and
    /// verifies post-redaction cleanliness before executing any FTS5 `INSERT`.
    pub fn index_artifact(
        &self,
        scope: &BoundScope,
        req: IndexArtifactRequest<'_>,
    ) -> Result<IndexStats> {
        WorkspaceScopeId::parse(scope.workspace_scope_id.as_str())?;
        SessionId::parse(scope.session_id.as_str())?;
        ArtifactId::parse(req.artifact_id.as_str())?;

        let mut total_findings_count = 0usize;
        let mut rule_id_set = std::collections::BTreeSet::new();

        // 1. Run SecretGuard on source_label so FTS5 column `source_label` can never store secrets.
        let label_scan = self.config.secret_guard.scan_str(req.source_label);
        if label_scan.has_secrets() {
            total_findings_count += label_scan.redacted_count();
            for id in label_scan.distinct_rule_ids() {
                rule_id_set.insert(id);
            }
        }
        let sanitized_label = if label_scan.sanitized_text.trim().is_empty() {
            "artifact".to_string()
        } else {
            let (bounded, _) = truncate_str_utf8_boundary(&label_scan.sanitized_text, 512);
            bounded.to_string()
        };

        // 2. Run SecretGuard on every full stream BEFORE chunking (catches multi-line PEM keys).
        let mut prepared_streams = Vec::with_capacity(req.streams.len());
        for stream_in in &req.streams {
            let report = self.config.secret_guard.scan_str(stream_in.text);
            if report.has_secrets() {
                total_findings_count += report.redacted_count();
                for id in report.distinct_rule_ids() {
                    rule_id_set.insert(id);
                }
            }
            let chunks = chunk_sanitized_text(&report.sanitized_text, self.config.chunk_config);

            // Defense-in-depth post-condition assertion on every individual chunk + label before SQL.
            if self.config.secret_guard.scan_str(&sanitized_label).has_secrets() {
                return Err(ContextError::SecretPolicyDenied {
                    findings_count: 1,
                    rule_ids: vec!["POST_REDACTION_ASSERTION".to_string()],
                });
            }
            for chunk in &chunks {
                let verify = self.config.secret_guard.scan_str(&chunk.body);
                if verify.has_secrets() {
                    return Err(ContextError::SecretPolicyDenied {
                        findings_count: verify.redacted_count(),
                        rule_ids: verify.distinct_rule_ids(),
                    });
                }
            }

            prepared_streams.push((stream_in.stream, chunks));
        }

        let distinct_rule_ids: Vec<String> = rule_id_set.into_iter().collect();

        // Enforce SecretPolicyMode::Deny / Quarantine before touching SQLite.
        let mut effective_originals_available = req.originals_available;
        let mut effective_unavailable_reason: Option<String> =
            req.unavailable_reason.map(str::to_string);

        if total_findings_count > 0 {
            match self.config.secret_guard.policy().mode {
                SecretPolicyMode::Deny => {
                    return Err(ContextError::SecretPolicyDenied {
                        findings_count: total_findings_count,
                        rule_ids: distinct_rule_ids,
                    });
                }
                SecretPolicyMode::Quarantine => {
                    effective_originals_available = false;
                    if effective_unavailable_reason.is_none() {
                        effective_unavailable_reason =
                            Some("quarantined by secret policy".to_string());
                    }
                }
                SecretPolicyMode::RedactBeforeIndex => {}
            }
        }

        if let Some(reason_raw) = effective_unavailable_reason.as_deref() {
            effective_unavailable_reason = Some(self.config.secret_guard.redact_str(reason_raw));
        }

        let indexed_at = now_rfc3339_utc();
        let indexed_unix_ms = Utc::now().timestamp_millis();

        let mut conn = self.lock_conn()?;
        let (total_chunks_after, total_bytes_after) =
            with_lock_retry("failed to index artifact chunks", || {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

                let existing_scope: Option<(String, String)> = tx
                    .query_row(
                        "SELECT workspace_scope_id, session_id
                         FROM search_artifacts
                         WHERE artifact_id = ?1",
                        params![req.artifact_id.as_str()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;

                // Defer scope mismatch outside rusqlite closure if found.
                if let Some((stored_ws, stored_sess)) = existing_scope {
                    if stored_ws != scope.workspace_scope_id.as_str()
                        || stored_sess != scope.session_id.as_str()
                    {
                        return Ok(Err((stored_ws, stored_sess)));
                    }
                } else {
                    tx.execute(
                        "INSERT INTO search_artifacts (
                            artifact_id,
                            workspace_scope_id,
                            session_id,
                            source_label,
                            indexed_at,
                            indexed_unix_ms,
                            originals_available,
                            unavailable_reason,
                            chunk_count,
                            sanitized_bytes
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0)",
                        params![
                            req.artifact_id.as_str(),
                            scope.workspace_scope_id.as_str(),
                            scope.session_id.as_str(),
                            sanitized_label.as_str(),
                            indexed_at.as_str(),
                            indexed_unix_ms,
                            i64::from(effective_originals_available),
                            effective_unavailable_reason.as_deref(),
                        ],
                    )?;
                }

                for (stream_kind, chunks) in &prepared_streams {
                    tx.execute(
                        "DELETE FROM search_chunks
                         WHERE artifact_id = ?1 AND stream = ?2",
                        params![req.artifact_id.as_str(), stream_kind.as_str()],
                    )?;

                    let mut insert_stmt = tx.prepare_cached(
                        "INSERT INTO search_chunks (
                            artifact_id,
                            workspace_scope_id,
                            session_id,
                            stream,
                            source_label,
                            chunk_seq,
                            line_start,
                            line_end,
                            sanitized_body,
                            indexed_at
                        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    )?;

                    for chunk in chunks {
                        insert_stmt.execute(params![
                            req.artifact_id.as_str(),
                            scope.workspace_scope_id.as_str(),
                            scope.session_id.as_str(),
                            stream_kind.as_str(),
                            sanitized_label.as_str(),
                            i64::try_from(chunk.chunk_seq).unwrap_or(i64::MAX),
                            i64::try_from(chunk.line_start).unwrap_or(i64::MAX),
                            i64::try_from(chunk.line_end).unwrap_or(i64::MAX),
                            chunk.body.as_str(),
                            indexed_at.as_str(),
                        ])?;
                    }
                }

                let (chunk_count_db, bytes_db): (i64, i64) = tx.query_row(
                    "SELECT COUNT(*), COALESCE(SUM(LENGTH(sanitized_body)), 0)
                     FROM search_chunks
                     WHERE artifact_id = ?1",
                    params![req.artifact_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;

                tx.execute(
                    "UPDATE search_artifacts
                     SET source_label = ?2,
                         indexed_at = ?3,
                         indexed_unix_ms = ?4,
                         originals_available = ?5,
                         unavailable_reason = ?6,
                         chunk_count = ?7,
                         sanitized_bytes = ?8
                     WHERE artifact_id = ?1",
                    params![
                        req.artifact_id.as_str(),
                        sanitized_label.as_str(),
                        indexed_at.as_str(),
                        indexed_unix_ms,
                        i64::from(effective_originals_available),
                        effective_unavailable_reason.as_deref(),
                        chunk_count_db,
                        bytes_db,
                    ],
                )?;

                tx.commit()?;
                Ok(Ok((chunk_count_db, bytes_db)))
            })?
            .map_err(|(stored_ws, stored_sess)| {
                if stored_ws != scope.workspace_scope_id.as_str() {
                    ContextError::ScopeViolation {
                        expected_workspace: scope.workspace_scope_id.as_str().to_string(),
                        actual_workspace: stored_ws,
                        detail: "cannot overwrite artifact belonging to another workspace"
                            .to_string(),
                    }
                } else {
                    ContextError::SessionMismatch {
                        expected_session: scope.session_id.as_str().to_string(),
                        actual_session: stored_sess,
                    }
                }
            })?;

        Ok(IndexStats {
            artifact_id: req.artifact_id,
            chunks_indexed: usize::try_from(total_chunks_after.max(0)).unwrap_or(0),
            sanitized_bytes: u64::try_from(total_bytes_after.max(0)).unwrap_or(0),
            secrets_redacted: total_findings_count,
            secret_rule_ids: distinct_rule_ids,
            originals_available: effective_originals_available,
        })
    }

    /// Executes a scoped FTS5 `bm25()` search over sanitized chunks.
    ///
    /// - Untrusted `query` strings are sanitized into quoted word tokens so arbitrary punctuation,
    ///   column prefixes (`col:term`), boolean operators, or SQL/FTS injection strings never trigger
    ///   syntax errors or cross-scope reads.
    /// - Enforces `WHERE workspace_scope_id = ?` unconditionally (plus `AND session_id = ?` when
    ///   `session_only` is `true`) in SQL AND verifies every returned row against `caller_scope`.
    pub fn search(
        &self,
        caller_scope: &BoundScope,
        query: &str,
        session_only: bool,
        limit: usize,
    ) -> Result<Vec<SearchHit>> {
        WorkspaceScopeId::parse(caller_scope.workspace_scope_id.as_str())?;
        SessionId::parse(caller_scope.session_id.as_str())?;

        if limit == 0 {
            return Ok(Vec::new());
        }

        let Some(fts_query) = sanitize_fts5_query(query) else {
            return Ok(Vec::new());
        };

        let effective_limit = limit.min(self.config.budget.max_search_results).max(1);
        let max_snippet_bytes = self.config.budget.max_search_snippet_bytes.max(32);
        let max_get_bytes = self.config.budget.max_get_bytes;
        let max_get_lines = self.config.budget.max_get_lines;

        let conn = self.lock_conn()?;

        struct RawRow {
            artifact_id: String,
            workspace_scope_id: String,
            session_id: String,
            stream: String,
            source_label: String,
            line_start: i64,
            line_end: i64,
            sanitized_body: String,
            raw_snippet: String,
            raw_bm25: f64,
            originals_available: i64,
            unavailable_reason: Option<String>,
        }

        let raw_rows: Vec<RawRow> = if session_only {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT
                        c.artifact_id,
                        c.workspace_scope_id,
                        c.session_id,
                        c.stream,
                        c.source_label,
                        c.line_start,
                        c.line_end,
                        c.sanitized_body,
                        snippet(search_chunks_fts, 0, '', '', ' ... ', 32) AS raw_snippet,
                        bm25(search_chunks_fts, 1.0, 0.5) AS raw_bm25,
                        a.originals_available,
                        a.unavailable_reason
                     FROM search_chunks_fts
                     JOIN search_chunks AS c ON c.chunk_id = search_chunks_fts.rowid
                     JOIN search_artifacts AS a ON a.artifact_id = c.artifact_id
                     WHERE search_chunks_fts MATCH ?1
                       AND c.workspace_scope_id = ?2
                       AND a.workspace_scope_id = ?2
                       AND c.session_id = ?3
                       AND a.session_id = ?3
                     ORDER BY raw_bm25 ASC, c.chunk_id ASC
                     LIMIT ?4",
                )
                .map_err(|err| map_sql_err("failed to prepare session search query", &err))?;

            let mapped = stmt
                .query_map(
                    params![
                        fts_query.as_str(),
                        caller_scope.workspace_scope_id.as_str(),
                        caller_scope.session_id.as_str(),
                        i64::try_from(effective_limit).unwrap_or(20),
                    ],
                    |row| {
                        Ok(RawRow {
                            artifact_id: row.get(0)?,
                            workspace_scope_id: row.get(1)?,
                            session_id: row.get(2)?,
                            stream: row.get(3)?,
                            source_label: row.get(4)?,
                            line_start: row.get(5)?,
                            line_end: row.get(6)?,
                            sanitized_body: row.get(7)?,
                            raw_snippet: row.get(8)?,
                            raw_bm25: row.get(9)?,
                            originals_available: row.get(10)?,
                            unavailable_reason: row.get(11)?,
                        })
                    },
                )
                .map_err(|err| map_sql_err("failed to execute session search query", &err))?;

            mapped
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|err| map_sql_err("failed to collect session search rows", &err))?
        } else {
            let mut stmt = conn
                .prepare_cached(
                    "SELECT
                        c.artifact_id,
                        c.workspace_scope_id,
                        c.session_id,
                        c.stream,
                        c.source_label,
                        c.line_start,
                        c.line_end,
                        c.sanitized_body,
                        snippet(search_chunks_fts, 0, '', '', ' ... ', 32) AS raw_snippet,
                        bm25(search_chunks_fts, 1.0, 0.5) AS raw_bm25,
                        a.originals_available,
                        a.unavailable_reason
                     FROM search_chunks_fts
                     JOIN search_chunks AS c ON c.chunk_id = search_chunks_fts.rowid
                     JOIN search_artifacts AS a ON a.artifact_id = c.artifact_id
                     WHERE search_chunks_fts MATCH ?1
                       AND c.workspace_scope_id = ?2
                       AND a.workspace_scope_id = ?2
                     ORDER BY raw_bm25 ASC, c.chunk_id ASC
                     LIMIT ?3",
                )
                .map_err(|err| map_sql_err("failed to prepare workspace search query", &err))?;

            let mapped = stmt
                .query_map(
                    params![
                        fts_query.as_str(),
                        caller_scope.workspace_scope_id.as_str(),
                        i64::try_from(effective_limit).unwrap_or(20),
                    ],
                    |row| {
                        Ok(RawRow {
                            artifact_id: row.get(0)?,
                            workspace_scope_id: row.get(1)?,
                            session_id: row.get(2)?,
                            stream: row.get(3)?,
                            source_label: row.get(4)?,
                            line_start: row.get(5)?,
                            line_end: row.get(6)?,
                            sanitized_body: row.get(7)?,
                            raw_snippet: row.get(8)?,
                            raw_bm25: row.get(9)?,
                            originals_available: row.get(10)?,
                            unavailable_reason: row.get(11)?,
                        })
                    },
                )
                .map_err(|err| map_sql_err("failed to execute workspace search query", &err))?;

            mapped
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|err| map_sql_err("failed to collect workspace search rows", &err))?
        };

        let mut hits = Vec::with_capacity(raw_rows.len());
        for (idx, row) in raw_rows.into_iter().enumerate() {
            let artifact_id = ArtifactId::parse(&row.artifact_id)?;
            let stored_ws = WorkspaceScopeId::parse(&row.workspace_scope_id)?;
            let stored_sess = SessionId::parse(&row.session_id)?;

            // Post-query defense-in-depth scope verification.
            if session_only {
                caller_scope.verify_exact_scope(&stored_ws, &stored_sess)?;
            } else {
                artifact_id
                    .verify_workspace_binding(&stored_ws, &caller_scope.workspace_scope_id)?;
            }

            let stream: StreamKind = row.stream.parse()?;
            let line_start = usize::try_from(row.line_start.max(1)).unwrap_or(1);
            let raw_end = usize::try_from(row.line_end.max(1)).unwrap_or(line_start).max(line_start);
            let clamped_end = if raw_end - line_start + 1 > max_get_lines {
                line_start + max_get_lines - 1
            } else {
                raw_end
            };
            let line_range = LineRange::new(line_start, clamped_end, max_get_lines)?;

            let candidate_excerpt = if row.sanitized_body.len() <= max_snippet_bytes {
                row.sanitized_body.as_str()
            } else if !row.raw_snippet.trim().is_empty() {
                row.raw_snippet.as_str()
            } else {
                row.sanitized_body.as_str()
            };
            let (bounded_snippet, _) =
                truncate_str_utf8_boundary(candidate_excerpt, max_snippet_bytes);

            let recovery = if row.originals_available != 0 {
                RecoveryHandle::for_artifact(artifact_id.clone(), Some(max_get_bytes))
            } else {
                RecoveryHandle::unavailable(
                    artifact_id.clone(),
                    row.unavailable_reason
                        .unwrap_or_else(|| "originals unavailable".to_string()),
                )
            };

            let finite_bm25 = if row.raw_bm25.is_finite() {
                row.raw_bm25
            } else {
                0.0
            };
            let positive_score = (-finite_bm25).max(0.0);

            hits.push(SearchHit {
                rank: idx + 1,
                score: positive_score,
                raw_bm25: finite_bm25,
                artifact_id,
                session_id: stored_sess,
                stream,
                source_label: row.source_label,
                line_start,
                line_end: raw_end,
                line_range,
                snippet: bounded_snippet.to_string(),
                recovery,
            });
        }

        Ok(hits)
    }

    /// Removes `artifact_id` and 100% of its relational + FTS5 chunks within `caller_scope`'s
    /// bound workspace.
    ///
    /// Fails closed with [`ContextError::ScopeViolation`] if `artifact_id` belongs to a different
    /// workspace. Returns `Ok(false)` if `artifact_id` is not present.
    pub fn remove_artifact(
        &self,
        caller_scope: &BoundScope,
        artifact_id: &ArtifactId,
    ) -> Result<bool> {
        self.remove_artifact_internal(caller_scope, artifact_id, false)
    }

    /// Removes `artifact_id` only when both `(workspace_scope_id, session_id)` match `caller_scope`.
    pub fn remove_artifact_in_session(
        &self,
        caller_scope: &BoundScope,
        artifact_id: &ArtifactId,
    ) -> Result<bool> {
        self.remove_artifact_internal(caller_scope, artifact_id, true)
    }

    fn remove_artifact_internal(
        &self,
        caller_scope: &BoundScope,
        artifact_id: &ArtifactId,
        enforce_session: bool,
    ) -> Result<bool> {
        WorkspaceScopeId::parse(caller_scope.workspace_scope_id.as_str())?;
        SessionId::parse(caller_scope.session_id.as_str())?;
        ArtifactId::parse(artifact_id.as_str())?;

        let mut conn = self.lock_conn()?;
        let outcome = with_lock_retry("failed to remove artifact from search index", || {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let found: Option<(String, String)> = tx
                .query_row(
                    "SELECT workspace_scope_id, session_id
                     FROM search_artifacts
                     WHERE artifact_id = ?1",
                    params![artifact_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;

            let Some((stored_ws, stored_sess)) = found else {
                return Ok(Ok(false));
            };

            if stored_ws != caller_scope.workspace_scope_id.as_str() {
                return Ok(Err((stored_ws, stored_sess, true)));
            }
            if enforce_session && stored_sess != caller_scope.session_id.as_str() {
                return Ok(Err((stored_ws, stored_sess, false)));
            }

            tx.execute(
                "DELETE FROM search_chunks WHERE artifact_id = ?1",
                params![artifact_id.as_str()],
            )?;
            let deleted = tx.execute(
                "DELETE FROM search_artifacts WHERE artifact_id = ?1 AND workspace_scope_id = ?2",
                params![artifact_id.as_str(), caller_scope.workspace_scope_id.as_str()],
            )?;
            tx.commit()?;
            Ok(Ok(deleted > 0))
        })?;

        match outcome {
            Ok(removed) => Ok(removed),
            Err((stored_ws, _stored_sess, true)) => Err(ContextError::ScopeViolation {
                expected_workspace: caller_scope.workspace_scope_id.as_str().to_string(),
                actual_workspace: stored_ws,
                detail: "cross-workspace artifact deletion denied".to_string(),
            }),
            Err((_stored_ws, stored_sess, false)) => Err(ContextError::SessionMismatch {
                expected_session: caller_scope.session_id.as_str().to_string(),
                actual_session: stored_sess,
            }),
        }
    }

    /// Prunes artifacts in `caller_scope.workspace_scope_id` older than `ttl_secs` relative to current UTC time.
    pub fn prune_expired(&self, caller_scope: &BoundScope, ttl_secs: u64) -> Result<PruneReport> {
        let now_ms = Utc::now().timestamp_millis();
        let ttl_ms = i64::try_from(ttl_secs.saturating_mul(1_000)).unwrap_or(i64::MAX);
        let cutoff_unix_ms = now_ms.saturating_sub(ttl_ms);
        self.prune_before_unix_ms(caller_scope, cutoff_unix_ms)
    }

    /// Prunes artifacts in `caller_scope.workspace_scope_id` whose `indexed_unix_ms <= cutoff_unix_ms`,
    /// removing relational metadata and FTS5 entries atomically.
    pub fn prune_before_unix_ms(
        &self,
        caller_scope: &BoundScope,
        cutoff_unix_ms: i64,
    ) -> Result<PruneReport> {
        WorkspaceScopeId::parse(caller_scope.workspace_scope_id.as_str())?;
        SessionId::parse(caller_scope.session_id.as_str())?;

        let mut conn = self.lock_conn()?;
        let (raw_ids, pruned_chunks, reclaimed_bytes) =
            with_lock_retry("failed to prune expired search artifacts", || {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

                let expired: Vec<(String, i64)> = {
                    let mut stmt = tx.prepare(
                        "SELECT artifact_id, sanitized_bytes
                         FROM search_artifacts
                         WHERE workspace_scope_id = ?1 AND indexed_unix_ms <= ?2
                         ORDER BY indexed_unix_ms ASC",
                    )?;
                    let rows = stmt.query_map(
                        params![caller_scope.workspace_scope_id.as_str(), cutoff_unix_ms],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?;
                    rows.collect::<std::result::Result<Vec<_>, _>>()?
                };

                let mut deleted_chunks = 0usize;
                let mut reclaimed_bytes = 0u64;
                let mut ids = Vec::with_capacity(expired.len());

                for (art_id, bytes) in expired {
                    deleted_chunks += tx.execute(
                        "DELETE FROM search_chunks WHERE artifact_id = ?1",
                        params![art_id.as_str()],
                    )?;
                    tx.execute(
                        "DELETE FROM search_artifacts WHERE artifact_id = ?1 AND workspace_scope_id = ?2",
                        params![art_id.as_str(), caller_scope.workspace_scope_id.as_str()],
                    )?;
                    reclaimed_bytes = reclaimed_bytes
                        .saturating_add(u64::try_from(bytes.max(0)).unwrap_or(0));
                    ids.push(art_id);
                }

                tx.commit()?;
                Ok((ids, deleted_chunks, reclaimed_bytes))
            })?;

        let mut pruned_artifacts = Vec::with_capacity(raw_ids.len());
        for raw in raw_ids {
            pruned_artifacts.push(ArtifactId::parse(&raw)?);
        }

        Ok(PruneReport {
            pruned_artifacts,
            pruned_chunks,
            reclaimed_sanitized_bytes: reclaimed_bytes,
        })
    }

    /// Runs SQLite WAL, foreign-key, schema-migration, `quick_check`, and FTS5 `'integrity-check'`
    /// diagnostics for `context_doctor`.
    pub fn health_check(&self) -> Result<SearchHealthReport> {
        let conn = self.lock_conn()?;
        run_health_check(&conn, self.db_path.as_deref())
    }

    fn lock_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(|_| ContextError::Search {
            message: "search index connection mutex poisoned".to_string(),
        })
    }
}
