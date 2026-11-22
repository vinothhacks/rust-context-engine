//! SQLite WAL connection setup, versioned migrations, and FTS5 schema definitions
//! for `context-search`.

use std::path::Path;
use std::thread;
use std::time::Duration;

use context_core::{now_rfc3339_utc, ContextError, Result};
use rusqlite::{params, Connection, ErrorCode, TransactionBehavior};
use serde::{Deserialize, Serialize};

/// Component namespace used in the shared `schema_migrations` ledger.
pub const SEARCH_SCHEMA_COMPONENT: &str = "context-search";

/// Current schema version for `context-search`.
pub const SEARCH_SCHEMA_VERSION: i64 = 1;

/// Default SQLite busy timeout (`5_000` ms) required by ADR 0002.
pub const DEFAULT_BUSY_TIMEOUT_MS: u64 = 5_000;

const MIGRATION_V1_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS search_artifacts (
    artifact_id         TEXT PRIMARY KEY,
    workspace_scope_id  TEXT NOT NULL,
    session_id          TEXT NOT NULL,
    source_label        TEXT NOT NULL,
    indexed_at          TEXT NOT NULL,
    indexed_unix_ms     INTEGER NOT NULL,
    originals_available INTEGER NOT NULL DEFAULT 1,
    unavailable_reason  TEXT,
    chunk_count         INTEGER NOT NULL DEFAULT 0,
    sanitized_bytes     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_search_artifacts_scope_session
    ON search_artifacts (workspace_scope_id, session_id);

CREATE INDEX IF NOT EXISTS idx_search_artifacts_scope_time
    ON search_artifacts (workspace_scope_id, indexed_unix_ms);

CREATE TABLE IF NOT EXISTS search_chunks (
    chunk_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id        TEXT NOT NULL REFERENCES search_artifacts(artifact_id) ON DELETE CASCADE,
    workspace_scope_id TEXT NOT NULL,
    session_id         TEXT NOT NULL,
    stream             TEXT NOT NULL,
    source_label       TEXT NOT NULL,
    chunk_seq          INTEGER NOT NULL,
    line_start         INTEGER NOT NULL,
    line_end           INTEGER NOT NULL,
    sanitized_body     TEXT NOT NULL,
    indexed_at         TEXT NOT NULL,
    UNIQUE (artifact_id, stream, chunk_seq)
);

CREATE INDEX IF NOT EXISTS idx_search_chunks_scope_session
    ON search_chunks (workspace_scope_id, session_id);

CREATE INDEX IF NOT EXISTS idx_search_chunks_artifact
    ON search_chunks (artifact_id);

CREATE VIRTUAL TABLE IF NOT EXISTS search_chunks_fts USING fts5(
    sanitized_body,
    source_label,
    content='search_chunks',
    content_rowid='chunk_id',
    tokenize='porter unicode61'
);

CREATE TRIGGER IF NOT EXISTS trg_search_chunks_ai AFTER INSERT ON search_chunks BEGIN
    INSERT INTO search_chunks_fts(rowid, sanitized_body, source_label)
    VALUES (new.chunk_id, new.sanitized_body, new.source_label);
END;

CREATE TRIGGER IF NOT EXISTS trg_search_chunks_ad AFTER DELETE ON search_chunks BEGIN
    INSERT INTO search_chunks_fts(search_chunks_fts, rowid, sanitized_body, source_label)
    VALUES ('delete', old.chunk_id, old.sanitized_body, old.source_label);
END;

CREATE TRIGGER IF NOT EXISTS trg_search_chunks_au AFTER UPDATE ON search_chunks BEGIN
    INSERT INTO search_chunks_fts(search_chunks_fts, rowid, sanitized_body, source_label)
    VALUES ('delete', old.chunk_id, old.sanitized_body, old.source_label);
    INSERT INTO search_chunks_fts(rowid, sanitized_body, source_label)
    VALUES (new.chunk_id, new.sanitized_body, new.source_label);
END;
"#;

/// Diagnostic snapshot returned by [`crate::SearchIndex::health_check`] for `context_doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchHealthReport {
    /// Whether all integrity, pragma, and migration checks succeeded.
    pub healthy: bool,
    /// Active SQLite journal mode (`"wal"` for disk-backed DBs, `"memory"` for `:memory:`).
    pub journal_mode: String,
    /// Whether `PRAGMA foreign_keys` is enabled (`true`).
    pub foreign_keys_enabled: bool,
    /// Applied `context-search` schema version.
    pub schema_version: i64,
    /// Result of `PRAGMA quick_check(1)` (`true` when `"ok"`).
    pub quick_check_ok: bool,
    /// Result of FTS5 `'integrity-check'` verifying 100% parity with `search_chunks`.
    pub fts_integrity_ok: bool,
    /// Total indexed artifacts across the database.
    pub total_artifacts: u64,
    /// Total indexed line-addressed chunks across the database.
    pub total_chunks: u64,
    /// Approximate database footprint in bytes.
    pub db_size_bytes: u64,
}

/// Converts a `rusqlite::Error` into [`ContextError::Search`].
pub(crate) fn map_sql_err(context: &str, err: &rusqlite::Error) -> ContextError {
    ContextError::Search {
        message: format!("{context}: {err}"),
    }
}

fn is_transient_lock_error(err: &rusqlite::Error) -> bool {
    matches!(
        err.sqlite_error_code(),
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

/// Retry helper for SQLite startup pragmas/migrations when multiple processes open a brand-new
/// WAL database concurrently on Windows NTFS.
pub(crate) fn with_lock_retry<T, F>(op_name: &str, mut f: F) -> Result<T>
where
    F: FnMut() -> std::result::Result<T, rusqlite::Error>,
{
    const MAX_ATTEMPTS: usize = 12;
    let mut attempt = 0usize;
    loop {
        match f() {
            Ok(val) => return Ok(val),
            Err(err) if is_transient_lock_error(&err) && attempt + 1 < MAX_ATTEMPTS => {
                attempt += 1;
                thread::sleep(Duration::from_millis(15 * attempt as u64));
            }
            Err(err) => return Err(map_sql_err(op_name, &err)),
        }
    }
}

/// Opens (or creates) a file-backed SQLite database with required WAL pragmas and migrations.
pub(crate) fn open_and_configure_file(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut conn =
        Connection::open(path).map_err(|err| map_sql_err("failed to open search database", &err))?;
    configure_connection(&mut conn, false)?;
    run_migrations(&mut conn)?;
    Ok(conn)
}

/// Opens an isolated in-memory SQLite database with required pragmas and migrations.
pub(crate) fn open_and_configure_in_memory() -> Result<Connection> {
    let mut conn = Connection::open_in_memory()
        .map_err(|err| map_sql_err("failed to open in-memory search database", &err))?;
    configure_connection(&mut conn, true)?;
    run_migrations(&mut conn)?;
    Ok(conn)
}

fn configure_connection(conn: &mut Connection, is_in_memory: bool) -> Result<()> {
    conn.busy_timeout(Duration::from_millis(DEFAULT_BUSY_TIMEOUT_MS))
        .map_err(|err| map_sql_err("failed to set busy_timeout(5000)", &err))?;

    let journal_mode = with_lock_retry("failed to configure SQLite pragmas", || {
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA synchronous = NORMAL;",
        )?;
        conn.query_row("PRAGMA journal_mode = WAL;", [], |row| row.get::<_, String>(0))
    })?;

    if !is_in_memory && !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(ContextError::Search {
            message: format!("expected SQLite journal_mode 'wal', got '{journal_mode}'"),
        });
    }

    let fk_on: i64 = conn
        .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))
        .map_err(|err| map_sql_err("failed to verify foreign_keys pragma", &err))?;
    if fk_on != 1 {
        return Err(ContextError::Search {
            message: "SQLite foreign_keys pragma failed to enable".to_string(),
        });
    }

    Ok(())
}

fn run_migrations(conn: &mut Connection) -> Result<()> {
    with_lock_retry("failed to apply context-search schema migrations", || {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                component   TEXT NOT NULL,
                version     INTEGER NOT NULL,
                description TEXT NOT NULL,
                applied_at  TEXT NOT NULL,
                PRIMARY KEY (component, version)
            );",
        )?;

        let current_version: i64 = tx.query_row(
            "SELECT COALESCE(MAX(version), 0)
             FROM schema_migrations
             WHERE component = ?1",
            params![SEARCH_SCHEMA_COMPONENT],
            |row| row.get(0),
        )?;

        if current_version < 1 {
            tx.execute_batch(MIGRATION_V1_SQL)?;
            tx.execute(
                "INSERT INTO schema_migrations (component, version, description, applied_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    SEARCH_SCHEMA_COMPONENT,
                    1_i64,
                    "initial scoped FTS5 porter unicode61 chunk index",
                    now_rfc3339_utc(),
                ],
            )?;
        }

        tx.commit()
    })
}

pub(crate) fn run_health_check(
    conn: &Connection,
    db_path: Option<&Path>,
) -> Result<SearchHealthReport> {
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
        .map_err(|err| map_sql_err("failed to query journal_mode", &err))?;

    let fk_raw: i64 = conn
        .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))
        .map_err(|err| map_sql_err("failed to query foreign_keys", &err))?;
    let foreign_keys_enabled = fk_raw == 1;

    let schema_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0)
             FROM schema_migrations
             WHERE component = ?1",
            params![SEARCH_SCHEMA_COMPONENT],
            |row| row.get(0),
        )
        .map_err(|err| map_sql_err("failed to query schema_migrations", &err))?;

    let quick_check_res: String = conn
        .query_row("PRAGMA quick_check(1);", [], |row| row.get(0))
        .map_err(|err| map_sql_err("failed to run PRAGMA quick_check", &err))?;
    let quick_check_ok = quick_check_res.eq_ignore_ascii_case("ok");

    let fts_integrity_ok = conn
        .execute(
            "INSERT INTO search_chunks_fts(search_chunks_fts) VALUES ('integrity-check')",
            [],
        )
        .is_ok();

    let total_artifacts: i64 = conn
        .query_row("SELECT COUNT(*) FROM search_artifacts", [], |row| row.get(0))
        .map_err(|err| map_sql_err("failed to count search_artifacts", &err))?;

    let total_chunks: i64 = conn
        .query_row("SELECT COUNT(*) FROM search_chunks", [], |row| row.get(0))
        .map_err(|err| map_sql_err("failed to count search_chunks", &err))?;

    let db_size_bytes = match db_path {
        Some(p) => std::fs::metadata(p).map(|m| m.len()).unwrap_or(0),
        None => {
            let page_count: i64 = conn
                .query_row("PRAGMA page_count;", [], |row| row.get(0))
                .unwrap_or(0);
            let page_size: i64 = conn
                .query_row("PRAGMA page_size;", [], |row| row.get(0))
                .unwrap_or(4_096);
            u64::try_from(page_count.max(0).saturating_mul(page_size.max(0))).unwrap_or(0)
        }
    };

    let expected_journal_ok = if db_path.is_some() {
        journal_mode.eq_ignore_ascii_case("wal")
    } else {
        journal_mode.eq_ignore_ascii_case("memory") || journal_mode.eq_ignore_ascii_case("wal")
    };

    let healthy = expected_journal_ok
        && foreign_keys_enabled
        && schema_version >= SEARCH_SCHEMA_VERSION
        && quick_check_ok
        && fts_integrity_ok;

    Ok(SearchHealthReport {
        healthy,
        journal_mode,
        foreign_keys_enabled,
        schema_version,
        quick_check_ok,
        fts_integrity_ok,
        total_artifacts: u64::try_from(total_artifacts.max(0)).unwrap_or(0),
        total_chunks: u64::try_from(total_chunks.max(0)).unwrap_or(0),
        db_size_bytes,
    })
}
