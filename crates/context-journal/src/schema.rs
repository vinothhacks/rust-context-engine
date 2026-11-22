//! SQLite WAL connection setup, append-only event schema, and migrations for `context-journal`.

use std::path::Path;
use std::thread;
use std::time::Duration;

use context_core::{now_rfc3339_utc, ContextError, Result};
use rusqlite::{params, Connection, ErrorCode, TransactionBehavior};
use serde::{Deserialize, Serialize};

/// Component namespace used in the shared `schema_migrations` ledger.
pub const JOURNAL_SCHEMA_COMPONENT: &str = "context-journal";

/// Current schema version for `context-journal`.
pub const JOURNAL_SCHEMA_VERSION: i64 = 1;

/// Default SQLite busy timeout (`5_000` ms).
pub const DEFAULT_JOURNAL_BUSY_TIMEOUT_MS: u64 = 5_000;

const MIGRATION_V1_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS journal_events (
    event_seq                  INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_scope_id         TEXT NOT NULL,
    session_id                 TEXT NOT NULL,
    event_kind                 TEXT NOT NULL,
    recorded_at                TEXT NOT NULL,
    recorded_unix_ms           INTEGER NOT NULL,
    artifact_id                TEXT,
    command_summary            TEXT,
    source_label               TEXT,
    stream                     TEXT,
    reducer_id                 TEXT,
    exit_code                  INTEGER,
    raw_bytes                  INTEGER NOT NULL DEFAULT 0,
    view_bytes                 INTEGER NOT NULL DEFAULT 0,
    retrieved_bytes            INTEGER NOT NULL DEFAULT 0,
    estimated_raw_tokens       INTEGER NOT NULL DEFAULT 0,
    estimated_view_tokens      INTEGER NOT NULL DEFAULT 0,
    estimated_retrieved_tokens INTEGER NOT NULL DEFAULT 0,
    deduplicated               INTEGER NOT NULL DEFAULT 0,
    originals_available        INTEGER NOT NULL DEFAULT 1,
    secrets_redacted           INTEGER NOT NULL DEFAULT 0,
    denial_code                TEXT,
    denial_reason              TEXT,
    failure_identifiers_json   TEXT NOT NULL DEFAULT '[]',
    search_hit_count           INTEGER,
    latency_ms                 INTEGER
);

CREATE INDEX IF NOT EXISTS idx_journal_events_scope_session_seq
    ON journal_events (workspace_scope_id, session_id, event_seq ASC);

CREATE INDEX IF NOT EXISTS idx_journal_events_scope_seq
    ON journal_events (workspace_scope_id, event_seq ASC);

CREATE INDEX IF NOT EXISTS idx_journal_events_scope_time
    ON journal_events (workspace_scope_id, recorded_unix_ms);

CREATE TRIGGER IF NOT EXISTS trg_journal_events_immutable_update
BEFORE UPDATE ON journal_events
BEGIN
    SELECT RAISE(ABORT, 'journal_events is strictly append-only; updates are prohibited');
END;

CREATE TABLE IF NOT EXISTS journal_checkpoints (
    checkpoint_id      TEXT PRIMARY KEY,
    workspace_scope_id TEXT NOT NULL,
    session_id         TEXT NOT NULL,
    up_to_event_seq    INTEGER NOT NULL,
    created_at         TEXT NOT NULL,
    created_unix_ms    INTEGER NOT NULL,
    note               TEXT,
    snapshot_json      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_journal_checkpoints_scope_session_seq
    ON journal_checkpoints (workspace_scope_id, session_id, up_to_event_seq DESC);
"#;

/// Diagnostic report returned by [`crate::SessionJournal::health_check`] for `context_doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalHealthReport {
    pub healthy: bool,
    pub journal_mode: String,
    pub foreign_keys_enabled: bool,
    pub schema_version: i64,
    pub quick_check_ok: bool,
    pub total_events: u64,
    pub total_checkpoints: u64,
    pub db_size_bytes: u64,
}

pub(crate) fn map_sql_err(context: &str, err: &rusqlite::Error) -> ContextError {
    ContextError::Journal {
        message: format!("{context}: {err}"),
    }
}

fn is_transient_lock_error(err: &rusqlite::Error) -> bool {
    matches!(
        err.sqlite_error_code(),
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

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

pub(crate) fn open_and_configure_file(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut conn = Connection::open(path)
        .map_err(|err| map_sql_err("failed to open session journal database", &err))?;
    configure_connection(&mut conn, false)?;
    run_migrations(&mut conn)?;
    Ok(conn)
}

pub(crate) fn open_and_configure_in_memory() -> Result<Connection> {
    let mut conn = Connection::open_in_memory()
        .map_err(|err| map_sql_err("failed to open in-memory session journal", &err))?;
    configure_connection(&mut conn, true)?;
    run_migrations(&mut conn)?;
    Ok(conn)
}

fn configure_connection(conn: &mut Connection, is_in_memory: bool) -> Result<()> {
    conn.busy_timeout(Duration::from_millis(DEFAULT_JOURNAL_BUSY_TIMEOUT_MS))
        .map_err(|err| map_sql_err("failed to set busy_timeout(5000)", &err))?;

    let journal_mode = with_lock_retry("failed to configure SQLite journal pragmas", || {
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA temp_store = MEMORY;
             PRAGMA synchronous = NORMAL;",
        )?;
        conn.query_row("PRAGMA journal_mode = WAL;", [], |row| row.get::<_, String>(0))
    })?;

    if !is_in_memory && !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(ContextError::Journal {
            message: format!("expected SQLite journal_mode 'wal', got '{journal_mode}'"),
        });
    }

    let fk_on: i64 = conn
        .query_row("PRAGMA foreign_keys;", [], |row| row.get(0))
        .map_err(|err| map_sql_err("failed to verify foreign_keys pragma", &err))?;
    if fk_on != 1 {
        return Err(ContextError::Journal {
            message: "SQLite foreign_keys pragma failed to enable".to_string(),
        });
    }

    Ok(())
}

fn run_migrations(conn: &mut Connection) -> Result<()> {
    with_lock_retry("failed to apply context-journal schema migrations", || {
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
            params![JOURNAL_SCHEMA_COMPONENT],
            |row| row.get(0),
        )?;

        if current_version < 1 {
            tx.execute_batch(MIGRATION_V1_SQL)?;
            tx.execute(
                "INSERT INTO schema_migrations (component, version, description, applied_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    JOURNAL_SCHEMA_COMPONENT,
                    1_i64,
                    "initial append-only journal_events and journal_checkpoints tables",
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
) -> Result<JournalHealthReport> {
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
            params![JOURNAL_SCHEMA_COMPONENT],
            |row| row.get(0),
        )
        .map_err(|err| map_sql_err("failed to query schema_migrations", &err))?;

    let quick_check_res: String = conn
        .query_row("PRAGMA quick_check(1);", [], |row| row.get(0))
        .map_err(|err| map_sql_err("failed to run PRAGMA quick_check", &err))?;
    let quick_check_ok = quick_check_res.eq_ignore_ascii_case("ok");

    let total_events: i64 = conn
        .query_row("SELECT COUNT(*) FROM journal_events", [], |row| row.get(0))
        .map_err(|err| map_sql_err("failed to count journal_events", &err))?;

    let total_checkpoints: i64 = conn
        .query_row("SELECT COUNT(*) FROM journal_checkpoints", [], |row| row.get(0))
        .map_err(|err| map_sql_err("failed to count journal_checkpoints", &err))?;

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
        && schema_version >= JOURNAL_SCHEMA_VERSION
        && quick_check_ok;

    Ok(JournalHealthReport {
        healthy,
        journal_mode,
        foreign_keys_enabled,
        schema_version,
        quick_check_ok,
        total_events: u64::try_from(total_events.max(0)).unwrap_or(0),
        total_checkpoints: u64::try_from(total_checkpoints.max(0)).unwrap_or(0),
        db_size_bytes,
    })
}
