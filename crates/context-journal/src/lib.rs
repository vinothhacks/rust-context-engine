//! Session continuity event journal, compression/retrieval telemetry, and deterministic checkpoints.
//!
//! ### Storage Architecture & Coexistence with `context-search`
//! - By default, [`SessionJournal::open_for_scope`] opens `<workspace>/.context-engine/index.db`
//!   ([`BoundScope::index_db_path`]) in SQLite WAL mode (`synchronous = NORMAL`, `foreign_keys = ON`,
//!   `temp_store = MEMORY`, `busy_timeout(5000)`).
//! - Uses namespaced `journal_*` tables (`journal_events`, `journal_checkpoints`) and the shared
//!   `schema_migrations (component, version)` table (`component = 'context-journal'`) so
//!   `context-search` and `context-journal` coexist cleanly in `.context-engine/index.db` (or can
//!   be pointed at separate `.db` files via [`SessionJournal::open`]).
//! - Enforces append-only immutability on `journal_events` via a SQLite `BEFORE UPDATE` trigger and
//!   scrubs every text/metadata field with [`context_core::SecretGuard`] so raw credentials are
//!   never logged.

pub mod journal;
pub mod model;
pub mod schema;

pub use context_core::{ArtifactId, BoundScope, RecoveryHandle, SessionId, StreamKind, WorkspaceScopeId};
pub use journal::{JournalConfig, SessionJournal};
pub use model::{
    ActiveArtifactHandle, JournalEventInput, JournalEventKind, JournalPruneReport,
    RecentCommandRecord, RecordedEvent, ResumePack, SessionCheckpoint, SessionStats,
};
pub use schema::{
    JournalHealthReport, DEFAULT_JOURNAL_BUSY_TIMEOUT_MS, JOURNAL_SCHEMA_COMPONENT,
    JOURNAL_SCHEMA_VERSION,
};

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use context_core::{
        sha256_hex, ArtifactEnvelope, ArtifactSource, ArtifactView, CaptureSummary, ContextError,
        StreamEncoding, ViewKind, EMPTY_SHA256_HEX, RECOVERY_TOOL_CONTEXT_GET,
        TRANSFORM_CARGO_TEST_V1, TRANSFORM_COMPILER_DIAG_V1, TRANSFORM_GIT_REDUCER_V1,
        TRANSFORM_STRIP_ANSI_V1,
    };
    use rusqlite::Connection;
    use tempfile::TempDir;

    use super::*;

    fn mint_art(scope: &BoundScope, seed: &[u8]) -> ArtifactId {
        ArtifactId::mint_from_seed(&scope.workspace_scope_id, &scope.session_id, seed)
    }

    #[test]
    fn wal_pragmas_migrations_append_only_trigger_and_health_check() {
        let ws = TempDir::new().expect("tempdir");
        let scope = BoundScope::bind(ws.path(), Some("sess-init")).expect("bind");
        let journal = SessionJournal::open_for_scope(&scope).expect("open journal");

        assert_eq!(journal.db_path(), Some(scope.index_db_path().as_path()));
        let health = journal.health_check().expect("health");
        assert!(health.healthy);
        assert_eq!(health.journal_mode.to_ascii_lowercase(), "wal");
        assert!(health.foreign_keys_enabled);
        assert_eq!(health.schema_version, JOURNAL_SCHEMA_VERSION);
        assert!(health.quick_check_ok);

        // Append one event and verify SQLite rejects in-place UPDATE on `journal_events`.
        let mut ev = JournalEventInput::new(JournalEventKind::CommandCaptured);
        ev.command_summary = Some("cargo check".into());
        ev.exit_code = Some(0);
        let recorded = journal.record_event(&scope, ev).expect("record event");
        assert_eq!(recorded.event_seq, 1);

        let raw_conn = Connection::open(scope.index_db_path()).expect("open raw");
        let update_err = raw_conn
            .execute(
                "UPDATE journal_events SET exit_code = 99 WHERE event_seq = 1",
                [],
            )
            .expect_err("append-only trigger must block UPDATE");
        assert!(update_err.to_string().contains("append-only"));

        // Verify `list_recent_events` chronological ordering and shared `.context-engine/index.db` coexistence.
        let recent = journal
            .list_recent_events(&scope, 10)
            .expect("list recent events");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].command_summary.as_deref(), Some("cargo check"));

        raw_conn
            .execute(
                "INSERT INTO schema_migrations (component, version, description, applied_at)
                 VALUES ('context-search', 1, 'coexistence check', '2026-11-22T00:00:00.000Z')",
                [],
            )
            .expect("insert sibling search migration");
        let reopened = SessionJournal::open_for_scope(&scope).expect("reopen alongside search");
        assert!(reopened.health_check().expect("reopened health").healthy);
    }

    #[test]
    fn net_token_and_byte_savings_account_for_retrieval_overhead_and_negative_expansion() {
        let ws = TempDir::new().expect("tempdir");
        let scope = BoundScope::bind(ws.path(), Some("sess-telemetry")).expect("bind");
        let journal = SessionJournal::open_in_memory().expect("in-memory journal");

        // Empty stats must have finite 0.0 ratios (no NaN / Inf).
        let empty = journal.stats(&scope, false).expect("empty stats");
        assert_eq!(empty.total_captures, 0);
        assert_eq!(empty.net_byte_savings_ratio, 0.0);
        assert_eq!(empty.net_token_savings_ratio, 0.0);
        assert_eq!(empty.retrieval_overhead_ratio, 0.0);

        let art_cmd = mint_art(&scope, b"cmd-1");
        let art_doc = mint_art(&scope, b"doc-1");

        // 1. Command capture: 80,000 raw bytes -> 4,000 compact view bytes (20,000 -> 1,000 tokens).
        let mut cmd_ev = JournalEventInput::new(JournalEventKind::CommandCaptured);
        cmd_ev.artifact_id = Some(art_cmd.clone());
        cmd_ev.command_summary = Some("cargo test --workspace".into());
        cmd_ev.reducer_id = Some(TRANSFORM_CARGO_TEST_V1.into());
        cmd_ev.exit_code = Some(101);
        cmd_ev.raw_bytes = 80_000;
        cmd_ev.view_bytes = 4_000;
        cmd_ev.failure_identifiers = vec!["tests::auth_fails".into()];
        cmd_ev.latency_ms = Some(1_100);
        journal.record_event(&scope, cmd_ev).expect("record cmd");

        // 2. Deduplicated document index: 20,000 raw bytes -> 1,000 view bytes (5,000 -> 250 tokens).
        let mut doc_ev = JournalEventInput::new(JournalEventKind::DocumentIndexed);
        doc_ev.artifact_id = Some(art_doc.clone());
        doc_ev.source_label = Some("docs/spec.md".into());
        doc_ev.raw_bytes = 20_000;
        doc_ev.view_bytes = 1_000;
        doc_ev.deduplicated = true;
        journal.record_event(&scope, doc_ev).expect("record doc");

        // Total raw = 100,000 bytes (25,000 tokens), view = 5,000 bytes (1,250 tokens) -> 95% view reduction.
        // 3. Search + two context_get retrievals totaling 15,000 bytes (3,750 tokens).
        journal
            .record_search(&scope, 3, 2_000, Some(8))
            .expect("record search");
        journal
            .record_retrieval(&scope, &art_cmd, StreamKind::Stderr, 8_000, Some(4))
            .expect("record get 1");
        journal
            .record_retrieval(&scope, &art_cmd, StreamKind::Stdout, 5_000, Some(3))
            .expect("record get 2");

        // 4. Security denial recorded without affecting byte ratios.
        let sec_err = ContextError::PathEscape {
            path: "../.env".into(),
            workspace_root: "/ws".into(),
            reason: "outside root".into(),
        };
        journal
            .record_security_denial(&scope, &sec_err, Some(1))
            .expect("record denial");

        let stats = journal.stats(&scope, false).expect("session stats");
        assert_eq!(stats.command_captures, 1);
        assert_eq!(stats.document_indexes, 1);
        assert_eq!(stats.total_captures, 2);
        assert_eq!(stats.search_queries, 1);
        assert_eq!(stats.retrieval_calls, 2);
        assert_eq!(stats.cache_dedup_hits, 1);
        assert_eq!(stats.security_denials, 1);

        assert_eq!(stats.raw_bytes, 100_000);
        assert_eq!(stats.view_bytes, 5_000);
        assert_eq!(stats.retrieved_bytes, 15_000);
        assert_eq!(stats.exposed_bytes, 20_000);
        assert_eq!(stats.net_saved_bytes, 80_000);

        assert_eq!(stats.estimated_raw_tokens, 25_000);
        assert_eq!(stats.estimated_view_tokens, 1_250);
        assert_eq!(stats.estimated_retrieved_tokens, 3_750);
        assert_eq!(stats.estimated_exposed_tokens, 5_000);
        assert_eq!(stats.estimated_net_saved_tokens, 20_000);

        assert!((stats.view_reduction_ratio - 0.95).abs() < 1e-9);
        assert!((stats.retrieval_overhead_ratio - 0.15).abs() < 1e-9);
        assert!((stats.net_byte_savings_ratio - 0.80).abs() < 1e-9);
        assert!((stats.net_token_savings_ratio - 0.80).abs() < 1e-9);
        assert!(
            ((stats.view_reduction_ratio - stats.retrieval_overhead_ratio)
                - stats.net_byte_savings_ratio)
                .abs()
                < 1e-9
        );

        // 5. Simulate pathological over-retrieval (retrieving 95,000 more bytes -> exposed = 115,000 > 100,000 raw).
        journal
            .record_retrieval(&scope, &art_cmd, StreamKind::Stdout, 95_000, Some(10))
            .expect("over-retrieve");
        let neg_stats = journal.stats(&scope, false).expect("negative stats");
        assert_eq!(neg_stats.exposed_bytes, 115_000);
        assert_eq!(neg_stats.net_saved_bytes, -15_000);
        assert!((neg_stats.net_byte_savings_ratio - (-0.15)).abs() < 1e-9);
        assert!(neg_stats.net_token_savings_ratio < 0.0);
    }

    #[test]
    fn checkpoint_and_resume_fidelity_tracks_unresolved_failures_across_families() {
        let ws = TempDir::new().expect("tempdir");
        let scope = BoundScope::bind(ws.path(), Some("sess-resume")).expect("bind");
        let journal = SessionJournal::open_for_scope(&scope).expect("open journal");

        let art_test_fail = mint_art(&scope, b"test-fail-1");
        let art_comp_fail = mint_art(&scope, b"comp-fail-1");
        let art_git_ok = mint_art(&scope, b"git-status-1");
        let art_comp_pass = mint_art(&scope, b"comp-pass-2");
        let art_test_pass = mint_art(&scope, b"test-pass-2");

        // Record failing `cargo test` via `ArtifactEnvelope`.
        let env_test_fail = ArtifactEnvelope::new_v1(
            &scope,
            art_test_fail.clone(),
            ArtifactSource::Command {
                argv: vec!["cargo".into(), "test".into()],
                cwd_relative: ".".into(),
                exit_code: Some(101),
                duration_ms: Some(900),
                timed_out: None,
                captured_at: "2026-11-22T12:00:00.000Z".into(),
            },
            CaptureSummary {
                stdout_sha256: sha256_hex(b"raw stdout"),
                stderr_sha256: EMPTY_SHA256_HEX.into(),
                stdout_bytes: 16_000,
                stderr_bytes: 4_000,
                stdout_truncated: false,
                stderr_truncated: false,
                complete: true,
                encoding: StreamEncoding::Utf8,
                originals_available: true,
                secrets_redacted: 0,
                secret_rule_ids: Vec::new(),
            },
            ArtifactView {
                kind: ViewKind::TestSummary,
                reducer_version: "1".into(),
                omitted: true,
                safe_excerpt: "2 failed".into(),
                transformations: vec![
                    TRANSFORM_STRIP_ANSI_V1.into(),
                    TRANSFORM_CARGO_TEST_V1.into(),
                ],
                reduction_error: None,
                failure_identifiers: vec![
                    "auth::rejects_expired_token".into(),
                    "auth::rotates_session".into(),
                ],
            },
            RecoveryHandle::for_artifact(art_test_fail.clone(), Some(32_768)),
        );
        journal
            .record_envelope(&scope, &env_test_fail, false, None)
            .expect("record test fail envelope");

        // Record failing `cargo check` (`compiler_diag@1`).
        let mut comp_fail = JournalEventInput::new(JournalEventKind::CommandCaptured);
        comp_fail.artifact_id = Some(art_comp_fail.clone());
        comp_fail.command_summary = Some("cargo check".into());
        comp_fail.reducer_id = Some(TRANSFORM_COMPILER_DIAG_V1.into());
        comp_fail.exit_code = Some(101);
        comp_fail.raw_bytes = 8_000;
        comp_fail.view_bytes = 600;
        comp_fail.failure_identifiers = vec!["E0308 src/auth.rs:42:9".into()];
        journal
            .record_event(&scope, comp_fail)
            .expect("record compiler fail");

        // Create checkpoint #1.
        let cp1 = journal
            .create_checkpoint(&scope, Some("investigating auth failure"))
            .expect("create checkpoint");
        assert!(cp1.checkpoint_id.starts_with("cp_"));
        assert_eq!(cp1.note.as_deref(), Some("investigating auth failure"));
        assert_eq!(cp1.recent_commands.len(), 2);
        assert_eq!(cp1.unresolved_failures.len(), 3);
        assert!(cp1
            .unresolved_failures
            .contains(&"auth::rejects_expired_token".to_string()));
        assert!(cp1
            .unresolved_failures
            .contains(&"E0308 src/auth.rs:42:9".to_string()));

        // Unrelated `git status` (exit 0) must NOT clear unresolved test or compiler failures!
        let mut git_ok = JournalEventInput::new(JournalEventKind::CommandCaptured);
        git_ok.artifact_id = Some(art_git_ok.clone());
        git_ok.command_summary = Some("git status".into());
        git_ok.reducer_id = Some(TRANSFORM_GIT_REDUCER_V1.into());
        git_ok.exit_code = Some(0);
        git_ok.raw_bytes = 1_200;
        git_ok.view_bytes = 200;
        journal.record_event(&scope, git_ok).expect("record git ok");

        // Passing `cargo check` (exit 0) clears compiler failure while test failures stay unresolved!
        let mut comp_pass = JournalEventInput::new(JournalEventKind::CommandCaptured);
        comp_pass.artifact_id = Some(art_comp_pass.clone());
        comp_pass.command_summary = Some("cargo check".into());
        comp_pass.reducer_id = Some(TRANSFORM_COMPILER_DIAG_V1.into());
        comp_pass.exit_code = Some(0);
        comp_pass.raw_bytes = 2_000;
        comp_pass.view_bytes = 120;
        journal
            .record_event(&scope, comp_pass)
            .expect("record compiler pass");

        let pack_mid = journal.resume(&scope).expect("resume mid-session");
        assert_eq!(pack_mid.latest_checkpoint.as_ref(), Some(&cp1));
        assert_eq!(pack_mid.events_since_checkpoint, 2);
        assert_eq!(pack_mid.recent_commands.len(), 4);
        assert_eq!(
            pack_mid.unresolved_failures,
            vec![
                "auth::rejects_expired_token".to_string(),
                "auth::rotates_session".to_string()
            ]
        );

        let handles = pack_mid.recovery_handles();
        assert!(!handles.is_empty());
        assert!(handles
            .iter()
            .all(|h| h.tool == RECOVERY_TOOL_CONTEXT_GET));
        // Failing artifacts are prioritized ahead of clean passing artifacts.
        assert!(pack_mid.active_artifacts[0].has_failures);

        // Passing `cargo test` resolves remaining test failures.
        let mut test_pass = JournalEventInput::new(JournalEventKind::CommandCaptured);
        test_pass.artifact_id = Some(art_test_pass);
        test_pass.command_summary = Some("cargo test".into());
        test_pass.reducer_id = Some(TRANSFORM_CARGO_TEST_V1.into());
        test_pass.exit_code = Some(0);
        test_pass.raw_bytes = 14_000;
        test_pass.view_bytes = 180;
        journal
            .record_event(&scope, test_pass)
            .expect("record test pass");

        let pack_green = journal.resume(&scope).expect("resume green");
        assert!(pack_green.unresolved_failures.is_empty());
        assert_eq!(pack_green.events_since_checkpoint, 3);
        assert!(pack_green.stats.net_byte_savings_ratio > 0.90);
    }

    #[test]
    fn journal_never_persists_raw_secret_values_in_events_or_checkpoints() {
        let ws = TempDir::new().expect("tempdir");
        let scope = BoundScope::bind(ws.path(), Some("sess-sec")).expect("bind");
        let journal = SessionJournal::open_for_scope(&scope).expect("open journal");

        let gh_pat = "ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD";
        let openai_sk = "sk-proj-0123456789abcdefghijklmnopqrstuvwxyzABCD";
        let pg_uri = "postgres://svc:Sup3rSecretPass99!@db.internal:5432/app";

        let mut ev = JournalEventInput::new(JournalEventKind::CommandCaptured);
        ev.command_summary = Some(format!("python sync.py --token={gh_pat}"));
        ev.failure_identifiers = vec![format!("conn failed for {pg_uri}")];
        ev.denial_reason = Some(format!("rejected header {openai_sk}"));
        journal
            .record_event(&scope, ev)
            .expect("record dirty metadata");

        let cp = journal
            .create_checkpoint(&scope, Some(&format!("note with {gh_pat} and {openai_sk}")))
            .expect("checkpoint dirty note");
        assert!(!cp.note.as_deref().unwrap_or("").contains(gh_pat));
        assert!(!cp.note.as_deref().unwrap_or("").contains(openai_sk));

        // Verify on-disk SQLite rows in both `journal_events` and `journal_checkpoints`.
        let raw_conn = Connection::open(scope.index_db_path()).expect("open raw db");
        let ev_dump: String = raw_conn
            .query_row(
                "SELECT COALESCE(command_summary, '') || ' ' || failure_identifiers_json || ' ' || COALESCE(denial_reason, '')
                 FROM journal_events
                 WHERE event_seq = 1",
                [],
                |row| row.get(0),
            )
            .expect("query event row");
        let cp_dump: String = raw_conn
            .query_row(
                "SELECT COALESCE(note, '') || ' ' || snapshot_json FROM journal_checkpoints LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("query cp row");

        for secret_sub in [gh_pat, openai_sk, "Sup3rSecretPass99!"] {
            assert!(
                !ev_dump.contains(secret_sub),
                "leaked secret in journal_events: {secret_sub}"
            );
            assert!(
                !cp_dump.contains(secret_sub),
                "leaked secret in journal_checkpoints: {secret_sub}"
            );
        }
    }

    #[test]
    fn strict_cross_workspace_and_cross_session_aggregation_isolation() {
        let ws_a = TempDir::new().expect("ws A");
        let ws_b = TempDir::new().expect("ws B");
        let db_dir = TempDir::new().expect("db dir");
        let journal = SessionJournal::open(db_dir.path().join("shared_journal.db")).expect("open");

        let scope_a_s1 = BoundScope::bind(ws_a.path(), Some("s1")).expect("bind A s1");
        let scope_a_s2 = scope_a_s1.with_session("s2").expect("bind A s2");
        let scope_b_s1 = BoundScope::bind(ws_b.path(), Some("s1")).expect("bind B s1");

        let mut ev_a1 = JournalEventInput::new(JournalEventKind::CommandCaptured);
        ev_a1.command_summary = Some("cargo test -p crate_a1".into());
        ev_a1.raw_bytes = 10_000;
        ev_a1.view_bytes = 1_000;
        journal.record_event(&scope_a_s1, ev_a1).expect("a1");
        journal
            .create_checkpoint(&scope_a_s1, Some("ws-a-s1-cp"))
            .expect("cp a1");

        let mut ev_a2 = JournalEventInput::new(JournalEventKind::CommandCaptured);
        ev_a2.command_summary = Some("cargo test -p crate_a2".into());
        ev_a2.raw_bytes = 20_000;
        ev_a2.view_bytes = 2_000;
        journal.record_event(&scope_a_s2, ev_a2).expect("a2");

        let mut ev_b1 = JournalEventInput::new(JournalEventKind::CommandCaptured);
        ev_b1.command_summary = Some("cargo test -p secret_ws_b".into());
        ev_b1.raw_bytes = 500_000;
        ev_b1.view_bytes = 5_000;
        ev_b1.failure_identifiers = vec!["ws_b_private_failure".into()];
        journal.record_event(&scope_b_s1, ev_b1).expect("b1");

        // 1. Single-session stats in A/s1
        let st_a_s1 = journal.stats(&scope_a_s1, false).expect("stats A s1");
        assert_eq!(st_a_s1.session_id, Some(scope_a_s1.session_id.clone()));
        assert_eq!(st_a_s1.distinct_sessions, 1);
        assert_eq!(st_a_s1.raw_bytes, 10_000);
        assert_eq!(st_a_s1.checkpoints_created, 1);

        // 2. Workspace-wide stats in A (`all_sessions_in_workspace = true`) sums s1 + s2, NEVER ws B!
        let st_a_all = journal.stats(&scope_a_s1, true).expect("stats A all");
        assert_eq!(st_a_all.session_id, None);
        assert_eq!(st_a_all.distinct_sessions, 2);
        assert_eq!(st_a_all.raw_bytes, 30_000);
        assert_eq!(st_a_all.view_bytes, 3_000);

        // 3. Resume in A/s2 does not see A/s1's checkpoint or B/s1's failures!
        let resume_a_s2 = journal.resume(&scope_a_s2).expect("resume A s2");
        assert!(resume_a_s2.latest_checkpoint.is_none());
        assert!(resume_a_s2.unresolved_failures.is_empty());
        assert_eq!(resume_a_s2.recent_commands.len(), 1);
        assert_eq!(
            resume_a_s2.recent_commands[0].command_summary,
            "cargo test -p crate_a2"
        );

        // 4. Pruning workspace A leaves workspace B untouched!
        let pruned = journal
            .prune_before_unix_ms(&scope_a_s1, i64::MAX)
            .expect("prune ws A");
        assert_eq!(pruned.pruned_checkpoints, 1);
        assert_eq!(pruned.pruned_events, 3); // 2 captures + 1 checkpoint event in ws A
        assert_eq!(
            journal.stats(&scope_b_s1, true).expect("ws B intact").raw_bytes,
            500_000
        );
    }

    #[test]
    fn concurrent_multi_connection_wal_event_appends_checkpoints_and_resumes() {
        let ws = TempDir::new().expect("tempdir");
        let scope = Arc::new(BoundScope::bind(ws.path(), Some("sess-wal-stress")).expect("bind"));

        // Initialize DB before spawning concurrent multi-connection workers.
        let init = SessionJournal::open_for_scope(&scope).expect("init open");
        drop(init);

        let workers = 6usize;
        let barrier = Arc::new(Barrier::new(workers));
        let mut handles = Vec::with_capacity(workers);

        for tid in 0..workers {
            let sc = Arc::clone(&scope);
            let bar = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let j = SessionJournal::open_for_scope(&sc).expect("worker open WAL");
                bar.wait();

                for step in 0..6usize {
                    let mut ev = JournalEventInput::new(JournalEventKind::CommandCaptured);
                    ev.command_summary = Some(format!("cargo test worker_{tid}_{step}"));
                    ev.exit_code = Some(0);
                    ev.raw_bytes = 4_000;
                    ev.view_bytes = 400;
                    j.record_event(&sc, ev).expect("concurrent append");

                    if step == 3 {
                        j.create_checkpoint(&sc, Some(&format!("cp-{tid}")))
                            .expect("concurrent checkpoint");
                    }

                    let pack = j.resume(&sc).expect("concurrent resume");
                    assert!(pack.stats.total_captures >= 1);
                }
            }));
        }

        for h in handles {
            h.join().expect("worker panicked");
        }

        let final_j = SessionJournal::open_for_scope(&scope).expect("final open");
        let health = final_j.health_check().expect("final health");
        assert!(health.healthy);
        assert_eq!(health.total_checkpoints, 6);
        // 6 workers * 6 captures + 6 checkpoint events = 42 total events
        assert_eq!(health.total_events, 42);
    }
}
