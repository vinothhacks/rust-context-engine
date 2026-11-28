//! Scoped SQLite WAL + FTS5 (`porter unicode61`) lexical search index over sanitized chunks.
//!
//! ### Architecture & Storage Coexistence
//! - Opens `<workspace>/.context-engine/index.db` ([`BoundScope::index_db_path`]) by default with
//!   `journal_mode = WAL`, `synchronous = NORMAL`, `foreign_keys = ON`, `temp_store = MEMORY`,
//!   and `busy_timeout(5000)`.
//! - Uses namespaced `search_*` tables (`search_artifacts`, `search_chunks`, `search_chunks_fts`)
//!   and the component-keyed `schema_migrations (component, version)` table so `context-search`
//!   and `context-journal` can safely share `.context-engine/index.db`.
//! - Enforces [`context_core::SecretGuard`] unconditionally before chunking and FTS5 insertion so
//!   raw credentials never enter SQLite FTS5 even if a caller forgot to pre-sanitize.

pub mod chunker;
pub mod index;
pub mod schema;

pub use chunker::{chunk_sanitized_text, sanitize_fts5_query, ChunkConfig, TextChunk};
pub use context_core::{
    ArtifactId, BoundScope, RecoveryHandle, SessionId, StreamKind, WorkspaceScopeId,
};
pub use index::{
    IndexArtifactRequest, IndexStats, IndexStreamRequest, PruneReport, SearchConfig, SearchHit,
    SearchIndex, StreamInput,
};
pub use schema::{
    SearchHealthReport, DEFAULT_BUSY_TIMEOUT_MS, SEARCH_SCHEMA_COMPONENT, SEARCH_SCHEMA_VERSION,
};

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use context_core::{
        sha256_hex, ArtifactEnvelope, ArtifactSource, ArtifactView, CaptureSummary,
        ReductionBudget, SecretGuard, SecretPolicy, SecretPolicyMode, StreamEncoding, ViewKind,
        EMPTY_SHA256_HEX, RECOVERY_TOOL_CONTEXT_GET, TRANSFORM_CARGO_TEST_V1,
    };
    use proptest::prelude::*;
    use rusqlite::Connection;
    use tempfile::TempDir;

    use super::*;

    fn mint_test_artifact(scope: &BoundScope, seed: &[u8]) -> ArtifactId {
        ArtifactId::mint_from_seed(&scope.workspace_scope_id, &scope.session_id, seed)
    }

    #[test]
    fn sqlite_wal_pragmas_migrations_and_doctor_health_check() {
        let ws = TempDir::new().expect("tempdir");
        let scope = BoundScope::bind(ws.path(), Some("sess-wal")).expect("bind scope");
        let index = SearchIndex::open_for_scope(&scope).expect("open search index");

        assert_eq!(index.db_path(), Some(scope.index_db_path().as_path()));
        let health = index.health_check().expect("health check");
        assert!(health.healthy);
        assert_eq!(health.journal_mode.to_ascii_lowercase(), "wal");
        assert!(health.foreign_keys_enabled);
        assert_eq!(health.schema_version, SEARCH_SCHEMA_VERSION);
        assert!(health.quick_check_ok);
        assert!(health.fts_integrity_ok);
        assert_eq!(health.total_artifacts, 0);
        assert_eq!(health.total_chunks, 0);

        // Re-opening idempotently preserves schema_migrations without duplicate errors.
        let reopened = SearchIndex::open_for_scope(&scope).expect("reopen search index");
        let health2 = reopened.health_check().expect("reopened health check");
        assert!(health2.healthy);
        assert_eq!(health2.schema_version, SEARCH_SCHEMA_VERSION);

        // Verify shared `.context-engine/index.db` coexistence with `context-journal` migration rows.
        let raw_conn = Connection::open(scope.index_db_path()).expect("open raw db");
        raw_conn
            .execute(
                "INSERT INTO schema_migrations (component, version, description, applied_at)
                 VALUES ('context-journal', 1, 'coexistence check', '2026-11-22T00:00:00.000Z')",
                [],
            )
            .expect("insert sibling component migration");
        let reopened_after_sibling =
            SearchIndex::open_for_scope(&scope).expect("reopen alongside sibling component");
        assert!(
            reopened_after_sibling
                .health_check()
                .expect("health")
                .healthy
        );
    }

    #[test]
    fn bm25_ranking_porter_stemming_line_spans_and_recovery_handles() {
        let ws = TempDir::new().expect("tempdir");
        let scope = BoundScope::bind(ws.path(), Some("sess-bm25")).expect("bind scope");

        let cfg = SearchConfig {
            chunk_config: ChunkConfig {
                max_lines_per_chunk: 4,
                max_bytes_per_chunk: 512,
            },
            budget: ReductionBudget {
                max_search_snippet_bytes: 160,
                ..ReductionBudget::default()
            },
            secret_guard: SecretGuard::default(),
        };
        let index =
            SearchIndex::open_for_scope_with_config(&scope, cfg).expect("open custom index");

        let art_weak = mint_test_artifact(&scope, b"weak-match");
        let art_strong = mint_test_artifact(&scope, b"strong-match");

        // Weak match mentions "deadlock" once in stdout.
        index
            .index_stream(
                &scope,
                IndexStreamRequest {
                    artifact_id: &art_weak,
                    stream: StreamKind::Stdout,
                    source_label: "cargo test --lib",
                    text: "running 4 tests\nnote: potential deadlock check ok\ntest done\n",
                    originals_available: true,
                },
            )
            .expect("index weak");

        // Strong match has dense "deadlock" + Porter-stemmed "panicking"/"panicked" on lines 5..=8 of stderr.
        let stderr_lines = [
            "compiling worker pool",
            "starting lock graph monitor",
            "spawning 4 threads",
            "entering critical section",
            "ERROR: mutex deadlock detected in scheduler::lock_order",
            "thread 'worker-2' panicked due to deadlock cycle on resource_b",
            "deadlock diagnostic trace dumped for recovery",
            "note: run with RUST_BACKTRACE=1",
        ]
        .join("\n");

        index
            .index_artifact(
                &scope,
                IndexArtifactRequest {
                    artifact_id: art_strong.clone(),
                    source_label: "cargo test --test concurrency",
                    streams: vec![
                        StreamInput {
                            stream: StreamKind::Stdout,
                            text: "running 1 test\ntest concurrency::pool ... FAILED\n",
                        },
                        StreamInput {
                            stream: StreamKind::Stderr,
                            text: &stderr_lines,
                        },
                    ],
                    originals_available: true,
                    unavailable_reason: None,
                },
            )
            .expect("index strong");

        // Query "deadlock": strong chunk must outrank weak chunk via BM25.
        let hits = index
            .search(&scope, "deadlock", true, 10)
            .expect("search deadlock");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].rank, 1);
        assert_eq!(hits[0].artifact_id, art_strong);
        assert_eq!(hits[0].stream, StreamKind::Stderr);
        assert_eq!(hits[0].line_span(), 5..=8);
        assert_eq!(hits[0].line_range.start_line, 5);
        assert_eq!(hits[0].line_range.end_line, 8);
        assert_eq!(hits[0].recovery.tool, RECOVERY_TOOL_CONTEXT_GET);
        assert_eq!(hits[0].recovery.artifact_id, art_strong);
        assert!(hits[0].recovery.unavailable_reason.is_none());
        assert!(hits[0].snippet.len() <= 160);

        assert_eq!(hits[1].rank, 2);
        assert_eq!(hits[1].artifact_id, art_weak);
        assert!(
            hits[0].score > hits[1].score,
            "expected stronger BM25 hit ({}) > weaker hit ({})",
            hits[0].score,
            hits[1].score
        );

        // Verify Porter stemming (`porter unicode61`): querying "panicking" matches "panicked".
        let stemmed_hits = index
            .search(&scope, "panicking scheduler", true, 5)
            .expect("porter stemmed search");
        assert_eq!(stemmed_hits.len(), 1);
        assert_eq!(stemmed_hits[0].artifact_id, art_strong);
        assert_eq!(stemmed_hits[0].line_span(), 5..=8);
    }

    #[test]
    fn secret_in_unredacted_input_is_blocked_from_fts5_across_all_policy_modes() {
        let ws = TempDir::new().expect("tempdir");
        let scope = BoundScope::bind(ws.path(), Some("sess-secrets")).expect("bind scope");
        let index = SearchIndex::open_for_scope(&scope).expect("open index");

        let gh_pat = "ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD";
        let aws_ak = "AKIAIOSFODNN7EXAMPLE";
        let anthropic_sk = "sk-ant-api03-0123456789abcdefghijklmnopqrstuvwxyz";
        let pem_block = concat!(
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "MIIEpAIBAAKCAQEA9876543210fedcba9876543210fedcba\n",
            "-----END RSA PRIVATE KEY-----"
        );
        let pg_uri = "postgres://admin_user:MySup3rSecretDBPass!@db.prod.internal:5432/app";

        // Caller deliberately forgets to pre-sanitize BOTH source_label and stream text!
        let dirty_label = format!("python deploy.py --token={gh_pat}");
        let dirty_body = format!(
            "Step 1: connecting to {pg_uri}\n\
             Step 2: AWS key {aws_ak}\n\
             Step 3: LLM key {anthropic_sk}\n\
             Step 4: key material:\n{pem_block}\n\
             ERROR: deployment migration_v42 failed on checksum mismatch\n"
        );

        let art_id = mint_test_artifact(&scope, b"dirty-capture");
        let stats = index
            .index_stream(
                &scope,
                IndexStreamRequest {
                    artifact_id: &art_id,
                    stream: StreamKind::Stderr,
                    source_label: &dirty_label,
                    text: &dirty_body,
                    originals_available: true,
                },
            )
            .expect("default RedactBeforeIndex must sanitize and succeed");

        assert!(stats.secrets_redacted >= 5);

        // Non-sensitive error context remains searchable.
        let safe_hits = index
            .search(&scope, "migration_v42 checksum mismatch", true, 5)
            .expect("search non-sensitive error");
        assert_eq!(safe_hits.len(), 1);
        assert!(safe_hits[0].source_label.contains("[REDACTED:"));

        // Searching for ANY raw secret substring must return 0 hits.
        for secret_needle in [
            gh_pat,
            aws_ak,
            anthropic_sk,
            "MIIEpAIBAAKCAQEA9876543210fedcba9876543210fedcba",
            "MySup3rSecretDBPass",
        ] {
            let leaked = index
                .search(&scope, secret_needle, false, 20)
                .expect("search secret needle");
            assert!(
                leaked.is_empty(),
                "raw secret '{secret_needle}' must never match in FTS5!"
            );
        }

        // Inspect raw SQLite tables directly on disk to prove zero secret substrings entered SQLite.
        let raw_conn = Connection::open(scope.index_db_path()).expect("open raw sqlite");
        let dump: Vec<(String, String)> = raw_conn
            .prepare("SELECT source_label, sanitized_body FROM search_chunks_fts")
            .expect("prepare dump")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("query dump")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("collect dump");
        assert!(!dump.is_empty());

        for (lbl, body) in &dump {
            for secret_needle in [
                gh_pat,
                aws_ak,
                anthropic_sk,
                "MIIEpAIBAAKCAQEA9876543210fedcba9876543210fedcba",
                "MySup3rSecretDBPass",
            ] {
                assert!(!lbl.contains(secret_needle));
                assert!(!body.contains(secret_needle));
            }
        }

        // Verify SecretPolicyMode::Quarantine marks recovery unavailable.
        let quarantine_index = SearchIndex::open_in_memory_with_config(SearchConfig {
            secret_guard: SecretGuard::new(SecretPolicy {
                mode: SecretPolicyMode::Quarantine,
                ..SecretPolicy::default()
            }),
            ..SearchConfig::default()
        })
        .expect("open quarantine index");
        let q_art = mint_test_artifact(&scope, b"quarantine-art");
        let q_stats = quarantine_index
            .index_stream(
                &scope,
                IndexStreamRequest {
                    artifact_id: &q_art,
                    stream: StreamKind::Stdout,
                    source_label: "env check",
                    text: &dirty_body,
                    originals_available: true,
                },
            )
            .expect("quarantine index succeeds with redaction");
        assert!(!q_stats.originals_available);
        let q_hits = quarantine_index
            .search(&scope, "migration_v42", true, 5)
            .expect("search quarantined");
        assert_eq!(q_hits.len(), 1);
        assert!(q_hits[0].recovery.unavailable_reason.is_some());

        // Verify SecretPolicyMode::Deny fails closed before writing any row.
        let deny_index = SearchIndex::open_in_memory_with_config(SearchConfig {
            secret_guard: SecretGuard::new(SecretPolicy {
                mode: SecretPolicyMode::Deny,
                ..SecretPolicy::default()
            }),
            ..SearchConfig::default()
        })
        .expect("open deny index");
        let deny_art = mint_test_artifact(&scope, b"deny-art");
        let err = deny_index
            .index_stream(
                &scope,
                IndexStreamRequest {
                    artifact_id: &deny_art,
                    stream: StreamKind::Stdout,
                    source_label: "env dump",
                    text: &dirty_body,
                    originals_available: true,
                },
            )
            .expect_err("Deny mode must fail closed on secret input");
        assert_eq!(err.error_code(), "SECRET_POLICY_DENIED");
        assert_eq!(
            deny_index.health_check().expect("health").total_artifacts,
            0
        );
    }

    #[test]
    fn strict_cross_workspace_and_cross_session_isolation() {
        let ws_a_dir = TempDir::new().expect("ws A");
        let ws_b_dir = TempDir::new().expect("ws B");
        let shared_db_dir = TempDir::new().expect("shared db");
        let db_path = shared_db_dir.path().join("multi_scope_test.db");

        let scope_a_s1 = BoundScope::bind(ws_a_dir.path(), Some("sess-1")).expect("bind A s1");
        let scope_a_s2 = scope_a_s1.with_session("sess-2").expect("bind A s2");
        let scope_b_s1 = BoundScope::bind(ws_b_dir.path(), Some("sess-1")).expect("bind B s1");

        let index = SearchIndex::open(&db_path).expect("open shared test db");

        let art_a1 = mint_test_artifact(&scope_a_s1, b"a1");
        let art_a2 = mint_test_artifact(&scope_a_s2, b"a2");
        let art_b1 = mint_test_artifact(&scope_b_s1, b"b1");

        index
            .index_stream(
                &scope_a_s1,
                IndexStreamRequest {
                    artifact_id: &art_a1,
                    stream: StreamKind::Stdout,
                    source_label: "ws-a-s1",
                    text: "shared_keyword alpha_session_one_only",
                    originals_available: true,
                },
            )
            .expect("index a1");

        index
            .index_stream(
                &scope_a_s2,
                IndexStreamRequest {
                    artifact_id: &art_a2,
                    stream: StreamKind::Stdout,
                    source_label: "ws-a-s2",
                    text: "shared_keyword alpha_session_two_only",
                    originals_available: true,
                },
            )
            .expect("index a2");

        index
            .index_stream(
                &scope_b_s1,
                IndexStreamRequest {
                    artifact_id: &art_b1,
                    stream: StreamKind::Stdout,
                    source_label: "ws-b-s1",
                    text: "shared_keyword bravo_secret_project_token_marker",
                    originals_available: true,
                },
            )
            .expect("index b1");

        // 1. Session-scoped search in A/sess-1 sees ONLY art_a1.
        let hits_a_s1 = index
            .search(&scope_a_s1, "shared_keyword", true, 20)
            .expect("search A s1");
        assert_eq!(hits_a_s1.len(), 1);
        assert_eq!(hits_a_s1[0].artifact_id, art_a1);

        // 2. Workspace-wide search in A (`session_only = false`) sees art_a1 + art_a2, NEVER art_b1!
        let hits_a_all = index
            .search(&scope_a_s1, "shared_keyword", false, 20)
            .expect("search A all sessions");
        assert_eq!(hits_a_all.len(), 2);
        assert!(hits_a_all.iter().all(|h| h.artifact_id != art_b1));

        // 3. Direct search for workspace B's unique marker from workspace A returns 0 hits.
        let cross_leak = index
            .search(&scope_a_s1, "bravo_secret_project_token_marker", false, 20)
            .expect("cross ws query");
        assert!(cross_leak.is_empty());

        // 4. Attempting to delete workspace B's artifact from workspace A fails closed with SCOPE_VIOLATION.
        let del_err = index
            .remove_artifact(&scope_a_s1, &art_b1)
            .expect_err("cross-workspace delete must fail");
        assert_eq!(del_err.error_code(), "SCOPE_VIOLATION");

        // 5. Attempting to delete sess-2's artifact via `remove_artifact_in_session` from sess-1 fails with SESSION_MISMATCH.
        let sess_err = index
            .remove_artifact_in_session(&scope_a_s1, &art_a2)
            .expect_err("cross-session delete must fail");
        assert_eq!(sess_err.error_code(), "SESSION_MISMATCH");
    }

    #[test]
    fn hostile_fts5_and_sql_injection_queries_never_error_or_leak() {
        let ws_a = TempDir::new().expect("ws A");
        let ws_b = TempDir::new().expect("ws B");
        let db_dir = TempDir::new().expect("db dir");
        let index = SearchIndex::open(db_dir.path().join("hostile.db")).expect("open index");

        let scope_a = BoundScope::bind(ws_a.path(), Some("s1")).expect("bind A");
        let scope_b = BoundScope::bind(ws_b.path(), Some("s1")).expect("bind B");

        let art_a = mint_test_artifact(&scope_a, b"a");
        let art_b = mint_test_artifact(&scope_b, b"b");

        index
            .index_stream(
                &scope_a,
                IndexStreamRequest {
                    artifact_id: &art_a,
                    stream: StreamKind::Stderr,
                    source_label: "rustc",
                    text: "error[E0308]: mismatched types at crates/app/src/main.rs:42:9",
                    originals_available: true,
                },
            )
            .expect("index A");
        index
            .index_stream(
                &scope_b,
                IndexStreamRequest {
                    artifact_id: &art_b,
                    stream: StreamKind::Stderr,
                    source_label: "rustc",
                    text: "error[E0308]: other_workspace_confidential_symbol",
                    originals_available: true,
                },
            )
            .expect("index B");

        let hostile_queries = [
            "",
            "    \t\r\n  ",
            "\"\"\"''':::((()))***^^^---+++",
            "AND OR NOT NEAR",
            "NEAR(error, 5",
            "\"unbalanced quote error[E0308]",
            "sanitized_body:error OR workspace_scope_id:ws_*",
            "'); DROP TABLE search_chunks; --",
            "\" OR 1=1 --",
            "error[E0308]: mismatched types",
            "crates\\app\\src\\main.rs:42:9",
            "null\0byte\0error",
            "___",
            "🦀🔥✨ E0308 αβγ",
        ];

        for q in hostile_queries {
            let hits = index
                .search(&scope_a, q, false, 10)
                .unwrap_or_else(|e| panic!("hostile query {q:?} failed with error: {e}"));
            for hit in &hits {
                assert_eq!(hit.artifact_id, art_a);
            }
        }

        // Compiler diagnostic syntax must actually match art_a cleanly!
        let diag_hits = index
            .search(&scope_a, "error[E0308]: mismatched types", true, 5)
            .expect("diag search");
        assert_eq!(diag_hits.len(), 1);
        assert_eq!(diag_hits[0].artifact_id, art_a);

        assert!(
            index
                .health_check()
                .expect("health after hostile queries")
                .healthy
        );
    }

    #[test]
    fn artifact_deletion_pruning_and_envelope_helper_maintain_100_percent_fts_consistency() {
        let ws = TempDir::new().expect("ws");
        let scope = BoundScope::bind(ws.path(), Some("sess-prune")).expect("bind");
        let index = SearchIndex::open_for_scope(&scope).expect("open index");

        let art_keep = mint_test_artifact(&scope, b"keep");
        let art_del = mint_test_artifact(&scope, b"delete-me");
        let art_env = mint_test_artifact(&scope, b"envelope-item");

        // Index via ArtifactEnvelope helper.
        let envelope = ArtifactEnvelope::new_v1(
            &scope,
            art_env.clone(),
            ArtifactSource::Command {
                argv: vec!["cargo".into(), "test".into()],
                cwd_relative: ".".into(),
                exit_code: Some(101),
                duration_ms: Some(250),
                timed_out: None,
                captured_at: "2026-11-22T12:00:00.000Z".into(),
            },
            CaptureSummary {
                stdout_sha256: sha256_hex(b"stdout unique_envelope_token\n"),
                stderr_sha256: EMPTY_SHA256_HEX.into(),
                stdout_bytes: 29,
                stderr_bytes: 0,
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
                omitted: false,
                safe_excerpt: "1 failed".into(),
                transformations: vec![TRANSFORM_CARGO_TEST_V1.into()],
                reduction_error: None,
                failure_identifiers: vec!["tests::it_works".into()],
            },
            RecoveryHandle::for_artifact(art_env.clone(), Some(32_768)),
        );
        index
            .index_envelope_streams(
                &scope,
                &envelope,
                Some("stdout unique_envelope_token\n"),
                None,
            )
            .expect("index envelope");

        index
            .index_stream(
                &scope,
                IndexStreamRequest {
                    artifact_id: &art_keep,
                    stream: StreamKind::Stdout,
                    source_label: "keep",
                    text: "persistent_canary_token",
                    originals_available: true,
                },
            )
            .expect("index keep");

        index
            .index_stream(
                &scope,
                IndexStreamRequest {
                    artifact_id: &art_del,
                    stream: StreamKind::Stdout,
                    source_label: "ephemeral",
                    text: "ephemeral_vanishing_token\nline two\nline three",
                    originals_available: true,
                },
            )
            .expect("index del");

        assert_eq!(
            index
                .search(&scope, "ephemeral_vanishing_token", true, 5)
                .expect("before delete")
                .len(),
            1
        );

        // Remove `art_del` and verify FTS5 + relational parity.
        assert!(index
            .remove_artifact(&scope, &art_del)
            .expect("remove art_del"));
        assert!(!index
            .remove_artifact(&scope, &art_del)
            .expect("idempotent second remove"));
        assert!(index
            .search(&scope, "ephemeral_vanishing_token", false, 5)
            .expect("after delete")
            .is_empty());

        let health_mid = index.health_check().expect("health after remove");
        assert!(health_mid.healthy);
        assert!(health_mid.fts_integrity_ok);
        assert_eq!(health_mid.total_artifacts, 2);

        // Prune everything up to far-future timestamp and verify 0 orphan chunks or FTS entries remain.
        let prune_report = index
            .prune_before_unix_ms(&scope, i64::MAX)
            .expect("prune all");
        assert_eq!(prune_report.pruned_artifacts.len(), 2);
        assert!(prune_report.pruned_chunks >= 2);
        assert!(prune_report.reclaimed_sanitized_bytes > 0);

        let health_end = index.health_check().expect("health after prune");
        assert!(health_end.healthy);
        assert!(health_end.fts_integrity_ok);
        assert_eq!(health_end.total_artifacts, 0);
        assert_eq!(health_end.total_chunks, 0);
    }

    #[test]
    fn concurrent_multi_connection_wal_reads_and_writes() {
        let ws = TempDir::new().expect("tempdir");
        let scope = Arc::new(BoundScope::bind(ws.path(), Some("sess-concurrent")).expect("bind"));

        // Pre-create WAL database so all threads hammer concurrent reads & writes simultaneously.
        let seed_idx = SearchIndex::open_for_scope(&scope).expect("seed open");
        let seed_art = mint_test_artifact(&scope, b"seed");
        seed_idx
            .index_stream(
                &scope,
                IndexStreamRequest {
                    artifact_id: &seed_art,
                    stream: StreamKind::Stdout,
                    source_label: "seed",
                    text: "concurrent_shared_token baseline",
                    originals_available: true,
                },
            )
            .expect("seed index");
        drop(seed_idx);

        let worker_count = 6usize;
        let barrier = Arc::new(Barrier::new(worker_count));
        let mut handles = Vec::with_capacity(worker_count);

        for tid in 0..worker_count {
            let scope_cl = Arc::clone(&scope);
            let bar_cl = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let conn_idx = SearchIndex::open_for_scope(&scope_cl).expect("worker open WAL");
                bar_cl.wait();

                for iter in 0..8usize {
                    let seed_bytes = format!("worker-{tid}-iter-{iter}");
                    let art = mint_test_artifact(&scope_cl, seed_bytes.as_bytes());
                    let body = format!(
                        "concurrent_shared_token worker_{tid} iteration_{iter}\nassertion ok"
                    );
                    conn_idx
                        .index_stream(
                            &scope_cl,
                            IndexStreamRequest {
                                artifact_id: &art,
                                stream: StreamKind::Stdout,
                                source_label: "worker",
                                text: &body,
                                originals_available: true,
                            },
                        )
                        .expect("concurrent WAL write");

                    let hits = conn_idx
                        .search(&scope_cl, "concurrent_shared_token", true, 15)
                        .expect("concurrent WAL read");
                    assert!(!hits.is_empty());
                }
            }));
        }

        for h in handles {
            h.join().expect("worker thread panicked");
        }

        let final_idx = SearchIndex::open_for_scope(&scope).expect("final open");
        let health = final_idx.health_check().expect("final health");
        assert!(health.healthy);
        assert!(health.fts_integrity_ok);
        // 1 seed + (6 workers * 8 iterations) = 49 artifacts
        assert_eq!(health.total_artifacts, 49);
    }

    proptest! {
        #[test]
        fn prop_arbitrary_queries_and_oversized_lines_never_fail(
            arbitrary_query in ".*",
            long_segment in "[a-zA-Z0-9_ ]{1,300}",
        ) {
            let ws = TempDir::new().expect("tempdir");
            let scope = BoundScope::bind(ws.path(), Some("prop-sess")).expect("bind");
            let index = SearchIndex::open_in_memory().expect("in memory index");
            let art = mint_test_artifact(&scope, b"prop-art");

            let repeated = long_segment.repeat(20);
            index.index_stream(
                &scope,
                IndexStreamRequest {
                    artifact_id: &art,
                    stream: StreamKind::Stdout,
                    source_label: "proptest",
                    text: &repeated,
                    originals_available: true,
                },
            ).expect("index repeated");

            let hits = index.search(&scope, &arbitrary_query, true, 10).expect("prop search never fails");
            for hit in hits {
                prop_assert!(hit.snippet.len() <= ReductionBudget::default().max_search_snippet_bytes);
                prop_assert_eq!(hit.artifact_id, art.clone());
            }
        }
    }
}
