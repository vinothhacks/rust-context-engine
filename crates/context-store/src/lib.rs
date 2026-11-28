//! Content-addressed private `zstd` blob storage, scoped artifact manifests,
//! bounded byte/line range recovery, and TTL/quota retention for the Rust Context Engine.

pub mod manifest;
pub mod permissions;
pub mod store;

pub use context_core::{ArtifactId, ByteRange, LineRange};
pub use manifest::{
    compute_scope_binding_sha256, ArtifactStreamInput, PutArtifactRequest, StoredArtifactManifest,
    StoredStreamRef, MANIFEST_SCHEMA_VERSION,
};
pub use permissions::{
    apply_private_dir_permissions, apply_private_file_permissions, verify_directory_permissions,
    StorePermissionReport,
};
pub use store::{
    BlobStore, ByteSlicePage, IndexedLine, LineSlicePage, ProtectedBlobOutcome, PrunePolicy,
    PruneReport, StoreStats, StoredArtifactOutcome,
};

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;

    use context_core::{
        now_rfc3339_utc, sha256_hex, ArtifactSource, BoundScope, ReductionBudget, SecretGuard,
        SecretPolicy, SecretPolicyMode, StreamEncoding, StreamKind,
    };
    use proptest::prelude::*;
    use tempfile::TempDir;

    use super::*;

    fn sample_command_source() -> ArtifactSource {
        ArtifactSource::Command {
            argv: vec!["cargo".to_string(), "test".to_string()],
            cwd_relative: ".".to_string(),
            exit_code: Some(101),
            duration_ms: Some(420),
            timed_out: None,
            captured_at: now_rfc3339_utc(),
        }
    }

    #[test]
    fn initializes_private_store_permissions_and_round_trips_utf8_and_binary_streams() {
        let ws = TempDir::new().expect("ws");
        let scope = BoundScope::bind(ws.path(), Some("store-s1")).expect("bind");
        let store = BlobStore::open(&scope).expect("open store");

        // Verify private directory ACL / mode diagnostic
        let perm_report = store
            .verify_store_permissions()
            .expect("verify permissions");
        assert!(perm_report.exists);
        assert!(
            perm_report.private_only,
            "expected owner-only store permissions, got: {perm_report:?}"
        );

        let stdout_data = b"line 1: alpha\nline 2: beta\nline 3: gamma\nline 4: delta\n";
        let stderr_binary = &[
            0xff, 0xfe, 0x00, b'B', b'I', b'N', b'\n', b't', b'a', b'i', b'l',
        ];

        let stored = store
            .put_artifact_streams(
                &scope,
                PutArtifactRequest {
                    artifact_id: None,
                    source: sample_command_source(),
                    streams: vec![
                        ArtifactStreamInput::new(StreamKind::Stdout, stdout_data, false),
                        ArtifactStreamInput::new(StreamKind::Stderr, stderr_binary, false),
                    ],
                    capture_complete: true,
                    view: None,
                },
            )
            .expect("put_artifact_streams");

        let art_id = &stored.envelope.artifact_id;
        assert!(store.manifest_path_for_id(art_id).expect("path").exists());
        assert!(store
            .blob_path_for_sha256(&sha256_hex(stdout_data))
            .expect("blob path")
            .exists());

        // Byte-range pagination on UTF-8 stdout
        let page1 = store
            .get_bytes(
                &scope,
                art_id,
                StreamKind::Stdout,
                ByteRange::parse("0:14", 1_024).expect("range"),
            )
            .expect("get_bytes page1");
        assert_eq!(page1.bytes, b"line 1: alpha\n");
        assert_eq!(page1.total_bytes, stdout_data.len() as u64);
        assert_eq!(page1.total_lines, Some(4));
        assert!(page1.has_more);
        assert_eq!(page1.returned_range, ByteRange { start: 0, end: 14 });

        // Byte-range pagination on raw non-UTF-8 binary stderr
        let bin_page = store
            .get_bytes(
                &scope,
                art_id,
                StreamKind::Stderr,
                ByteRange::parse("0:64", 1_024).expect("range"),
            )
            .expect("get_bytes binary");
        assert_eq!(bin_page.bytes, stderr_binary);
        assert_eq!(bin_page.encoding, StreamEncoding::Binary);
        assert_eq!(bin_page.total_lines, None);
        assert!(!bin_page.has_more);

        // 1-indexed inclusive LineRange pagination on UTF-8 stdout
        let lines_p1 = store
            .get_lines(
                &scope,
                art_id,
                StreamKind::Stdout,
                LineRange::parse("2:3", 50).expect("line range"),
            )
            .expect("get_lines 2:3");
        assert_eq!(lines_p1.total_lines, 4);
        assert!(lines_p1.has_more);
        assert_eq!(
            lines_p1.returned_range,
            Some(LineRange {
                start_line: 2,
                end_line: 3
            })
        );
        assert_eq!(lines_p1.text, "line 2: beta\nline 3: gamma");
        assert_eq!(lines_p1.lines.len(), 2);
        assert_eq!(lines_p1.lines[0].line_number, 2);

        // Derived lossy UTF-8 LineRange on binary stderr
        let bin_lines = store
            .get_lines(
                &scope,
                art_id,
                StreamKind::Stderr,
                LineRange::parse("1:5", 50).expect("line range"),
            )
            .expect("get_lines lossy binary");
        assert_eq!(bin_lines.encoding, StreamEncoding::Utf8Lossy);
        assert_eq!(bin_lines.total_lines, 2);
        assert!(!bin_lines.has_more);
        assert!(bin_lines.text.contains("BIN"));
        assert!(bin_lines.text.contains("tail"));
    }

    #[test]
    fn detects_sha256_and_zstd_tampering_on_read() {
        let ws = TempDir::new().expect("ws");
        let scope = BoundScope::bind(ws.path(), Some("tamper-sess")).expect("bind");
        let store = BlobStore::open(&scope).expect("open");

        let payload = b"authentic compiler output\n";
        let out = store
            .put_artifact_streams(
                &scope,
                PutArtifactRequest {
                    artifact_id: None,
                    source: sample_command_source(),
                    streams: vec![ArtifactStreamInput::new(StreamKind::Stdout, payload, false)],
                    capture_complete: true,
                    view: None,
                },
            )
            .expect("persist");
        let art_id = &out.envelope.artifact_id;
        let blob_path = store
            .blob_path_for_sha256(&sha256_hex(payload))
            .expect("blob path");

        // 1. Replace `.zst` with valid zstd compression of DIFFERENT bytes -> INTEGRITY_MISMATCH
        let forged_zst = zstd::stream::encode_all(Cursor::new(b"tampered payload\n"), 3)
            .expect("encode forged zst");
        fs::write(&blob_path, forged_zst).expect("overwrite with forged zst");

        let err_mismatch = store
            .get_bytes(
                &scope,
                art_id,
                StreamKind::Stdout,
                ByteRange::parse("0:100", 1_024).expect("range"),
            )
            .expect_err("forged payload must fail SHA-256 verification");
        assert_eq!(err_mismatch.error_code(), "INTEGRITY_MISMATCH");

        // 2. Replace `.zst` with corrupt non-zstd garbage -> INTEGRITY_MISMATCH
        fs::write(&blob_path, b"not-a-valid-zstd-frame").expect("overwrite with garbage");
        let err_corrupt = store
            .get_lines(
                &scope,
                art_id,
                StreamKind::Stdout,
                LineRange::parse("1:10", 50).expect("range"),
            )
            .expect_err("corrupt zstd must fail integrity check");
        assert_eq!(err_corrupt.error_code(), "INTEGRITY_MISMATCH");
    }

    #[test]
    fn rejects_cross_workspace_and_cross_session_artifact_forgery() {
        let ws_a = TempDir::new().expect("ws_a");
        let ws_b = TempDir::new().expect("ws_b");

        let scope_a_s1 = BoundScope::bind(ws_a.path(), Some("sess-1")).expect("bind A s1");
        let scope_a_s2 = scope_a_s1.with_session("sess-2").expect("bind A s2");
        let scope_b_s1 = BoundScope::bind(ws_b.path(), Some("sess-1")).expect("bind B s1");

        let store_a = BlobStore::open(&scope_a_s1).expect("store A");
        let store_b = BlobStore::open(&scope_b_s1).expect("store B");

        let out = store_a
            .put_artifact_streams(
                &scope_a_s1,
                PutArtifactRequest {
                    artifact_id: None,
                    source: sample_command_source(),
                    streams: vec![ArtifactStreamInput::new(
                        StreamKind::Stdout,
                        b"secret workspace A evidence\n",
                        false,
                    )],
                    capture_complete: true,
                    view: None,
                },
            )
            .expect("persist in A");
        let art_a = &out.envelope.artifact_id;

        // 1. Cross-session access inside same workspace -> SESSION_MISMATCH
        let sess_err = store_a
            .get_bytes(
                &scope_a_s2,
                art_a,
                StreamKind::Stdout,
                ByteRange::parse("0:64", 1_024).expect("range"),
            )
            .expect_err("cross-session read must fail");
        assert_eq!(sess_err.error_code(), "SESSION_MISMATCH");
        assert!(sess_err.is_security_denial());

        // 2. Direct cross-workspace scope passed to Store A -> SCOPE_VIOLATION
        let ws_err = store_a
            .get_bytes(
                &scope_b_s1,
                art_a,
                StreamKind::Stdout,
                ByteRange::parse("0:64", 1_024).expect("range"),
            )
            .expect_err("wrong workspace scope must fail");
        assert_eq!(ws_err.error_code(), "SCOPE_VIOLATION");

        // 3. Transplanted manifest from Workspace A copied into Workspace B's store -> SCOPE_VIOLATION
        let src_manifest = store_a.manifest_path_for_id(art_a).expect("src manifest");
        let dst_manifest = store_b.manifest_path_for_id(art_a).expect("dst manifest");
        fs::copy(&src_manifest, &dst_manifest).expect("copy forged manifest");

        let transplanted_err = store_b
            .get_bytes(
                &scope_b_s1,
                art_a,
                StreamKind::Stdout,
                ByteRange::parse("0:64", 1_024).expect("range"),
            )
            .expect_err("transplanted manifest in workspace B must fail");
        assert_eq!(transplanted_err.error_code(), "SCOPE_VIOLATION");
    }

    #[test]
    fn enforces_secret_guard_redact_quarantine_and_deny_policies() {
        let secret_out = b"normal log\nGITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD\n";

        // 1. Default RedactBeforeIndex: persists redacted text, never raw secret
        let ws_redact = TempDir::new().expect("ws_redact");
        let scope_r = BoundScope::bind(ws_redact.path(), None).expect("bind");
        let store_r = BlobStore::open(&scope_r).expect("open");
        let stored_r = store_r
            .put_artifact_streams(
                &scope_r,
                PutArtifactRequest {
                    artifact_id: None,
                    source: sample_command_source(),
                    streams: vec![ArtifactStreamInput::new(
                        StreamKind::Stdout,
                        secret_out,
                        false,
                    )],
                    capture_complete: true,
                    view: None,
                },
            )
            .expect("persist redacted");
        assert_eq!(stored_r.envelope.capture.secrets_redacted, 1);
        let recovered_r = store_r
            .get_lines(
                &scope_r,
                &stored_r.envelope.artifact_id,
                StreamKind::Stdout,
                LineRange::parse("1:10", 50).expect("range"),
            )
            .expect("recover sanitized");
        assert!(!recovered_r.exact_raw_preserved);
        assert!(recovered_r.text.contains("[REDACTED:GITHUB_TOKEN]"));
        assert!(!recovered_r.text.contains("ghp_0123456789"));

        // 2. Quarantine mode: metadata stored, raw blob NOT stored, `get_bytes` denied
        let ws_q = TempDir::new().expect("ws_q");
        let scope_q = BoundScope::bind(ws_q.path(), None).expect("bind");
        let store_q = BlobStore::open_with_config(
            &scope_q,
            SecretGuard::new(SecretPolicy {
                mode: SecretPolicyMode::Quarantine,
                ..SecretPolicy::default()
            }),
            ReductionBudget::default(),
        )
        .expect("open q");
        let stored_q = store_q
            .put_artifact_streams(
                &scope_q,
                PutArtifactRequest {
                    artifact_id: None,
                    source: sample_command_source(),
                    streams: vec![ArtifactStreamInput::new(
                        StreamKind::Stdout,
                        secret_out,
                        false,
                    )],
                    capture_complete: true,
                    view: None,
                },
            )
            .expect("quarantine manifest");
        assert!(!stored_q.envelope.capture.originals_available);
        assert_eq!(store_q.stats().expect("stats").blob_count, 0);
        let q_err = store_q
            .get_bytes(
                &scope_q,
                &stored_q.envelope.artifact_id,
                StreamKind::Stdout,
                ByteRange::parse("0:64", 1_024).expect("range"),
            )
            .expect_err("quarantined stream must refuse recovery");
        assert_eq!(q_err.error_code(), "SECRET_QUARANTINED");

        // 3. Deny mode: secret in stderr aborts entire multi-stream write leaving 0 blobs & 0 manifests
        let ws_d = TempDir::new().expect("ws_d");
        let scope_d = BoundScope::bind(ws_d.path(), None).expect("bind");
        let store_d = BlobStore::open_with_config(
            &scope_d,
            SecretGuard::new(SecretPolicy {
                mode: SecretPolicyMode::Deny,
                ..SecretPolicy::default()
            }),
            ReductionBudget::default(),
        )
        .expect("open d");
        let deny_err = store_d
            .put_artifact_streams(
                &scope_d,
                PutArtifactRequest {
                    artifact_id: None,
                    source: sample_command_source(),
                    streams: vec![
                        ArtifactStreamInput::new(StreamKind::Stdout, b"clean stdout\n", false),
                        ArtifactStreamInput::new(StreamKind::Stderr, secret_out, false),
                    ],
                    capture_complete: true,
                    view: None,
                },
            )
            .expect_err("deny mode must abort");
        assert_eq!(deny_err.error_code(), "SECRET_POLICY_DENIED");
        let stats_d = store_d.stats().expect("stats");
        assert_eq!(stats_d.artifact_count, 0);
        assert_eq!(stats_d.blob_count, 0);
    }

    #[test]
    fn prune_enforces_ttl_expiry_lru_quota_and_shared_blob_refcounting() {
        let ws = TempDir::new().expect("ws");
        let scope = BoundScope::bind(ws.path(), Some("prune-sess")).expect("bind");
        let store = BlobStore::open(&scope).expect("open");

        let shared_payload = b"shared stdout content across runs\n";
        let unique_middle = vec![b'M'; 8_192];
        let unique_newest = vec![b'N'; 8_192];

        // Artifact 1 (shared blob)
        let a1 = store
            .put_artifact_streams(
                &scope,
                PutArtifactRequest {
                    artifact_id: None,
                    source: sample_command_source(),
                    streams: vec![ArtifactStreamInput::new(
                        StreamKind::Stdout,
                        shared_payload,
                        false,
                    )],
                    capture_complete: true,
                    view: None,
                },
            )
            .expect("a1")
            .envelope
            .artifact_id;

        std::thread::sleep(std::time::Duration::from_millis(5));

        // Artifact 2 (unique middle blob)
        let a2 = store
            .put_artifact_streams(
                &scope,
                PutArtifactRequest {
                    artifact_id: None,
                    source: sample_command_source(),
                    streams: vec![ArtifactStreamInput::new(
                        StreamKind::Stdout,
                        &unique_middle,
                        false,
                    )],
                    capture_complete: true,
                    view: None,
                },
            )
            .expect("a2")
            .envelope
            .artifact_id;

        std::thread::sleep(std::time::Duration::from_millis(5));

        // Artifact 3 (also references `shared_payload` + `unique_newest`)
        let a3 = store
            .put_artifact_streams(
                &scope,
                PutArtifactRequest {
                    artifact_id: None,
                    source: sample_command_source(),
                    streams: vec![
                        ArtifactStreamInput::new(StreamKind::Stdout, shared_payload, false),
                        ArtifactStreamInput::new(StreamKind::Stderr, &unique_newest, false),
                    ],
                    capture_complete: true,
                    view: None,
                },
            )
            .expect("a3")
            .envelope
            .artifact_id;

        // Touch `a1` via `get_bytes` so `a2` becomes the least-recently-used artifact!
        std::thread::sleep(std::time::Duration::from_millis(5));
        store
            .get_bytes(
                &scope,
                &a1,
                StreamKind::Stdout,
                ByteRange::parse("0:16", 1_024).expect("range"),
            )
            .expect("touch a1");

        let pre_stats = store.stats().expect("pre stats");
        assert_eq!(pre_stats.artifact_count, 3);
        assert_eq!(pre_stats.blob_count, 3); // shared + middle + newest

        // Evict one artifact by setting `max_store_bytes` slightly below current total.
        let quota_report = store
            .prune(PrunePolicy {
                ttl_secs: None,
                max_store_bytes: Some(pre_stats.total_store_bytes - 100),
                now_unix_ms: None,
            })
            .expect("quota prune");

        assert_eq!(quota_report.quota_evicted_artifacts, 1);
        assert_eq!(quota_report.evicted_artifact_ids, vec![a2.clone()]);
        assert_eq!(quota_report.remaining_artifacts, 2);
        // `a2`'s unique blob was removed, while `shared_payload` and `unique_newest` remain!
        assert_eq!(quota_report.removed_blobs, 1);
        assert!(quota_report.freed_bytes > 0);
        assert_eq!(
            store
                .get_manifest(&scope, &a2)
                .expect_err("a2 evicted")
                .error_code(),
            "ARTIFACT_NOT_FOUND"
        );

        // Advance simulated clock past TTL (+30 days) -> remaining artifacts & blobs purged cleanly
        let future_ms = store
            .get_manifest(&scope, &a3)
            .expect("a3 live")
            .created_at_unix_ms
            + 30 * 24 * 3_600 * 1_000;

        let ttl_report = store
            .prune(PrunePolicy {
                ttl_secs: Some(7 * 24 * 3_600),
                max_store_bytes: None,
                now_unix_ms: Some(future_ms),
            })
            .expect("ttl prune");
        assert_eq!(ttl_report.expired_artifacts, 2);
        assert_eq!(ttl_report.remaining_artifacts, 0);
        assert_eq!(ttl_report.remaining_blobs, 0);
        assert_eq!(ttl_report.remaining_bytes, 0);
    }

    #[test]
    fn enforces_megaline_byte_budget_combined_stream_view_update_and_manifest_binding() {
        let ws = TempDir::new().expect("ws");
        let scope = BoundScope::bind(ws.path(), Some("extra-sess")).expect("bind");
        let tight_budget = ReductionBudget {
            max_get_bytes: 32,
            max_view_bytes: 128,
            max_preview_bytes: 32,
            ..ReductionBudget::default()
        };
        let store = BlobStore::open_with_config(&scope, SecretGuard::default(), tight_budget)
            .expect("open");

        let megaline = "αβγ🦀".repeat(20); // > 32 UTF-8 bytes on a single line
        let out = store
            .put_artifact_streams(
                &scope,
                PutArtifactRequest {
                    artifact_id: None,
                    source: sample_command_source(),
                    streams: vec![
                        ArtifactStreamInput::new(StreamKind::Stdout, megaline.as_bytes(), false),
                        ArtifactStreamInput::new(StreamKind::Stderr, b"err\n", false),
                    ],
                    capture_complete: true,
                    view: None,
                },
            )
            .expect("persist");
        let art_id = &out.envelope.artifact_id;

        // Mega-line is safely truncated on a valid UTF-8 codepoint boundary <= 32 bytes
        let line_page = store
            .get_lines(
                &scope,
                art_id,
                StreamKind::Stdout,
                LineRange::parse("1:5", 50).expect("range"),
            )
            .expect("get_lines megaline");
        assert!(line_page.byte_budget_truncated);
        assert!(line_page.has_more);
        assert!(line_page.text.len() <= 32);

        // Combined stream merges stdout + stderr
        let comb_page = store
            .get_bytes(
                &scope,
                art_id,
                StreamKind::Combined,
                ByteRange::parse("0:32", 32).expect("range"),
            )
            .expect("combined bytes");
        assert_eq!(
            comb_page.total_bytes,
            (megaline.len() + 1 + b"err\n".len()) as u64
        );

        // `update_artifact_view` persists reduced view atomically
        let updated_env = store
            .update_artifact_view(
                &scope,
                art_id,
                context_core::ArtifactView {
                    kind: context_core::ViewKind::TestSummary,
                    reducer_version: "1".to_string(),
                    omitted: true,
                    safe_excerpt: "1 failed".to_string(),
                    transformations: vec!["cargo_test@1".to_string()],
                    reduction_error: None,
                    failure_identifiers: vec!["tests::it_works".to_string()],
                },
            )
            .expect("update_artifact_view");
        assert_eq!(updated_env.view.safe_excerpt, "1 failed");

        // Tampering with `scope_binding_sha256` inside manifest JSON is caught as INTEGRITY_MISMATCH
        let manifest_path = store.manifest_path_for_id(art_id).expect("manifest path");
        let raw_json = fs::read_to_string(&manifest_path).expect("read manifest");
        let tampered_json = raw_json.replace(
            &out.manifest.scope_binding_sha256,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        fs::write(&manifest_path, tampered_json).expect("write tampered manifest");

        let binding_err = store
            .get_manifest(&scope, art_id)
            .expect_err("tampered binding must fail");
        assert_eq!(binding_err.error_code(), "INTEGRITY_MISMATCH");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]
        #[test]
        fn prop_arbitrary_binary_and_utf8_byte_pagination_reconstructs_exact_payload(
            payload in proptest::collection::vec(any::<u8>(), 0..1500),
            page_size in 1usize..256usize,
        ) {
            let ws = TempDir::new().expect("ws");
            let scope = BoundScope::bind(ws.path(), None).expect("bind");
            // Disable entropy detection in this pure byte-recovery property test so arbitrary
            // random ASCII runs are stored verbatim rather than rewritten by SecretGuard.
            let guard = SecretGuard::new(SecretPolicy {
                enable_entropy_detection: false,
                ..SecretPolicy::default()
            });
            let store = BlobStore::open_with_config(&scope, guard, ReductionBudget::default())
                .expect("open");

            let out = store
                .put_artifact_streams(
                    &scope,
                    PutArtifactRequest {
                        artifact_id: None,
                        source: sample_command_source(),
                        streams: vec![ArtifactStreamInput::new(StreamKind::Stdout, &payload, false)],
                        capture_complete: true,
                        view: None,
                    },
                )
                .expect("persist");

            if out.manifest.streams[0].exact_raw_preserved {
                let art_id = &out.envelope.artifact_id;
                let mut reconstructed = Vec::with_capacity(payload.len());
                let mut cursor = 0u64;

                loop {
                    let req_range = ByteRange::new(
                        cursor,
                        cursor + page_size as u64,
                        store.budget().max_get_bytes,
                    )
                    .expect("valid range");
                    let page = store
                        .get_bytes(&scope, art_id, StreamKind::Stdout, req_range)
                        .expect("get_bytes");
                    reconstructed.extend_from_slice(&page.bytes);
                    cursor = page.returned_range.end;
                    if !page.has_more {
                        break;
                    }
                }

                prop_assert_eq!(reconstructed, payload);
            }
        }
    }
}
