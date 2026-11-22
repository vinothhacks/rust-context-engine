//! Core contracts, server-bound identities, budgets, policies, and `SecretGuard`
//! for the self-hosted Rust Context Engine.

pub mod budget;
pub mod envelope;
pub mod error;
pub mod ledger;
pub mod policy;
pub mod scope;
pub mod secrets;

pub use budget::{
    estimate_tokens_from_bytes, estimate_tokens_from_str, truncate_str_utf8_boundary,
    ReductionBudget,
};
pub use envelope::{
    ArtifactEnvelope, ArtifactSource, ArtifactView, ByteRange, CaptureSummary, LineRange,
    RecoveryHandle, StreamEncoding, StreamKind, ViewKind, ARTIFACT_SCHEMA_VERSION,
    RECOVERY_TOOL_CONTEXT_GET,
};
pub use error::{ContextError, Result};
pub use ledger::{
    TransformationLedger, LEDGER_HEADER_PREFIX, TRANSFORM_CARGO_TEST_V1,
    TRANSFORM_COMPILER_DIAG_V1, TRANSFORM_GIT_REDUCER_V1, TRANSFORM_LOG_DEDUP_V1,
    TRANSFORM_PYTEST_JEST_V1, TRANSFORM_SEARCH_HITS_V1, TRANSFORM_SECRET_REDACT_V1,
    TRANSFORM_STRIP_ANSI_V1, TRANSFORM_STRUCTURED_JSON_V1, TRANSFORM_UNKNOWN_SAFE_V1,
};
pub use policy::ExecutionPolicyConfig;
pub use scope::{
    now_rfc3339_utc, sha256_hex, ArtifactId, BoundScope, SessionId, WorkspaceScopeId,
    DEFAULT_SESSION_ID, EMPTY_SHA256_HEX,
};
pub use secrets::{
    shannon_entropy_bits, SecretFinding, SecretGuard, SecretPolicy, SecretPolicyMode,
    SecretRuleKind, SecretScanReport, StreamProtectionOutcome,
};

#[cfg(test)]
mod tests {
    use std::path::Path;

    use proptest::prelude::*;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn workspace_scope_binding_and_cross_scope_isolation() {
        let ws_a = TempDir::new().expect("tempdir A");
        let ws_b = TempDir::new().expect("tempdir B");

        let scope_a1 = BoundScope::bind(ws_a.path(), Some("sess_alpha")).expect("bind A1");
        let scope_a2 = BoundScope::bind(ws_a.path(), Some("sess_alpha")).expect("bind A2");
        let scope_b = BoundScope::bind(ws_b.path(), Some("sess_alpha")).expect("bind B");

        assert_eq!(scope_a1.workspace_scope_id, scope_a2.workspace_scope_id);
        assert_ne!(scope_a1.workspace_scope_id, scope_b.workspace_scope_id);
        assert!(scope_a1.workspace_scope_id.as_str().starts_with("ws_"));
        assert_eq!(scope_a1.workspace_scope_id.as_str().len(), 35);

        // Windows drive-letter case normalization determinism check
        let lower_drive = WorkspaceScopeId::from_canonical_path_str(r"d:\research 1\proj\");
        let upper_drive = WorkspaceScopeId::from_canonical_path_str(r"D:\research 1\proj");
        assert_eq!(lower_drive, upper_drive);

        // Forged client project_scope must fail closed
        let forged_err = scope_a1
            .resolve_request_scope(Some(scope_b.workspace_scope_id.as_str()), None)
            .expect_err("forged workspace scope must fail");
        assert_eq!(forged_err.error_code(), "SCOPE_VIOLATION");
        assert!(forged_err.is_security_denial());

        // Minting and verifying ArtifactId binding
        let art_a = ArtifactId::mint(
            &scope_a1,
            "2026-11-22T12:00:00.000Z",
            1,
            EMPTY_SHA256_HEX,
            Some(EMPTY_SHA256_HEX),
        );
        assert!(art_a.as_str().starts_with("a_"));
        assert_eq!(art_a.hex_digest().len(), 64);
        assert_eq!(ArtifactId::parse(art_a.as_str()).expect("valid id"), art_a);

        // Valid within same workspace + session
        art_a
            .verify_binding(&scope_a1.workspace_scope_id, &scope_a1.session_id, &scope_a2)
            .expect("matching scope allowed");

        // Denied across workspaces
        let cross_ws = art_a
            .verify_binding(&scope_a1.workspace_scope_id, &scope_a1.session_id, &scope_b)
            .expect_err("cross workspace denied");
        assert_eq!(cross_ws.error_code(), "SCOPE_VIOLATION");

        // Denied across sessions
        let scope_a_other_sess = scope_a1.with_session("sess_beta").expect("other session");
        let cross_sess = art_a
            .verify_binding(
                &scope_a1.workspace_scope_id,
                &scope_a1.session_id,
                &scope_a_other_sess,
            )
            .expect_err("cross session denied");
        assert_eq!(cross_sess.error_code(), "SESSION_MISMATCH");
    }

    #[test]
    fn invalid_session_and_artifact_ids_rejected() {
        for bad_session in ["", ".", "..", "-flag", "bad/slash", "bad\\slash", "bad space"] {
            assert!(
                SessionId::parse(bad_session).is_err(),
                "expected session '{bad_session}' to be rejected"
            );
        }

        for bad_artifact in [
            "",
            "123",
            "a_short",
            "a_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "a_0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
            "../a_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            assert!(
                ArtifactId::parse(bad_artifact).is_err(),
                "expected artifact '{bad_artifact}' to be rejected"
            );
        }
    }

    #[test]
    fn artifact_envelope_v1_schema_round_trip_and_ledger_detection() {
        let tmp = TempDir::new().expect("tempdir");
        let scope = BoundScope::bind(tmp.path(), Some("ci-run-1")).expect("bind");
        let stdout_hash = sha256_hex(b"test result: FAILED. 1 passed; 2 failed\n");
        let stderr_hash = sha256_hex(b"error: test failed\n");
        let artifact_id = ArtifactId::mint(
            &scope,
            "2026-11-22T12:00:00.000Z",
            42,
            &stdout_hash,
            Some(&stderr_hash),
        );

        let mut ledger = TransformationLedger::new();
        assert!(ledger.record(TRANSFORM_STRIP_ANSI_V1));
        assert!(!ledger.has_domain_reducer());
        assert!(ledger.record_domain_reducer(TRANSFORM_CARGO_TEST_V1));
        assert!(ledger.has_domain_reducer());
        // Single-pass invariant: second domain reducer must be rejected
        assert!(!ledger.record_domain_reducer(TRANSFORM_LOG_DEDUP_V1));

        let envelope = ArtifactEnvelope::new_v1(
            &scope,
            artifact_id.clone(),
            ArtifactSource::Command {
                argv: vec!["cargo".to_string(), "test".to_string()],
                cwd_relative: ".".to_string(),
                exit_code: Some(101),
                duration_ms: Some(1_250),
                timed_out: None,
                captured_at: "2026-11-22T12:00:00.000Z".to_string(),
            },
            CaptureSummary {
                stdout_sha256: stdout_hash,
                stderr_sha256: stderr_hash,
                stdout_bytes: 123_456,
                stderr_bytes: 32_768,
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
                reducer_version: "1".to_string(),
                omitted: true,
                safe_excerpt: "2 tests failed".to_string(),
                transformations: ledger.into_vec(),
                reduction_error: None,
                failure_identifiers: vec!["tests::auth_fails".to_string()],
            },
            RecoveryHandle::for_artifact(artifact_id.clone(), Some(32_768)),
        );

        envelope.validate(&scope).expect("valid envelope");
        assert_eq!(envelope.total_raw_bytes(), 156_224);
        assert!(envelope.estimated_raw_tokens() > envelope.estimated_view_tokens());

        let json = serde_json::to_string_pretty(&envelope).expect("serialize");
        assert!(json.contains("\"schema_version\": 1"));
        assert!(json.contains("\"kind\": \"command\""));
        assert!(json.contains("\"kind\": \"test_summary\""));
        assert!(json.contains("\"tool\": \"context_get\""));
        assert!(TransformationLedger::is_already_reduced_payload(&json));

        let banner =
            TransformationLedger::format_banner(&artifact_id, &envelope.view.transformations);
        assert!(TransformationLedger::is_already_reduced_payload(&banner));
        assert!(!TransformationLedger::is_already_reduced_payload(
            "running 12 tests\ntest foo ... ok\n"
        ));

        let decoded: ArtifactEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn stream_encoding_and_range_validation() {
        assert_eq!(StreamEncoding::detect(b"hello rust\n"), StreamEncoding::Utf8);
        assert_eq!(
            StreamEncoding::detect(b"hello\0world"),
            StreamEncoding::Binary
        );
        assert_eq!(
            StreamEncoding::detect(&[0xff, 0xfe, 0xfd]),
            StreamEncoding::Binary
        );

        let br = ByteRange::parse("100:500", 1_024).expect("valid byte range");
        assert_eq!(br.len(), 400);
        assert!(ByteRange::parse("500:100", 1_024).is_err());
        assert_eq!(
            ByteRange::parse("0:2048", 1_024)
                .expect_err("exceeds budget")
                .error_code(),
            "BUDGET_EXCEEDED"
        );

        let lr = LineRange::parse("10:70", 200).expect("valid line range");
        assert_eq!(lr.line_count(), 61);
        assert!(LineRange::parse("0:10", 200).is_err());
        assert!(LineRange::parse("20:10", 200).is_err());
        assert_eq!(
            LineRange::parse("1:250", 200)
                .expect_err("exceeds max lines")
                .error_code(),
            "BUDGET_EXCEEDED"
        );
    }

    #[test]
    fn budget_utf8_safe_truncation_handles_multibyte_boundaries() {
        let budget = ReductionBudget::default();
        budget.validate().expect("default budget valid");

        let text = "αβγ🦀δεζ";
        for limit in 0..=text.len() + 2 {
            let (slice, truncated) = budget.truncate_utf8_safe(text, limit);
            assert!(slice.len() <= limit);
            assert_eq!(truncated, slice.len() < text.len());
        }
    }

    #[test]
    fn execution_policy_enforces_allowlist_denylist_paths_and_env_scrubbing() {
        let policy = ExecutionPolicyConfig::default();

        // Allowed dev commands
        assert_eq!(
            policy
                .validate_argv(&["cargo".into(), "test".into(), "--workspace".into()])
                .expect("cargo allowed"),
            "cargo"
        );
        assert_eq!(
            policy
                .validate_argv(&["git.exe".into(), "status".into()])
                .expect("git.exe allowed"),
            "git"
        );

        // Shell interpreters and destructive commands denied
        for blocked_argv in [
            vec!["cmd", "/c", "dir"],
            vec!["powershell.exe", "-Command", "Get-ChildItem"],
            vec!["pwsh", "-c", "ls"],
            vec!["bash", "-c", "echo hi"],
            vec!["rm", "-rf", "target"],
            vec!["Remove-Item", "-Recurse", "-Force", "target"],
            vec!["git", "reset", "--hard", "HEAD~1"],
            vec!["git", "clean", "-fdx"],
            vec!["git", "push", "--force", "origin", "main"],
            vec!["git", "checkout", "--", "."],
            vec!["curl", "https://example.com"],
            vec!["..\\cargo.exe", "test"],
            vec!["./bin/cargo", "test"],
        ] {
            let argv: Vec<String> = blocked_argv.into_iter().map(str::to_string).collect();
            let err = policy
                .validate_argv(&argv)
                .expect_err("expected command to be blocked");
            assert_eq!(err.error_code(), "EXECUTION_DENIED", "argv={argv:?}");
        }

        // Sensitive path denylist
        for blocked_path in [
            ".env",
            ".env.production",
            "config/.env.local",
            "certs/server.pem",
            "secrets/tls.key",
            "certs/client.pfx",
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            ".aws/credentials",
            ".git/credentials",
        ] {
            assert!(
                policy.ensure_non_sensitive_path(Path::new(blocked_path)).is_err(),
                "expected '{blocked_path}' to be blocked"
            );
        }

        // Permitted workspace paths (including public SSH key `.pub` and normal source files)
        for safe_path in ["src/main.rs", "Cargo.toml", "docs/id_ed25519.pub", ".gitignore"] {
            policy
                .ensure_non_sensitive_path(Path::new(safe_path))
                .expect("safe path permitted");
        }

        // Environment variable scrubbing
        let raw_env = vec![
            ("PATH", "/usr/bin"),
            ("SYSTEMROOT", "C:\\Windows"),
            ("CARGO_HOME", "C:\\Users\\dev\\.cargo"),
            ("OPENAI_API_KEY", "sk-secret"),
            ("ANTHROPIC_API_KEY", "sk-ant-secret"),
            ("AWS_SECRET_ACCESS_KEY", "aws-secret"),
            ("GITHUB_TOKEN", "ghp_secret"),
            ("DATABASE_URL", "postgres://u:p@localhost/db"),
        ];
        let scrubbed = policy.filter_safe_env(raw_env);
        let keys: Vec<&str> = scrubbed.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["PATH", "SYSTEMROOT", "CARGO_HOME"]);
    }

    #[test]
    fn secret_guard_detects_all_credential_families_without_leaking_values() {
        let guard = SecretGuard::default();

        // Construct synthetic test fixtures dynamically so even static repo scanners see test shapes clearly.
        let pem = concat!(
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "MIIEpAIBAAKCAQEA0123456789abcdef0123456789abcdef\n",
            "-----END RSA PRIVATE KEY-----"
        );
        let aws_ak = "AKIAIOSFODNN7EXAMPLE";
        let aws_sk_line = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let gcp_key = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe";
        let gcp_oauth = "ya29.a0AfH6SMBx9q8w7e6r5t4y3u2i1o0pLkJhGfDsA";
        let gh_pat = "ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD";
        let gh_fine = "github_pat_11ABCDEFG0123456789abcdef_0123456789abcdefghijklmnop";
        let gl_pat = "glpat-0123456789abcdefghij_XYZ";
        let openai_key = "sk-proj-0123456789abcdefghijklmnopqrstuvwxyzABCD";
        let anthropic_key = "sk-ant-api03-0123456789abcdefghijklmnopqrstuvwxyz";
        let slack_tok = format!("{}{}", "xoxb-", "123456789012-1234567890123-abcdefghijklmnopqrstuvwx");
        let slack_hook = format!(
            "https://{}/services/{}/{}/{}",
            "hooks.slack.com",
            "T01234567",
            "B01234567",
            "aBcDeFgHiJkLmNoPqRsTuVwX",
        );
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let bearer = "Authorization: Bearer mySuperSecretOpaqueBearerToken987654";
        let conn_uri = "postgres://dbadmin:Sup3rS3cr3t!@db.internal.local:5432/prod";
        let dotenv_line = "WEBHOOK_SIGNING_SECRET=\"whsec_custom_value_998877\"";
        let high_entropy = "K9mPq2xZv8nL4wRt7yHj5bCf3gDs1aUe+W2z";

        let combined = [
            pem,
            aws_ak,
            aws_sk_line,
            gcp_key,
            gcp_oauth,
            gh_pat,
            gh_fine,
            gl_pat,
            openai_key,
            anthropic_key,
            &slack_tok,
            &slack_hook,
            jwt,
            bearer,
            conn_uri,
            dotenv_line,
            high_entropy,
        ]
        .join("\n");

        let report = guard.scan_str(&combined);
        assert!(report.has_secrets());
        assert_eq!(report.redacted_count(), 17);

        // Verify zero raw secrets remain in sanitized output
        for raw_secret in [
            "MIIEpAIBAAKCAQEA0123456789abcdef0123456789abcdef",
            aws_ak,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            gcp_key,
            gcp_oauth,
            gh_pat,
            gh_fine,
            gl_pat,
            openai_key,
            anthropic_key,
            &slack_tok,
            &slack_hook,
            jwt,
            "mySuperSecretOpaqueBearerToken987654",
            "dbadmin:Sup3rS3cr3t!",
            "whsec_custom_value_998877",
            high_entropy,
        ] {
            assert!(
                !report.sanitized_text.contains(raw_secret),
                "leaked secret in sanitized_text: {raw_secret}"
            );
        }

        // Verify URI host/scheme and .env variable key are preserved for debugging context
        assert!(report
            .sanitized_text
            .contains("postgres://[REDACTED:CONNECTION_URI]@db.internal.local:5432/prod"));
        assert!(report
            .sanitized_text
            .contains("WEBHOOK_SIGNING_SECRET=\"[REDACTED:ENV_SECRET]\""));

        // Verify serialized findings never include raw secret substrings
        let findings_json = serde_json::to_string(&report.findings).expect("serialize findings");
        assert!(!findings_json.contains(gh_pat));
        assert!(!findings_json.contains("Sup3rS3cr3t!"));

        // Idempotency: scanning already-redacted text produces 0 new findings and identical text
        let second_pass = guard.scan_str(&report.sanitized_text);
        assert!(!second_pass.has_secrets());
        assert_eq!(second_pass.sanitized_text, report.sanitized_text);
    }

    #[test]
    fn secret_guard_preserves_shas_artifact_ids_uuids_and_token_telemetry() {
        let guard = SecretGuard::default();
        let clean_dev_output = concat!(
            "commit 8f3c2a1b9e4d7c6f5a0b1c2d3e4f5a6b7c8d9e0f\n",
            "stdout_sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
            "artifact_id: a_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            "workspace: ws_0123456789abcdef0123456789abcdef\n",
            "trace_id: 550e8400-e29b-41d4-a716-446655440000\n",
            "telemetry: max_tokens=4096 input_tokens=1280 output_tokens=312 secrets_redacted=0\n",
            "at crates/context-reducers/src/cargo_test.rs:142:9\n",
        );

        let report = guard.scan_str(clean_dev_output);
        assert!(
            !report.has_secrets(),
            "unexpected false positive findings: {:?}",
            report.findings
        );
        assert_eq!(report.sanitized_text, clean_dev_output);
    }

    #[test]
    fn secret_policy_modes_enforce_redact_quarantine_and_deny_on_bytes() {
        let secret_payload = b"log line before\nGITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD\n";

        // 1. Default RedactBeforeIndex
        let redact_guard = SecretGuard::new(SecretPolicy {
            mode: SecretPolicyMode::RedactBeforeIndex,
            ..SecretPolicy::default()
        });
        let out_redact = redact_guard
            .protect_bytes(secret_payload)
            .expect("redact succeeds");
        assert!(!out_redact.exact_raw_preserved);
        assert!(out_redact.originals_available);
        assert!(!out_redact.quarantined);
        assert!(out_redact
            .sanitized_index_text
            .as_deref()
            .expect("utf8 text")
            .contains("[REDACTED:GITHUB_TOKEN]"));
        assert!(!String::from_utf8_lossy(&out_redact.persistence_bytes).contains("ghp_"));

        // 2. Quarantine mode
        let quarantine_guard = SecretGuard::new(SecretPolicy {
            mode: SecretPolicyMode::Quarantine,
            ..SecretPolicy::default()
        });
        let out_quarantine = quarantine_guard
            .protect_bytes(secret_payload)
            .expect("quarantine succeeds");
        assert!(out_quarantine.quarantined);
        assert!(!out_quarantine.originals_available);
        assert!(out_quarantine.persistence_bytes.is_empty());

        // 3. Deny mode
        let deny_guard = SecretGuard::new(SecretPolicy {
            mode: SecretPolicyMode::Deny,
            ..SecretPolicy::default()
        });
        let err = deny_guard
            .protect_bytes(secret_payload)
            .expect_err("deny mode must fail closed");
        assert_eq!(err.error_code(), "SECRET_POLICY_DENIED");
        assert!(err.is_security_denial());

        // 4. Clean binary stream passes untouched
        let clean_bin = &[0x00, 0x89, b'P', b'N', b'G', 0xff, 0xfe];
        let out_bin = deny_guard
            .protect_bytes(clean_bin)
            .expect("clean binary allowed");
        assert!(out_bin.exact_raw_preserved);
        assert!(out_bin.originals_available);
        assert!(out_bin.sanitized_index_text.is_none());
        assert_eq!(out_bin.persistence_bytes, clean_bin);
    }

    #[test]
    fn secret_guard_handles_openssh_pem_truncated_pem_redis_and_mongodb_uris() {
        let guard = SecretGuard::default();

        let openssh = concat!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n",
            "-----END OPENSSH PRIVATE KEY-----"
        );
        let r1 = guard.scan_str(openssh);
        assert_eq!(r1.distinct_rule_ids(), vec!["PEM_PRIVATE_KEY"]);
        assert!(!r1.sanitized_text.contains("b3BlbnNzaC1rZXktdjE"));

        let truncated_pem = "panic: leaked header -----BEGIN EC PRIVATE KEY----- MIIk99";
        let r2 = guard.scan_str(truncated_pem);
        assert_eq!(r2.distinct_rule_ids(), vec!["PEM_PRIVATE_KEY"]);
        assert!(!r2.sanitized_text.contains("MIIk99"));

        let uris = concat!(
            "redis://:myRedisPass99@127.0.0.1:6379/0\n",
            "mongodb+srv://svc_user:m0ng0S3cr3t@cluster0.example.mongodb.net/prod\n",
            "Authorization: Basic dXNlcjpzZWNyZXRwYXNzd29yZA==\n",
        );
        let r3 = guard.scan_str(uris);
        assert_eq!(r3.redacted_count(), 3);
        assert!(r3
            .sanitized_text
            .contains("redis://[REDACTED:CONNECTION_URI]@127.0.0.1:6379/0"));
        assert!(r3
            .sanitized_text
            .contains("mongodb+srv://[REDACTED:CONNECTION_URI]@cluster0.example.mongodb.net/prod"));
        assert!(r3
            .sanitized_text
            .contains("Authorization: Basic [REDACTED:AUTH_HEADER]"));
    }

    #[test]
    fn secret_guard_protects_mixed_binary_stream_containing_embedded_secret() {
        let mut mixed = vec![0xff, 0xfe, 0x00, b'k', b'e', b'y', b'='];
        mixed.extend_from_slice(b"sk-ant-api03-0123456789abcdefghijklmnopqrstuvwxyz\n");

        let guard = SecretGuard::default();
        let outcome = guard.protect_bytes(&mixed).expect("redact mixed binary");
        assert!(!outcome.exact_raw_preserved);
        assert!(!outcome.originals_available);
        assert_eq!(outcome.distinct_rule_ids(), vec!["ANTHROPIC_API_KEY"]);
        assert!(!String::from_utf8_lossy(&outcome.persistence_bytes).contains("sk-ant-api03"));
    }

    #[test]
    fn document_envelope_and_unavailable_recovery_validation() {
        let tmp = TempDir::new().expect("tempdir");
        let scope = BoundScope::bind(tmp.path(), None).expect("default session bind");
        assert_eq!(scope.session_id.as_str(), DEFAULT_SESSION_ID);
        assert!(scope.store_dir().ends_with(Path::new(".context-engine").join("store")));
        assert!(scope
            .index_db_path()
            .ends_with(Path::new(".context-engine").join("index.db")));

        let artifact_id = ArtifactId::mint_from_seed(
            &scope.workspace_scope_id,
            &scope.session_id,
            b"README.md:v1",
        );
        let doc_bytes = b"# Architecture Overview\nClean room Rust engine.\n";
        let capture = CaptureSummary::for_document(
            sha256_hex(doc_bytes),
            doc_bytes.len() as u64,
            true,
            StreamEncoding::Utf8,
            false,
        );
        let envelope = ArtifactEnvelope::new_v1(
            &scope,
            artifact_id.clone(),
            ArtifactSource::Document {
                path_relative: Some("README.md".to_string()),
                label: Some("readme".to_string()),
                media_type: Some("text/markdown".to_string()),
                captured_at: now_rfc3339_utc(),
            },
            capture,
            ArtifactView {
                kind: ViewKind::DocumentIndex,
                reducer_version: "1".to_string(),
                omitted: false,
                safe_excerpt: "# Architecture Overview".to_string(),
                transformations: vec![TRANSFORM_UNKNOWN_SAFE_V1.to_string()],
                reduction_error: None,
                failure_identifiers: Vec::new(),
            },
            RecoveryHandle::unavailable(artifact_id, "quarantined by policy"),
        );

        envelope.validate(&scope).expect("valid document envelope");
        assert_eq!(envelope.source.exit_code(), None);
        assert_eq!("stderr".parse::<StreamKind>().expect("stderr"), StreamKind::Stderr);
        assert_eq!("stdout".parse::<StreamKind>().expect("stdout"), StreamKind::Stdout);
        assert!("invalid_stream".parse::<StreamKind>().is_err());
    }

    #[test]
    fn budget_bound_view_excerpt_and_timeout_resolution() {
        let budget = ReductionBudget {
            max_view_lines: 3,
            max_view_bytes: 24,
            max_preview_bytes: 16,
            ..ReductionBudget::default()
        };
        budget.validate().expect("valid custom budget");

        let (bounded_lines, was_cut_lines) = budget.bound_view_excerpt("l1\nl2\nl3\nl4\nl5");
        assert!(was_cut_lines);
        assert_eq!(bounded_lines, "l1\nl2\nl3");

        let (bounded_bytes, was_cut_bytes) =
            budget.bound_view_excerpt("0123456789abcdef0123456789abcdef");
        assert!(was_cut_bytes);
        assert_eq!(bounded_bytes.len(), 24);

        let exec_policy = ExecutionPolicyConfig::default();
        assert_eq!(
            exec_policy.resolve_timeout_ms(None).expect("default timeout"),
            120_000
        );
        assert!(exec_policy.resolve_timeout_ms(Some(0)).is_err());
        assert_eq!(
            exec_policy
                .resolve_timeout_ms(Some(999_999))
                .expect_err("over max timeout")
                .error_code(),
            "BUDGET_EXCEEDED"
        );
    }

    #[test]
    fn error_codes_and_security_denial_classification() {
        let sec_err = ContextError::PathEscape {
            path: "../secret".to_string(),
            workspace_root: "/repo".to_string(),
            reason: "outside root".to_string(),
        };
        assert_eq!(sec_err.error_code(), "PATH_ESCAPE");
        assert!(sec_err.is_security_denial());

        let io_like = ContextError::ArtifactNotFound {
            artifact_id: "a_00".to_string(),
        };
        assert_eq!(io_like.error_code(), "ARTIFACT_NOT_FOUND");
        assert!(!io_like.is_security_denial());
    }

    proptest! {
        #[test]
        fn prop_secret_guard_and_utf8_truncation_never_panic(
            arbitrary_text in ".*",
            max_bytes in 0usize..512usize,
        ) {
            let guard = SecretGuard::default();
            let report = guard.scan_str(&arbitrary_text);
            let (slice, _) = truncate_str_utf8_boundary(&report.sanitized_text, max_bytes);
            prop_assert!(slice.len() <= max_bytes);
        }
    }
}
