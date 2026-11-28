//! Golden vertical-slice tests, domain reducer accuracy & byte-reduction benchmarks,
//! and `proptest` arbitrary `Vec<u8>` panic-freedom & invariant verification.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Once;

use context_core::{
    sha256_hex, ArtifactId, BoundScope, ReductionBudget, SecretGuard, StreamEncoding, StreamKind,
    ViewKind, TRANSFORM_CARGO_TEST_V1, TRANSFORM_COMPILER_DIAG_V1, TRANSFORM_GIT_REDUCER_V1,
    TRANSFORM_LOG_DEDUP_V1, TRANSFORM_PYTEST_JEST_V1, TRANSFORM_SEARCH_HITS_V1,
    TRANSFORM_STRIP_ANSI_V1, TRANSFORM_STRUCTURED_JSON_V1, TRANSFORM_UNKNOWN_SAFE_V1,
};
use context_reducers::{
    prepare_stream, reduce_command_output, reduce_command_with_input, reduce_document,
    reduce_stream, strip_ansi_and_normalize, CommandReductionInput, ReducerEngine, ReducerTarget,
};
use proptest::prelude::*;
use tempfile::TempDir;

static INIT_FIXTURES: Once = Once::new();

fn workspace_fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("fixtures")
}

/// Ensures deterministic binary and 5,000+-line fixtures exist on disk in `fixtures/commands/`
/// with exact reproducible byte content (idempotent: skips writing when bytes already match).
fn ensure_deterministic_fixtures() -> PathBuf {
    let root = workspace_fixtures_dir();
    INIT_FIXTURES.call_once(|| {
        let cmd_dir = root.join("commands");
        fs::create_dir_all(&cmd_dir).expect("create fixtures/commands");

        // 1. Mandatory Vertical-Slice Fixture 2: >= 5,000-line noisy passing cargo test
        let mut lines: Vec<String> = Vec::with_capacity(5_300);
        lines.push(String::new());
        lines.push("running 80 tests".to_string());
        for t in 0..80usize {
            for step in 0..60usize {
                lines.push(format!(
                    "[2026-11-22T12:00:{:02}.120Z DEBUG engine::worker] test_case={t:03} step={step:02} chunk_bytes=4096 status=ok",
                    t % 60
                ));
            }
            lines.push(format!("test reducer_suite::case_{t:03}_roundtrip ... ok"));
        }
        lines.push("test reducer_suite::slow_soak_benchmark ... ignored".to_string());
        lines.push("test reducer_suite::optional_gpu_probe ... ignored".to_string());
        lines.push(String::new());
        lines.push(
            "test result: ok. 80 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 1.84s"
                .to_string(),
        );
        lines.push(String::new());
        lines.push("running 40 tests".to_string());
        for t in 0..40usize {
            for step in 0..10usize {
                lines.push(format!(
                    "[trace] integration_check idx={t:02} iter={step} verified=true"
                ));
            }
            lines.push(format!("test integration::check_{t:02} ... ok"));
        }
        lines.push(String::new());
        lines.push(
            "test result: ok. 40 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.42s"
                .to_string(),
        );
        lines.push(String::new());
        lines.push("   Doc-tests context_reducers".to_string());
        lines.push(String::new());
        lines.push("running 3 tests".to_string());
        for d in 0..3usize {
            lines.push(format!(
                "test crates/context-reducers/src/lib.rs - example_{d} (line {}) ... ok",
                20 + d * 15
            ));
        }
        lines.push(String::new());
        lines.push(
            "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.21s\n"
                .to_string(),
        );
        let noisy_cargo_bytes = lines.join("\n").into_bytes();
        write_if_changed(
            &cmd_dir.join("cargo_test_passing_noisy_5k.stdout.txt"),
            &noisy_cargo_bytes,
        );

        // 2. Mandatory Vertical-Slice Fixture 3: Binary / non-UTF-8 stream (4,096 bytes)
        let mut bin_buf: Vec<u8> = Vec::with_capacity(4_096);
        bin_buf.extend_from_slice(
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06\x00\x00\x00",
        );
        let mut idx = 0usize;
        while bin_buf.len() < 4_096 {
            bin_buf.push(((idx.wrapping_mul(73)).wrapping_add(0x80)) as u8);
            idx += 1;
        }
        write_if_changed(&cmd_dir.join("binary_non_utf8_stream.bin"), &bin_buf);

        // 3. ANSI + CRLF + bare `\r` progress-bar spinner torture fixture
        let mut ansi_out = String::from("\x1b[?25l\x1b[?2004h");
        for p in 1..=120usize {
            ansi_out.push_str(&format!(
                "\x1b[36m  Downloading\x1b[0m crate_{p:03} v0.1.{} ({}%)\r",
                p % 10,
                (p * 100) / 120
            ));
        }
        ansi_out.push_str(
            "\x1b[32;1m   Finished\x1b[0m `test` profile [unoptimized + debuginfo] target(s) in 0.91s\r\n",
        );
        ansi_out.push_str("\x1bP1$r0m\x1b\\running 12 tests\r\n");
        for i in 0..11usize {
            ansi_out.push_str(&format!(
                "test ansi_suite::case_{i:02} ... \x1b[32mok\x1b[0m\r\n"
            ));
        }
        ansi_out.push_str(
            "test ansi_suite::hyperlink_diagnostic_failure ... \x1b[38;2;255;64;64;1mFAILED\x1b[0m\r\n\r\n",
        );
        ansi_out.push_str("failures:\r\n\r\n");
        ansi_out.push_str("---- ansi_suite::hyperlink_diagnostic_failure stdout ----\r\n");
        ansi_out.push_str(
            "thread 'ansi_suite::hyperlink_diagnostic_failure' panicked at \x1b]8;;file:///D:/repo/crates/context-reducers/src/ansi.rs\x07crates/context-reducers/src/ansi.rs:118:9\x1b]8;;\x07:\r\n",
        );
        ansi_out.push_str(
            "assertion `left == right` failed: hyperlink wrapper leaked ESC bytes\r\n",
        );
        ansi_out.push_str("  left: \x1b[31m\"\\u{1b}]8;;url\"\x1b[0m\r\n");
        ansi_out.push_str(" right: \x1b[32m\"clean\"\x1b[0m\r\n\r\n");
        ansi_out.push_str("failures:\r\n    ansi_suite::hyperlink_diagnostic_failure\r\n\r\n");
        ansi_out.push_str(
            "test result: \x1b[31mFAILED\x1b[0m. 11 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s\x1b[?2004l\x1b[?25h\r\n",
        );
        write_if_changed(
            &cmd_dir.join("ansi_crlf_spinner_torture.stdout.txt"),
            ansi_out.as_bytes(),
        );
    });
    root
}

fn write_if_changed(path: &Path, expected: &[u8]) {
    if let Ok(existing) = fs::read(path) {
        if existing == expected {
            return;
        }
    }
    fs::write(path, expected).expect("write deterministic fixture");
}

#[test]
fn vertical_slice_1_failing_cargo_test_retains_100_percent_failures_locations_and_exit() {
    let fixtures = ensure_deterministic_fixtures();
    let stdout = fs::read(fixtures.join("commands/cargo_test_failing_multiline.stdout.txt"))
        .expect("stdout");
    let stderr = fs::read(fixtures.join("commands/cargo_test_failing_multiline.stderr.txt"))
        .expect("stderr");

    let tmp = TempDir::new().expect("tempdir");
    let scope = BoundScope::bind(tmp.path(), Some("vs1")).expect("bind");
    let art_id = ArtifactId::mint(
        &scope,
        "2026-11-22T12:00:00.000Z",
        1,
        &sha256_hex(&stdout),
        Some(&sha256_hex(&stderr)),
    );

    let argv = vec![
        "cargo".to_string(),
        "test".to_string(),
        "--workspace".to_string(),
    ];
    let mut input = CommandReductionInput::new(&argv, Some(101), &stdout, &stderr);
    input.artifact_id = Some(&art_id);

    let outcome =
        reduce_command_with_input(&input, &ReductionBudget::default(), &SecretGuard::default());

    assert_eq!(outcome.target, ReducerTarget::CargoTest);
    assert_eq!(outcome.view.kind, ViewKind::TestSummary);
    assert!(outcome.view.omitted);
    assert_eq!(
        outcome.view.transformations,
        vec![
            TRANSFORM_STRIP_ANSI_V1.to_string(),
            TRANSFORM_CARGO_TEST_V1.to_string()
        ]
    );

    // 1. Exact exit status + multi-suite aggregated counts (14+5+3=22 passed, 2+1+1=4 failed, 2 ignored)
    assert!(outcome
        .view
        .safe_excerpt
        .contains("FAIL (exit 101) | 22 passed, 4 failed, 2 ignored across 3 suites"));

    // 2. 100% of distinct failing test names across unit, integration, and Doc-tests
    let expected_failures = [
        "scope::tests::rejects_forged_scope_override",
        "envelope::tests::schema_v1_round_trip",
        "cross_workspace_artifact_probe_denied",
        "crates/context-core/src/scope.rs - scope::BoundScope::bind (line 208)",
    ];
    assert_eq!(
        outcome.view.failure_identifiers.len(),
        expected_failures.len()
    );
    for expected in expected_failures {
        assert!(
            outcome
                .view
                .failure_identifiers
                .iter()
                .any(|f| f == expected),
            "missing failing test identifier: {expected}; got {:?}",
            outcome.view.failure_identifiers
        );
    }

    // 3. Exact `file:line:col` locations and multi-line assertion evidence
    for expected_snippet in [
        "crates/context-core/src/scope.rs:246:13",
        "crates/context-core/src/envelope.rs:348:9",
        "crates/context-core/tests/integration_auth.rs:89:5",
        "crates/context-core/src/scope.rs:214:18",
        "forged client scope must return SCOPE_VIOLATION",
        "effective_scope: \"ws_ffffffffffffffffffffffffffffffff\"",
        art_id.as_str(),
    ] {
        assert!(
            outcome.view.safe_excerpt.contains(expected_snippet),
            "expected '{expected_snippet}' in safe_excerpt:\n{}",
            outcome.view.safe_excerpt
        );
    }
}

#[test]
fn vertical_slice_2_passing_noisy_5k_cargo_test_exceeds_80_percent_reduction() {
    let fixtures = ensure_deterministic_fixtures();
    let stdout =
        fs::read(fixtures.join("commands/cargo_test_passing_noisy_5k.stdout.txt")).expect("stdout");
    let stderr =
        fs::read(fixtures.join("commands/cargo_test_passing_noisy_5k.stderr.txt")).expect("stderr");

    let line_count = std::str::from_utf8(&stdout).expect("utf8").lines().count();
    assert!(
        line_count >= 5_000,
        "mandatory fixture 2 must have >= 5,000 lines, got {line_count}"
    );

    let argv = vec!["cargo".to_string(), "test".to_string()];
    let outcome = reduce_command_output(
        &argv,
        Some(0),
        &stdout,
        &stderr,
        &ReductionBudget::default(),
        &SecretGuard::default(),
    );

    assert_eq!(outcome.target, ReducerTarget::CargoTest);
    assert_eq!(outcome.view.kind, ViewKind::TestSummary);
    assert!(outcome.view.omitted);
    assert!(outcome.view.failure_identifiers.is_empty());
    assert!(outcome
        .view
        .safe_excerpt
        .contains("PASS (exit 0) | 123 passed, 0 failed, 2 ignored, 3 filtered across 3 suites"));
    assert!(outcome.view.safe_excerpt.contains("context_get"));

    let ratio = outcome.byte_reduction_ratio();
    assert!(
        ratio >= 0.80,
        "expected >= 80% byte reduction on 5k-line passing Cargo suite, got {:.2}% (raw={}B, reduced={}B)",
        ratio * 100.0,
        outcome.raw_bytes,
        outcome.reduced_bytes
    );
}

#[test]
fn vertical_slice_3_binary_non_utf8_stream_degrades_to_unknown_safe_with_hash_and_byte_recovery() {
    let fixtures = ensure_deterministic_fixtures();
    let bin_bytes =
        fs::read(fixtures.join("commands/binary_non_utf8_stream.bin")).expect("binary fixture");
    let expected_sha = sha256_hex(&bin_bytes);

    let outcome = reduce_stream(
        &bin_bytes,
        StreamKind::Stdout,
        &ReductionBudget::default(),
        &SecretGuard::default(),
    );

    assert_eq!(outcome.encoding, StreamEncoding::Binary);
    assert_eq!(outcome.target, ReducerTarget::UnknownSafe);
    assert_eq!(outcome.view.kind, ViewKind::UnknownSafe);
    assert!(outcome.view.omitted);
    assert_eq!(
        outcome.view.transformations,
        vec![TRANSFORM_UNKNOWN_SAFE_V1.to_string()]
    );
    assert!(outcome.view.safe_excerpt.contains("bytes=4096"));
    assert!(outcome.view.safe_excerpt.contains("encoding=binary"));
    assert!(outcome.view.safe_excerpt.contains(&expected_sha));
    assert!(outcome.view.safe_excerpt.contains("PNG image"));
    assert!(outcome
        .view
        .safe_excerpt
        .contains("hex_head(24B): 89 50 4e 47"));
    assert!(outcome
        .view
        .safe_excerpt
        .contains("context_get --stream stdout --bytes 0:4096"));
}

#[test]
fn golden_pytest_and_jest_retain_all_failures_errors_xpass_and_locations() {
    let fixtures = ensure_deterministic_fixtures();
    let engine = ReducerEngine::default();

    // Pytest
    let pytest_stdout =
        fs::read(fixtures.join("commands/pytest_failing_suite.stdout.txt")).expect("pytest");
    let pytest_out = engine.reduce_command_output(&["pytest".into()], Some(1), &pytest_stdout, b"");
    assert_eq!(pytest_out.target, ReducerTarget::PytestJest);
    assert_eq!(pytest_out.view.kind, ViewKind::TestSummary);
    assert!(pytest_out
        .view
        .transformations
        .contains(&TRANSFORM_PYTEST_JEST_V1.to_string()));
    assert!(pytest_out
        .view
        .safe_excerpt
        .contains("FAIL (exit 1) | 19 passed, 2 failed, 1 error(s), 1 skipped, 1 xpassed"));

    for expected_id in [
        "tests/test_classifier.py::TestUnicodeTraps::test_emoji_char_spans",
        "tests/test_mcp.py::test_context_get_byte_bounds",
        "tests/test_storage.py::test_db_pool_fixture",
        "tests/test_legacy.py::test_strict_xfail_contract",
    ] {
        assert!(
            pytest_out
                .view
                .failure_identifiers
                .contains(&expected_id.to_string()),
            "missing pytest failure id '{expected_id}' in {:?}",
            pytest_out.view.failure_identifiers
        );
    }
    assert!(pytest_out
        .view
        .safe_excerpt
        .contains("tests/test_classifier.py:88"));
    assert!(pytest_out
        .view
        .safe_excerpt
        .contains("tests/test_mcp.py:142"));
    assert!(pytest_out
        .view
        .safe_excerpt
        .contains("RuntimeError: fixture pool bootstrap failed"));

    // Jest / Vitest
    let jest_stdout =
        fs::read(fixtures.join("commands/vitest_jest_failing.stdout.txt")).expect("jest");
    let jest_out =
        engine.reduce_command_output(&["npx".into(), "jest".into()], Some(1), &jest_stdout, b"");
    assert_eq!(jest_out.target, ReducerTarget::PytestJest);
    assert!(jest_out
        .view
        .safe_excerpt
        .contains("FAIL (exit 1) | 30 passed, 2 failed, 1 skipped"));
    assert_eq!(
        jest_out.view.failure_identifiers,
        vec![
            "src/classifier.test.ts::Classifier › Windows paths › parses ripgrep drive-letter hits",
            "src/classifier.test.ts::Classifier › JSON reducer › retains embedded error items in bulk array",
        ]
    );
    assert!(jest_out
        .view
        .safe_excerpt
        .contains("src/classifier.test.ts:58:20"));
    assert!(jest_out
        .view
        .safe_excerpt
        .contains("src/classifier.test.ts:104:22"));
}

#[test]
fn golden_rustc_and_tsc_deduplicate_errors_and_retain_codes_and_spans() {
    let fixtures = ensure_deterministic_fixtures();
    let engine = ReducerEngine::default();

    // Cargo check `--all-targets` with duplicate diagnostics across lib + lib test
    let rustc_stderr =
        fs::read(fixtures.join("commands/rustc_cargo_check_errors.stderr.txt")).expect("rustc");
    let r_out = engine.reduce_command_output(
        &["cargo".into(), "check".into(), "--all-targets".into()],
        Some(101),
        b"",
        &rustc_stderr,
    );
    assert_eq!(r_out.target, ReducerTarget::CompilerDiag);
    assert_eq!(r_out.view.kind, ViewKind::CompilerDiagnostics);
    assert!(r_out
        .view
        .transformations
        .contains(&TRANSFORM_COMPILER_DIAG_V1.to_string()));
    assert!(r_out
        .view
        .safe_excerpt
        .contains("FAIL (exit 101) | 3 unique error(s) (6 total), 3 unique warning(s) (6 total)"));
    assert_eq!(
        r_out.view.failure_identifiers,
        vec![
            "crates/context-reducers/src/structured_json.rs:112:20 [E0308]",
            "crates/context-reducers/src/cargo_test.rs:204:36 [E0425]",
            "crates/context-reducers/src/lib.rs:412:22 [E0599]",
        ]
    );
    // Errors must appear before warnings in `safe_excerpt`
    let first_err_pos = r_out.view.safe_excerpt.find("error[E0308]").expect("E0308");
    let first_warn_pos = r_out
        .view
        .safe_excerpt
        .find("warning[unused_imports]")
        .expect("warning");
    assert!(first_err_pos < first_warn_pos);

    // TypeScript `tsc --noEmit`
    let tsc_stdout = fs::read(fixtures.join("commands/tsc_diagnostics.stdout.txt")).expect("tsc");
    let t_out = engine.reduce_command_output(
        &["tsc".into(), "--noEmit".into()],
        Some(2),
        &tsc_stdout,
        b"",
    );
    assert_eq!(t_out.target, ReducerTarget::CompilerDiag);
    assert_eq!(
        t_out.view.failure_identifiers,
        vec![
            "adapters/opencode/src/plugin.ts:29:11 [TS2322]",
            "adapters/opencode/src/plugin.ts:64:25 [TS2345]",
            "adapters/opencode/src/hooks.ts:18:14 [TS7006]",
        ]
    );
}

#[test]
fn golden_git_json_logs_search_ansi_and_document_fixtures() {
    let fixtures = ensure_deterministic_fixtures();
    let engine = ReducerEngine::default();

    // 1. Git diff
    let diff_bytes =
        fs::read(fixtures.join("commands/git_diff_large.stdout.txt")).expect("git diff");
    let diff_out =
        engine.reduce_command_output(&["git".into(), "diff".into()], Some(0), &diff_bytes, b"");
    assert_eq!(diff_out.target, ReducerTarget::GitReducer);
    assert!(diff_out
        .view
        .transformations
        .contains(&TRANSFORM_GIT_REDUCER_V1.to_string()));
    assert!(diff_out.view.omitted);
    assert!(diff_out.view.safe_excerpt.contains("3 file(s) changed"));
    assert!(diff_out.view.safe_excerpt.contains(
        "crates/context-reducers/src/legacy.rs -> crates/context-reducers/src/ported.rs (renamed)"
    ));
    assert!(diff_out
        .view
        .safe_excerpt
        .contains("crates/context-reducers/src/ansi.rs (new)"));
    assert!(diff_out.view.safe_excerpt.contains("@@ -1,6 +1,52 @@"));

    // 2. Git status
    let status_bytes =
        fs::read(fixtures.join("commands/git_status_dirty.stdout.txt")).expect("git status");
    let status_out = engine.reduce_command_output(
        &["git".into(), "status".into()],
        Some(0),
        &status_bytes,
        b"",
    );
    assert_eq!(status_out.target, ReducerTarget::GitReducer);
    assert!(status_out.view.safe_excerpt.contains(
        "On branch feat/phase3-reducers (exit 0) | staged=3, unstaged=2, untracked=4, conflicted=1"
    ));
    assert_eq!(
        status_out.view.failure_identifiers,
        vec!["both modified: crates/context-mcp/src/router.rs"]
    );

    // 3. Structured JSON array
    let json_bytes =
        fs::read(fixtures.join("documents/large_api_records.json")).expect("large json");
    let json_out = engine.reduce_document(
        &json_bytes,
        Some("fixtures/documents/large_api_records.json"),
        Some("application/json"),
    );
    assert_eq!(json_out.target, ReducerTarget::StructuredJson);
    assert_eq!(json_out.view.kind, ViewKind::StructuredJson);
    assert!(json_out
        .view
        .transformations
        .contains(&TRANSFORM_STRUCTURED_JSON_V1.to_string()));
    assert!(json_out.view.omitted);
    assert!(json_out
        .view
        .safe_excerpt
        .contains("Array(len=40) schema={"));
    assert!(json_out.view.safe_excerpt.contains("\"total_count\": 40"));
    assert!(json_out.view.safe_excerpt.contains("SQLITE_BUSY"));
    assert!(json_out.view.safe_excerpt.contains("INTEGRITY_MISMATCH"));
    assert!(json_out
        .view
        .failure_identifiers
        .iter()
        .any(|id| id.contains("SQLITE_BUSY")));
    assert!(json_out
        .view
        .failure_identifiers
        .iter()
        .any(|id| id.contains("INTEGRITY_MISMATCH")));

    // 4. Noisy service logs (`log_dedup@1`)
    let log_bytes = fs::read(fixtures.join("documents/noisy_service.log")).expect("service log");
    let log_out = engine.reduce_document(
        &log_bytes,
        Some("fixtures/documents/noisy_service.log"),
        Some("text/plain"),
    );
    assert_eq!(log_out.target, ReducerTarget::LogDedup);
    assert_eq!(log_out.view.kind, ViewKind::LogSummary);
    assert!(log_out
        .view
        .transformations
        .contains(&TRANSFORM_LOG_DEDUP_V1.to_string()));
    assert!(log_out
        .view
        .safe_excerpt
        .contains("FATAL=1 ERROR=3 WARN=3 INFO=33 DEBUG=5"));
    assert!(log_out
        .view
        .safe_excerpt
        .contains("timestamps: 2026-11-22T12:00:01.104Z .. 2026-11-22T12:00:45.500Z"));
    assert!(log_out.view.safe_excerpt.contains("<UUID>"));
    assert!(log_out.view.safe_excerpt.contains("<IP>"));
    assert_eq!(log_out.view.failure_identifiers.len(), 3);
    assert!(log_out.view.safe_excerpt.contains("E_BLOB_CHECKSUM"));
    assert!(log_out.view.safe_excerpt.contains("E_SCOPE_DENIED"));
    assert!(log_out
        .view
        .safe_excerpt
        .contains("Caused by: I/O error: disk quota exceeded"));

    // 5. Ripgrep output (`search_hits@1`)
    let rg_bytes = fs::read(fixtures.join("commands/ripgrep_hits.stdout.txt")).expect("rg hits");
    let rg_out = engine.reduce_command_output(
        &[
            "rg".into(),
            "-n".into(),
            "-C".into(),
            "1".into(),
            "scan_str".into(),
        ],
        Some(0),
        &rg_bytes,
        b"",
    );
    assert_eq!(rg_out.target, ReducerTarget::SearchHits);
    assert_eq!(rg_out.view.kind, ViewKind::SearchHits);
    assert!(rg_out
        .view
        .transformations
        .contains(&TRANSFORM_SEARCH_HITS_V1.to_string()));
    assert!(rg_out
        .view
        .safe_excerpt
        .contains("15 match(es) across 4 file(s)"));
    assert!(rg_out
        .view
        .safe_excerpt
        .contains(r"D:\research 1\mcp\token reducer\crates\context-core\src\secrets.rs"));
    assert!(rg_out
        .view
        .safe_excerpt
        .contains("crates/context-core/src/pre-commit-guard.yaml"));

    // 6. ANSI + CRLF + Spinner torture (`strip_ansi@1` + `cargo_test@1`)
    let ansi_bytes =
        fs::read(fixtures.join("commands/ansi_crlf_spinner_torture.stdout.txt")).expect("ansi");
    let ansi_out = engine.reduce_command_output(
        &["cargo".into(), "test".into()],
        Some(101),
        &ansi_bytes,
        b"",
    );
    assert_eq!(ansi_out.target, ReducerTarget::CargoTest);
    assert!(!ansi_out.view.safe_excerpt.contains('\x1b'));
    assert!(!ansi_out.view.safe_excerpt.contains('\r'));
    assert!(!ansi_out.view.safe_excerpt.contains("crate_001"));
    assert_eq!(
        ansi_out.view.failure_identifiers,
        vec!["ansi_suite::hyperlink_diagnostic_failure"]
    );
    assert!(ansi_out
        .view
        .safe_excerpt
        .contains("crates/context-reducers/src/ansi.rs:118:9"));

    // 7. Markdown prose document -> `unknown_safe@1` / `ViewKind::DocumentIndex`
    let doc_bytes = fs::read(fixtures.join("documents/architecture_notes.md")).expect("md doc");
    let doc_out = engine.reduce_document(
        &doc_bytes,
        Some("fixtures/documents/architecture_notes.md"),
        Some("text/markdown"),
    );
    assert_eq!(doc_out.target, ReducerTarget::UnknownSafe);
    assert_eq!(doc_out.view.kind, ViewKind::DocumentIndex);
    assert!(!doc_out.view.omitted);
}

#[test]
fn median_byte_reduction_across_noisy_fixtures_exceeds_40_percent() {
    let fixtures = ensure_deterministic_fixtures();
    let engine = ReducerEngine::default();

    let mut ratios: Vec<(&str, usize, usize, f64)> = Vec::new();

    // 1. Noisy 5k passing cargo test
    let f2_out =
        fs::read(fixtures.join("commands/cargo_test_passing_noisy_5k.stdout.txt")).expect("f2");
    let f2_err =
        fs::read(fixtures.join("commands/cargo_test_passing_noisy_5k.stderr.txt")).expect("f2e");
    let r =
        engine.reduce_command_output(&["cargo".into(), "test".into()], Some(0), &f2_out, &f2_err);
    ratios.push((
        "cargo_test_passing_noisy_5k",
        r.raw_bytes,
        r.reduced_bytes,
        r.byte_reduction_ratio(),
    ));

    // 2. Failing multi-suite cargo test
    let f1_out =
        fs::read(fixtures.join("commands/cargo_test_failing_multiline.stdout.txt")).expect("f1");
    let f1_err =
        fs::read(fixtures.join("commands/cargo_test_failing_multiline.stderr.txt")).expect("f1e");
    let r = engine.reduce_command_output(
        &["cargo".into(), "test".into()],
        Some(101),
        &f1_out,
        &f1_err,
    );
    ratios.push((
        "cargo_test_failing_multiline",
        r.raw_bytes,
        r.reduced_bytes,
        r.byte_reduction_ratio(),
    ));

    // 3. Binary 4KB stream
    let f3 = fs::read(fixtures.join("commands/binary_non_utf8_stream.bin")).expect("f3");
    let r = engine.reduce_stream(&f3, StreamKind::Stdout);
    ratios.push((
        "binary_non_utf8_stream",
        r.raw_bytes,
        r.reduced_bytes,
        r.byte_reduction_ratio(),
    ));

    // 4. Pytest failing suite
    let fp = fs::read(fixtures.join("commands/pytest_failing_suite.stdout.txt")).expect("pytest");
    let r = engine.reduce_command_output(&["pytest".into()], Some(1), &fp, b"");
    ratios.push((
        "pytest_failing_suite",
        r.raw_bytes,
        r.reduced_bytes,
        r.byte_reduction_ratio(),
    ));

    // 5. Rustc duplicate cargo check errors/warnings
    let fr =
        fs::read(fixtures.join("commands/rustc_cargo_check_errors.stderr.txt")).expect("rustc");
    let r = engine.reduce_command_output(&["cargo".into(), "check".into()], Some(101), b"", &fr);
    ratios.push((
        "rustc_cargo_check_errors",
        r.raw_bytes,
        r.reduced_bytes,
        r.byte_reduction_ratio(),
    ));

    // 6. Git diff large
    let fg = fs::read(fixtures.join("commands/git_diff_large.stdout.txt")).expect("git diff");
    let r = engine.reduce_command_output(&["git".into(), "diff".into()], Some(0), &fg, b"");
    ratios.push((
        "git_diff_large",
        r.raw_bytes,
        r.reduced_bytes,
        r.byte_reduction_ratio(),
    ));

    // 7. Large JSON array
    let fj = fs::read(fixtures.join("documents/large_api_records.json")).expect("json");
    let r = engine.reduce_document(
        &fj,
        Some("large_api_records.json"),
        Some("application/json"),
    );
    ratios.push((
        "large_api_records.json",
        r.raw_bytes,
        r.reduced_bytes,
        r.byte_reduction_ratio(),
    ));

    // 8. Noisy service log
    let fl = fs::read(fixtures.join("documents/noisy_service.log")).expect("log");
    let r = engine.reduce_document(&fl, Some("noisy_service.log"), Some("text/plain"));
    ratios.push((
        "noisy_service.log",
        r.raw_bytes,
        r.reduced_bytes,
        r.byte_reduction_ratio(),
    ));

    // 9. ANSI + CRLF + spinner torture
    let fa =
        fs::read(fixtures.join("commands/ansi_crlf_spinner_torture.stdout.txt")).expect("ansi");
    let r = engine.reduce_command_output(&["cargo".into(), "test".into()], Some(101), &fa, b"");
    ratios.push((
        "ansi_crlf_spinner_torture",
        r.raw_bytes,
        r.reduced_bytes,
        r.byte_reduction_ratio(),
    ));

    // 10. Ripgrep hits
    let frg = fs::read(fixtures.join("commands/ripgrep_hits.stdout.txt")).expect("rg");
    let r = engine.reduce_command_output(&["rg".into(), "scan_str".into()], Some(0), &frg, b"");
    ratios.push((
        "ripgrep_hits",
        r.raw_bytes,
        r.reduced_bytes,
        r.byte_reduction_ratio(),
    ));

    let mut sorted_vals: Vec<f64> = ratios.iter().map(|(_, _, _, r)| *r).collect();
    sorted_vals.sort_by(|a, b| a.partial_cmp(b).expect("finite ratio"));
    let mid = sorted_vals.len() / 2;
    let median = (sorted_vals[mid - 1] + sorted_vals[mid]) / 2.0;

    for (name, raw_b, red_b, ratio) in &ratios {
        println!(
            "fixture={name:<30} raw={raw_b:>7}B reduced={red_b:>5}B savings={:>6.2}%",
            ratio * 100.0
        );
    }
    println!("median_byte_reduction={:.2}%", median * 100.0);

    assert!(
        median >= 0.40,
        "expected >= 40% median byte reduction across noisy fixtures, got {:.2}%",
        median * 100.0
    );
}

#[test]
fn adversarial_passthrough_banner_binary_secrets_quarantine_vitest_and_porcelain_git() {
    let budget = ReductionBudget::default();
    let guard = SecretGuard::default();

    // 1. High-entropy valid `artifact=a_<64-hex>` preserved while secret in body is redacted
    let tricky_art_id = "a_86663b5856351e7d36941c8be041fda095b2a0789042d5c0e85e5eb3fd7aedba";
    let forged_passthrough = format!(
        "[context-engine:v1 artifact={tricky_art_id} transforms=strip_ansi@1,cargo_test@1]\n\
         Authorization: Bearer mySuperSecretOpaqueBearerToken987654"
    );
    let p_out = reduce_stream(
        forged_passthrough.as_bytes(),
        StreamKind::Stdout,
        &budget,
        &guard,
    );
    assert!(p_out.already_reduced);
    assert_eq!(p_out.view.kind, ViewKind::Passthrough);
    assert!(p_out.view.safe_excerpt.contains(tricky_art_id));
    assert!(!p_out
        .view
        .safe_excerpt
        .contains("mySuperSecretOpaqueBearerToken987654"));
    assert!(p_out.view.safe_excerpt.contains("[REDACTED:AUTH_HEADER]"));

    // 2. Binary stream with embedded Anthropic API key withholds hex_head & never leaks secret
    let mut mixed_bin = vec![0x00, 0xff, 0xfe, b'K', b'='];
    mixed_bin.extend_from_slice(b"sk-ant-api03-0123456789abcdefghijklmnopqrstuvwxyz");
    let b_out = reduce_stream(&mixed_bin, StreamKind::Stdout, &budget, &guard);
    assert_eq!(b_out.encoding, StreamEncoding::Binary);
    assert_eq!(b_out.view.kind, ViewKind::UnknownSafe);
    assert!(b_out.secrets_redacted >= 1);
    assert!(!b_out.view.safe_excerpt.contains("sk-ant-api03"));
    assert!(b_out.view.safe_excerpt.contains("withheld"));

    // 3. Quarantined command output (`originals_available = false`) never advertises `context_get`
    let argv = vec!["cargo".to_string(), "test".to_string()];
    let mut q_in = CommandReductionInput::new(
        &argv,
        Some(0),
        b"running 2 tests\ntest a ... ok\ntest b ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",
        b"",
    );
    q_in.originals_available = false;
    let q_out = reduce_command_with_input(&q_in, &budget, &guard);
    assert!(q_out
        .view
        .safe_excerpt
        .contains("recovery: unavailable (raw stream withheld by secret policy)"));
    assert!(!q_out.view.safe_excerpt.contains("context_get"));

    // 4. Vitest `FAIL file > suite > spec` + `❯ file:line:col` location
    let vitest_stdout = b" RUN  v2.1.4 D:/repo\n \xE2\x9C\x93 src/ok.spec.ts (4 tests) 8ms\n FAIL  src/auth.spec.ts > AuthGuard > rejects expired JWT\nAssertionError: expected 200 to be 401\n \xE2\x9D\xAF src/auth.spec.ts:33:14\n\n Test Files  1 failed | 1 passed (2)\n      Tests  1 failed | 4 passed (5)\n";
    let v_out = reduce_command_output(
        &["pnpm".into(), "vitest".into(), "run".into()],
        Some(1),
        vitest_stdout,
        b"",
        &budget,
        &guard,
    );
    assert_eq!(v_out.target, ReducerTarget::PytestJest);
    assert_eq!(
        v_out.view.failure_identifiers,
        vec!["src/auth.spec.ts > AuthGuard > rejects expired JWT"]
    );
    assert!(v_out.view.safe_excerpt.contains("src/auth.spec.ts:33:14"));

    // 5. Git porcelain status (`git status -sb`) + EOF-newline-only `git diff`
    let porcelain = b"## main...origin/main [ahead 1]\nM  src/lib.rs\n M src/ansi.rs\nUU src/conflict.rs\n?? tmp.log\n";
    let gs_out = reduce_command_output(
        &["git".into(), "status".into(), "-sb".into()],
        Some(0),
        porcelain,
        b"",
        &budget,
        &guard,
    );
    assert_eq!(gs_out.target, ReducerTarget::GitReducer);
    assert!(gs_out
        .view
        .safe_excerpt
        .contains("staged=1, unstaged=1, untracked=1, conflicted=1"));
    assert_eq!(gs_out.view.failure_identifiers, vec!["UU src/conflict.rs"]);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 192,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn prop_arbitrary_bytes_never_panic_and_always_respect_budget(
        raw_stdout in prop::collection::vec(any::<u8>(), 0..2048),
        raw_stderr in prop::collection::vec(any::<u8>(), 0..512),
        cmd_choice in 0usize..8usize,
        exit_code in prop::option::of(-1i32..130i32),
    ) {
        let budget = ReductionBudget::default();
        let guard = SecretGuard::default();

        // 1. ANSI stripper & prepare_stream never panic on arbitrary bytes
        let prep = prepare_stream(&raw_stdout);
        let lossy = String::from_utf8_lossy(&raw_stdout);
        let stripped = strip_ansi_and_normalize(&lossy);
        prop_assert!(!stripped.text.contains("\r\n"));

        // 2. Single-stream & document reducers never panic and obey budget
        let s_out = reduce_stream(&raw_stdout, StreamKind::Stdout, &budget, &guard);
        prop_assert!(s_out.view.safe_excerpt.len() <= budget.max_view_bytes);
        prop_assert!(s_out.view.safe_excerpt.lines().count() <= budget.max_view_lines);

        let d_out = reduce_document(&raw_stdout, Some("fuzz.bin"), None, &budget, &guard);
        prop_assert!(d_out.view.safe_excerpt.len() <= budget.max_view_bytes);
        prop_assert!(d_out.view.safe_excerpt.lines().count() <= budget.max_view_lines);
        prop_assert_eq!(d_out.encoding, prep.encoding);

        // 3. Command reducer across all argv priors never panics and obeys budget
        let argv: Vec<String> = match cmd_choice {
            0 => vec!["cargo".into(), "test".into()],
            1 => vec!["pytest".into()],
            2 => vec!["cargo".into(), "check".into()],
            3 => vec!["tsc".into()],
            4 => vec!["git".into(), "diff".into()],
            5 => vec!["git".into(), "status".into()],
            6 => vec!["rg".into(), "needle".into()],
            _ => vec!["custom-tool".into()],
        };
        let c_out = reduce_command_output(&argv, exit_code, &raw_stdout, &raw_stderr, &budget, &guard);
        prop_assert!(c_out.view.safe_excerpt.len() <= budget.max_view_bytes);
        prop_assert!(c_out.view.safe_excerpt.lines().count() <= budget.max_view_lines);
    }
}
