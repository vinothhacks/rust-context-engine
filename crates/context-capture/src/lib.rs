//! Bounded async `stdout`/`stderr` process capture and confined document ingestion
//! for the Rust Context Engine.

pub mod command;
pub mod document;
pub mod stream;

pub use command::{
    capture_command, capture_command_strict, capture_command_with_cancel, CapturedCommand,
};
pub use context_core::{CaptureSummary, StreamEncoding, StreamKind};
pub use document::{capture_bytes, capture_file, CapturedDocument};
pub use stream::{combine_stream_encodings, CaptureCancelToken, CapturedStream};

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::time::Duration;

    use context_core::{sha256_hex, BoundScope, ExecutionPolicyConfig};
    use context_execution::{CommandRequest, ExecutionGate};
    use proptest::prelude::*;
    use tempfile::TempDir;

    use super::*;
    use crate::stream::StreamAccumulator;

    #[tokio::test]
    async fn captures_independent_stdout_stderr_exit_code_and_scrubs_env() {
        let ws = TempDir::new().expect("ws");
        let scope = BoundScope::bind(ws.path(), Some("cap-normal")).expect("bind");
        let gate = ExecutionGate::default();

        let script = concat!(
            "import os, sys\n",
            "val = os.environ.get('OPENAI_API_KEY', 'SCRUBBED').encode('utf-8')\n",
            "sys.stdout.buffer.write(b'hello-stdout:' + val + b'\\n')\n",
            "sys.stderr.buffer.write(b'hello-stderr\\n')\n",
            "sys.exit(17)\n"
        );
        let req = CommandRequest::new(["python", "-c", script])
            .with_extra_env([("OPENAI_API_KEY", "sk-should-never-reach-child")]);
        let approved = gate.authorize(&scope, &req).expect("authorize python");

        let captured = capture_command(&approved).await.expect("capture succeeds");
        assert_eq!(captured.exit_code, Some(17));
        assert!(!captured.timed_out);
        assert!(!captured.cancelled);
        assert!(captured.is_complete());
        assert_eq!(captured.stdout.bytes, b"hello-stdout:SCRUBBED\n");
        assert_eq!(captured.stderr.bytes, b"hello-stderr\n");
        assert_eq!(captured.stdout.encoding, StreamEncoding::Utf8);
        assert_eq!(captured.stderr.encoding, StreamEncoding::Utf8);
        assert_eq!(
            captured.stdout.sha256,
            sha256_hex(b"hello-stdout:SCRUBBED\n")
        );
        assert_eq!(captured.stderr.sha256, sha256_hex(b"hello-stderr\n"));

        let summary = captured.to_capture_summary(true);
        assert!(summary.complete);
        assert_eq!(summary.encoding, StreamEncoding::Utf8);
        assert_eq!(summary.stdout_bytes, 22);
        assert_eq!(summary.stderr_bytes, 13);
    }

    #[tokio::test]
    async fn captures_exact_non_utf8_raw_binary_bytes() {
        let ws = TempDir::new().expect("ws");
        let scope = BoundScope::bind(ws.path(), None).expect("bind");
        let gate = ExecutionGate::default();

        let script = concat!(
            "import sys\n",
            "sys.stdout.buffer.write(b'\\xff\\xfe\\x00BIN_OUT\\x80')\n",
            "sys.stderr.buffer.write(b'\\xc3\\x28BAD_UTF8')\n",
        );
        let approved = gate
            .authorize(&scope, &CommandRequest::new(["python", "-c", script]))
            .expect("authorize");

        let captured = capture_command(&approved).await.expect("capture binary");
        assert_eq!(captured.exit_code, Some(0));
        assert_eq!(captured.stdout.bytes, b"\xff\xfe\x00BIN_OUT\x80");
        assert_eq!(captured.stderr.bytes, b"\xc3\x28BAD_UTF8");
        assert_eq!(captured.stdout.encoding, StreamEncoding::Binary);
        assert_eq!(captured.stderr.encoding, StreamEncoding::Binary);
        assert_eq!(
            captured.to_capture_summary(true).encoding,
            StreamEncoding::Binary
        );
    }

    #[tokio::test]
    async fn truncates_oversized_stream_while_counting_total_observed_bytes() {
        let ws = TempDir::new().expect("ws");
        let scope = BoundScope::bind(ws.path(), None).expect("bind");
        let gate = ExecutionGate::default();

        let script = concat!(
            "import sys\n",
            "sys.stdout.buffer.write(b'X' * 65536)\n",
            "sys.stderr.buffer.write(b'ok-err')\n",
        );
        let req = CommandRequest::new(["python", "-c", script]).with_max_stream_bytes(4_096);
        let approved = gate.authorize(&scope, &req).expect("authorize");

        let captured = capture_command(&approved).await.expect("capture flood");
        assert_eq!(captured.exit_code, Some(0));
        assert!(captured.stdout.truncated);
        assert_eq!(captured.stdout.bytes.len(), 4_096);
        assert_eq!(captured.stdout.observed_bytes, 65_536);
        assert_eq!(captured.stdout.sha256, sha256_hex(&vec![b'X'; 4_096]));
        assert_eq!(
            captured.stdout.observed_sha256,
            sha256_hex(&vec![b'X'; 65_536])
        );
        assert!(!captured.stderr.truncated);
        assert_eq!(captured.stderr.bytes, b"ok-err");
        assert_eq!(captured.stderr.observed_bytes, 6);
        assert!(!captured.is_complete());
    }

    #[tokio::test]
    async fn enforces_deadline_timeout_and_cancellation_terminating_child() {
        let ws = TempDir::new().expect("ws");
        let scope = BoundScope::bind(ws.path(), None).expect("bind");
        let gate = ExecutionGate::default();

        let script = concat!(
            "import sys, time\n",
            "sys.stdout.buffer.write(b'before-sleep\\n')\n",
            "sys.stdout.buffer.flush()\n",
            "time.sleep(10)\n",
        );
        // Leave time for a cold Python process to flush its first line on a busy runner.
        let req = CommandRequest::new(["python", "-c", script]).with_timeout_ms(2_500);
        let approved = gate.authorize(&scope, &req).expect("authorize");

        let captured = capture_command(&approved).await.expect("timeout handled");
        assert!(captured.timed_out);
        assert!(!captured.cancelled);
        assert_eq!(captured.exit_code, None);
        assert!(!captured.is_complete());
        assert_eq!(captured.stdout.bytes, b"before-sleep\n");
        assert_eq!(
            captured.check_timeout().expect_err("timed out").error_code(),
            "EXECUTION_TIMEOUT"
        );

        let strict_err = capture_command_strict(&approved)
            .await
            .expect_err("strict timeout must return error");
        assert_eq!(strict_err.error_code(), "EXECUTION_TIMEOUT");

        // Cooperative cancellation via CaptureCancelToken
        let cancel_req = CommandRequest::new(["python", "-c", script]).with_timeout_ms(10_000);
        let cancel_approved = gate.authorize(&scope, &cancel_req).expect("authorize");
        let token = CaptureCancelToken::new();
        let token_bg = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            token_bg.cancel();
        });

        let cancelled_res = capture_command_with_cancel(&cancel_approved, &token)
            .await
            .expect("cancelled capture returns cleanly");
        assert!(cancelled_res.cancelled);
        assert!(!cancelled_res.timed_out);
        assert_eq!(cancelled_res.exit_code, None);
    }

    #[tokio::test]
    async fn reports_spawn_failure_when_allowlisted_binary_missing() {
        let ws = TempDir::new().expect("ws");
        let scope = BoundScope::bind(ws.path(), None).expect("bind");

        let mut policy = ExecutionPolicyConfig::default();
        policy
            .allowed_programs
            .push("nonexistent_context_engine_test_bin_98765".to_string());
        let gate = ExecutionGate::new(policy);

        let approved = gate
            .authorize(
                &scope,
                &CommandRequest::new(["nonexistent_context_engine_test_bin_98765", "--version"]),
            )
            .expect("policy authorizes synthetic binary");

        let err = capture_command(&approved)
            .await
            .expect_err("missing executable must fail to spawn");
        assert_eq!(err.error_code(), "IO_ERROR");
    }

    #[tokio::test]
    async fn captures_confined_workspace_files_and_rejects_dotenv_or_escape() {
        let ws = TempDir::new().expect("ws");
        fs::write(ws.path().join("notes.md"), b"# Title\nBody line\n").expect("write md");
        fs::write(ws.path().join("blob.bin"), [0x00, 0xff, 0x10, 0x20]).expect("write bin");
        fs::write(ws.path().join(".env"), b"SECRET_KEY=abc\n").expect("write .env");

        let scope = BoundScope::bind(ws.path(), None).expect("bind");
        let gate = ExecutionGate::default();

        let md_doc = capture_file(&scope, &gate, Path::new("notes.md"), 1_024)
            .await
            .expect("capture markdown");
        assert_eq!(md_doc.path_relative.as_deref(), Some("notes.md"));
        assert_eq!(md_doc.media_type.as_deref(), Some("text/markdown"));
        assert_eq!(md_doc.stream.encoding, StreamEncoding::Utf8);
        assert!(md_doc.is_complete());

        let bin_doc = capture_file(&scope, &gate, Path::new("blob.bin"), 2)
            .await
            .expect("capture truncated bin");
        assert_eq!(bin_doc.stream.encoding, StreamEncoding::Binary);
        assert!(bin_doc.stream.truncated);
        assert_eq!(bin_doc.stream.bytes, vec![0x00, 0xff]);
        assert_eq!(bin_doc.stream.observed_bytes, 4);

        let dotenv_err = capture_file(&scope, &gate, Path::new(".env"), 1_024)
            .await
            .expect_err(".env must be denied");
        assert_eq!(dotenv_err.error_code(), "SENSITIVE_PATH_BLOCKED");

        let escape_err = capture_file(&scope, &gate, Path::new("../outside.txt"), 1_024)
            .await
            .expect_err("escape must be denied");
        assert_eq!(escape_err.error_code(), "PATH_ESCAPE");

        let inline_doc = capture_bytes(b"inline text", Some("snippet".to_string()), None, 64)
            .expect("capture_bytes");
        assert_eq!(inline_doc.label.as_deref(), Some("snippet"));
        assert_eq!(inline_doc.media_type.as_deref(), Some("text/plain"));
    }

    #[tokio::test]
    async fn dropping_capture_future_cleanly_kills_child_on_drop() {
        let ws = TempDir::new().expect("ws");
        let scope = BoundScope::bind(ws.path(), None).expect("bind");
        let gate = ExecutionGate::default();

        let approved = gate
            .authorize(
                &scope,
                &CommandRequest::new(["python", "-c", "import time; time.sleep(30)"])
                    .with_timeout_ms(30_000),
            )
            .expect("authorize");

        let outer = tokio::time::timeout(Duration::from_millis(120), capture_command(&approved)).await;
        assert!(outer.is_err(), "outer timeout should drop capture_command future");
    }

    proptest! {
        #[test]
        fn prop_chunked_accumulator_matches_slice_capture(
            chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..128), 0..16),
            max_bytes in 1u64..512u64,
        ) {
            let mut flat = Vec::new();
            let mut acc = StreamAccumulator::new(max_bytes);
            for c in &chunks {
                flat.extend_from_slice(c);
                acc.push_chunk(c);
            }
            let streamed = acc.finalize();
            let sliced = CapturedStream::from_slice_bounded(&flat, max_bytes);

            prop_assert_eq!(streamed, sliced);
        }
    }
}
