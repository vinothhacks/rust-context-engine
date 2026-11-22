//! Comprehensive Phase 6 End-to-End Subprocess, Dual-Framing MCP, CLI Matrix,
//! Zero-Egress Socket Audit, and Live Agent Adapter/Hook Verification Suite.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use base64::Engine as _;
use context_core::{sha256_hex, ArtifactEnvelope};
use context_journal::ResumePack;
use context_mcp::{
    DoctorReport, EnginePruneReport, EngineStatsReport, GetSliceOutcome, SearchQueryOutcome,
};
use serde_json::{json, Value};
use tempfile::{Builder as TempBuilder, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

/// Creates a temporary directory strictly inside `<repo_root>/target/wave4-e2e/test-tmp`
/// so tests never touch paths outside the repository root.
fn workspace_tempdir(prefix: &str) -> TempDir {
    let base = repo_root()
        .join("target")
        .join("wave4-e2e")
        .join("test-tmp");
    fs::create_dir_all(&base).expect("create test-tmp inside target/wave4-e2e");
    TempBuilder::new()
        .prefix(prefix)
        .tempdir_in(&base)
        .expect("create scoped tempdir")
}

async fn send_newline_rpc<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, msg: &Value) {
    let mut bytes = serde_json::to_vec(msg).expect("serialize rpc");
    bytes.push(b'\n');
    writer.write_all(&bytes).await.expect("write rpc line");
    writer.flush().await.expect("flush rpc line");
}

async fn recv_newline_rpc<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Value {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await.expect("read rpc line");
    assert!(n > 0, "unexpected EOF waiting for newline JSON-RPC reply");
    serde_json::from_str(&line).unwrap_or_else(|err| {
        panic!("stdout was not pure JSON-RPC ({err}): {line:?}");
    })
}

async fn send_content_length_rpc<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, msg: &Value) {
    let body = serde_json::to_vec(msg).expect("serialize lsp rpc");
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    writer
        .write_all(header.as_bytes())
        .await
        .expect("write Content-Length header");
    writer.write_all(&body).await.expect("write rpc body");
    writer.flush().await.expect("flush Content-Length frame");
}

async fn recv_content_length_rpc<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Value {
    let mut header_line = String::new();
    let n = reader
        .read_line(&mut header_line)
        .await
        .expect("read Content-Length line");
    assert!(n > 0, "unexpected EOF waiting for Content-Length header");
    assert!(
        header_line.starts_with("Content-Length: "),
        "expected Content-Length header, got {header_line:?}"
    );
    let body_len: usize = header_line["Content-Length: ".len()..]
        .trim()
        .parse()
        .expect("parse Content-Length integer");

    loop {
        let mut sep = String::new();
        reader.read_line(&mut sep).await.expect("read header sep");
        if sep == "\r\n" || sep == "\n" {
            break;
        }
    }

    let mut body = vec![0u8; body_len];
    reader
        .read_exact(&mut body)
        .await
        .expect("read exact JSON-RPC body");
    serde_json::from_slice(&body).expect("parse Content-Length JSON-RPC body")
}

/// Queries Windows TCP/UDP socket tables for `pid` and asserts zero outbound/network endpoints.
async fn assert_zero_network_sockets_for_pid(pid: u32) {
    let ps_script = format!(
        "$tcp = @(Get-NetTCPConnection -OwningProcess {pid} -ErrorAction SilentlyContinue); \
         $udp = @(Get-NetUDPEndpoint -OwningProcess {pid} -ErrorAction SilentlyContinue); \
         [Console]::Out.WriteLine(($tcp.Count + $udp.Count))"
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .output()
        .await
        .expect("run Get-NetTCPConnection check");
    assert!(
        out.status.success(),
        "socket audit PowerShell command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let count_str = String::from_utf8_lossy(&out.stdout);
    let socket_count: usize = count_str
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("unexpected socket count output: {count_str:?}"));
    assert_eq!(
        socket_count, 0,
        "context-engine PID {pid} must open zero TCP/UDP sockets, observed {socket_count}"
    );
}

fn build_poc_lib_rs(with_bug: bool) -> String {
    let checksum_expr = if with_bug {
        "acc.wrapping_add(0xDEAD_BEEF)"
    } else {
        "acc"
    };

    let mut code = format!(
        r#"use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFrameHeader {{
    pub magic: &'static str,
    pub sequence: u64,
    pub payload_len: usize,
    pub crc32_digest: u32,
}}

pub fn compute_packet_digest(bytes: &[u8]) -> u32 {{
    let mut acc = 0x1020_3040u32;
    for (idx, &b) in bytes.iter().enumerate() {{
        acc = acc.rotate_left(3) ^ (u32::from(b).wrapping_mul((idx as u32) + 17));
    }}
    {checksum_expr}
}}

#[cfg(test)]
mod tests {{
    use super::*;

    #[test]
    fn verifies_packet_checksum_and_increments_marker() {{
        let marker_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("execution_counter.txt");
        let prev: u64 = fs::read_to_string(&marker_path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        fs::write(&marker_path, format!("{{}}\n", prev + 1)).expect("write counter");

        let sample = b"context-engine-v1-frame-payload";
        let expected_crc = {{
            let mut acc = 0x1020_3040u32;
            for (idx, &b) in sample.iter().enumerate() {{
                acc = acc.rotate_left(3) ^ (u32::from(b).wrapping_mul((idx as u32) + 17));
            }}
            acc
        }};

        let actual_header = PacketFrameHeader {{
            magic: "CEV1",
            sequence: 42,
            payload_len: sample.len(),
            crc32_digest: compute_packet_digest(sample),
        }};
        let expected_header = PacketFrameHeader {{
            magic: "CEV1",
            sequence: 42,
            payload_len: sample.len(),
            crc32_digest: expected_crc,
        }};

        assert_eq!(
            actual_header,
            expected_header,
            "packet_decoder_multiline_assertion_9941: frame CRC digest mismatch during decode"
        );
    }}
"#
    );

    // Add 36 deterministic passing unit tests + verbose stdout lines (when --nocapture isn't passed,
    // libtest prints 37 `test tests::... ... ok` lines so two runs produce substantial raw output
    // alongside compiler/runner stderr lines, yielding clear positive net byte/token savings!).
    for idx in 0..36usize {
        code.push_str(&format!(
            r#"
    #[test]
    fn regression_frame_window_invariant_case_{idx:02}_validates_bounds_cleanly() {{
        let slice = [0xAAu8; 32];
        assert_eq!(slice.len(), 32);
    }}
"#
        ));
    }
    code.push_str("}\n");
    code
}

#[tokio::test]
async fn dod_poc_live_mcp_stdio_failing_cargo_project_search_get_fix_resume_stats_and_zero_egress()
{
    let temp_proj = workspace_tempdir("dod-poc-cargo-");
    let src_dir = temp_proj.path().join("src");
    fs::create_dir_all(&src_dir).expect("mkdir src");

    // Standalone `[workspace]` prevents Cargo from climbing up to the parent workspace Cargo.toml.
    fs::write(
        temp_proj.path().join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"poc-frame-decoder\"\n",
            "version = \"0.1.0\"\n",
            "edition = \"2021\"\n\n",
            "[workspace]\n",
        ),
    )
    .expect("write temp Cargo.toml");
    fs::write(src_dir.join("lib.rs"), build_poc_lib_rs(true)).expect("write buggy lib.rs");

    let counter_file = temp_proj.path().join("execution_counter.txt");
    let bin = env!("CARGO_BIN_EXE_context-engine");

    let mut child = Command::new(bin)
        .args([
            "mcp",
            "--workspace",
            temp_proj.path().to_str().expect("utf8 workspace"),
            "--session",
            "poc-dod-session",
        ])
        .env("RUST_LOG", "info")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn context-engine mcp subprocess");

    let child_pid = child.id().expect("child pid");
    let mut stdin = child.stdin.take().expect("child stdin");
    let stdout = child.stdout.take().expect("child stdout");
    let mut reader = BufReader::new(stdout);

    // 1. `initialize` -> `notifications/initialized` -> `tools/list` -> `context_doctor`
    send_newline_rpc(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "wave4-e2e-harness", "version": "1.0.0" }
            }
        }),
    )
    .await;
    let init_resp = recv_newline_rpc(&mut reader).await;
    assert_eq!(init_resp["id"], 1);
    assert_eq!(init_resp["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(init_resp["result"]["serverInfo"]["name"], "context-engine");

    send_newline_rpc(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    )
    .await;

    send_newline_rpc(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }),
    )
    .await;
    let list_resp = recv_newline_rpc(&mut reader).await;
    let tools = list_resp["result"]["tools"]
        .as_array()
        .expect("tools array");
    assert_eq!(tools.len(), 7);
    let expected_names = [
        "context_run",
        "context_index",
        "context_search",
        "context_get",
        "context_resume",
        "context_stats",
        "context_doctor",
    ];
    for expected in expected_names {
        let descriptor = tools
            .iter()
            .find(|t| t["name"] == expected)
            .unwrap_or_else(|| panic!("missing MCP tool '{expected}'"));
        assert_eq!(descriptor["inputSchema"]["type"], "object");
        assert_eq!(descriptor["inputSchema"]["additionalProperties"], false);
    }

    send_newline_rpc(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "context_doctor",
                "arguments": {}
            }
        }),
    )
    .await;
    let doc_resp = recv_newline_rpc(&mut reader).await;
    assert_eq!(doc_resp["result"]["isError"], false);
    let doctor: DoctorReport = serde_json::from_str(
        doc_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("doctor text"),
    )
    .expect("parse DoctorReport");
    assert!(doctor.healthy);
    assert!(doctor.store_permissions.private_only);
    assert!(!doctor.execution_policy.allow_shell);

    // Audit zero outbound/inbound TCP/UDP sockets on live `context-engine` PID!
    assert_zero_network_sockets_for_pid(child_pid).await;

    // 2. Run failing `cargo test` via `context_run { argv: ["cargo", "test"] }`
    send_newline_rpc(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "context_run",
                "arguments": {
                    "argv": ["cargo", "test"],
                    "timeout_ms": 180000
                }
            }
        }),
    )
    .await;
    let fail_run_resp = recv_newline_rpc(&mut reader).await;
    assert_eq!(fail_run_resp["result"]["isError"], false);
    let fail_env: ArtifactEnvelope = serde_json::from_str(
        fail_run_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("fail envelope text"),
    )
    .expect("parse failing ArtifactEnvelope");

    // Verify `cargo test` ran STRICTLY ONCE (`execution_counter.txt == 1`)!
    let count_after_fail: u64 = fs::read_to_string(&counter_file)
        .expect("read execution_counter.txt")
        .trim()
        .parse()
        .expect("parse counter");
    assert_eq!(
        count_after_fail, 1,
        "cargo test must execute strictly once during context_run"
    );

    // Verify exit code 101 preserved, failing test identifier retained, originals_available == true
    assert_eq!(fail_env.source.exit_code(), Some(101));
    assert!(fail_env.capture.originals_available);
    assert!(fail_env.capture.complete);
    assert!(fail_env
        .view
        .failure_identifiers
        .iter()
        .any(|id| id.contains("verifies_packet_checksum_and_increments_marker")));
    assert!(fail_env
        .view
        .safe_excerpt
        .contains("verifies_packet_checksum_and_increments_marker"));

    // Zero-egress check immediately after subprocess execution
    assert_zero_network_sockets_for_pid(child_pid).await;

    // 3. `context_search` for the failed assertion string -> ranked hit with artifact_id & LineRange
    send_newline_rpc(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "context_search",
                "arguments": {
                    "query": "packet_decoder_multiline_assertion_9941"
                }
            }
        }),
    )
    .await;
    let search_resp = recv_newline_rpc(&mut reader).await;
    assert_eq!(search_resp["result"]["isError"], false);
    let search_out: SearchQueryOutcome = serde_json::from_str(
        search_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("search text"),
    )
    .expect("parse SearchQueryOutcome");
    assert!(search_out.hit_count >= 1);
    let top_hit = &search_out.hits[0];
    assert_eq!(top_hit.artifact_id, fail_env.artifact_id);

    // 4. `context_get` for the exact line range -> byte/line-accurate recovery WITHOUT re-running `cargo test`
    send_newline_rpc(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "context_get",
                "arguments": {
                    "artifact_id": fail_env.artifact_id.as_str(),
                    "stream": top_hit.stream.as_str(),
                    "lines": {
                        "start": top_hit.line_range.start_line,
                        "end": top_hit.line_range.end_line
                    }
                }
            }
        }),
    )
    .await;
    let get_resp = recv_newline_rpc(&mut reader).await;
    assert_eq!(get_resp["result"]["isError"], false);
    let get_slice: GetSliceOutcome = serde_json::from_str(
        get_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("get text"),
    )
    .expect("parse GetSliceOutcome");
    match get_slice {
        GetSliceOutcome::Lines(page) => {
            assert_eq!(page.sha256, fail_env.capture.stdout_sha256);
            assert!(page
                .text
                .contains("packet_decoder_multiline_assertion_9941: frame CRC digest mismatch"));
            assert!(page.text.contains("PacketFrameHeader"));
            assert!(page.text.contains("crc32_digest"));
        }
        GetSliceOutcome::Bytes(_) => panic!("expected Lines slice outcome"),
    }

    // Also recover stderr lines (`Compiling poc-frame-decoder` / `error: test failed`)
    send_newline_rpc(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": "6-stderr",
            "method": "tools/call",
            "params": {
                "name": "context_get",
                "arguments": {
                    "artifact_id": fail_env.artifact_id.as_str(),
                    "stream": "stderr",
                    "lines": "1:25"
                }
            }
        }),
    )
    .await;
    let stderr_get_resp = recv_newline_rpc(&mut reader).await;
    assert_eq!(stderr_get_resp["result"]["isError"], false);

    // Execution counter MUST STILL BE 1 after `context_search` + `context_get`!
    let count_after_get: u64 = fs::read_to_string(&counter_file)
        .expect("read execution_counter.txt after get")
        .trim()
        .parse()
        .expect("parse counter");
    assert_eq!(
        count_after_get, 1,
        "context_search and context_get must NEVER re-run cargo test"
    );

    // Verify `context_resume` currently tracks the unresolved failure before the fix
    send_newline_rpc(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": "6-pre-resume",
            "method": "tools/call",
            "params": {
                "name": "context_resume",
                "arguments": { "create_checkpoint": false }
            }
        }),
    )
    .await;
    let pre_resume_resp = recv_newline_rpc(&mut reader).await;
    let pre_resume: ResumePack = serde_json::from_str(
        pre_resume_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("pre_resume text"),
    )
    .expect("parse pre ResumePack");
    assert!(
        pre_resume
            .unresolved_failures
            .iter()
            .any(|f| f.contains("verifies_packet_checksum_and_increments_marker")),
        "expected active unresolved failure before fix, got {:?}",
        pre_resume.unresolved_failures
    );

    // 5. Fix the buggy Rust file in `<temp_proj>` and re-run `context_run { argv: ["cargo", "test"] }`
    fs::write(src_dir.join("lib.rs"), build_poc_lib_rs(false)).expect("write fixed lib.rs");

    send_newline_rpc(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "context_run",
                "arguments": {
                    "argv": ["cargo", "test"],
                    "timeout_ms": 180000
                }
            }
        }),
    )
    .await;
    let pass_run_resp = recv_newline_rpc(&mut reader).await;
    assert_eq!(pass_run_resp["result"]["isError"], false);
    let pass_env: ArtifactEnvelope = serde_json::from_str(
        pass_run_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("pass envelope text"),
    )
    .expect("parse passing ArtifactEnvelope");

    assert_eq!(pass_env.source.exit_code(), Some(0));
    assert!(pass_env.view.failure_identifiers.is_empty());
    assert!(pass_env.view.safe_excerpt.contains("PASS (exit 0)"));
    assert!(pass_env.view.safe_excerpt.contains("37 passed, 0 failed"));

    let count_after_fix: u64 = fs::read_to_string(&counter_file)
        .expect("read counter after fix")
        .trim()
        .parse()
        .expect("parse counter");
    assert_eq!(count_after_fix, 2);

    // 6. `context_resume { create_checkpoint: true, note: "fixed bug" }` -> resolved failure tracking!
    send_newline_rpc(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "context_resume",
                "arguments": {
                    "create_checkpoint": true,
                    "note": "fixed bug"
                }
            }
        }),
    )
    .await;
    let resume_resp = recv_newline_rpc(&mut reader).await;
    assert_eq!(resume_resp["result"]["isError"], false);
    let resume_pack: ResumePack = serde_json::from_str(
        resume_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("resume text"),
    )
    .expect("parse ResumePack");
    let cp = resume_pack
        .latest_checkpoint
        .expect("checkpoint must exist");
    assert_eq!(cp.note.as_deref(), Some("fixed bug"));
    assert!(
        resume_pack.unresolved_failures.is_empty(),
        "passing cargo test in same family must clear unresolved_failures, got {:?}",
        resume_pack.unresolved_failures
    );

    // 7. `context_stats` -> verify positive net saved bytes & tokens even after search + get overhead
    send_newline_rpc(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "context_stats",
                "arguments": {}
            }
        }),
    )
    .await;
    let stats_resp = recv_newline_rpc(&mut reader).await;
    assert_eq!(stats_resp["result"]["isError"], false);
    let stats: EngineStatsReport = serde_json::from_str(
        stats_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("stats text"),
    )
    .expect("parse EngineStatsReport");
    assert_eq!(stats.session.command_captures, 2);
    assert_eq!(stats.session.search_queries, 1);
    assert_eq!(stats.session.retrieval_calls, 2);
    assert_eq!(stats.session.checkpoints_created, 1);
    assert!(
        stats.session.net_saved_bytes > 0,
        "expected positive net_saved_bytes, got {} (raw={}, view={}, retrieved={})",
        stats.session.net_saved_bytes,
        stats.session.raw_bytes,
        stats.session.view_bytes,
        stats.session.retrieved_bytes
    );
    assert!(
        stats.session.estimated_net_saved_tokens > 0,
        "expected positive estimated_net_saved_tokens, got {}",
        stats.session.estimated_net_saved_tokens
    );

    drop(stdin);
    let exit_status = child.wait().await.expect("wait mcp child");
    assert!(exit_status.success());
}

#[tokio::test]
async fn live_mcp_subprocess_content_length_framing_and_cli_binary_roundtrip_matrix() {
    let ws = workspace_tempdir("lsp-and-cli-matrix-");
    let bin = env!("CARGO_BIN_EXE_context-engine");

    // Copy both a structured document and a 4,096-byte binary fixture into the test workspace
    let repo_fixtures = repo_root().join("fixtures");
    let log_src = fs::read(repo_fixtures.join("documents/noisy_service.log")).expect("read log");
    fs::write(ws.path().join("noisy_service.log"), &log_src).expect("write workspace log");

    // Deterministic 4,096-byte non-UTF-8 binary payload (PNG magic + high-bit bytes + NULs)
    let mut original_binary: Vec<u8> = Vec::with_capacity(4_096);
    original_binary.extend_from_slice(
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00\x00\x00\x01\x00\x08\x06\x00\x00\x00",
    );
    let mut b_idx = 0usize;
    while original_binary.len() < 4_096 {
        original_binary.push(((b_idx.wrapping_mul(73)).wrapping_add(0x80)) as u8);
        b_idx += 1;
    }
    let expected_bin_sha = sha256_hex(&original_binary);
    let ws_bin_file = ws.path().join("artifact_sample.bin");
    fs::write(&ws_bin_file, &original_binary).expect("write binary file");

    // =========================================================================
    // Part A: Real subprocess MCP over `Content-Length:` LSP-style framing
    // =========================================================================
    let mut mcp_child = Command::new(bin)
        .args([
            "mcp",
            "--workspace",
            ws.path().to_str().expect("utf8"),
            "--session",
            "lsp-framing-s1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn mcp child for Content-Length test");

    let mut lsp_in = mcp_child.stdin.take().expect("stdin");
    let lsp_out = mcp_child.stdout.take().expect("stdout");
    let mut lsp_reader = BufReader::new(lsp_out);

    send_content_length_rpc(
        &mut lsp_in,
        &json!({
            "jsonrpc": "2.0",
            "id": "cl-1",
            "method": "initialize",
            "params": { "protocolVersion": "2024-11-05" }
        }),
    )
    .await;
    let cl_init = recv_content_length_rpc(&mut lsp_reader).await;
    assert_eq!(cl_init["id"], "cl-1");
    assert_eq!(cl_init["result"]["protocolVersion"], "2024-11-05");

    send_content_length_rpc(
        &mut lsp_in,
        &json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }),
    )
    .await;

    send_content_length_rpc(
        &mut lsp_in,
        &json!({
            "jsonrpc": "2.0",
            "id": "cl-2",
            "method": "tools/call",
            "params": {
                "name": "context_index",
                "arguments": { "path": "noisy_service.log" }
            }
        }),
    )
    .await;
    let cl_idx = recv_content_length_rpc(&mut lsp_reader).await;
    assert_eq!(cl_idx["result"]["isError"], false);
    let idx_env: ArtifactEnvelope = serde_json::from_str(
        cl_idx["result"]["content"][0]["text"]
            .as_str()
            .expect("idx text"),
    )
    .expect("parse idx envelope");

    send_content_length_rpc(
        &mut lsp_in,
        &json!({
            "jsonrpc": "2.0",
            "id": "cl-3",
            "method": "tools/call",
            "params": {
                "name": "context_search",
                "arguments": { "query": "E_BLOB_CHECKSUM" }
            }
        }),
    )
    .await;
    let cl_search = recv_content_length_rpc(&mut lsp_reader).await;
    assert_eq!(cl_search["result"]["isError"], false);
    let search_res: SearchQueryOutcome = serde_json::from_str(
        cl_search["result"]["content"][0]["text"]
            .as_str()
            .expect("search text"),
    )
    .expect("parse search");
    assert_eq!(search_res.hit_count, 1);
    assert_eq!(search_res.hits[0].artifact_id, idx_env.artifact_id);

    drop(lsp_in);
    assert!(mcp_child.wait().await.expect("wait lsp mcp").success());

    // =========================================================================
    // Part B: Full CLI Subcommand Matrix + 100% Binary SHA-256 Round-Trip
    // =========================================================================
    let ws_str = ws.path().to_str().expect("utf8");

    // 1. `index <binary_file> --json`
    let idx_bin_out = Command::new(bin)
        .args([
            "index",
            "artifact_sample.bin",
            "--workspace",
            ws_str,
            "--session",
            "cli-matrix",
            "--json",
        ])
        .output()
        .await
        .expect("cli index binary");
    assert!(idx_bin_out.status.success());
    let bin_env: ArtifactEnvelope =
        serde_json::from_slice(&idx_bin_out.stdout).expect("parse binary envelope");
    assert_eq!(bin_env.capture.stdout_sha256, expected_bin_sha);
    assert_eq!(bin_env.capture.stdout_bytes, 4_096);

    // 2. Paginated `get --bytes` reconstructing 100% of binary bytes with SHA-256 match
    let mut reconstructed = Vec::with_capacity(4_096);
    for range_spec in ["0:1500", "1500:3100", "3100:4096"] {
        let get_out = Command::new(bin)
            .args([
                "get",
                bin_env.artifact_id.as_str(),
                "--bytes",
                range_spec,
                "--workspace",
                ws_str,
                "--session",
                "cli-matrix",
                "--json",
            ])
            .output()
            .await
            .expect("cli get --bytes");
        assert!(get_out.status.success());
        let page_json: Value = serde_json::from_slice(&get_out.stdout).expect("parse byte page");
        assert_eq!(page_json["mode"], "bytes");
        assert_eq!(page_json["sha256"], expected_bin_sha);
        let chunk = base64::engine::general_purpose::STANDARD
            .decode(page_json["base64_bytes"].as_str().expect("base64_bytes"))
            .expect("decode base64");
        reconstructed.extend_from_slice(&chunk);
    }
    assert_eq!(reconstructed.len(), original_binary.len());
    assert_eq!(sha256_hex(&reconstructed), expected_bin_sha);
    assert_eq!(reconstructed, original_binary);

    // 3. `index --stdin` + `search --all-sessions` + `get --lines` (compact text mode)
    let mut stdin_idx = Command::new(bin)
        .args([
            "index",
            "--stdin",
            "--label",
            "stdin-doc",
            "--workspace",
            ws_str,
            "--session",
            "cli-matrix",
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn index --stdin");
    {
        let mut pipe = stdin_idx.stdin.take().expect("stdin");
        pipe.write_all(b"alpha line 1\ncanary_cli_matrix_token_8842 on line 2\nomega line 3\n")
            .await
            .expect("write stdin");
    }
    let stdin_idx_out = stdin_idx.wait_with_output().await.expect("wait index");
    assert!(stdin_idx_out.status.success());
    let stdin_env: ArtifactEnvelope =
        serde_json::from_slice(&stdin_idx_out.stdout).expect("parse stdin env");

    let search_all_out = Command::new(bin)
        .args([
            "search",
            "canary_cli_matrix_token_8842",
            "--workspace",
            ws_str,
            "--all-sessions",
        ])
        .output()
        .await
        .expect("cli search");
    assert!(search_all_out.status.success());
    let search_text = String::from_utf8_lossy(&search_all_out.stdout);
    assert!(search_text.contains(stdin_env.artifact_id.as_str()));

    let get_lines_text_out = Command::new(bin)
        .args([
            "get",
            stdin_env.artifact_id.as_str(),
            "--lines",
            "1:3",
            "--workspace",
            ws_str,
            "--session",
            "cli-matrix",
        ])
        .output()
        .await
        .expect("cli get --lines text");
    assert!(get_lines_text_out.status.success());
    assert!(String::from_utf8_lossy(&get_lines_text_out.stdout)
        .contains("canary_cli_matrix_token_8842"));

    // 4. `run` compact text banner & exit code passthrough + `resume` + `stats` + `doctor` + `prune`
    let run_compact = Command::new(bin)
        .args([
            "run",
            "--workspace",
            ws_str,
            "--session",
            "cli-matrix",
            "--",
            "python",
            "-c",
            "import sys; sys.stdout.write('hello compact banner\\n'); sys.exit(17)",
        ])
        .output()
        .await
        .expect("cli run");
    assert_eq!(run_compact.status.code(), Some(17));
    assert!(String::from_utf8_lossy(&run_compact.stdout).starts_with("[context-engine:v1 "));

    let resume_cli = Command::new(bin)
        .args([
            "resume",
            "--workspace",
            ws_str,
            "--session",
            "cli-matrix",
            "--checkpoint",
            "--note",
            "matrix-checkpoint",
        ])
        .output()
        .await
        .expect("cli resume");
    assert!(resume_cli.status.success());
    assert!(String::from_utf8_lossy(&resume_cli.stdout).contains("cp_"));

    let stats_cli = Command::new(bin)
        .args(["stats", "--workspace", ws_str, "--all-sessions"])
        .output()
        .await
        .expect("cli stats");
    assert!(stats_cli.status.success());
    assert!(String::from_utf8_lossy(&stats_cli.stdout).contains("stats [scope=ws_"));

    let doctor_cli = Command::new(bin)
        .args(["doctor", "--workspace", ws_str])
        .output()
        .await
        .expect("cli doctor");
    assert!(doctor_cli.status.success());
    assert!(String::from_utf8_lossy(&doctor_cli.stdout).contains("doctor: HEALTHY"));

    let prune_cli = Command::new(bin)
        .args([
            "prune",
            "--workspace",
            ws_str,
            "--ttl-secs",
            "0",
            "--json",
        ])
        .output()
        .await
        .expect("cli prune");
    assert!(prune_cli.status.success());
    let prune_report: EnginePruneReport =
        serde_json::from_slice(&prune_cli.stdout).expect("parse EnginePruneReport");
    assert!(prune_report.store.expired_artifacts >= 3);
    assert_eq!(prune_report.store.remaining_artifacts, 0);
}

#[tokio::test]
async fn live_setup_generator_and_real_agent_adapters_hooks_idempotence_and_coexistence() {
    let bin = env!("CARGO_BIN_EXE_context-engine");
    let adapters_dir = repo_root().join("adapters");

    // =========================================================================
    // 1. `context-engine setup --client all --output-dir <temp_integrations>`
    // =========================================================================
    let target_ws = workspace_tempdir("setup-target-ws-");
    let integrations_out = workspace_tempdir("setup-integrations-out-");

    let setup_out = Command::new(bin)
        .args([
            "setup",
            "--client",
            "all",
            "--workspace",
            target_ws.path().to_str().expect("utf8"),
            "--binary",
            bin,
            "--output-dir",
            integrations_out.path().to_str().expect("utf8"),
            "--json",
        ])
        .output()
        .await
        .expect("run setup --client all");
    assert!(
        setup_out.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&setup_out.stderr)
    );
    let setup_json: Value = serde_json::from_slice(&setup_out.stdout).expect("parse setup report");
    assert_eq!(setup_json["mode"], "output_dir");
    assert_eq!(setup_json["dry_run"], false);
    assert_eq!(setup_json["clients"].as_array().expect("clients").len(), 5);
    assert_eq!(setup_json["files"].as_array().expect("files").len(), 22);

    // Validate every rendered client config file on disk (`cursor`, `claude-code`, `opencode`, `codex`, `generic`)
    let expected_json_configs = [
        ".cursor/mcp.json",
        ".cursor/hooks.json",
        ".mcp.json",
        ".claude/settings.local.json",
        "opencode.json",
        ".mcp.stdio.json",
    ];
    for rel in expected_json_configs {
        let content = fs::read_to_string(integrations_out.path().join(rel))
            .unwrap_or_else(|e| panic!("missing rendered JSON config {rel}: {e}"));
        assert!(
            !content.contains("{{"),
            "unresolved template placeholder in {rel}"
        );
        let parsed: Value = serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("invalid JSON in {rel}: {e}"));
        assert!(parsed.is_object(), "{rel} must be a JSON object");
    }

    let codex_toml = fs::read_to_string(integrations_out.path().join(".codex/config.toml"))
        .expect("read rendered .codex/config.toml");
    assert!(!codex_toml.contains("{{"));
    assert!(codex_toml.contains("[mcp_servers.context_engine]"));
    assert!(codex_toml.contains("command = "));
    assert!(codex_toml.contains("args = [\"mcp\", \"--workspace\", "));

    for static_rel in [
        ".cursor/rules/context-engine.mdc",
        ".cursor/hooks/post-command-capture.ps1",
        ".cursor/hooks/post-command-capture.sh",
        ".claude/skills/context-engine/SKILL.md",
        ".claude/context-engine.CLAUDE.snippet.md",
        ".claude/hooks/post-tool-reduce.mjs",
        ".opencode/plugin/context-engine-plugin.mjs",
        ".codex/context-engine.AGENTS.snippet.md",
        ".context-engine/bin/ce-run.ps1",
        ".context-engine/bin/ce-run.sh",
    ] {
        assert!(
            integrations_out.path().join(static_rel).is_file(),
            "expected rendered static asset {static_rel}"
        );
    }

    // Build a realistic > 6 KiB noisy Cargo test output for live adapter/hook runs
    let noisy_raw_output = fs::read_to_string(
        repo_root().join("fixtures/commands/cargo_test_failing_multiline.stdout.txt"),
    )
    .expect("read failing cargo fixture")
    .repeat(3);
    assert!(noisy_raw_output.len() > 6_000);

    // =========================================================================
    // 2. Claude Code Hook (`adapters/claude-code/hooks/post-tool-reduce.mjs` via `node`)
    // =========================================================================
    let claude_ws = workspace_tempdir("claude-hook-ws-");
    let claude_hook = adapters_dir.join("claude-code/hooks/post-tool-reduce.mjs");

    let claude_event = json!({
        "hook_event_name": "PostToolUse",
        "session_id": "claude-hook-s1",
        "cwd": claude_ws.path().to_str().expect("utf8"),
        "tool_name": "Bash",
        "tool_input": { "command": "cargo test --workspace" },
        "tool_response": {
            "stdout": noisy_raw_output,
            "stderr": ""
        }
    });

    let mut node_child = Command::new("node")
        .args([
            claude_hook.to_str().expect("utf8"),
            "--binary",
            bin,
            "--workspace",
            claude_ws.path().to_str().expect("utf8"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn node for post-tool-reduce.mjs");
    {
        let mut s = node_child.stdin.take().expect("stdin");
        s.write_all(claude_event.to_string().as_bytes())
            .await
            .expect("write hook stdin");
    }
    let claude_out = node_child.wait_with_output().await.expect("wait claude hook");
    assert!(claude_out.status.success());
    let claude_hook_json: Value =
        serde_json::from_slice(&claude_out.stdout).expect("parse claude hook JSON");
    let add_ctx = claude_hook_json["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("additionalContext");
    assert!(add_ctx.starts_with("[context-engine:reduced artifact_id=a_"));
    assert!(add_ctx.contains("cargo_test@1"));

    // Verify idempotence & coexistence: already-reduced, Envelope JSON, Headroom, and Caveman
    // MUST all yield empty stdout and MUST NOT index a second artifact!
    let envelope_marker = format!(
        "{{\"schema_version\":1,\"artifact_id\":\"a_{}\",\"view\":{{\"transformations\":[\"cargo_test@1\"]}},\"padding\":\"{}\"}}",
        "0".repeat(64),
        "x".repeat(5_000)
    );
    let headroom_marker = format!("[headroom smart_crusher CCR-abcdef12]\n{}", "h".repeat(5_000));
    let caveman_marker = format!("<!-- caveman-compress -->\n{}", "c".repeat(5_000));
    let already_reduced_banner = format!("{add_ctx}\n{}", "r".repeat(5_000));

    for (label, skip_output) in [
        ("already_reduced_banner", already_reduced_banner),
        ("artifact_envelope_json", envelope_marker.clone()),
        ("headroom_marker", headroom_marker.clone()),
        ("caveman_marker", caveman_marker.clone()),
    ] {
        let repeat_event = json!({
            "hook_event_name": "PostToolUse",
            "session_id": "claude-hook-s1",
            "cwd": claude_ws.path().to_str().expect("utf8"),
            "tool_name": "Bash",
            "tool_input": { "command": "cargo test" },
            "tool_response": { "stdout": skip_output, "stderr": "" }
        });
        let mut ch = Command::new("node")
            .args([
                claude_hook.to_str().expect("utf8"),
                "--binary",
                bin,
                "--workspace",
                claude_ws.path().to_str().expect("utf8"),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn claude hook idempotence check");
        {
            let mut s = ch.stdin.take().expect("stdin");
            s.write_all(repeat_event.to_string().as_bytes())
                .await
                .expect("write");
        }
        let out = ch.wait_with_output().await.expect("wait");
        assert!(out.status.success());
        assert!(
            out.stdout.is_empty(),
            "expected silent pass-through for '{label}', got: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    let claude_stats_out = Command::new(bin)
        .args([
            "stats",
            "--workspace",
            claude_ws.path().to_str().expect("utf8"),
            "--session",
            "claude-hook-s1",
            "--json",
        ])
        .output()
        .await
        .expect("stats claude_ws");
    let claude_stats: EngineStatsReport =
        serde_json::from_slice(&claude_stats_out.stdout).expect("parse claude stats");
    assert_eq!(
        claude_stats.session.document_indexes, 1,
        "Claude hook must index noisy output once and skip all 4 already-reduced/coexisting payloads"
    );

    // =========================================================================
    // 3. OpenCode Plugin (`adapters/opencode/plugin/context-engine-plugin.mjs` via `node`)
    // =========================================================================
    let opencode_ws = workspace_tempdir("opencode-plugin-ws-");
    let opencode_plugin_url = format!(
        "file:///{}",
        adapters_dir
            .join("opencode/plugin/context-engine-plugin.mjs")
            .to_string_lossy()
            .replace('\\', "/")
    );
    let opencode_driver_mjs = format!(
        r#"
import fs from "node:fs";
import {{ ContextEnginePlugin, invokeContextEngineRun }} from {plugin_url:?};

const ws = process.env.CONTEXT_ENGINE_WORKSPACE;
const bin = process.env.CONTEXT_ENGINE_BIN;
const noisy = fs.readFileSync(process.env.NOISY_FILE, "utf8");

const hooks = await ContextEnginePlugin({{ worktree: ws }});

// 1. Reduce noisy bash output
const out1 = {{ output: noisy, metadata: {{}} }};
await hooks["tool.execute.after"](
  {{ tool: "bash", sessionID: "opencode-s1", args: {{ command: "cargo test" }} }},
  out1
);
const reducedOnce = out1.output;
const firstArtId = out1.metadata?.contextEngine?.artifactId || "";

// 2. Re-run hook on already-reduced output -> must be strictly idempotent!
await hooks["tool.execute.after"](
  {{ tool: "bash", sessionID: "opencode-s1", args: {{ command: "cargo test" }} }},
  out1
);
const unchangedAfterSecondPass = out1.output === reducedOnce;

// 3. Coexistence with Headroom & Caveman markers
const hrOut = {{ output: "[headroom smart_crusher CCR-11223344]\n" + "x".repeat(6000), metadata: {{}} }};
await hooks["tool.execute.after"](
  {{ tool: "bash", sessionID: "opencode-s1", args: {{ command: "pytest" }} }},
  hrOut
);
const cvOut = {{ output: "[caveman compressed]\n" + "y".repeat(6000), metadata: {{}} }};
await hooks["tool.execute.after"](
  {{ tool: "bash", sessionID: "opencode-s1", args: {{ command: "pytest" }} }},
  cvOut
);

// 4. Direct argv invokeContextEngineRun
const runEnv = invokeContextEngineRun({{
  binaryPath: bin,
  workspacePath: ws,
  argv: ["python", "-c", "import sys; sys.stdout.write('opencode-argv-ok\\n'); sys.exit(9)"],
  sessionId: "opencode-s1",
}});

console.log(JSON.stringify({{
  reducedStartsWithMarker: reducedOnce.startsWith("[context-engine:reduced artifact_id=a_"),
  smallerThanRaw: Buffer.byteLength(reducedOnce, "utf8") < Buffer.byteLength(noisy, "utf8"),
  firstArtId,
  unchangedAfterSecondPass,
  headroomUntouched: hrOut.output.startsWith("[headroom"),
  cavemanUntouched: cvOut.output.startsWith("[caveman"),
  runExitCode: runEnv.source.exit_code,
}}));
"#,
        plugin_url = opencode_plugin_url
    );
    let noisy_file_path = opencode_ws.path().join("noisy_input.txt");
    fs::write(&noisy_file_path, &noisy_raw_output).expect("write noisy_input.txt");

    let opencode_out = Command::new("node")
        .args(["--input-type=module", "-e", &opencode_driver_mjs])
        .env("CONTEXT_ENGINE_BIN", bin)
        .env(
            "CONTEXT_ENGINE_WORKSPACE",
            opencode_ws.path().to_str().expect("utf8"),
        )
        .env("NOISY_FILE", noisy_file_path.to_str().expect("utf8"))
        .output()
        .await
        .expect("run OpenCode plugin driver");
    assert!(
        opencode_out.status.success(),
        "OpenCode plugin driver failed: {}",
        String::from_utf8_lossy(&opencode_out.stderr)
    );
    let oc_res: Value =
        serde_json::from_slice(&opencode_out.stdout).expect("parse OpenCode result");
    assert_eq!(oc_res["reducedStartsWithMarker"], true);
    assert_eq!(oc_res["smallerThanRaw"], true);
    assert_eq!(oc_res["unchangedAfterSecondPass"], true);
    assert_eq!(oc_res["headroomUntouched"], true);
    assert_eq!(oc_res["cavemanUntouched"], true);
    assert_eq!(oc_res["runExitCode"], 9);

    let oc_stats_out = Command::new(bin)
        .args([
            "stats",
            "--workspace",
            opencode_ws.path().to_str().expect("utf8"),
            "--session",
            "opencode-s1",
            "--json",
        ])
        .output()
        .await
        .expect("stats opencode_ws");
    let oc_stats: EngineStatsReport =
        serde_json::from_slice(&oc_stats_out.stdout).expect("parse opencode stats");
    assert_eq!(oc_stats.session.document_indexes, 1);
    assert_eq!(oc_stats.session.command_captures, 1);

    // =========================================================================
    // 4. Cursor Hook (`adapters/cursor/hooks/post-command-capture.ps1` via `powershell`)
    // =========================================================================
    let cursor_ws = workspace_tempdir("cursor-hook-ws-");
    let cursor_hook = adapters_dir.join("cursor/hooks/post-command-capture.ps1");

    let cursor_noisy_payload = json!({
        "command": "cargo test --all-targets",
        "output": noisy_raw_output,
        "cwd": cursor_ws.path().to_str().expect("utf8"),
        "conversation_id": "cursor-conv-1"
    });
    let mut ps_hook = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            cursor_hook.to_str().expect("utf8"),
            "-BinaryPath",
            bin,
            "-WorkspacePath",
            cursor_ws.path().to_str().expect("utf8"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cursor hook");
    {
        let mut s = ps_hook.stdin.take().expect("stdin");
        s.write_all(cursor_noisy_payload.to_string().as_bytes())
            .await
            .expect("write cursor hook stdin");
    }
    let ps_out = ps_hook.wait_with_output().await.expect("wait cursor hook");
    assert!(ps_out.status.success());
    assert_eq!(String::from_utf8_lossy(&ps_out.stdout).trim(), "{}");

    // Feed already-reduced & coexisting optimizer payloads to Cursor hook -> must NOT re-index!
    for skip_text in [&envelope_marker, &headroom_marker, &caveman_marker] {
        let skip_payload = json!({
            "command": "cargo test",
            "output": skip_text,
            "cwd": cursor_ws.path().to_str().expect("utf8"),
            "conversation_id": "cursor-conv-1"
        });
        let mut ps_skip = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                cursor_hook.to_str().expect("utf8"),
                "-BinaryPath",
                bin,
                "-WorkspacePath",
                cursor_ws.path().to_str().expect("utf8"),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn cursor skip hook");
        {
            let mut s = ps_skip.stdin.take().expect("stdin");
            s.write_all(skip_payload.to_string().as_bytes())
                .await
                .expect("write");
        }
        let skip_res = ps_skip.wait_with_output().await.expect("wait");
        assert!(skip_res.status.success());
        assert_eq!(String::from_utf8_lossy(&skip_res.stdout).trim(), "{}");
    }

    let cursor_stats_out = Command::new(bin)
        .args([
            "stats",
            "--workspace",
            cursor_ws.path().to_str().expect("utf8"),
            "--session",
            "cursor-conv-1",
            "--json",
        ])
        .output()
        .await
        .expect("stats cursor_ws");
    let cursor_stats: EngineStatsReport =
        serde_json::from_slice(&cursor_stats_out.stdout).expect("parse cursor stats");
    assert_eq!(cursor_stats.session.document_indexes, 1);

    // =========================================================================
    // 5. Generic Wrapper (`adapters/generic-mcp/wrappers/ce-run.ps1` via `powershell`)
    // =========================================================================
    let ce_ws = workspace_tempdir("ce-run-wrapper-ws-");
    let ce_run_ps1 = adapters_dir.join("generic-mcp/wrappers/ce-run.ps1");

    let ce_out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ce_run_ps1.to_str().expect("utf8"),
            "--",
            "python",
            "-c",
            "import sys; sys.stdout.write('ce-run line\\n' * 200); sys.exit(23)",
        ])
        .env("CONTEXT_ENGINE_BIN", bin)
        .env(
            "CONTEXT_ENGINE_WORKSPACE",
            ce_ws.path().to_str().expect("utf8"),
        )
        .env("CONTEXT_ENGINE_SESSION", "ce-run-s1")
        .output()
        .await
        .expect("run ce-run.ps1");
    assert_eq!(
        ce_out.status.code(),
        Some(23),
        "ce-run.ps1 must preserve child exit code 23; stderr={}",
        String::from_utf8_lossy(&ce_out.stderr)
    );
    let ce_stdout = String::from_utf8_lossy(&ce_out.stdout);
    assert!(
        ce_stdout.starts_with("[context-engine:v1 artifact=a_"),
        "expected compact banner from ce-run.ps1, got: {ce_stdout}"
    );

    // Recursion guard: calling `ce-run.ps1 <bin> --version` must pass straight through without capturing!
    let ce_passthrough = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            ce_run_ps1.to_str().expect("utf8"),
            bin,
            "--version",
        ])
        .env("CONTEXT_ENGINE_BIN", bin)
        .env(
            "CONTEXT_ENGINE_WORKSPACE",
            ce_ws.path().to_str().expect("utf8"),
        )
        .env("CONTEXT_ENGINE_SESSION", "ce-run-s1")
        .output()
        .await
        .expect("run ce-run.ps1 recursion guard");
    assert!(ce_passthrough.status.success());
    assert!(String::from_utf8_lossy(&ce_passthrough.stdout).contains("context-engine"));

    let ce_stats_out = Command::new(bin)
        .args([
            "stats",
            "--workspace",
            ce_ws.path().to_str().expect("utf8"),
            "--session",
            "ce-run-s1",
            "--json",
        ])
        .output()
        .await
        .expect("stats ce_ws");
    let ce_stats: EngineStatsReport =
        serde_json::from_slice(&ce_stats_out.stdout).expect("parse ce stats");
    assert_eq!(
        ce_stats.session.command_captures, 1,
        "ce-run recursion guard must prevent capturing context-engine itself"
    );
}
