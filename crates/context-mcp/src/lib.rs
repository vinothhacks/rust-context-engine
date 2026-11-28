//! Server-scoped stdio JSON-RPC 2.0 MCP server and unified 9-step `ContextEngine` pipeline.

#![forbid(unsafe_code)]

pub mod engine;
pub mod protocol;
pub mod tools;

pub use context_core::{ArtifactEnvelope, BoundScope};
pub use engine::{
    ByteSliceResponse, ContextEngine, DoctorReport, EngineConfig, EnginePruneReport,
    EngineStatsReport, ExecutionPolicySummary, GetRangeSelector, GetSliceOutcome, GetSliceRequest,
    IndexDocumentOutcome, IndexDocumentRequest, IndexSource, ResumeRequest, RunCommandOutcome,
    RunCommandRequest, SearchQueryOutcome, SearchQueryRequest, SecretPolicySummary,
};
pub use protocol::{
    run_server_over_streams, run_stdio_server, FramingMode, JsonRpcError, JsonRpcResponse,
    DEFAULT_MCP_PROTOCOL_VERSION, JSONRPC_INTERNAL_ERROR, JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST, JSONRPC_METHOD_NOT_FOUND, JSONRPC_PARSE_ERROR, MAX_RPC_FRAME_BYTES,
    SUPPORTED_MCP_PROTOCOL_VERSIONS,
};
pub use tools::{
    dispatch_tool_call, tool_definitions, CallToolResult, InvalidToolParams, McpToolDescriptor,
    ToolErrorPayload, ToolTextContent, MAX_MCP_TOOL_OUTPUT_BYTES, TOOL_CONTEXT_DOCTOR,
    TOOL_CONTEXT_GET, TOOL_CONTEXT_INDEX, TOOL_CONTEXT_RESUME, TOOL_CONTEXT_RUN,
    TOOL_CONTEXT_SEARCH, TOOL_CONTEXT_STATS,
};

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;
    use std::time::Duration;

    use base64::Engine as _;
    use context_core::sha256_hex;
    use context_journal::ResumePack;
    use serde_json::{json, Value};
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    use super::*;

    async fn send_newline_rpc<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, msg: &Value) {
        let mut line = serde_json::to_vec(msg).expect("serialize rpc");
        line.push(b'\n');
        writer.write_all(&line).await.expect("write line");
        writer.flush().await.expect("flush line");
    }

    async fn recv_newline_rpc<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Value {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.expect("read line");
        assert!(n > 0, "unexpected EOF waiting for JSON-RPC line");
        serde_json::from_str(&line).expect("parse JSON-RPC line")
    }

    #[tokio::test]
    async fn full_7_tool_pipeline_over_newline_delimited_stdio_protocol() {
        let ws = TempDir::new().expect("workspace");
        fs::write(
            ws.path().join("service.log"),
            concat!(
                "2026-11-22T12:00:00Z INFO Booting service\n",
                "2026-11-22T12:00:01Z ERROR Database pool exhausted code=DB_POOL_99 token=ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD\n",
                "2026-11-22T12:00:02Z INFO Retrying connection\n",
            ),
        )
        .expect("write service.log");

        let engine = Arc::new(
            ContextEngine::open_workspace(ws.path(), Some("mcp-e2e")).expect("open engine"),
        );

        let (mut client_wr, server_rd) = tokio::io::duplex(256 * 1024);
        let (server_wr, client_rd) = tokio::io::duplex(256 * 1024);
        let mut client_buf = BufReader::new(client_rd);

        let srv_engine = Arc::clone(&engine);
        let server_task = tokio::spawn(async move {
            run_server_over_streams(srv_engine, BufReader::new(server_rd), server_wr)
                .await
                .expect("server exited cleanly");
        });

        // 1. `initialize` with `"2025-06-18"` protocol negotiation + `notifications/initialized` + `ping`
        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "test-client", "version": "1.0.0" }
                }
            }),
        )
        .await;
        let init_resp = recv_newline_rpc(&mut client_buf).await;
        assert_eq!(init_resp["id"], 1);
        assert_eq!(init_resp["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(init_resp["result"]["serverInfo"]["name"], "context-engine");
        assert_eq!(
            init_resp["result"]["capabilities"]["tools"]["listChanged"],
            false
        );

        // Notification must NOT emit a response frame.
        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }),
        )
        .await;

        send_newline_rpc(
            &mut client_wr,
            &json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" }),
        )
        .await;
        let ping_resp = recv_newline_rpc(&mut client_buf).await;
        assert_eq!(ping_resp["id"], 2);
        assert_eq!(ping_resp["result"], json!({}));

        // 2. `tools/list` exposes all 7 tools with `additionalProperties: false`
        send_newline_rpc(
            &mut client_wr,
            &json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" }),
        )
        .await;
        let list_resp = recv_newline_rpc(&mut client_buf).await;
        let tools = list_resp["result"]["tools"]
            .as_array()
            .expect("tools array");
        assert_eq!(tools.len(), 7);
        for t in tools {
            assert_eq!(t["inputSchema"]["additionalProperties"], false);
        }

        // 3. `context_run` capturing both stdout test summary and stderr diagnostic lines
        let py_script = concat!(
            "import sys\n",
            "sys.stdout.write('running 2 tests\\ntest alpha ... ok\\ntest beta ... FAILED\\n\\nfailures:\\n\\n---- beta stdout ----\\nthread \\'beta\\' panicked at src/lib.rs:42:5:\\nassertion failed: expected_valid_signature\\n\\nfailures:\\n    beta\\n\\ntest result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\\n')\n",
            "sys.stderr.write('error: test failed, to rerun pass `--lib`\\n')\n",
            "sys.exit(101)\n",
        );
        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "context_run",
                    "arguments": {
                        "argv": ["python", "-c", py_script]
                    }
                }
            }),
        )
        .await;
        let run_resp = recv_newline_rpc(&mut client_buf).await;
        assert_eq!(run_resp["result"]["isError"], false);
        let run_text = run_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("text");
        let run_env: ArtifactEnvelope = serde_json::from_str(run_text).expect("ArtifactEnvelope");
        assert_eq!(run_env.source.exit_code(), Some(101));
        assert_eq!(run_env.view.failure_identifiers, vec!["beta"]);
        assert!(run_env.view.safe_excerpt.contains("FAIL beta"));

        // 4. `context_index` on workspace file (containing a GitHub token that must be redacted before FTS5)
        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "context_index",
                    "arguments": {
                        "path": "service.log"
                    }
                }
            }),
        )
        .await;
        let idx_resp = recv_newline_rpc(&mut client_buf).await;
        assert_eq!(idx_resp["result"]["isError"], false);
        let idx_env: ArtifactEnvelope = serde_json::from_str(
            idx_resp["result"]["content"][0]["text"]
                .as_str()
                .expect("text"),
        )
        .expect("index envelope");
        assert!(idx_env.capture.secrets_redacted >= 1);
        assert!(!idx_env.view.safe_excerpt.contains("ghp_0123456789"));

        // 5. `context_search` finds both DB_POOL_99 and expected_valid_signature, NEVER the raw secret
        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "context_search",
                    "arguments": {
                        "query": "expected_valid_signature",
                        "limit": 5
                    }
                }
            }),
        )
        .await;
        let search_resp = recv_newline_rpc(&mut client_buf).await;
        assert_eq!(search_resp["result"]["isError"], false);
        let search_out: SearchQueryOutcome = serde_json::from_str(
            search_resp["result"]["content"][0]["text"]
                .as_str()
                .expect("search text"),
        )
        .expect("SearchQueryOutcome");
        assert!(search_out.hit_count >= 1);
        assert_eq!(search_out.hits[0].artifact_id, run_env.artifact_id);
        assert_eq!(search_out.hits[0].stream, context_core::StreamKind::Stdout);

        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": "6b",
                "method": "tools/call",
                "params": {
                    "name": "context_search",
                    "arguments": {
                        "query": "DB_POOL_99"
                    }
                }
            }),
        )
        .await;
        let log_search_resp = recv_newline_rpc(&mut client_buf).await;
        let log_search_out: SearchQueryOutcome = serde_json::from_str(
            log_search_resp["result"]["content"][0]["text"]
                .as_str()
                .expect("text"),
        )
        .expect("SearchQueryOutcome");
        assert_eq!(log_search_out.hit_count, 1);
        assert_eq!(log_search_out.hits[0].artifact_id, idx_env.artifact_id);

        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "context_search",
                    "arguments": {
                        "query": "ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD"
                    }
                }
            }),
        )
        .await;
        let secret_search = recv_newline_rpc(&mut client_buf).await;
        let secret_hits: SearchQueryOutcome = serde_json::from_str(
            secret_search["result"]["content"][0]["text"]
                .as_str()
                .expect("text"),
        )
        .expect("SearchQueryOutcome");
        assert_eq!(secret_hits.hit_count, 0);

        // 6. `context_get` via string `"1:20"` AND object `{"start": 0, "end": 64}`
        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {
                    "name": "context_get",
                    "arguments": {
                        "artifact_id": run_env.artifact_id.as_str(),
                        "stream": "stdout",
                        "lines": "6:11"
                    }
                }
            }),
        )
        .await;
        let get_lines_resp = recv_newline_rpc(&mut client_buf).await;
        assert_eq!(get_lines_resp["result"]["isError"], false);
        let get_lines_val: Value = serde_json::from_str(
            get_lines_resp["result"]["content"][0]["text"]
                .as_str()
                .expect("text"),
        )
        .expect("json");
        assert_eq!(get_lines_val["mode"], "lines");
        assert!(get_lines_val["text"]
            .as_str()
            .expect("text")
            .contains("expected_valid_signature"));

        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "context_get",
                    "arguments": {
                        "artifact_id": run_env.artifact_id.as_str(),
                        "stream": "stderr",
                        "bytes": { "start": 0, "end": 64 }
                    }
                }
            }),
        )
        .await;
        let get_bytes_resp = recv_newline_rpc(&mut client_buf).await;
        assert_eq!(get_bytes_resp["result"]["isError"], false);
        let get_bytes_val: Value = serde_json::from_str(
            get_bytes_resp["result"]["content"][0]["text"]
                .as_str()
                .expect("text"),
        )
        .expect("json");
        assert_eq!(get_bytes_val["mode"], "bytes");
        let raw_decoded = base64::engine::general_purpose::STANDARD
            .decode(get_bytes_val["base64_bytes"].as_str().expect("b64"))
            .expect("decode b64");
        assert_eq!(sha256_hex(&raw_decoded), run_env.capture.stderr_sha256);

        // 7. `context_resume` with `create_checkpoint: true`
        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "context_resume",
                    "arguments": {
                        "create_checkpoint": true,
                        "note": "captured failing beta test"
                    }
                }
            }),
        )
        .await;
        let resume_resp = recv_newline_rpc(&mut client_buf).await;
        assert_eq!(resume_resp["result"]["isError"], false);
        let resume_pack: ResumePack = serde_json::from_str(
            resume_resp["result"]["content"][0]["text"]
                .as_str()
                .expect("text"),
        )
        .expect("ResumePack");
        assert!(resume_pack.latest_checkpoint.is_some());
        assert_eq!(resume_pack.unresolved_failures, vec!["beta"]);

        // 8. `context_stats` & `context_doctor`
        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "context_stats",
                    "arguments": {}
                }
            }),
        )
        .await;
        let stats_resp = recv_newline_rpc(&mut client_buf).await;
        let stats: EngineStatsReport = serde_json::from_str(
            stats_resp["result"]["content"][0]["text"]
                .as_str()
                .expect("text"),
        )
        .expect("EngineStatsReport");
        assert_eq!(stats.session.command_captures, 1);
        assert_eq!(stats.session.document_indexes, 1);
        assert_eq!(stats.session.retrieval_calls, 2);
        assert_eq!(stats.store.artifact_count, 2);

        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "context_doctor",
                    "arguments": {}
                }
            }),
        )
        .await;
        let doc_resp = recv_newline_rpc(&mut client_buf).await;
        let doctor: DoctorReport = serde_json::from_str(
            doc_resp["result"]["content"][0]["text"]
                .as_str()
                .expect("text"),
        )
        .expect("DoctorReport");
        assert!(doctor.healthy);
        assert!(doctor.store_permissions.private_only);
        assert!(doctor.search_health.healthy);
        assert!(doctor.journal_health.healthy);
        assert!(!doctor.execution_policy.allow_shell);

        drop(client_wr);
        server_task.await.expect("join server");
    }

    #[tokio::test]
    async fn auto_detects_and_replies_with_content_length_framing() {
        let ws = TempDir::new().expect("workspace");
        let engine = Arc::new(ContextEngine::open_workspace(ws.path(), None).expect("open engine"));

        let (mut client_wr, server_rd) = tokio::io::duplex(64 * 1024);
        let (server_wr, client_rd) = tokio::io::duplex(64 * 1024);
        let mut client_buf = BufReader::new(client_rd);

        let server_task = tokio::spawn(async move {
            run_server_over_streams(engine, BufReader::new(server_rd), server_wr)
                .await
                .expect("server ok");
        });

        let req_bytes = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": "lsp-1",
            "method": "initialize",
            "params": { "protocolVersion": "2024-11-05" }
        }))
        .expect("serialize");
        let framed = format!(
            "Content-Length: {}\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n",
            req_bytes.len()
        );
        client_wr
            .write_all(framed.as_bytes())
            .await
            .expect("write header");
        client_wr.write_all(&req_bytes).await.expect("write body");
        client_wr.flush().await.expect("flush");

        // Verify reply uses `Content-Length: <N>\r\n\r\n<body>`!
        let mut hdr_line = String::new();
        client_buf
            .read_line(&mut hdr_line)
            .await
            .expect("read Content-Length header");
        assert!(
            hdr_line.starts_with("Content-Length: "),
            "expected Content-Length header, got: {hdr_line:?}"
        );
        let resp_len: usize = hdr_line["Content-Length: ".len()..]
            .trim()
            .parse()
            .expect("parse length");

        let mut blank = String::new();
        client_buf.read_line(&mut blank).await.expect("read blank");
        assert_eq!(blank, "\r\n");

        let mut body = vec![0u8; resp_len];
        client_buf.read_exact(&mut body).await.expect("read body");
        let resp: Value = serde_json::from_slice(&body).expect("valid JSON body");
        assert_eq!(resp["id"], "lsp-1");
        assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");

        drop(client_wr);
        server_task.await.expect("join");
    }

    #[tokio::test]
    async fn strict_schema_validation_security_denials_and_cancellation() {
        let ws_a = TempDir::new().expect("ws_a");
        let ws_b = TempDir::new().expect("ws_b");
        fs::write(ws_a.path().join(".env"), "SECRET_KEY=topsecret\n").expect("write .env");

        let engine_a =
            Arc::new(ContextEngine::open_workspace(ws_a.path(), Some("sec-sess")).expect("open A"));
        let engine_b =
            ContextEngine::open_workspace(ws_b.path(), Some("sec-sess")).expect("open B");
        let foreign_art = engine_b
            .index_document(IndexDocumentRequest {
                source: IndexSource::InlineBytes(b"confidential B".to_vec()),
                label: Some("b-doc".into()),
                media_type: None,
                session_id: None,
                client_project_scope: None,
            })
            .await
            .expect("index B")
            .envelope
            .artifact_id;

        // Transplant manifest into A's store directory to test active forged cross-workspace rejection!
        let src_m = engine_b
            .store()
            .manifest_path_for_id(&foreign_art)
            .expect("src");
        let dst_m = engine_a
            .store()
            .manifest_path_for_id(&foreign_art)
            .expect("dst");
        fs::copy(src_m, dst_m).expect("copy forged manifest");

        let (mut client_wr, server_rd) = tokio::io::duplex(128 * 1024);
        let (server_wr, client_rd) = tokio::io::duplex(128 * 1024);
        let mut client_buf = BufReader::new(client_rd);

        let srv_engine = Arc::clone(&engine_a);
        let server_task = tokio::spawn(async move {
            run_server_over_streams(srv_engine, BufReader::new(server_rd), server_wr)
                .await
                .expect("server ok");
        });

        // 1. Malformed JSON -> -32700 Parse error, server stays alive!
        client_wr
            .write_all(b"{not-valid-json\n")
            .await
            .expect("write bad json");
        client_wr.flush().await.expect("flush");
        let parse_err = recv_newline_rpc(&mut client_buf).await;
        assert_eq!(parse_err["error"]["code"], JSONRPC_PARSE_ERROR);

        // 2. Unknown property (`additionalProperties: false`) -> -32602 Invalid params
        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": "bad-prop",
                "method": "tools/call",
                "params": {
                    "name": "context_run",
                    "arguments": {
                        "argv": ["git", "status"],
                        "unexpected_flag": true
                    }
                }
            }),
        )
        .await;
        let bad_prop = recv_newline_rpc(&mut client_buf).await;
        assert_eq!(bad_prop["error"]["code"], JSONRPC_INVALID_PARAMS);

        // 3. Blocked command (`cmd /c dir`), blocked `.env`, and forged cross-workspace `context_get`
        //    all return `isError: true` AND increment `security_denials` in SessionJournal!
        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": "deny-shell",
                "method": "tools/call",
                "params": {
                    "name": "context_run",
                    "arguments": { "argv": ["cmd", "/c", "dir"] }
                }
            }),
        )
        .await;
        let deny_shell = recv_newline_rpc(&mut client_buf).await;
        assert_eq!(deny_shell["result"]["isError"], true);
        assert!(deny_shell["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("EXECUTION_DENIED"));

        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": "deny-dotenv",
                "method": "tools/call",
                "params": {
                    "name": "context_index",
                    "arguments": { "path": ".env" }
                }
            }),
        )
        .await;
        let deny_dotenv = recv_newline_rpc(&mut client_buf).await;
        assert_eq!(deny_dotenv["result"]["isError"], true);
        assert!(deny_dotenv["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("SENSITIVE_PATH_BLOCKED"));

        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": "deny-forged",
                "method": "tools/call",
                "params": {
                    "name": "context_get",
                    "arguments": { "artifact_id": foreign_art.as_str() }
                }
            }),
        )
        .await;
        let deny_forged = recv_newline_rpc(&mut client_buf).await;
        assert_eq!(deny_forged["result"]["isError"], true);
        assert!(deny_forged["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("SCOPE_VIOLATION"));

        let stats = engine_a.stats(None, false).expect("stats");
        assert_eq!(stats.session.security_denials, 3);

        // 4. Cooperative `notifications/cancelled` terminates a long-running `context_run`
        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "id": "slow-1",
                "method": "tools/call",
                "params": {
                    "name": "context_run",
                    "arguments": {
                        "argv": ["python", "-c", "import time; time.sleep(20)"],
                        "timeout_ms": 20000
                    }
                }
            }),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        send_newline_rpc(
            &mut client_wr,
            &json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": { "requestId": "slow-1", "reason": "user aborted" }
            }),
        )
        .await;

        let cancelled_resp =
            tokio::time::timeout(Duration::from_secs(5), recv_newline_rpc(&mut client_buf))
                .await
                .expect("cancelled command must finish promptly");
        assert_eq!(cancelled_resp["id"], "slow-1");
        let cancelled_env: ArtifactEnvelope = serde_json::from_str(
            cancelled_resp["result"]["content"][0]["text"]
                .as_str()
                .expect("text"),
        )
        .expect("envelope");
        assert!(!cancelled_env.capture.complete);

        drop(client_wr);
        server_task.await.expect("join");
    }
}
