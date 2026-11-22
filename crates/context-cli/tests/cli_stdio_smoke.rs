//! Real binary subprocess tests verifying pure MCP `stdout` framing (even with `RUST_LOG=debug`),
//! `index --stdin`, `get`, and exact `run` exit-code passthrough.

#![forbid(unsafe_code)]

use std::process::Stdio;

use context_core::ArtifactEnvelope;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

#[tokio::test]
async fn real_binary_mcp_stdio_emits_zero_stray_stdout_logs_and_runs_end_to_end() {
    let ws = TempDir::new().expect("ws");
    let bin = env!("CARGO_BIN_EXE_context-engine");

    let mut child = Command::new(bin)
        .args(["mcp", "--workspace", ws.path().to_str().expect("utf8")])
        // Even with verbose `RUST_LOG=debug`, stdout MUST carry ONLY pure JSON-RPC frames!
        .env("RUST_LOG", "debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn context-engine mcp");

    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut reader = BufReader::new(stdout);

    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": { "protocolVersion": "2024-11-05" }
    });
    stdin
        .write_all(format!("{init_req}\n").as_bytes())
        .await
        .expect("write init");
    stdin.flush().await.expect("flush");

    let mut line1 = String::new();
    reader.read_line(&mut line1).await.expect("read init reply");
    let resp1: Value = serde_json::from_str(&line1).expect("pure JSON-RPC on stdout");
    assert_eq!(resp1["id"], 1);
    assert_eq!(resp1["result"]["serverInfo"]["name"], "context-engine");

    let doc_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "context_doctor",
            "arguments": {}
        }
    });
    stdin
        .write_all(format!("{doc_req}\n").as_bytes())
        .await
        .expect("write doctor");
    stdin.flush().await.expect("flush");

    let mut line2 = String::new();
    reader.read_line(&mut line2).await.expect("read doctor reply");
    let resp2: Value = serde_json::from_str(&line2).expect("pure JSON-RPC on stdout");
    assert_eq!(resp2["result"]["isError"], false);

    drop(stdin);
    let status = child.wait().await.expect("wait child");
    assert!(status.success());
}

#[tokio::test]
async fn real_binary_index_stdin_get_and_exit_code_passthrough() {
    let ws = TempDir::new().expect("ws");
    let bin = env!("CARGO_BIN_EXE_context-engine");

    // 1. `index --stdin --json`
    let mut idx_child = Command::new(bin)
        .args([
            "index",
            "--stdin",
            "--json",
            "--label",
            "piped-log",
            "--workspace",
            ws.path().to_str().expect("utf8"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn index --stdin");

    {
        let mut s = idx_child.stdin.take().expect("stdin");
        s.write_all(b"line one\nERROR: fatal_ disk_corruption_777\nline three\n")
            .await
            .expect("write stdin");
    }
    let idx_out = idx_child.wait_with_output().await.expect("wait index");
    assert!(idx_out.status.success());
    let env: ArtifactEnvelope =
        serde_json::from_slice(&idx_out.stdout).expect("parse ArtifactEnvelope");

    // 2. `get <artifact_id> --lines 1:3 --json`
    let get_out = Command::new(bin)
        .args([
            "get",
            env.artifact_id.as_str(),
            "--lines",
            "1:3",
            "--workspace",
            ws.path().to_str().expect("utf8"),
            "--json",
        ])
        .output()
        .await
        .expect("run get");
    assert!(get_out.status.success());
    let get_val: Value = serde_json::from_slice(&get_out.stdout).expect("parse get json");
    assert!(get_val["text"]
        .as_str()
        .expect("text")
        .contains("disk_corruption_777"));

    // 3. `run` exit code passthrough (child exits 37 -> context-engine exits 37!)
    let run_out = Command::new(bin)
        .args([
            "run",
            "--workspace",
            ws.path().to_str().expect("utf8"),
            "--",
            "python",
            "-c",
            "import sys; sys.exit(37)",
        ])
        .output()
        .await
        .expect("run passthrough");
    assert_eq!(run_out.status.code(), Some(37));
}
