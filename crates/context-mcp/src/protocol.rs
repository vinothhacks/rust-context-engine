//! MCP stdio JSON-RPC 2.0 transport supporting both official newline-delimited JSON-RPC
//! and auto-detected `Content-Length:` LSP-style header framing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use context_capture::CaptureCancelToken;
use context_core::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinSet;

use crate::engine::ContextEngine;
use crate::tools::{dispatch_tool_call, tool_definitions, InvalidToolParams};

/// Default advertised MCP protocol version.
pub const DEFAULT_MCP_PROTOCOL_VERSION: &str = "2024-11-05";

/// Supported MCP protocol versions for clean client negotiation.
pub const SUPPORTED_MCP_PROTOCOL_VERSIONS: &[&str] = &["2024-11-05", "2025-03-26", "2025-06-18"];

/// Maximum byte size of a single inbound JSON-RPC frame (`18 MiB`).
pub const MAX_RPC_FRAME_BYTES: usize = 18 * 1024 * 1024;

/// Maximum number of HTTP-style header lines permitted in a `Content-Length:` frame.
const MAX_HEADER_LINES: usize = 16;
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;

/// Standard JSON-RPC 2.0 error codes.
pub const JSONRPC_PARSE_ERROR: i32 = -32700;
pub const JSONRPC_INVALID_REQUEST: i32 = -32600;
pub const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
pub const JSONRPC_INVALID_PARAMS: i32 = -32602;
pub const JSONRPC_INTERNAL_ERROR: i32 = -32603;

/// Wire framing mode detected per inbound message and echoed on its reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingMode {
    /// Official MCP stdio transport: one UTF-8 JSON message per `\n`-terminated line.
    NewlineDelimited,
    /// LSP-compatible `Content-Length: <bytes>\r\n\r\n<utf8-json>` header framing.
    ContentLength,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    #[must_use]
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub fn error(id: Value, code: i32, message: impl Into<String>, data: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data,
            }),
        }
    }
}

enum FrameReadOutcome {
    Eof,
    Message {
        framing: FramingMode,
        payload: Vec<u8>,
    },
    ProtocolError {
        framing: FramingMode,
        code: i32,
        message: String,
    },
}

struct ServerState<W> {
    engine: Arc<ContextEngine>,
    writer: Arc<AsyncMutex<W>>,
    in_flight: Arc<StdMutex<HashMap<String, CaptureCancelToken>>>,
    initialized: AtomicBool,
}

/// Runs the MCP JSON-RPC 2.0 server over `tokio::io::stdin()` and `tokio::io::stdout()`.
///
/// Guarantees zero stray diagnostic writes to `stdout`; all protocol frames are written
/// exclusively through the synchronized response writer.
pub async fn run_stdio_server(engine: Arc<ContextEngine>) -> Result<()> {
    let stdin = BufReader::new(tokio::io::stdin());
    let stdout = tokio::io::stdout();
    run_server_over_streams(engine, stdin, stdout).await
}

/// Runs the MCP JSON-RPC 2.0 server over arbitrary async `reader` and `writer` streams.
pub async fn run_server_over_streams<R, W>(
    engine: Arc<ContextEngine>,
    mut reader: R,
    writer: W,
) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let state = Arc::new(ServerState {
        engine,
        writer: Arc::new(AsyncMutex::new(writer)),
        in_flight: Arc::new(StdMutex::new(HashMap::new())),
        initialized: AtomicBool::new(false),
    });

    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut last_framing = FramingMode::NewlineDelimited;

    loop {
        // Reap any completed background tool tasks without blocking.
        while tasks.try_join_next().is_some() {}

        match read_next_frame(&mut reader, last_framing).await? {
            FrameReadOutcome::Eof => break,
            FrameReadOutcome::ProtocolError {
                framing,
                code,
                message,
            } => {
                last_framing = framing;
                let err_resp = JsonRpcResponse::error(Value::Null, code, message, None);
                write_frame(&state.writer, framing, &serde_json::to_vec(&err_resp)?).await?;
            }
            FrameReadOutcome::Message { framing, payload } => {
                last_framing = framing;
                let parsed: Value = match serde_json::from_slice(&payload) {
                    Ok(v) => v,
                    Err(err) => {
                        let resp = JsonRpcResponse::error(
                            Value::Null,
                            JSONRPC_PARSE_ERROR,
                            format!("JSON parse error: {err}"),
                            None,
                        );
                        write_frame(&state.writer, framing, &serde_json::to_vec(&resp)?).await?;
                        continue;
                    }
                };

                match parsed {
                    Value::Object(obj) => {
                        dispatch_single_object(Arc::clone(&state), &mut tasks, framing, obj)
                            .await?;
                    }
                    Value::Array(batch) => {
                        dispatch_batch(Arc::clone(&state), &mut tasks, framing, batch).await?;
                    }
                    _ => {
                        let resp = JsonRpcResponse::error(
                            Value::Null,
                            JSONRPC_INVALID_REQUEST,
                            "JSON-RPC 2.0 payload must be an object or non-empty batch array",
                            None,
                        );
                        write_frame(&state.writer, framing, &serde_json::to_vec(&resp)?).await?;
                    }
                }
            }
        }
    }

    // Drain any in-flight asynchronous tool calls cleanly before closing stdout.
    while tasks.join_next().await.is_some() {}
    let mut guard = state.writer.lock().await;
    guard.flush().await?;
    Ok(())
}

async fn dispatch_single_object<W>(
    state: Arc<ServerState<W>>,
    tasks: &mut JoinSet<()>,
    framing: FramingMode,
    obj: Map<String, Value>,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    match classify_rpc_object(obj) {
        RpcEnvelope::Invalid { id, message } => {
            let resp = JsonRpcResponse::error(id, JSONRPC_INVALID_REQUEST, message, None);
            write_frame(&state.writer, framing, &serde_json::to_vec(&resp)?).await
        }
        RpcEnvelope::Notification { method, params } => {
            handle_notification(&state, &method, params.as_ref());
            Ok(())
        }
        RpcEnvelope::Request { id, method, params } => {
            if method == "tools/call" {
                let state_bg = Arc::clone(&state);
                tasks.spawn(async move {
                    let resp = handle_tools_call(&state_bg, id, params.as_ref()).await;
                    if let Ok(bytes) = serde_json::to_vec(&resp) {
                        let _ = write_frame(&state_bg.writer, framing, &bytes).await;
                    }
                });
                Ok(())
            } else {
                let resp = handle_sync_request(&state, id, &method, params.as_ref());
                write_frame(&state.writer, framing, &serde_json::to_vec(&resp)?).await
            }
        }
    }
}

async fn dispatch_batch<W>(
    state: Arc<ServerState<W>>,
    _tasks: &mut JoinSet<()>,
    framing: FramingMode,
    batch: Vec<Value>,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    if batch.is_empty() {
        let resp = JsonRpcResponse::error(
            Value::Null,
            JSONRPC_INVALID_REQUEST,
            "JSON-RPC 2.0 batch array must not be empty",
            None,
        );
        return write_frame(&state.writer, framing, &serde_json::to_vec(&resp)?).await;
    }

    let mut responses: Vec<JsonRpcResponse> = Vec::new();
    for item in batch {
        let Value::Object(obj) = item else {
            responses.push(JsonRpcResponse::error(
                Value::Null,
                JSONRPC_INVALID_REQUEST,
                "batch item must be a JSON object",
                None,
            ));
            continue;
        };
        match classify_rpc_object(obj) {
            RpcEnvelope::Invalid { id, message } => {
                responses.push(JsonRpcResponse::error(
                    id,
                    JSONRPC_INVALID_REQUEST,
                    message,
                    None,
                ));
            }
            RpcEnvelope::Notification { method, params } => {
                handle_notification(&state, &method, params.as_ref());
            }
            RpcEnvelope::Request { id, method, params } => {
                if method == "tools/call" {
                    responses.push(handle_tools_call(&state, id, params.as_ref()).await);
                } else {
                    responses.push(handle_sync_request(&state, id, &method, params.as_ref()));
                }
            }
        }
    }

    if !responses.is_empty() {
        write_frame(&state.writer, framing, &serde_json::to_vec(&responses)?).await?;
    }
    Ok(())
}

enum RpcEnvelope {
    Request {
        id: Value,
        method: String,
        params: Option<Value>,
    },
    Notification {
        method: String,
        params: Option<Value>,
    },
    Invalid {
        id: Value,
        message: String,
    },
}

fn classify_rpc_object(mut obj: Map<String, Value>) -> RpcEnvelope {
    let has_id = obj.contains_key("id");
    let raw_id = obj.remove("id").unwrap_or(Value::Null);

    if has_id && !matches!(raw_id, Value::Null | Value::String(_) | Value::Number(_)) {
        return RpcEnvelope::Invalid {
            id: Value::Null,
            message: "JSON-RPC 'id' must be a string, number, or null".to_string(),
        };
    }

    match obj.get("jsonrpc").and_then(Value::as_str) {
        Some("2.0") => {}
        _ => {
            return RpcEnvelope::Invalid {
                id: if has_id { raw_id } else { Value::Null },
                message: "JSON-RPC 'jsonrpc' field must equal '2.0'".to_string(),
            };
        }
    }

    let Some(method) = obj.remove("method").and_then(|v| match v {
        Value::String(s) if !s.is_empty() => Some(s),
        _ => None,
    }) else {
        return RpcEnvelope::Invalid {
            id: if has_id { raw_id } else { Value::Null },
            message: "JSON-RPC 'method' must be a non-empty string".to_string(),
        };
    };

    let params = obj.remove("params");
    if let Some(ref p) = params {
        if !p.is_object() && !p.is_array() && !p.is_null() {
            return RpcEnvelope::Invalid {
                id: if has_id { raw_id } else { Value::Null },
                message: "JSON-RPC 'params' must be an object or array when present".to_string(),
            };
        }
    }

    if has_id {
        RpcEnvelope::Request {
            id: raw_id,
            method,
            params,
        }
    } else {
        RpcEnvelope::Notification { method, params }
    }
}

fn handle_notification<W>(state: &ServerState<W>, method: &str, params: Option<&Value>) {
    match method {
        "notifications/initialized" | "initialized" => {
            state.initialized.store(true, Ordering::Release);
        }
        "notifications/cancelled" | "$/cancelRequest" => {
            if let Some(Value::Object(map)) = params {
                let target_id = map.get("requestId").or_else(|| map.get("id"));
                if let Some(id_val) = target_id {
                    if let Some(key) = request_id_key(id_val) {
                        if let Ok(guard) = state.in_flight.lock() {
                            if let Some(token) = guard.get(&key) {
                                token.cancel();
                            }
                        }
                    }
                }
            }
        }
        _ => {
            // Per JSON-RPC 2.0 & MCP spec, unknown notifications are ignored silently.
        }
    }
}

fn handle_sync_request<W>(
    state: &ServerState<W>,
    id: Value,
    method: &str,
    params: Option<&Value>,
) -> JsonRpcResponse {
    match method {
        "initialize" => handle_initialize(state, id, params),
        "ping" => JsonRpcResponse::success(id, json!({})),
        "tools/list" => handle_tools_list(state, id, params),
        _ => JsonRpcResponse::error(
            id,
            JSONRPC_METHOD_NOT_FOUND,
            format!("method not found: '{method}'"),
            None,
        ),
    }
}

fn handle_initialize<W>(
    state: &ServerState<W>,
    id: Value,
    params: Option<&Value>,
) -> JsonRpcResponse {
    let mut requested_version: Option<&str> = None;

    if let Some(p) = params {
        let Some(obj) = p.as_object() else {
            return JsonRpcResponse::error(
                id,
                JSONRPC_INVALID_PARAMS,
                "initialize params must be a JSON object",
                None,
            );
        };
        if let Some(pv) = obj.get("protocolVersion") {
            let Some(pv_str) = pv.as_str() else {
                return JsonRpcResponse::error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "initialize params.protocolVersion must be a string",
                    None,
                );
            };
            requested_version = Some(pv_str);
        }
    }

    let negotiated = match requested_version {
        Some(req_v) if SUPPORTED_MCP_PROTOCOL_VERSIONS.contains(&req_v) => req_v,
        _ => DEFAULT_MCP_PROTOCOL_VERSION,
    };

    state.initialized.store(true, Ordering::Release);

    JsonRpcResponse::success(
        id,
        json!({
            "protocolVersion": negotiated,
            "capabilities": {
                "tools": {
                    "listChanged": false
                }
            },
            "serverInfo": {
                "name": "context-engine",
                "version": env!("CARGO_PKG_VERSION")
            },
            "instructions": "Workspace-bound Rust Context Engine. Prefer context_run (explicit argv array) for noisy build/test/Git/search commands, inspect compact ArtifactEnvelope views first, use context_search and bounded context_get instead of re-running commands, and call context_resume after context window compaction."
        }),
    )
}

fn handle_tools_list<W>(
    state: &ServerState<W>,
    id: Value,
    params: Option<&Value>,
) -> JsonRpcResponse {
    if let Some(p) = params {
        if !p.is_null() {
            let Some(obj) = p.as_object() else {
                return JsonRpcResponse::error(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "tools/list params must be a JSON object when provided",
                    None,
                );
            };
            if let Some(cursor) = obj.get("cursor") {
                if !cursor.is_null() && !cursor.is_string() {
                    return JsonRpcResponse::error(
                        id,
                        JSONRPC_INVALID_PARAMS,
                        "tools/list cursor must be a string",
                        None,
                    );
                }
            }
        }
    }

    let tools = tool_definitions(state.engine.budget());
    JsonRpcResponse::success(id, json!({ "tools": tools }))
}

async fn handle_tools_call<W>(
    state: &ServerState<W>,
    id: Value,
    params: Option<&Value>,
) -> JsonRpcResponse {
    let Some(Value::Object(params_obj)) = params else {
        return JsonRpcResponse::error(
            id,
            JSONRPC_INVALID_PARAMS,
            "tools/call requires a JSON object 'params'",
            None,
        );
    };

    for key in params_obj.keys() {
        if !matches!(key.as_str(), "name" | "arguments" | "_meta") {
            return JsonRpcResponse::error(
                id,
                JSONRPC_INVALID_PARAMS,
                format!("unknown tools/call param '{key}'"),
                None,
            );
        }
    }

    let Some(tool_name) = params_obj.get("name").and_then(Value::as_str) else {
        return JsonRpcResponse::error(
            id,
            JSONRPC_INVALID_PARAMS,
            "tools/call requires string field 'params.name'",
            None,
        );
    };

    let raw_arguments = params_obj.get("arguments");

    let cancel_token = CaptureCancelToken::new();
    let id_key = request_id_key(&id);
    if let Some(ref key) = id_key {
        if let Ok(mut guard) = state.in_flight.lock() {
            guard.insert(key.clone(), cancel_token.clone());
        }
    }

    let dispatch_res =
        dispatch_tool_call(&state.engine, tool_name, raw_arguments, &cancel_token).await;

    if let Some(ref key) = id_key {
        if let Ok(mut guard) = state.in_flight.lock() {
            guard.remove(key);
        }
    }

    match dispatch_res {
        Ok(call_result) => match serde_json::to_value(call_result) {
            Ok(val) => JsonRpcResponse::success(id, val),
            Err(err) => JsonRpcResponse::error(
                id,
                JSONRPC_INTERNAL_ERROR,
                format!("failed to serialize tool result: {err}"),
                None,
            ),
        },
        Err(InvalidToolParams { tool, reason }) => JsonRpcResponse::error(
            id,
            JSONRPC_INVALID_PARAMS,
            format!("Invalid params for '{tool}': {reason}"),
            Some(json!({
                "error_code": "INVALID_PARAMS",
                "tool": tool,
                "reason": reason
            })),
        ),
    }
}

fn request_id_key(id: &Value) -> Option<String> {
    match id {
        Value::String(s) => Some(format!("s:{s}")),
        Value::Number(n) => Some(format!("n:{n}")),
        _ => None,
    }
}

async fn write_frame<W>(
    writer: &AsyncMutex<W>,
    framing: FramingMode,
    json_bytes: &[u8],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut guard = writer.lock().await;
    match framing {
        FramingMode::NewlineDelimited => {
            guard.write_all(json_bytes).await?;
            guard.write_all(b"\n").await?;
        }
        FramingMode::ContentLength => {
            let header = format!("Content-Length: {}\r\n\r\n", json_bytes.len());
            guard.write_all(header.as_bytes()).await?;
            guard.write_all(json_bytes).await?;
        }
    }
    guard.flush().await?;
    Ok(())
}

async fn read_next_frame<R>(
    reader: &mut R,
    fallback_framing: FramingMode,
) -> Result<FrameReadOutcome>
where
    R: AsyncBufRead + Unpin,
{
    loop {
        match read_bounded_line(reader, MAX_RPC_FRAME_BYTES).await? {
            BoundedLine::Eof => return Ok(FrameReadOutcome::Eof),
            BoundedLine::Oversized => {
                return Ok(FrameReadOutcome::ProtocolError {
                    framing: fallback_framing,
                    code: JSONRPC_INVALID_REQUEST,
                    message: format!(
                        "inbound JSON-RPC line exceeded maximum frame limit ({MAX_RPC_FRAME_BYTES} bytes)"
                    ),
                });
            }
            BoundedLine::Bytes(line) => {
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }

                if starts_with_ignore_ascii_case(&line, b"content-length:") {
                    return read_content_length_frame(reader, &line).await;
                }

                return Ok(FrameReadOutcome::Message {
                    framing: FramingMode::NewlineDelimited,
                    payload: line,
                });
            }
        }
    }
}

async fn read_content_length_frame<R>(
    reader: &mut R,
    first_header_line: &[u8],
) -> Result<FrameReadOutcome>
where
    R: AsyncBufRead + Unpin,
{
    let raw_len_part = &first_header_line[b"content-length:".len()..];
    let content_length = if first_header_line.len() <= MAX_HEADER_LINE_BYTES {
        std::str::from_utf8(raw_len_part)
            .ok()
            .map(|value| value.trim_matches([' ', '\t']))
            .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<usize>().ok())
    } else {
        None
    };
    let Some(content_length) = content_length else {
        // Consume remaining headers up to blank line so stream stays aligned where possible.
        let _ = drain_headers(reader).await?;
        return Ok(FrameReadOutcome::ProtocolError {
            framing: FramingMode::ContentLength,
            code: JSONRPC_INVALID_REQUEST,
            message: "invalid Content-Length header value".to_string(),
        });
    };

    if !drain_headers(reader).await? {
        return Ok(FrameReadOutcome::ProtocolError {
            framing: FramingMode::ContentLength,
            code: JSONRPC_INVALID_REQUEST,
            message: "excessive or unterminated Content-Length header block".to_string(),
        });
    }

    if content_length > MAX_RPC_FRAME_BYTES {
        drain_exact_bytes(reader, content_length).await?;
        return Ok(FrameReadOutcome::ProtocolError {
            framing: FramingMode::ContentLength,
            code: JSONRPC_INVALID_REQUEST,
            message: format!(
                "Content-Length ({content_length}) exceeds maximum frame limit ({MAX_RPC_FRAME_BYTES} bytes)"
            ),
        });
    }

    let mut body = vec![0u8; content_length];
    if let Err(err) = reader.read_exact(&mut body).await {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(FrameReadOutcome::Eof);
        }
        return Err(err.into());
    }

    Ok(FrameReadOutcome::Message {
        framing: FramingMode::ContentLength,
        payload: body,
    })
}

async fn drain_headers<R>(reader: &mut R) -> Result<bool>
where
    R: AsyncBufRead + Unpin,
{
    for _ in 0..MAX_HEADER_LINES {
        match read_bounded_line(reader, MAX_HEADER_LINE_BYTES).await? {
            BoundedLine::Eof | BoundedLine::Oversized => return Ok(false),
            BoundedLine::Bytes(hdr) if hdr.is_empty() => return Ok(true),
            BoundedLine::Bytes(_) => {}
        }
    }
    Ok(false)
}

async fn drain_exact_bytes<R>(reader: &mut R, mut remaining: usize) -> Result<()>
where
    R: AsyncBufRead + Unpin,
{
    while remaining > 0 {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            break;
        }
        let step = buf.len().min(remaining);
        reader.consume(step);
        remaining -= step;
    }
    Ok(())
}

enum BoundedLine {
    Eof,
    Bytes(Vec<u8>),
    Oversized,
}

async fn read_bounded_line<R>(reader: &mut R, max_bytes: usize) -> Result<BoundedLine>
where
    R: AsyncBufRead + Unpin,
{
    let mut out: Vec<u8> = Vec::new();
    let mut oversized = false;

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if out.is_empty() && !oversized {
                return Ok(BoundedLine::Eof);
            }
            break;
        }

        if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
            let take_len = newline_pos + 1;
            if !oversized {
                if out.len().saturating_add(take_len) <= max_bytes + 2 {
                    out.extend_from_slice(&available[..take_len]);
                } else {
                    oversized = true;
                    out.clear();
                }
            }
            reader.consume(take_len);
            break;
        }

        let chunk_len = available.len();
        if !oversized {
            if out.len().saturating_add(chunk_len) <= max_bytes + 2 {
                out.extend_from_slice(available);
            } else {
                oversized = true;
                out.clear();
            }
        }
        reader.consume(chunk_len);
    }

    trim_crlf(&mut out);
    if oversized || out.len() > max_bytes {
        Ok(BoundedLine::Oversized)
    } else {
        Ok(BoundedLine::Bytes(out))
    }
}

fn trim_crlf(buf: &mut Vec<u8>) {
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
}

fn starts_with_ignore_ascii_case(haystack: &[u8], prefix: &[u8]) -> bool {
    haystack.len() >= prefix.len() && haystack[..prefix.len()].eq_ignore_ascii_case(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_line_checks_payload_length_with_lf_crlf_and_eof() {
        for input in ["abc\n", "abc\r\n", "abc"] {
            let line = read_bounded_line(&mut input.as_bytes(), 3).await.unwrap();
            assert!(matches!(line, BoundedLine::Bytes(bytes) if bytes == b"abc"));
        }
        for input in ["abcd\n", "abcd\r\n", "abcd"] {
            let line = read_bounded_line(&mut input.as_bytes(), 3).await.unwrap();
            assert!(matches!(line, BoundedLine::Oversized));
        }
    }

    #[tokio::test]
    async fn malformed_content_length_has_a_fixed_error_message() {
        for input in [
            "Content-Length: invalid\r\n\r\n".to_string(),
            "Content-Length: +2\r\n\r\n".to_string(),
            format!(
                "Content-Length: {}2\r\n\r\n",
                " ".repeat(MAX_HEADER_LINE_BYTES)
            ),
        ] {
            let frame = read_next_frame(&mut input.as_bytes(), FramingMode::NewlineDelimited)
                .await
                .unwrap();
            assert!(matches!(
                frame,
                FrameReadOutcome::ProtocolError {
                    framing: FramingMode::ContentLength,
                    code: JSONRPC_INVALID_REQUEST,
                    message,
                } if message == "invalid Content-Length header value"
            ));
        }
    }
}
