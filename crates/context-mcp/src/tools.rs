//! MCP tool catalog (`tools/list`), strict JSON Schema input validation (`additionalProperties: false`),
//! tool dispatch (`tools/call`), and bounded structured output guards.

use std::path::PathBuf;

use context_capture::CaptureCancelToken;
use context_core::{
    truncate_str_utf8_boundary, ByteRange, ContextError, LineRange, ReductionBudget, StreamKind,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::engine::{
    ContextEngine, GetRangeSelector, GetSliceRequest, IndexDocumentRequest, IndexSource,
    ResumeRequest, RunCommandRequest, SearchQueryRequest,
};

/// Hard ceiling on serialized UTF-8 text returned in any single MCP `CallToolResult` (`96 KiB`).
///
/// Accommodates a full `32 KiB` `context_get` binary slice encoded in Base64 (`~44 KiB`) plus
/// envelope metadata while guaranteeing bounded output on stdout.
pub const MAX_MCP_TOOL_OUTPUT_BYTES: usize = 96 * 1024;

/// Maximum number of `argv` items accepted by `context_run`.
pub const MAX_ARGV_ITEMS: usize = 256;
/// Maximum UTF-8 byte length of a single `argv` element.
pub const MAX_ARG_BYTES: usize = 16 * 1024;
/// Maximum UTF-8 byte length of `cwd` or `path` tool parameters.
pub const MAX_PATH_BYTES: usize = 4 * 1024;
/// Maximum UTF-8 byte length of `query` in `context_search`.
pub const MAX_QUERY_BYTES: usize = 2 * 1024;
/// Maximum UTF-8 byte length of `label` in `context_index`.
pub const MAX_LABEL_BYTES: usize = 256;
/// Maximum UTF-8 byte length of `media_type` in `context_index`.
pub const MAX_MEDIA_TYPE_BYTES: usize = 128;
/// Maximum UTF-8 byte length of `note` in `context_resume`.
pub const MAX_NOTE_BYTES: usize = 1_024;

/// Canonical MCP tool names exposed by `context-mcp`.
pub const TOOL_CONTEXT_RUN: &str = "context_run";
pub const TOOL_CONTEXT_INDEX: &str = "context_index";
pub const TOOL_CONTEXT_SEARCH: &str = "context_search";
pub const TOOL_CONTEXT_GET: &str = "context_get";
pub const TOOL_CONTEXT_RESUME: &str = "context_resume";
pub const TOOL_CONTEXT_STATS: &str = "context_stats";
pub const TOOL_CONTEXT_DOCTOR: &str = "context_doctor";

/// MCP `Tool` descriptor returned by `tools/list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolDescriptor {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// MCP text content block inside [`CallToolResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolTextContent {
    #[serde(rename = "type")]
    pub kind: String,
    pub text: String,
}

impl ToolTextContent {
    #[must_use]
    pub fn text(value: impl Into<String>) -> Self {
        Self {
            kind: "text".to_string(),
            text: value.into(),
        }
    }
}

/// MCP `CallToolResult` returned by `tools/call`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    pub content: Vec<ToolTextContent>,
    #[serde(default)]
    pub is_error: bool,
}

/// Structured error body emitted inside [`CallToolResult`] when `is_error == true`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolErrorPayload {
    pub error_code: String,
    pub message: String,
    pub security_denial: bool,
}

/// Schema-level validation failure mapped to JSON-RPC `-32602` (`Invalid params`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidToolParams {
    pub tool: String,
    pub reason: String,
}

impl InvalidToolParams {
    fn new(tool: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            reason: reason.into(),
        }
    }
}

/// Builds the complete catalog of all 7 MCP tools with strict `additionalProperties: false` schemas.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn tool_definitions(budget: &ReductionBudget) -> Vec<McpToolDescriptor> {
    let session_prop = json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 128,
        "pattern": "^[A-Za-z0-9._-]+$",
        "description": "Optional session slug ([A-Za-z0-9._-]{1,128}); defaults to server session."
    });

    let line_range_schema = json!({
        "description": format!(
            "1-indexed inclusive line range (max {} lines per call), either 'start:end' (e.g. '1:80') or {{\"start\": 1, \"end\": 80}}.",
            budget.max_get_lines
        ),
        "oneOf": [
            {
                "type": "string",
                "pattern": "^[0-9]+:[0-9]+$"
            },
            {
                "type": "object",
                "properties": {
                    "start": { "type": "integer", "minimum": 1 },
                    "end": { "type": "integer", "minimum": 1 }
                },
                "required": ["start", "end"],
                "additionalProperties": false
            }
        ]
    });

    let byte_range_schema = json!({
        "description": format!(
            "Half-open byte offset range [start, end) (max {} bytes per call), either 'start:end' (e.g. '0:4096') or {{\"start\": 0, \"end\": 4096}}.",
            budget.max_get_bytes
        ),
        "oneOf": [
            {
                "type": "string",
                "pattern": "^[0-9]+:[0-9]+$"
            },
            {
                "type": "object",
                "properties": {
                    "start": { "type": "integer", "minimum": 0 },
                    "end": { "type": "integer", "minimum": 0 }
                },
                "required": ["start", "end"],
                "additionalProperties": false
            }
        ]
    });

    vec![
        McpToolDescriptor {
            name: TOOL_CONTEXT_RUN.to_string(),
            description: "Execute an allowlisted command directly via argv (no shell) inside the server-bound workspace, persist exact stdout/stderr blobs, index sanitized chunks in FTS5, and return a compact ArtifactEnvelope with a bounded context_get recovery handle.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "argv": {
                        "type": "array",
                        "description": "Direct command argv array (e.g. [\"cargo\", \"test\", \"--workspace\"]). Never pass shell command strings.",
                        "minItems": 1,
                        "maxItems": MAX_ARGV_ITEMS,
                        "items": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_ARG_BYTES
                        }
                    },
                    "cwd": {
                        "type": "string",
                        "maxLength": MAX_PATH_BYTES,
                        "description": "Optional working directory relative to the bound workspace root (defaults to '.')."
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 600_000,
                        "description": "Optional timeout in milliseconds (default 120000, max 600000)."
                    },
                    "session_id": session_prop
                },
                "required": ["argv"],
                "additionalProperties": false
            }),
        },
        McpToolDescriptor {
            name: TOOL_CONTEXT_INDEX.to_string(),
            description: "Ingest an allowed workspace file (`path`) OR inline text (`content` + `label`) through SecretGuard into the private zstd blob store and SQLite FTS5 index, returning a compact ArtifactEnvelope.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_PATH_BYTES,
                        "description": "Workspace-confined file path to index (mutually exclusive with `content`)."
                    },
                    "content": {
                        "type": "string",
                        "maxLength": budget.max_capture_stream_bytes,
                        "description": "Inline UTF-8 text to index (mutually exclusive with `path`; requires `label`)."
                    },
                    "label": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_LABEL_BYTES,
                        "description": "Provenance label (required when `content` is supplied; optional override for `path`)."
                    },
                    "media_type": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_MEDIA_TYPE_BYTES,
                        "description": "Optional MIME media type hint (e.g. 'application/json', 'text/plain')."
                    },
                    "session_id": session_prop
                },
                "additionalProperties": false
            }),
        },
        McpToolDescriptor {
            name: TOOL_CONTEXT_SEARCH.to_string(),
            description: "Search sanitized SQLite FTS5 chunks (`bm25()` ranked with Porter stemming) in the bound workspace/session, returning bounded snippets, exact 1-indexed line spans, and `context_get` recovery handles.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_QUERY_BYTES,
                        "description": "Focused lexical keywords, error code, test identifier, or symbol."
                    },
                    "session_only": {
                        "type": "boolean",
                        "default": true,
                        "description": "When true (default), search only the active session; when false, search all sessions in the bound workspace."
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": budget.max_search_results,
                        "default": 10,
                        "description": format!("Maximum ranked hits to return (1..={}, default 10).", budget.max_search_results)
                    },
                    "session_id": session_prop
                },
                "required": ["query"],
                "additionalProperties": false
            }),
        },
        McpToolDescriptor {
            name: TOOL_CONTEXT_GET.to_string(),
            description: "Recover a bounded original slice from `artifact_id` (`stdout`, `stderr`, `combined`, or `document`) by 1-indexed `lines` range or half-open `bytes` range without re-executing commands.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "artifact_id": {
                        "type": "string",
                        "pattern": "^a_[0-9a-f]{64}$",
                        "description": "Opaque server-minted artifact identifier (`a_<64-hex>`)."
                    },
                    "stream": {
                        "type": "string",
                        "enum": ["stdout", "stderr", "combined", "document"],
                        "description": "Target stream; defaults automatically ('stderr' if stdout is empty and stderr is non-empty, 'document' for indexed files, else 'stdout')."
                    },
                    "lines": line_range_schema,
                    "bytes": byte_range_schema,
                    "session_id": session_prop
                },
                "required": ["artifact_id"],
                "additionalProperties": false
            }),
        },
        McpToolDescriptor {
            name: TOOL_CONTEXT_RESUME.to_string(),
            description: "Restore deterministic session state (`ResumePack`) after context compaction or session resume, optionally persisting a fresh checkpoint first. Returns unresolved failure identifiers, recent commands, and active `context_get` handles.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": session_prop,
                    "create_checkpoint": {
                        "type": "boolean",
                        "default": false,
                        "description": "When true, persist a new deterministic session checkpoint before returning the ResumePack."
                    },
                    "note": {
                        "type": "string",
                        "maxLength": MAX_NOTE_BYTES,
                        "description": "Optional sanitized note stored on the checkpoint."
                    }
                },
                "additionalProperties": false
            }),
        },
        McpToolDescriptor {
            name: TOOL_CONTEXT_STATS.to_string(),
            description: "Return non-sensitive session or workspace telemetry: raw vs compact view bytes/tokens, retrieval overhead, net byte/token savings ratios, cache deduplication hits, secrets redacted, and security denial counts.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": session_prop,
                    "all_sessions": {
                        "type": "boolean",
                        "default": false,
                        "description": "Aggregate metrics across all sessions in the bound workspace instead of a single session."
                    }
                },
                "additionalProperties": false
            }),
        },
        McpToolDescriptor {
            name: TOOL_CONTEXT_DOCTOR.to_string(),
            description: "Run a read-only diagnostic check over the bound workspace scope, private `.context-engine/store` ACLs, SQLite WAL + FTS5 integrity, session journal health, command allowlist policy, and SecretGuard mode.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
    ]
}

/// Validates and dispatches an MCP `tools/call` invocation against `engine`.
///
/// - Schema / unknown-tool / unknown-property / oversized-input violations return `Err(InvalidToolParams)`
///   so the JSON-RPC layer responds with `-32602` (`Invalid params`).
/// - Domain / confinement / policy / storage errors return `Ok(CallToolResult { is_error: true, .. })`
///   with a structured [`ToolErrorPayload`] JSON body, never panicking or dropping the stdio connection.
pub async fn dispatch_tool_call(
    engine: &ContextEngine,
    tool_name: &str,
    raw_arguments: Option<&Value>,
    cancel_token: &CaptureCancelToken,
) -> std::result::Result<CallToolResult, InvalidToolParams> {
    let args_obj = extract_arguments_object(tool_name, raw_arguments)?;

    match tool_name {
        TOOL_CONTEXT_RUN => {
            let req = parse_context_run_args(args_obj)?;
            Ok(render_domain_result(
                engine
                    .run_command_with_cancel(req, cancel_token)
                    .await
                    .map(|out| out.envelope),
                engine,
            ))
        }
        TOOL_CONTEXT_INDEX => {
            let req = parse_context_index_args(args_obj, engine.budget())?;
            Ok(render_domain_result(
                engine.index_document(req).await.map(|out| out.envelope),
                engine,
            ))
        }
        TOOL_CONTEXT_SEARCH => {
            let req = parse_context_search_args(args_obj, engine.budget())?;
            Ok(render_domain_result(engine.search(req), engine))
        }
        TOOL_CONTEXT_GET => {
            let req = match parse_context_get_args(args_obj, engine.budget())? {
                Ok(parsed) => parsed,
                Err(domain_err) => return Ok(render_domain_error(&domain_err, engine)),
            };
            Ok(render_domain_result(engine.get_slice(req), engine))
        }
        TOOL_CONTEXT_RESUME => {
            let req = parse_context_resume_args(args_obj)?;
            Ok(render_domain_result(engine.resume(req), engine))
        }
        TOOL_CONTEXT_STATS => {
            let (session_id, all_sessions) = parse_context_stats_args(args_obj)?;
            Ok(render_domain_result(
                engine.stats(session_id.as_deref(), all_sessions),
                engine,
            ))
        }
        TOOL_CONTEXT_DOCTOR => {
            ensure_allowed_keys(TOOL_CONTEXT_DOCTOR, args_obj, &[])?;
            Ok(render_domain_result(engine.doctor(), engine))
        }
        unknown => Err(InvalidToolParams::new(
            unknown,
            format!("unknown tool '{unknown}'"),
        )),
    }
}

fn render_domain_result<T: Serialize>(
    res: context_core::Result<T>,
    engine: &ContextEngine,
) -> CallToolResult {
    match res {
        Ok(payload) => match serde_json::to_string(&payload) {
            Ok(serialized) => build_bounded_success_result(serialized, engine),
            Err(ser_err) => render_domain_error(&ContextError::Serialization(ser_err), engine),
        },
        Err(err) => render_domain_error(&err, engine),
    }
}

fn render_domain_error(err: &ContextError, engine: &ContextEngine) -> CallToolResult {
    let redacted_msg = engine.secret_guard().redact_str(&err.to_string());
    let (bounded_msg, _) = truncate_str_utf8_boundary(&redacted_msg, 2_048);
    let payload = ToolErrorPayload {
        error_code: err.error_code().to_string(),
        message: bounded_msg.to_string(),
        security_denial: err.is_security_denial(),
    };
    let text = serde_json::to_string(&payload).unwrap_or_else(|_| {
        format!(
            "{{\"error_code\":\"{}\",\"message\":\"tool execution failed\",\"security_denial\":{}}}",
            err.error_code(),
            err.is_security_denial()
        )
    });
    CallToolResult {
        content: vec![ToolTextContent::text(text)],
        is_error: true,
    }
}

fn build_bounded_success_result(serialized: String, engine: &ContextEngine) -> CallToolResult {
    if serialized.len() <= MAX_MCP_TOOL_OUTPUT_BYTES {
        return CallToolResult {
            content: vec![ToolTextContent::text(serialized)],
            is_error: false,
        };
    }

    let err = ContextError::BudgetExceeded {
        resource: "mcp.tool_output_bytes",
        requested: serialized.len(),
        limit: MAX_MCP_TOOL_OUTPUT_BYTES,
    };
    render_domain_error(&err, engine)
}

fn extract_arguments_object<'a>(
    tool_name: &str,
    raw: Option<&'a Value>,
) -> std::result::Result<&'a Map<String, Value>, InvalidToolParams> {
    static EMPTY_MAP: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);

    match raw {
        None | Some(Value::Null) => Ok(&EMPTY_MAP),
        Some(Value::Object(map)) => Ok(map),
        Some(other) => Err(InvalidToolParams::new(
            tool_name,
            format!(
                "expected JSON object for tool arguments, got {}",
                json_type_name(other)
            ),
        )),
    }
}

fn ensure_allowed_keys(
    tool_name: &str,
    map: &Map<String, Value>,
    allowed: &[&str],
) -> std::result::Result<(), InvalidToolParams> {
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(InvalidToolParams::new(
                tool_name,
                format!("unknown property '{key}' (additionalProperties: false)"),
            ));
        }
    }
    Ok(())
}

fn get_required_string<'a>(
    tool_name: &str,
    map: &'a Map<String, Value>,
    field: &str,
    min_len: usize,
    max_len: usize,
) -> std::result::Result<&'a str, InvalidToolParams> {
    let Some(val) = map.get(field) else {
        return Err(InvalidToolParams::new(
            tool_name,
            format!("missing required string property '{field}'"),
        ));
    };
    let Some(s) = val.as_str() else {
        return Err(InvalidToolParams::new(
            tool_name,
            format!(
                "property '{field}' must be a string, got {}",
                json_type_name(val)
            ),
        ));
    };
    if s.len() < min_len {
        return Err(InvalidToolParams::new(
            tool_name,
            format!("property '{field}' must have length >= {min_len}"),
        ));
    }
    if s.len() > max_len {
        return Err(InvalidToolParams::new(
            tool_name,
            format!(
                "property '{field}' length {} exceeds maximum {max_len} bytes",
                s.len()
            ),
        ));
    }
    Ok(s)
}

fn get_optional_string<'a>(
    tool_name: &str,
    map: &'a Map<String, Value>,
    field: &str,
    min_len: usize,
    max_len: usize,
) -> std::result::Result<Option<&'a str>, InvalidToolParams> {
    let Some(val) = map.get(field) else {
        return Ok(None);
    };
    if val.is_null() {
        return Err(InvalidToolParams::new(
            tool_name,
            format!("property '{field}' must be a string when provided, got null"),
        ));
    }
    let Some(s) = val.as_str() else {
        return Err(InvalidToolParams::new(
            tool_name,
            format!(
                "property '{field}' must be a string, got {}",
                json_type_name(val)
            ),
        ));
    };
    if s.len() < min_len {
        return Err(InvalidToolParams::new(
            tool_name,
            format!("property '{field}' must have length >= {min_len}"),
        ));
    }
    if s.len() > max_len {
        return Err(InvalidToolParams::new(
            tool_name,
            format!(
                "property '{field}' length {} exceeds maximum {max_len} bytes",
                s.len()
            ),
        ));
    }
    Ok(Some(s))
}

fn get_optional_bool(
    tool_name: &str,
    map: &Map<String, Value>,
    field: &str,
) -> std::result::Result<Option<bool>, InvalidToolParams> {
    let Some(val) = map.get(field) else {
        return Ok(None);
    };
    val.as_bool().map(Some).ok_or_else(|| {
        InvalidToolParams::new(
            tool_name,
            format!(
                "property '{field}' must be a boolean, got {}",
                json_type_name(val)
            ),
        )
    })
}

fn get_optional_u64(
    tool_name: &str,
    map: &Map<String, Value>,
    field: &str,
    min: u64,
    max: u64,
) -> std::result::Result<Option<u64>, InvalidToolParams> {
    let Some(val) = map.get(field) else {
        return Ok(None);
    };
    let Some(num) = val.as_u64() else {
        return Err(InvalidToolParams::new(
            tool_name,
            format!(
                "property '{field}' must be a non-negative integer, got {}",
                json_type_name(val)
            ),
        ));
    };
    if num < min || num > max {
        return Err(InvalidToolParams::new(
            tool_name,
            format!("property '{field}' ({num}) must be in {min}..={max}"),
        ));
    }
    Ok(Some(num))
}

fn parse_context_run_args(
    map: &Map<String, Value>,
) -> std::result::Result<RunCommandRequest, InvalidToolParams> {
    ensure_allowed_keys(
        TOOL_CONTEXT_RUN,
        map,
        &["argv", "cwd", "timeout_ms", "session_id"],
    )?;

    let Some(argv_val) = map.get("argv") else {
        return Err(InvalidToolParams::new(
            TOOL_CONTEXT_RUN,
            "missing required property 'argv'",
        ));
    };
    let Some(arr) = argv_val.as_array() else {
        return Err(InvalidToolParams::new(
            TOOL_CONTEXT_RUN,
            format!(
                "property 'argv' must be an array of strings, got {}",
                json_type_name(argv_val)
            ),
        ));
    };
    if arr.is_empty() || arr.len() > MAX_ARGV_ITEMS {
        return Err(InvalidToolParams::new(
            TOOL_CONTEXT_RUN,
            format!(
                "property 'argv' must contain between 1 and {MAX_ARGV_ITEMS} items (got {})",
                arr.len()
            ),
        ));
    }

    let mut argv = Vec::with_capacity(arr.len());
    for (idx, item) in arr.iter().enumerate() {
        let Some(s) = item.as_str() else {
            return Err(InvalidToolParams::new(
                TOOL_CONTEXT_RUN,
                format!("argv[{idx}] must be a string, got {}", json_type_name(item)),
            ));
        };
        if s.is_empty() && idx == 0 {
            return Err(InvalidToolParams::new(
                TOOL_CONTEXT_RUN,
                "argv[0] executable name cannot be empty",
            ));
        }
        if s.len() > MAX_ARG_BYTES {
            return Err(InvalidToolParams::new(
                TOOL_CONTEXT_RUN,
                format!(
                    "argv[{idx}] length {} exceeds maximum {MAX_ARG_BYTES} bytes",
                    s.len()
                ),
            ));
        }
        argv.push(s.to_string());
    }

    let cwd =
        get_optional_string(TOOL_CONTEXT_RUN, map, "cwd", 1, MAX_PATH_BYTES)?.map(PathBuf::from);
    let timeout_ms = get_optional_u64(TOOL_CONTEXT_RUN, map, "timeout_ms", 1, 600_000)?;
    let session_id =
        get_optional_string(TOOL_CONTEXT_RUN, map, "session_id", 1, 128)?.map(str::to_string);

    Ok(RunCommandRequest {
        argv,
        cwd,
        timeout_ms,
        session_id,
        client_project_scope: None,
    })
}

fn parse_context_index_args(
    map: &Map<String, Value>,
    budget: &ReductionBudget,
) -> std::result::Result<IndexDocumentRequest, InvalidToolParams> {
    ensure_allowed_keys(
        TOOL_CONTEXT_INDEX,
        map,
        &["path", "content", "label", "media_type", "session_id"],
    )?;

    let max_content = usize::try_from(budget.max_capture_stream_bytes).unwrap_or(16 * 1024 * 1024);
    let path_opt = get_optional_string(TOOL_CONTEXT_INDEX, map, "path", 1, MAX_PATH_BYTES)?;
    let content_opt = get_optional_string(TOOL_CONTEXT_INDEX, map, "content", 0, max_content)?;
    let label = get_optional_string(TOOL_CONTEXT_INDEX, map, "label", 1, MAX_LABEL_BYTES)?
        .map(str::to_string);
    let media_type = get_optional_string(
        TOOL_CONTEXT_INDEX,
        map,
        "media_type",
        1,
        MAX_MEDIA_TYPE_BYTES,
    )?
    .map(str::to_string);
    let session_id =
        get_optional_string(TOOL_CONTEXT_INDEX, map, "session_id", 1, 128)?.map(str::to_string);

    let source = match (path_opt, content_opt) {
        (Some(_), Some(_)) => {
            return Err(InvalidToolParams::new(
                TOOL_CONTEXT_INDEX,
                "provide either 'path' or 'content', not both",
            ));
        }
        (None, None) => {
            return Err(InvalidToolParams::new(
                TOOL_CONTEXT_INDEX,
                "must provide either 'path' or ('content' + 'label')",
            ));
        }
        (Some(p), None) => IndexSource::FilePath(PathBuf::from(p)),
        (None, Some(c)) => {
            if label.as_deref().map_or(true, |l| l.trim().is_empty()) {
                return Err(InvalidToolParams::new(
                    TOOL_CONTEXT_INDEX,
                    "property 'label' is required when indexing inline 'content'",
                ));
            }
            IndexSource::InlineBytes(c.as_bytes().to_vec())
        }
    };

    Ok(IndexDocumentRequest {
        source,
        label,
        media_type,
        session_id,
        client_project_scope: None,
    })
}

fn parse_context_search_args(
    map: &Map<String, Value>,
    budget: &ReductionBudget,
) -> std::result::Result<SearchQueryRequest, InvalidToolParams> {
    ensure_allowed_keys(
        TOOL_CONTEXT_SEARCH,
        map,
        &["query", "session_only", "limit", "session_id"],
    )?;

    let query =
        get_required_string(TOOL_CONTEXT_SEARCH, map, "query", 1, MAX_QUERY_BYTES)?.to_string();
    let session_only = get_optional_bool(TOOL_CONTEXT_SEARCH, map, "session_only")?.unwrap_or(true);
    let max_res = budget.max_search_results as u64;
    let limit = get_optional_u64(TOOL_CONTEXT_SEARCH, map, "limit", 1, max_res)?
        .map(|n| usize::try_from(n).unwrap_or(10));
    let session_id =
        get_optional_string(TOOL_CONTEXT_SEARCH, map, "session_id", 1, 128)?.map(str::to_string);

    Ok(SearchQueryRequest {
        query,
        session_only,
        limit,
        session_id,
        client_project_scope: None,
    })
}

fn parse_context_get_args(
    map: &Map<String, Value>,
    budget: &ReductionBudget,
) -> std::result::Result<context_core::Result<GetSliceRequest>, InvalidToolParams> {
    ensure_allowed_keys(
        TOOL_CONTEXT_GET,
        map,
        &["artifact_id", "stream", "lines", "bytes", "session_id"],
    )?;

    let artifact_id =
        get_required_string(TOOL_CONTEXT_GET, map, "artifact_id", 1, 256)?.to_string();

    let stream = match get_optional_string(TOOL_CONTEXT_GET, map, "stream", 1, 32)? {
        Some(raw) => Some(raw.parse::<StreamKind>().map_err(|_| {
            InvalidToolParams::new(
                TOOL_CONTEXT_GET,
                format!(
                    "invalid 'stream' value '{raw}' (expected stdout, stderr, combined, or document)"
                ),
            )
        })?),
        None => None,
    };

    let session_id =
        get_optional_string(TOOL_CONTEXT_GET, map, "session_id", 1, 128)?.map(str::to_string);

    let has_lines = map.contains_key("lines");
    let has_bytes = map.contains_key("bytes");
    if has_lines && has_bytes {
        return Err(InvalidToolParams::new(
            TOOL_CONTEXT_GET,
            "properties 'lines' and 'bytes' are mutually exclusive",
        ));
    }

    let range = if let Some(lines_val) = map.get("lines") {
        match parse_line_range_value(lines_val, budget.max_get_lines)? {
            Ok(lr) => GetRangeSelector::Lines(lr),
            Err(domain_err) => return Ok(Err(domain_err)),
        }
    } else if let Some(bytes_val) = map.get("bytes") {
        match parse_byte_range_value(bytes_val, budget.max_get_bytes)? {
            Ok(br) => GetRangeSelector::Bytes(br),
            Err(domain_err) => return Ok(Err(domain_err)),
        }
    } else {
        GetRangeSelector::DefaultWindow
    };

    Ok(Ok(GetSliceRequest {
        artifact_id,
        stream,
        range,
        session_id,
        client_project_scope: None,
    }))
}

fn parse_line_range_value(
    val: &Value,
    max_lines: usize,
) -> std::result::Result<context_core::Result<LineRange>, InvalidToolParams> {
    match val {
        Value::String(spec) => {
            if spec.len() > 64 {
                return Err(InvalidToolParams::new(
                    TOOL_CONTEXT_GET,
                    "property 'lines' string is too long",
                ));
            }
            Ok(LineRange::parse(spec, max_lines))
        }
        Value::Object(obj) => {
            ensure_allowed_keys(TOOL_CONTEXT_GET, obj, &["start", "end"])?;
            let Some(start_u64) = obj.get("start").and_then(Value::as_u64) else {
                return Err(InvalidToolParams::new(
                    TOOL_CONTEXT_GET,
                    "lines.start must be a positive integer",
                ));
            };
            let Some(end_u64) = obj.get("end").and_then(Value::as_u64) else {
                return Err(InvalidToolParams::new(
                    TOOL_CONTEXT_GET,
                    "lines.end must be a positive integer",
                ));
            };
            let start = usize::try_from(start_u64).unwrap_or(usize::MAX);
            let end = usize::try_from(end_u64).unwrap_or(usize::MAX);
            Ok(LineRange::new(start, end, max_lines))
        }
        other => Err(InvalidToolParams::new(
            TOOL_CONTEXT_GET,
            format!(
                "property 'lines' must be 'start:end' string or {{start, end}} object, got {}",
                json_type_name(other)
            ),
        )),
    }
}

fn parse_byte_range_value(
    val: &Value,
    max_bytes: usize,
) -> std::result::Result<context_core::Result<ByteRange>, InvalidToolParams> {
    match val {
        Value::String(spec) => {
            if spec.len() > 64 {
                return Err(InvalidToolParams::new(
                    TOOL_CONTEXT_GET,
                    "property 'bytes' string is too long",
                ));
            }
            Ok(ByteRange::parse(spec, max_bytes))
        }
        Value::Object(obj) => {
            ensure_allowed_keys(TOOL_CONTEXT_GET, obj, &["start", "end"])?;
            let Some(start) = obj.get("start").and_then(Value::as_u64) else {
                return Err(InvalidToolParams::new(
                    TOOL_CONTEXT_GET,
                    "bytes.start must be a non-negative integer",
                ));
            };
            let Some(end) = obj.get("end").and_then(Value::as_u64) else {
                return Err(InvalidToolParams::new(
                    TOOL_CONTEXT_GET,
                    "bytes.end must be a non-negative integer",
                ));
            };
            Ok(ByteRange::new(start, end, max_bytes))
        }
        other => Err(InvalidToolParams::new(
            TOOL_CONTEXT_GET,
            format!(
                "property 'bytes' must be 'start:end' string or {{start, end}} object, got {}",
                json_type_name(other)
            ),
        )),
    }
}

fn parse_context_resume_args(
    map: &Map<String, Value>,
) -> std::result::Result<ResumeRequest, InvalidToolParams> {
    ensure_allowed_keys(
        TOOL_CONTEXT_RESUME,
        map,
        &["session_id", "create_checkpoint", "note"],
    )?;

    let session_id =
        get_optional_string(TOOL_CONTEXT_RESUME, map, "session_id", 1, 128)?.map(str::to_string);
    let create_checkpoint =
        get_optional_bool(TOOL_CONTEXT_RESUME, map, "create_checkpoint")?.unwrap_or(false);
    let note = get_optional_string(TOOL_CONTEXT_RESUME, map, "note", 0, MAX_NOTE_BYTES)?
        .map(str::to_string);

    Ok(ResumeRequest {
        session_id,
        create_checkpoint,
        note,
        client_project_scope: None,
    })
}

fn parse_context_stats_args(
    map: &Map<String, Value>,
) -> std::result::Result<(Option<String>, bool), InvalidToolParams> {
    ensure_allowed_keys(TOOL_CONTEXT_STATS, map, &["session_id", "all_sessions"])?;
    let session_id =
        get_optional_string(TOOL_CONTEXT_STATS, map, "session_id", 1, 128)?.map(str::to_string);
    let all_sessions = get_optional_bool(TOOL_CONTEXT_STATS, map, "all_sessions")?.unwrap_or(false);
    Ok((session_id, all_sessions))
}

const fn json_type_name(val: &Value) -> &'static str {
    match val {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
