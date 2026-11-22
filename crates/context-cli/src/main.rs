//! Unified CLI and stdio MCP server binary (`context-engine`).

#![forbid(unsafe_code)]

pub mod setup;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use context_core::{
    ByteRange, ContextError, LineRange, Result, StreamKind, TransformationLedger,
};
use context_journal::ResumePack;
use context_mcp::{
    run_stdio_server, ContextEngine, DoctorReport, EnginePruneReport, EngineStatsReport,
    GetRangeSelector, GetSliceOutcome, GetSliceRequest, IndexDocumentRequest, IndexSource,
    ResumeRequest, RunCommandRequest, SearchQueryOutcome, SearchQueryRequest,
};
use serde::Serialize;
use tokio::io::AsyncReadExt;
use tracing_subscriber::EnvFilter;

use crate::setup::{run_setup, SetupOptions, SetupReport, SetupWriteMode};

/// Self-hosted Rust Context Engine: bounded capture, deterministic single-pass reduction,
/// scoped SQLite FTS5 search, byte-exact zstd recovery, and MCP stdio server.
#[derive(Debug, Parser)]
#[command(name = "context-engine", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Execute an allowlisted command via direct argv, persist exact streams, and emit a compact view.
    Run {
        /// Target project workspace root (defaults to CONTEXT_ENGINE_WORKSPACE or current directory).
        #[arg(long)]
        workspace: Option<PathBuf>,

        /// Session identifier ([A-Za-z0-9._-]{1,128}).
        #[arg(long)]
        session: Option<String>,

        /// Working directory relative to the bound workspace root.
        #[arg(long)]
        cwd: Option<PathBuf>,

        /// Command wall-clock timeout in milliseconds.
        #[arg(long = "timeout-ms")]
        timeout_ms: Option<u64>,

        /// Emit full v1 ArtifactEnvelope JSON instead of compact text view.
        #[arg(long)]
        json: bool,

        /// Exit 0 after capturing even when the child command exits non-zero.
        #[arg(long = "no-exit-code-passthrough")]
        no_exit_code_passthrough: bool,

        /// Direct argv vector (`-- <program> [args...]`).
        #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },

    /// Ingest and index a confined workspace file or piped `--stdin` payload.
    Index {
        /// Workspace-relative or confined file path to ingest (omit when `--stdin` is set).
        #[arg(value_name = "FILE_PATH", conflicts_with = "stdin")]
        file_path: Option<PathBuf>,

        /// Read document payload from standard input instead of a file path.
        #[arg(long)]
        stdin: bool,

        /// Provenance label stored with the indexed artifact.
        #[arg(long)]
        label: Option<String>,

        /// Optional MIME media type override (e.g. `application/json`, `text/plain`).
        #[arg(long = "media-type")]
        media_type: Option<String>,

        /// Target project workspace root.
        #[arg(long)]
        workspace: Option<PathBuf>,

        /// Session identifier.
        #[arg(long)]
        session: Option<String>,

        /// Emit full v1 ArtifactEnvelope JSON.
        #[arg(long)]
        json: bool,
    },

    /// Search sanitized SQLite FTS5 chunks (`bm25()`) within the bound workspace.
    Search {
        /// Lexical search query.
        query: String,

        /// Target project workspace root.
        #[arg(long)]
        workspace: Option<PathBuf>,

        /// Session identifier.
        #[arg(long)]
        session: Option<String>,

        /// Search across all sessions in the bound workspace (defaults to current session only).
        #[arg(long = "all-sessions")]
        all_sessions: bool,

        /// Maximum ranked hits to return (default 10, max 20).
        #[arg(long)]
        limit: Option<usize>,

        /// Emit structured JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Recover a bounded line or byte slice from a stored artifact stream without re-running commands.
    Get {
        /// Opaque server-minted artifact identifier (`a_<64-hex>`).
        artifact_id: String,

        /// Stream selector (`stdout`, `stderr`, `combined`, or `document`).
        #[arg(long)]
        stream: Option<String>,

        /// 1-indexed inclusive line range (`start:end`, e.g. `1:80`).
        #[arg(long, conflicts_with = "bytes")]
        lines: Option<String>,

        /// Half-open byte offset range (`start:end`, e.g. `0:4096`).
        #[arg(long, conflicts_with = "lines")]
        bytes: Option<String>,

        /// Target project workspace root.
        #[arg(long)]
        workspace: Option<PathBuf>,

        /// Session identifier.
        #[arg(long)]
        session: Option<String>,

        /// Emit structured JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Restore deterministic session state (`ResumePack`) and optionally persist a checkpoint.
    Resume {
        /// Target project workspace root.
        #[arg(long)]
        workspace: Option<PathBuf>,

        /// Session identifier.
        #[arg(long)]
        session: Option<String>,

        /// Persist a new deterministic checkpoint before returning the resume pack.
        #[arg(long)]
        checkpoint: bool,

        /// Optional note attached to the newly created checkpoint.
        #[arg(long)]
        note: Option<String>,

        /// Emit structured JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Report non-sensitive capture, compression, retrieval-overhead, and net token savings metrics.
    Stats {
        /// Target project workspace root.
        #[arg(long)]
        workspace: Option<PathBuf>,

        /// Session identifier.
        #[arg(long)]
        session: Option<String>,

        /// Aggregate across all sessions in the bound workspace.
        #[arg(long = "all-sessions")]
        all_sessions: bool,

        /// Emit structured JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Enforce TTL and byte-quota retention across `BlobStore`, `SearchIndex`, and `SessionJournal`.
    Prune {
        /// Target project workspace root.
        #[arg(long)]
        workspace: Option<PathBuf>,

        /// Optional retention TTL override in seconds.
        #[arg(long = "ttl-secs")]
        ttl_secs: Option<u64>,

        /// Optional workspace store byte ceiling override.
        #[arg(long = "max-bytes")]
        max_bytes: Option<u64>,

        /// Emit structured JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Run read-only workspace confinement, store ACL, SQLite WAL + FTS5, and policy health checks.
    Doctor {
        /// Target project workspace root.
        #[arg(long)]
        workspace: Option<PathBuf>,

        /// Emit structured JSON output.
        #[arg(long)]
        json: bool,
    },

    /// Start the server-scoped stdio JSON-RPC 2.0 MCP server bound to `--workspace`.
    Mcp {
        /// Canonical project workspace root bound for the lifetime of this MCP server.
        #[arg(long)]
        workspace: PathBuf,

        /// Default session identifier (`default` when omitted).
        #[arg(long)]
        session: Option<String>,
    },

    /// Render or install opt-in, project-scoped integration bundles (defaults safely to `--dry-run`).
    Setup {
        /// Target coding agent (`cursor`, `claude-code`, `opencode`, `codex`, `generic`, or `all`).
        #[arg(long)]
        client: String,

        /// Target project workspace root.
        #[arg(long)]
        workspace: Option<PathBuf>,

        /// Explicit `context-engine` binary path embedded into generated MCP/hook templates.
        #[arg(long)]
        binary: Option<PathBuf>,

        /// Emit rendered files into `<dir>` rather than the project directory.
        #[arg(long = "output-dir")]
        output_dir: Option<PathBuf>,

        /// Explicitly opt in to writing rendered integration files into `<workspace>`.
        #[arg(long = "write-project")]
        write_project: bool,

        /// Preview rendered files without touching disk (default when neither `--output-dir` nor `--write-project` is set).
        #[arg(long = "dry-run")]
        dry_run: bool,

        /// Emit structured JSON output.
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_stderr_tracing();

    let exit_code = match run_cli(cli).await {
        Ok(code) => code,
        Err(err) => {
            let _ = writeln!(
                io::stderr(),
                "context-engine error [{}]: {err}",
                err.error_code()
            );
            exit_code_for_error(&err)
        }
    };

    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

fn init_stderr_tracing() {
    // Route any optional `RUST_LOG` diagnostics strictly to `stderr` so `stdout` stays 100% pure
    // for MCP JSON-RPC frames and `--json` CLI pipelines.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_ansi(false)
        .without_time()
        .try_init();
}

/// Executes a parsed [`Cli`] command and returns the desired process exit code.
#[allow(clippy::too_many_lines)]
pub async fn run_cli(cli: Cli) -> Result<i32> {
    match cli.command {
        Commands::Run {
            workspace,
            session,
            cwd,
            timeout_ms,
            json,
            no_exit_code_passthrough,
            argv,
        } => {
            let ws_path = resolve_workspace_arg(workspace)?;
            let sess_ref = resolve_session_arg(session);
            let engine = ContextEngine::open_workspace(&ws_path, sess_ref.as_deref())?;

            let outcome = engine
                .run_command(RunCommandRequest {
                    argv,
                    cwd,
                    timeout_ms,
                    session_id: sess_ref,
                    client_project_scope: None,
                })
                .await?;

            if json {
                write_stdout_json(&outcome.envelope)?;
            } else {
                write_stdout_envelope_compact(&outcome.envelope)?;
            }

            if no_exit_code_passthrough {
                Ok(0)
            } else if let Some(code) = outcome.exit_code {
                Ok(code)
            } else if outcome.timed_out {
                Ok(124)
            } else if outcome.cancelled {
                Ok(130)
            } else {
                Ok(1)
            }
        }

        Commands::Index {
            file_path,
            stdin,
            label,
            media_type,
            workspace,
            session,
            json,
        } => {
            let ws_path = resolve_workspace_arg(workspace)?;
            let sess_ref = resolve_session_arg(session);
            let engine = ContextEngine::open_workspace(&ws_path, sess_ref.as_deref())?;

            let source = match (file_path, stdin) {
                (Some(path), false) => IndexSource::FilePath(path),
                (None, true) => {
                    let max_read = engine
                        .budget()
                        .max_capture_stream_bytes
                        .saturating_add(1);
                    let bytes = read_stdin_bounded(max_read).await?;
                    IndexSource::InlineBytes(bytes)
                }
                (Some(_), true) => {
                    return Err(ContextError::InvalidConfig {
                        field: "stdin",
                        reason: "provide either <FILE_PATH> or --stdin, not both".to_string(),
                    });
                }
                (None, false) => {
                    return Err(ContextError::InvalidConfig {
                        field: "file_path",
                        reason: "provide either <FILE_PATH> or --stdin".to_string(),
                    });
                }
            };

            let effective_label = if stdin && label.is_none() {
                Some("stdin".to_string())
            } else {
                label
            };

            let outcome = engine
                .index_document(IndexDocumentRequest {
                    source,
                    label: effective_label,
                    media_type,
                    session_id: sess_ref,
                    client_project_scope: None,
                })
                .await?;

            if json {
                write_stdout_json(&outcome.envelope)?;
            } else {
                write_stdout_envelope_compact(&outcome.envelope)?;
            }
            Ok(0)
        }

        Commands::Search {
            query,
            workspace,
            session,
            all_sessions,
            limit,
            json,
        } => {
            let ws_path = resolve_workspace_arg(workspace)?;
            let sess_ref = resolve_session_arg(session);
            let engine = ContextEngine::open_workspace(&ws_path, sess_ref.as_deref())?;

            let outcome = engine.search(SearchQueryRequest {
                query,
                session_only: !all_sessions,
                limit,
                session_id: sess_ref,
                client_project_scope: None,
            })?;

            if json {
                write_stdout_json(&outcome)?;
            } else {
                write_stdout_search(&outcome)?;
            }
            Ok(0)
        }

        Commands::Get {
            artifact_id,
            stream,
            lines,
            bytes,
            workspace,
            session,
            json,
        } => {
            let ws_path = resolve_workspace_arg(workspace)?;
            let sess_ref = resolve_session_arg(session);
            let engine = ContextEngine::open_workspace(&ws_path, sess_ref.as_deref())?;

            let parsed_stream = match stream {
                Some(ref raw) => Some(raw.parse::<StreamKind>()?),
                None => None,
            };

            let range = if let Some(ref line_spec) = lines {
                GetRangeSelector::Lines(LineRange::parse(
                    line_spec,
                    engine.budget().max_get_lines,
                )?)
            } else if let Some(ref byte_spec) = bytes {
                GetRangeSelector::Bytes(ByteRange::parse(
                    byte_spec,
                    engine.budget().max_get_bytes,
                )?)
            } else {
                GetRangeSelector::DefaultWindow
            };

            let outcome = engine.get_slice(GetSliceRequest {
                artifact_id,
                stream: parsed_stream,
                range,
                session_id: sess_ref,
                client_project_scope: None,
            })?;

            if json {
                write_stdout_json(&outcome)?;
            } else {
                write_stdout_get(&outcome)?;
            }
            Ok(0)
        }

        Commands::Resume {
            workspace,
            session,
            checkpoint,
            note,
            json,
        } => {
            let ws_path = resolve_workspace_arg(workspace)?;
            let sess_ref = resolve_session_arg(session);
            let engine = ContextEngine::open_workspace(&ws_path, sess_ref.as_deref())?;

            let pack = engine.resume(ResumeRequest {
                session_id: sess_ref,
                create_checkpoint: checkpoint,
                note,
                client_project_scope: None,
            })?;

            if json {
                write_stdout_json(&pack)?;
            } else {
                write_stdout_resume(&pack)?;
            }
            Ok(0)
        }

        Commands::Stats {
            workspace,
            session,
            all_sessions,
            json,
        } => {
            let ws_path = resolve_workspace_arg(workspace)?;
            let sess_ref = resolve_session_arg(session);
            let engine = ContextEngine::open_workspace(&ws_path, sess_ref.as_deref())?;

            let report = engine.stats(sess_ref.as_deref(), all_sessions)?;
            if json {
                write_stdout_json(&report)?;
            } else {
                write_stdout_stats(&report)?;
            }
            Ok(0)
        }

        Commands::Prune {
            workspace,
            ttl_secs,
            max_bytes,
            json,
        } => {
            let ws_path = resolve_workspace_arg(workspace)?;
            let engine = ContextEngine::open_workspace(&ws_path, None)?;

            let report = engine.prune(ttl_secs, max_bytes)?;
            if json {
                write_stdout_json(&report)?;
            } else {
                write_stdout_prune(&report)?;
            }
            Ok(0)
        }

        Commands::Doctor { workspace, json } => {
            let ws_path = resolve_workspace_arg(workspace)?;
            let engine = ContextEngine::open_workspace(&ws_path, None)?;

            let report = engine.doctor()?;
            if json {
                write_stdout_json(&report)?;
            } else {
                write_stdout_doctor(&report)?;
            }
            Ok(if report.healthy { 0 } else { 1 })
        }

        Commands::Mcp { workspace, session } => {
            let sess_ref = resolve_session_arg(session);
            let engine = Arc::new(ContextEngine::open_workspace(
                &workspace,
                sess_ref.as_deref(),
            )?);
            run_stdio_server(engine).await?;
            Ok(0)
        }

        Commands::Setup {
            client,
            workspace,
            binary,
            output_dir,
            write_project,
            dry_run,
            json,
        } => {
            let ws_path = resolve_workspace_arg(workspace)?;
            let report = run_setup(&SetupOptions {
                client,
                workspace: ws_path,
                binary,
                output_dir,
                write_project,
                dry_run,
            })?;

            if json {
                write_stdout_json(&report)?;
            } else {
                write_stdout_setup(&report)?;
            }
            Ok(0)
        }
    }
}

fn resolve_workspace_arg(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Some(env_ws) = std::env::var_os("CONTEXT_ENGINE_WORKSPACE") {
        if !env_ws.is_empty() {
            return Ok(PathBuf::from(env_ws));
        }
    }
    Ok(std::env::current_dir()?)
}

fn resolve_session_arg(explicit: Option<String>) -> Option<String> {
    if let Some(s) = explicit {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Ok(env_sess) = std::env::var("CONTEXT_ENGINE_SESSION") {
        let trimmed = env_sess.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

async fn read_stdin_bounded(max_bytes: u64) -> Result<Vec<u8>> {
    let mut stdin = tokio::io::stdin();
    let mut buf = Vec::new();
    let mut limited = (&mut stdin).take(max_bytes);
    limited.read_to_end(&mut buf).await?;
    Ok(buf)
}

fn exit_code_for_error(err: &ContextError) -> i32 {
    if err.is_security_denial() {
        77 // EX_NOPERM
    } else {
        match err {
            ContextError::ExecutionTimeout { .. } => 124,
            ContextError::InvalidConfig { .. }
            | ContextError::InvalidRange { .. }
            | ContextError::InvalidSessionId { .. }
            | ContextError::InvalidArtifactId { .. } => 64, // EX_USAGE
            ContextError::InvalidWorkspacePath { .. } | ContextError::ArtifactNotFound { .. } => 66,
            _ => 1,
        }
    }
}

fn write_stdout_json<T: Serialize>(value: &T) -> Result<()> {
    let rendered = serde_json::to_string_pretty(value)?;
    let mut out = io::stdout().lock();
    writeln!(out, "{rendered}")?;
    Ok(())
}

fn write_stdout_envelope_compact(envelope: &context_core::ArtifactEnvelope) -> Result<()> {
    let banner = TransformationLedger::format_banner(
        &envelope.artifact_id,
        &envelope.view.transformations,
    );
    let mut out = io::stdout().lock();
    writeln!(out, "{banner}")?;
    if !envelope.view.safe_excerpt.is_empty() {
        writeln!(out, "{}", envelope.view.safe_excerpt)?;
    }
    if envelope.view.omitted
        && !envelope
            .view
            .safe_excerpt
            .contains(envelope.artifact_id.as_str())
    {
        if envelope.capture.originals_available {
            writeln!(
                out,
                "[recovery] context-engine get {} --lines 1:80",
                envelope.artifact_id
            )?;
        } else if let Some(ref reason) = envelope.recovery.unavailable_reason {
            writeln!(out, "[recovery:unavailable] {reason}")?;
        }
    }
    Ok(())
}

fn write_stdout_search(outcome: &SearchQueryOutcome) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "search '{}' -> {} hit(s) [scope={} session={} session_only={}]",
        outcome.query,
        outcome.hit_count,
        outcome.workspace_scope_id,
        outcome.session_id,
        outcome.session_only
    )?;
    for hit in &outcome.hits {
        writeln!(
            out,
            "  #{} score={:.3} {} [{} L{}-L{}] ({})",
            hit.rank,
            hit.score,
            hit.artifact_id,
            hit.stream,
            hit.line_start,
            hit.line_end,
            hit.source_label
        )?;
        for ln in hit.snippet.lines() {
            writeln!(out, "      {ln}")?;
        }
    }
    Ok(())
}

fn write_stdout_get(outcome: &GetSliceOutcome) -> Result<()> {
    let mut out = io::stdout().lock();
    match outcome {
        GetSliceOutcome::Lines(page) => {
            let range_label = match page.returned_range {
                Some(r) => format!("{}:{}", r.start_line, r.end_line),
                None => "empty".to_string(),
            };
            writeln!(
                out,
                "[context-engine:get artifact={} stream={} lines={}/{} has_more={} sha256={}]",
                page.artifact_id,
                page.stream,
                range_label,
                page.total_lines,
                page.has_more,
                &page.sha256[..16]
            )?;
            for line in &page.lines {
                writeln!(out, "{:>6} | {}", line.line_number, line.content)?;
            }
        }
        GetSliceOutcome::Bytes(page) => {
            writeln!(
                out,
                "[context-engine:get artifact={} stream={} bytes={}:{}/{} encoding={} has_more={} sha256={}]",
                page.artifact_id,
                page.stream,
                page.returned_range.start,
                page.returned_range.end,
                page.total_bytes,
                page.encoding,
                page.has_more,
                &page.sha256[..16]
            )?;
            if let Some(ref text) = page.utf8_text {
                write!(out, "{text}")?;
                if !text.ends_with('\n') && !text.is_empty() {
                    writeln!(out)?;
                }
            } else {
                writeln!(out, "base64: {}", page.base64_bytes)?;
            }
        }
    }
    Ok(())
}

fn write_stdout_resume(pack: &ResumePack) -> Result<()> {
    let mut out = io::stdout().lock();
    let cp_label = pack
        .latest_checkpoint
        .as_ref()
        .map_or("<none>", |cp| cp.checkpoint_id.as_str());
    writeln!(
        out,
        "resume [scope={} session={} checkpoint={} events_since_cp={}]",
        pack.workspace_scope_id, pack.session_id, cp_label, pack.events_since_checkpoint
    )?;
    if pack.unresolved_failures.is_empty() {
        writeln!(out, "  unresolved_failures: 0")?;
    } else {
        writeln!(
            out,
            "  unresolved_failures ({}):",
            pack.unresolved_failures.len()
        )?;
        for f in &pack.unresolved_failures {
            writeln!(out, "    - {f}")?;
        }
    }
    if !pack.recent_commands.is_empty() {
        writeln!(out, "  recent_commands ({}):", pack.recent_commands.len())?;
        for cmd in &pack.recent_commands {
            let status = cmd
                .exit_code
                .map_or_else(|| "none".to_string(), |c| c.to_string());
            let art = cmd
                .artifact_id
                .as_ref()
                .map_or("<none>", context_core::ArtifactId::as_str);
            writeln!(
                out,
                "    - [exit={status}] {} (artifact={art})",
                cmd.command_summary
            )?;
        }
    }
    if !pack.active_artifacts.is_empty() {
        writeln!(out, "  active_artifacts ({}):", pack.active_artifacts.len())?;
        for a in &pack.active_artifacts {
            writeln!(
                out,
                "    - {} label='{}' failures={}",
                a.artifact_id, a.label, a.has_failures
            )?;
        }
    }
    Ok(())
}

fn write_stdout_stats(report: &EngineStatsReport) -> Result<()> {
    let s = &report.session;
    let sess_label = s
        .session_id
        .as_ref()
        .map_or("<all-sessions>", context_core::SessionId::as_str);
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "stats [scope={} session={} distinct_sessions={}]",
        s.workspace_scope_id, sess_label, s.distinct_sessions
    )?;
    writeln!(
        out,
        "  captures={} (commands={}, docs={}) | searches={} | retrievals={} | dedup_hits={} | security_denials={} | secrets_redacted={}",
        s.total_captures,
        s.command_captures,
        s.document_indexes,
        s.search_queries,
        s.retrieval_calls,
        s.cache_dedup_hits,
        s.security_denials,
        s.secrets_redacted_total
    )?;
    writeln!(
        out,
        "  bytes: raw={} view={} retrieved={} exposed={} net_saved={} (view_reduction={:.1}%, net_savings={:.1}%)",
        s.raw_bytes,
        s.view_bytes,
        s.retrieved_bytes,
        s.exposed_bytes,
        s.net_saved_bytes,
        s.view_reduction_ratio * 100.0,
        s.net_byte_savings_ratio * 100.0
    )?;
    writeln!(
        out,
        "  tokens(est): raw={} view={} retrieved={} exposed={} net_saved={} (net_token_savings={:.1}%)",
        s.estimated_raw_tokens,
        s.estimated_view_tokens,
        s.estimated_retrieved_tokens,
        s.estimated_exposed_tokens,
        s.estimated_net_saved_tokens,
        s.net_token_savings_ratio * 100.0
    )?;
    writeln!(
        out,
        "  store: artifacts={} blobs={} total_store_bytes={}",
        report.store.artifact_count, report.store.blob_count, report.store.total_store_bytes
    )?;
    Ok(())
}

fn write_stdout_prune(report: &EnginePruneReport) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "prune [scope={}]: expired_artifacts={} quota_evicted={} removed_blobs={} freed_bytes={} search_pruned_artifacts={} journal_pruned_events={}",
        report.workspace_scope_id,
        report.store.expired_artifacts,
        report.store.quota_evicted_artifacts,
        report.store.removed_blobs,
        report.store.freed_bytes,
        report.search_pruned_artifacts,
        report.journal.pruned_events
    )?;
    Ok(())
}

fn write_stdout_doctor(report: &DoctorReport) -> Result<()> {
    let mut out = io::stdout().lock();
    let badge = if report.healthy { "HEALTHY" } else { "DEGRADED" };
    writeln!(
        out,
        "doctor: {badge} (context-engine v{}, schema v{})",
        report.engine_version, report.schema_version
    )?;
    writeln!(
        out,
        "  workspace: {} ({})",
        report.workspace_root, report.workspace_scope_id
    )?;
    writeln!(
        out,
        "  store_acl: private_only={} mechanism='{}' ({})",
        report.store_permissions.private_only,
        report.store_permissions.platform_mechanism,
        report.store_permissions.details
    )?;
    writeln!(
        out,
        "  search_db: healthy={} mode={} fts_integrity_ok={} artifacts={} chunks={}",
        report.search_health.healthy,
        report.search_health.journal_mode,
        report.search_health.fts_integrity_ok,
        report.search_health.total_artifacts,
        report.search_health.total_chunks
    )?;
    writeln!(
        out,
        "  journal_db: healthy={} mode={} events={} checkpoints={}",
        report.journal_health.healthy,
        report.journal_health.journal_mode,
        report.journal_health.total_events,
        report.journal_health.total_checkpoints
    )?;
    writeln!(
        out,
        "  execution_policy: allow_shell={} allowlist_count={} default_timeout_ms={}",
        report.execution_policy.allow_shell,
        report.execution_policy.allowed_programs.len(),
        report.execution_policy.default_timeout_ms
    )?;
    writeln!(
        out,
        "  secret_policy: mode={:?} entropy_detection={} allow_raw_when_redacted={}",
        report.secret_policy.mode,
        report.secret_policy.enable_entropy_detection,
        report.secret_policy.allow_raw_blob_when_redacted
    )?;
    Ok(())
}

fn write_stdout_setup(report: &SetupReport) -> Result<()> {
    let mut out = io::stdout().lock();
    let mode_label = match report.mode {
        SetupWriteMode::DryRun => "DRY-RUN (no files written; pass --write-project or --output-dir <dir> to write)",
        SetupWriteMode::OutputDir => "WROTE TO --output-dir",
        SetupWriteMode::WriteProject => "WROTE TO PROJECT WORKSPACE",
    };
    writeln!(out, "setup: {mode_label}")?;
    writeln!(out, "  clients: {}", report.clients.join(", "))?;
    writeln!(out, "  workspace: {}", report.workspace_path)?;
    writeln!(out, "  binary: {}", report.binary_path)?;
    for f in &report.files {
        let status = if f.written {
            if f.merged_existing {
                "merged"
            } else {
                "wrote"
            }
        } else {
            "preview"
        };
        writeln!(
            out,
            "  [{status}] ({}) {} -> {} ({} bytes)",
            f.client_id, f.source_path, f.target_path, f.byte_len
        )?;
        if report.dry_run && f.kind == "template" {
            for ln in f.content.lines() {
                writeln!(out, "      {ln}")?;
            }
        }
    }
    let _ = Path::new(&report.target_root);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use clap::Parser;
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn cli_subcommands_preserve_exit_codes_and_execute_shared_pipeline() {
        let ws = TempDir::new().expect("ws");
        let doc_path = ws.path().join("notes.txt");
        fs::write(&doc_path, "unique_cli_canary_phrase\nsecond line\n").expect("write notes.txt");

        // 1. `run` preserves child non-zero exit code by default (e.g. exit 42)
        let cli_fail = Cli::try_parse_from([
            "context-engine",
            "run",
            "--workspace",
            ws.path().to_str().expect("utf8"),
            "--session",
            "cli-s1",
            "--json",
            "--",
            "python",
            "-c",
            "import sys; sys.stdout.write('hello cli\\n'); sys.exit(42)",
        ])
        .expect("parse run");
        let code = run_cli(cli_fail).await.expect("run_cli");
        assert_eq!(code, 42);

        // 2. `run --no-exit-code-passthrough` returns exit code 0 even when child exits 42
        let cli_no_pass = Cli::try_parse_from([
            "context-engine",
            "run",
            "--workspace",
            ws.path().to_str().expect("utf8"),
            "--session",
            "cli-s1",
            "--no-exit-code-passthrough",
            "--",
            "python",
            "-c",
            "import sys; sys.exit(42)",
        ])
        .expect("parse run no-passthrough");
        assert_eq!(run_cli(cli_no_pass).await.expect("run"), 0);

        // 3. `index`, `search`, `resume --checkpoint`, `stats`, `doctor`, `prune`, and `setup`
        let cli_idx = Cli::try_parse_from([
            "context-engine",
            "index",
            "notes.txt",
            "--workspace",
            ws.path().to_str().expect("utf8"),
            "--session",
            "cli-s1",
            "--json",
        ])
        .expect("parse index");
        assert_eq!(run_cli(cli_idx).await.expect("index"), 0);

        let cli_search = Cli::try_parse_from([
            "context-engine",
            "search",
            "unique_cli_canary_phrase",
            "--workspace",
            ws.path().to_str().expect("utf8"),
            "--session",
            "cli-s1",
            "--json",
        ])
        .expect("parse search");
        assert_eq!(run_cli(cli_search).await.expect("search"), 0);

        let cli_resume = Cli::try_parse_from([
            "context-engine",
            "resume",
            "--workspace",
            ws.path().to_str().expect("utf8"),
            "--session",
            "cli-s1",
            "--checkpoint",
            "--note",
            "cli-cp",
            "--json",
        ])
        .expect("parse resume");
        assert_eq!(run_cli(cli_resume).await.expect("resume"), 0);

        let cli_stats = Cli::try_parse_from([
            "context-engine",
            "stats",
            "--workspace",
            ws.path().to_str().expect("utf8"),
            "--all-sessions",
            "--json",
        ])
        .expect("parse stats");
        assert_eq!(run_cli(cli_stats).await.expect("stats"), 0);

        let cli_doc = Cli::try_parse_from([
            "context-engine",
            "doctor",
            "--workspace",
            ws.path().to_str().expect("utf8"),
            "--json",
        ])
        .expect("parse doctor");
        assert_eq!(run_cli(cli_doc).await.expect("doctor"), 0);

        let cli_prune = Cli::try_parse_from([
            "context-engine",
            "prune",
            "--workspace",
            ws.path().to_str().expect("utf8"),
            "--ttl-secs",
            "86400",
            "--json",
        ])
        .expect("parse prune");
        assert_eq!(run_cli(cli_prune).await.expect("prune"), 0);

        let cli_setup = Cli::try_parse_from([
            "context-engine",
            "setup",
            "--client",
            "codex",
            "--workspace",
            ws.path().to_str().expect("utf8"),
            "--json",
        ])
        .expect("parse setup");
        assert_eq!(run_cli(cli_setup).await.expect("setup"), 0);
        // Default dry-run must not write `.codex/config.toml`!
        assert!(!ws.path().join(".codex").exists());
    }
}
