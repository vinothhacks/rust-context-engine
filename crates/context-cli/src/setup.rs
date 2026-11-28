//! Self-contained, opt-in project integration generator (`context-engine setup`).
//!
//! Embeds all 23 files under `adapters/` via `include_str!`, enforces `adapters/MANIFEST.json`,
//! defaults safely to `--dry-run`, unconditionally refuses global user config directories
//! (`~/.cursor`, `~/.claude`, `~/.codex`, `~/.config/opencode`, `%APPDATA%`, `$HOME`), and
//! validates rendered JSON and TOML syntax before atomic file replacement.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use context_core::{ContextError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tempfile::Builder as TempBuilder;

const MANIFEST_JSON: &str = include_str!("../../../adapters/MANIFEST.json");

/// Complete compile-time table of all 23 files in `adapters/`.
pub const EMBEDDED_ADAPTER_FILES: &[(&str, &str)] = &[
    ("MANIFEST.json", MANIFEST_JSON),
    (
        "cursor/mcp.json.template",
        include_str!("../../../adapters/cursor/mcp.json.template"),
    ),
    (
        "cursor/rules/context-engine.mdc",
        include_str!("../../../adapters/cursor/rules/context-engine.mdc"),
    ),
    (
        "cursor/hooks/hooks.json.template",
        include_str!("../../../adapters/cursor/hooks/hooks.json.template"),
    ),
    (
        "cursor/hooks/post-command-capture.ps1",
        include_str!("../../../adapters/cursor/hooks/post-command-capture.ps1"),
    ),
    (
        "cursor/hooks/post-command-capture.sh",
        include_str!("../../../adapters/cursor/hooks/post-command-capture.sh"),
    ),
    (
        "cursor/README.md",
        include_str!("../../../adapters/cursor/README.md"),
    ),
    (
        "claude-code/.mcp.json.template",
        include_str!("../../../adapters/claude-code/.mcp.json.template"),
    ),
    (
        "claude-code/SKILL.md",
        include_str!("../../../adapters/claude-code/SKILL.md"),
    ),
    (
        "claude-code/CLAUDE.snippet.md",
        include_str!("../../../adapters/claude-code/CLAUDE.snippet.md"),
    ),
    (
        "claude-code/hooks/settings.hooks.json.template",
        include_str!("../../../adapters/claude-code/hooks/settings.hooks.json.template"),
    ),
    (
        "claude-code/hooks/post-tool-reduce.mjs",
        include_str!("../../../adapters/claude-code/hooks/post-tool-reduce.mjs"),
    ),
    (
        "claude-code/README.md",
        include_str!("../../../adapters/claude-code/README.md"),
    ),
    (
        "opencode/opencode.json.template",
        include_str!("../../../adapters/opencode/opencode.json.template"),
    ),
    (
        "opencode/plugin/context-engine-plugin.mjs",
        include_str!("../../../adapters/opencode/plugin/context-engine-plugin.mjs"),
    ),
    (
        "opencode/README.md",
        include_str!("../../../adapters/opencode/README.md"),
    ),
    (
        "codex/config.toml.template",
        include_str!("../../../adapters/codex/config.toml.template"),
    ),
    (
        "codex/AGENTS.snippet.md",
        include_str!("../../../adapters/codex/AGENTS.snippet.md"),
    ),
    (
        "codex/README.md",
        include_str!("../../../adapters/codex/README.md"),
    ),
    (
        "generic-mcp/mcp-stdio.json.template",
        include_str!("../../../adapters/generic-mcp/mcp-stdio.json.template"),
    ),
    (
        "generic-mcp/wrappers/ce-run.ps1",
        include_str!("../../../adapters/generic-mcp/wrappers/ce-run.ps1"),
    ),
    (
        "generic-mcp/wrappers/ce-run.sh",
        include_str!("../../../adapters/generic-mcp/wrappers/ce-run.sh"),
    ),
    (
        "generic-mcp/README.md",
        include_str!("../../../adapters/generic-mcp/README.md"),
    ),
];

const CANONICAL_CLIENT_ORDER: &[&str] =
    &["cursor", "claude-code", "opencode", "codex", "generic-mcp"];

#[derive(Debug, Clone, Deserialize)]
struct AdapterManifest {
    schema_version: u32,
    clients: BTreeMap<String, ManifestClientSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestClientSpec {
    client_id: String,
    #[serde(default)]
    aliases: Vec<String>,
    display_name: String,
    files: Vec<ManifestFileSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestFileSpec {
    source_path: String,
    default_target_path: String,
    kind: String,
    format: String,
    category: String,
    #[serde(default)]
    executable: bool,
    #[serde(default)]
    optional: bool,
    merge_strategy: String,
    #[serde(default)]
    placeholders: Vec<String>,
}

/// Environment snapshot used to enforce global-path refusal hermetically.
#[derive(Debug, Clone, Default)]
pub struct HostEnvPaths {
    pub home: Option<PathBuf>,
    pub userprofile: Option<PathBuf>,
    pub appdata: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
}

impl HostEnvPaths {
    #[must_use]
    pub fn from_process_env() -> Self {
        Self {
            home: std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            userprofile: std::env::var_os("USERPROFILE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            appdata: std::env::var_os("APPDATA")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            xdg_config_home: std::env::var_os("XDG_CONFIG_HOME")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
        }
    }
}

/// Parameters controlling [`run_setup`].
#[derive(Debug, Clone)]
pub struct SetupOptions {
    pub client: String,
    pub workspace: PathBuf,
    pub binary: Option<PathBuf>,
    pub output_dir: Option<PathBuf>,
    pub write_project: bool,
    pub dry_run: bool,
}

/// Execution mode resolved for a `setup` run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupWriteMode {
    DryRun,
    OutputDir,
    WriteProject,
}

/// Single rendered integration asset included in [`SetupReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedSetupFile {
    pub client_id: String,
    pub source_path: String,
    pub target_path: String,
    pub kind: String,
    pub format: String,
    pub category: String,
    pub optional: bool,
    pub merge_strategy: String,
    pub written: bool,
    pub merged_existing: bool,
    pub byte_len: usize,
    pub content: String,
}

/// Complete report returned by `context-engine setup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupReport {
    pub mode: SetupWriteMode,
    pub dry_run: bool,
    pub clients: Vec<String>,
    pub workspace_path: String,
    pub binary_path: String,
    pub target_root: String,
    pub files: Vec<GeneratedSetupFile>,
}

/// Executes `context-engine setup` using the real process environment for global-path protection.
pub fn run_setup(options: &SetupOptions) -> Result<SetupReport> {
    run_setup_with_env(options, &HostEnvPaths::from_process_env())
}

/// Executes `context-engine setup` with an explicit [`HostEnvPaths`] snapshot.
pub fn run_setup_with_env(options: &SetupOptions, env_paths: &HostEnvPaths) -> Result<SetupReport> {
    let manifest = load_embedded_manifest()?;
    let selected_clients = resolve_client_selection(&options.client, &manifest)?;

    // 1. Validate raw & canonical workspace path against forbidden global directories BEFORE any I/O.
    reject_raw_global_syntax(&options.workspace)?;
    let canonical_workspace = dunce::canonicalize(&options.workspace).map_err(|err| {
        ContextError::InvalidWorkspacePath {
            path: options.workspace.display().to_string(),
            reason: err.to_string(),
        }
    })?;
    if !canonical_workspace.is_dir() {
        return Err(ContextError::InvalidWorkspacePath {
            path: canonical_workspace.display().to_string(),
            reason: "workspace path must be an existing directory".to_string(),
        });
    }
    ensure_not_forbidden_global_root(&canonical_workspace, env_paths)?;

    // 2. Resolve write mode (defaults to DryRun unless `--output-dir` or `--write-project` is set,
    //    and `--dry-run` always overrides write flags!).
    let mode = if options.dry_run {
        SetupWriteMode::DryRun
    } else if options.output_dir.is_some() {
        SetupWriteMode::OutputDir
    } else if options.write_project {
        SetupWriteMode::WriteProject
    } else {
        SetupWriteMode::DryRun
    };

    // 3. Resolve and validate target root (`output_dir` or `canonical_workspace`).
    let target_root = if let Some(ref out_dir) = options.output_dir {
        reject_raw_global_syntax(out_dir)?;
        let resolved_out = resolve_possibly_new_dir(out_dir)?;
        ensure_not_forbidden_global_root(&resolved_out, env_paths)?;
        resolved_out
    } else {
        canonical_workspace.clone()
    };

    // 4. Normalize `{{WORKSPACE_PATH}}` and `{{BINARY_PATH}}` per `adapters/MANIFEST.json`.
    let workspace_placeholder = format_template_path(&canonical_workspace, true);
    let resolved_binary = resolve_binary_path(options.binary.as_deref())?;
    let binary_placeholder = format_template_path(&resolved_binary, false);

    let embedded_map: BTreeMap<&str, &str> = EMBEDDED_ADAPTER_FILES.iter().copied().collect();
    let mut generated_files: Vec<GeneratedSetupFile> = Vec::new();

    // Phase A: Render and syntax-validate 100% of files in memory before touching disk!
    struct PendingWrite {
        abs_target: PathBuf,
        executable: bool,
        meta: GeneratedSetupFile,
    }
    let mut pending_writes: Vec<PendingWrite> = Vec::new();

    for client_id in &selected_clients {
        let client_spec =
            manifest
                .clients
                .get(client_id)
                .ok_or_else(|| ContextError::InvalidConfig {
                    field: "client",
                    reason: format!("client '{client_id}' missing from embedded MANIFEST.json"),
                })?;

        for file_spec in &client_spec.files {
            let raw_source = embedded_map
                .get(file_spec.source_path.as_str())
                .copied()
                .ok_or_else(|| ContextError::Storage {
                    message: format!(
                        "embedded adapter source '{}' not found in binary",
                        file_spec.source_path
                    ),
                })?;

            let rendered = render_file_spec(
                file_spec,
                raw_source,
                &binary_placeholder,
                &workspace_placeholder,
            )?;

            let rel_target = sanitize_relative_target(&file_spec.default_target_path)?;
            let abs_target = target_root.join(&rel_target);
            ensure_not_forbidden_global_path(&abs_target, env_paths)?;

            let (final_content, merged_existing) = if abs_target.exists() {
                merge_with_existing_if_needed(&abs_target, file_spec, &rendered)?
            } else {
                (rendered, false)
            };

            // Re-validate merged syntax before allowing any disk mutation.
            validate_rendered_syntax(file_spec, &final_content)?;

            let byte_len = final_content.len();
            let meta = GeneratedSetupFile {
                client_id: client_spec.client_id.clone(),
                source_path: file_spec.source_path.clone(),
                target_path: abs_target.display().to_string(),
                kind: file_spec.kind.clone(),
                format: file_spec.format.clone(),
                category: file_spec.category.clone(),
                optional: file_spec.optional,
                merge_strategy: file_spec.merge_strategy.clone(),
                written: mode != SetupWriteMode::DryRun,
                merged_existing,
                byte_len,
                content: final_content,
            };

            pending_writes.push(PendingWrite {
                abs_target,
                executable: file_spec.executable,
                meta,
            });
        }
    }

    // Phase B: Commit atomically only when not in `DryRun` mode.
    if mode != SetupWriteMode::DryRun {
        for item in &pending_writes {
            ensure_not_forbidden_global_path(&item.abs_target, env_paths)?;
            write_file_atomic(
                &item.abs_target,
                item.meta.content.as_bytes(),
                item.executable,
            )?;
        }
    }

    for item in pending_writes {
        let _ = &manifest.clients[&item.meta.client_id].display_name;
        generated_files.push(item.meta);
    }

    Ok(SetupReport {
        mode,
        dry_run: mode == SetupWriteMode::DryRun,
        clients: selected_clients,
        workspace_path: workspace_placeholder,
        binary_path: binary_placeholder,
        target_root: target_root.display().to_string(),
        files: generated_files,
    })
}

fn load_embedded_manifest() -> Result<AdapterManifest> {
    let manifest: AdapterManifest = serde_json::from_str(MANIFEST_JSON)?;
    if manifest.schema_version != 1 {
        return Err(ContextError::Protocol {
            message: format!(
                "unsupported adapters/MANIFEST.json schema_version {}",
                manifest.schema_version
            ),
        });
    }
    Ok(manifest)
}

fn resolve_client_selection(raw_client: &str, manifest: &AdapterManifest) -> Result<Vec<String>> {
    let normalized = raw_client.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(ContextError::InvalidConfig {
            field: "client",
            reason: "client cannot be empty".to_string(),
        });
    }

    if normalized == "all" {
        return Ok(CANONICAL_CLIENT_ORDER
            .iter()
            .map(|s| (*s).to_string())
            .collect());
    }

    if normalized == "claude" {
        return Ok(vec!["claude-code".to_string()]);
    }

    if manifest.clients.contains_key(&normalized) {
        return Ok(vec![normalized]);
    }

    for (id, spec) in &manifest.clients {
        if spec
            .aliases
            .iter()
            .any(|alias| alias.eq_ignore_ascii_case(&normalized))
        {
            return Ok(vec![id.clone()]);
        }
    }

    Err(ContextError::InvalidConfig {
        field: "client",
        reason: format!(
            "unknown client '{raw_client}' (expected cursor, claude-code, opencode, codex, generic, or all)"
        ),
    })
}

fn resolve_binary_path(explicit: Option<&Path>) -> Result<PathBuf> {
    let candidate = match explicit {
        Some(p) => p.to_path_buf(),
        None => std::env::current_exe()?,
    };
    let raw_str = candidate
        .to_string_lossy()
        .trim()
        .trim_matches('"')
        .to_string();
    if raw_str.is_empty() {
        return Err(ContextError::InvalidConfig {
            field: "binary",
            reason: "binary path cannot be empty".to_string(),
        });
    }
    let cleaned = PathBuf::from(&raw_str);
    if cleaned.exists() {
        Ok(dunce::canonicalize(&cleaned).unwrap_or(cleaned))
    } else {
        Ok(dunce::simplified(&cleaned).to_path_buf())
    }
}

fn format_template_path(path: &Path, strip_trailing_sep: bool) -> String {
    let simplified = dunce::simplified(path).to_string_lossy();
    let stripped = simplified.strip_prefix(r"\\?\").unwrap_or(&simplified);
    let mut forward = stripped.replace('\\', "/");

    if strip_trailing_sep {
        while forward.len() > 3 && forward.ends_with('/') {
            forward.pop();
        }
        if forward.len() == 2 && forward.ends_with('/') {
            forward.pop();
        }
    }

    forward.replace('"', "\\\"")
}

fn render_file_spec(
    spec: &ManifestFileSpec,
    raw_source: &str,
    binary_placeholder: &str,
    workspace_placeholder: &str,
) -> Result<String> {
    let rendered = match spec.kind.as_str() {
        "template" => {
            for expected in &spec.placeholders {
                if !raw_source.contains(expected.as_str()) {
                    return Err(ContextError::Protocol {
                        message: format!(
                            "template '{}' missing declared placeholder '{expected}'",
                            spec.source_path
                        ),
                    });
                }
            }
            let out = raw_source
                .replace("{{BINARY_PATH}}", binary_placeholder)
                .replace("{{WORKSPACE_PATH}}", workspace_placeholder);
            if out.contains("{{") {
                return Err(ContextError::Protocol {
                    message: format!(
                        "rendered template '{}' still contains unresolved '{{{{' placeholder token",
                        spec.source_path
                    ),
                });
            }
            out
        }
        "static" => raw_source.to_string(),
        other => {
            return Err(ContextError::Protocol {
                message: format!("unknown manifest file kind '{other}'"),
            });
        }
    };

    validate_rendered_syntax(spec, &rendered)?;
    Ok(rendered)
}

fn validate_rendered_syntax(spec: &ManifestFileSpec, content: &str) -> Result<()> {
    if spec.kind == "template" && content.contains("{{") {
        return Err(ContextError::Protocol {
            message: format!(
                "file '{}' contains unresolved '{{{{' placeholder token",
                spec.source_path
            ),
        });
    }

    match spec.format.as_str() {
        "json" => {
            let parsed: Value =
                serde_json::from_str(content).map_err(|err| ContextError::Protocol {
                    message: format!(
                        "rendered JSON validation failed for '{}': {err}",
                        spec.source_path
                    ),
                })?;
            if !parsed.is_object() {
                return Err(ContextError::Protocol {
                    message: format!(
                        "rendered JSON for '{}' must be a top-level object",
                        spec.source_path
                    ),
                });
            }
        }
        "toml" => {
            validate_toml_config(content, &spec.source_path)?;
        }
        _ => {}
    }

    Ok(())
}

/// Validates rendered Codex `config.toml` syntax and required `[mcp_servers.context_engine]` keys.
pub fn validate_toml_config(content: &str, label: &str) -> Result<()> {
    if content.contains("{{") {
        return Err(ContextError::Protocol {
            message: format!("TOML '{label}' contains unresolved '{{{{' placeholder token"),
        });
    }

    let mut current_section: Option<String> = None;
    let mut saw_context_engine_section = false;
    let mut saw_command = false;
    let mut saw_args = false;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let code = strip_toml_line_comment(raw_line).trim();
        if code.is_empty() {
            continue;
        }

        if code.starts_with('[') {
            if !code.ends_with(']') {
                return Err(ContextError::Protocol {
                    message: format!("TOML '{label}' line {line_no}: unclosed table header"),
                });
            }
            let inner = code.trim_start_matches('[').trim_end_matches(']').trim();
            if inner.is_empty()
                || !inner.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'"' | b'\'')
                })
            {
                return Err(ContextError::Protocol {
                    message: format!(
                        "TOML '{label}' line {line_no}: invalid table header '[{inner}]'"
                    ),
                });
            }
            if inner == "mcp_servers.context_engine" {
                saw_context_engine_section = true;
            }
            current_section = Some(inner.to_string());
            continue;
        }

        let Some((raw_key, raw_val)) = code.split_once('=') else {
            return Err(ContextError::Protocol {
                message: format!("TOML '{label}' line {line_no}: expected 'key = value'"),
            });
        };
        let key = raw_key.trim();
        let val = raw_val.trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(ContextError::Protocol {
                message: format!("TOML '{label}' line {line_no}: invalid key '{key}'"),
            });
        }
        validate_toml_value(val, label, line_no)?;

        if current_section.as_deref() == Some("mcp_servers.context_engine") {
            if key == "command" {
                saw_command = true;
            } else if key == "args" {
                saw_args = true;
            }
        }
    }

    if !saw_context_engine_section || !saw_command || !saw_args {
        return Err(ContextError::Protocol {
            message: format!(
                "TOML '{label}' missing required [mcp_servers.context_engine] command/args entries"
            ),
        });
    }

    Ok(())
}

fn validate_toml_value(val: &str, label: &str, line_no: usize) -> Result<()> {
    if val.is_empty() {
        return Err(ContextError::Protocol {
            message: format!("TOML '{label}' line {line_no}: empty value"),
        });
    }
    if val == "true" || val == "false" || val.parse::<i64>().is_ok() || val.parse::<f64>().is_ok() {
        return Ok(());
    }
    if val.starts_with('"') {
        validate_toml_basic_string(val, label, line_no)?;
        return Ok(());
    }
    if val.starts_with('\'') && val.len() >= 2 && val.ends_with('\'') {
        return Ok(());
    }
    if val.starts_with('[') && val.ends_with(']') {
        let inner = val[1..val.len() - 1].trim();
        if inner.is_empty() {
            return Ok(());
        }
        for elem in split_toml_array_elements(inner, label, line_no)? {
            let trimmed = elem.trim();
            if !trimmed.is_empty() {
                validate_toml_value(trimmed, label, line_no)?;
            }
        }
        return Ok(());
    }

    Err(ContextError::Protocol {
        message: format!("TOML '{label}' line {line_no}: invalid TOML value '{val}'"),
    })
}

fn validate_toml_basic_string(val: &str, label: &str, line_no: usize) -> Result<()> {
    let bytes = val.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return Err(ContextError::Protocol {
            message: format!("TOML '{label}' line {line_no}: unterminated double-quoted string"),
        });
    }
    let mut idx = 1usize;
    while idx < bytes.len() - 1 {
        let b = bytes[idx];
        if b == b'\\' {
            idx += 1;
            if idx >= bytes.len() - 1 {
                return Err(ContextError::Protocol {
                    message: format!("TOML '{label}' line {line_no}: trailing backslash escape"),
                });
            }
            let esc = bytes[idx];
            if !matches!(
                esc,
                b'\\' | b'"' | b'n' | b'r' | b't' | b'b' | b'f' | b'u' | b'U'
            ) {
                return Err(ContextError::Protocol {
                    message: format!(
                        "TOML '{label}' line {line_no}: invalid TOML string escape '\\{}'",
                        char::from(esc)
                    ),
                });
            }
        } else if b == b'"' {
            return Err(ContextError::Protocol {
                message: format!(
                    "TOML '{label}' line {line_no}: unescaped '\"' inside basic string"
                ),
            });
        }
        idx += 1;
    }
    Ok(())
}

fn split_toml_array_elements<'a>(
    inner: &'a str,
    label: &str,
    line_no: usize,
) -> Result<Vec<&'a str>> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;

    for (idx, ch) in inner.char_indices() {
        if in_quotes {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quotes = false;
            }
            continue;
        }
        if ch == '"' {
            in_quotes = true;
        } else if ch == ',' {
            parts.push(&inner[start..idx]);
            start = idx + 1;
        }
    }
    if in_quotes {
        return Err(ContextError::Protocol {
            message: format!("TOML '{label}' line {line_no}: unterminated string inside array"),
        });
    }
    parts.push(&inner[start..]);
    Ok(parts)
}

fn strip_toml_line_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;

    for (idx, ch) in line.char_indices() {
        if in_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        match ch {
            '"' => in_double = true,
            '\'' => in_single = true,
            '#' => return &line[..idx],
            _ => {}
        }
    }
    line
}

fn merge_with_existing_if_needed(
    existing_path: &Path,
    spec: &ManifestFileSpec,
    rendered: &str,
) -> Result<(String, bool)> {
    match spec.merge_strategy.as_str() {
        "merge_json_mcp_servers" => {
            let existing_raw = fs::read_to_string(existing_path)?;
            let mut existing_val: Value = serde_json::from_str(&existing_raw)?;
            let rendered_val: Value = serde_json::from_str(rendered)?;
            let Some(root_obj) = existing_val.as_object_mut() else {
                return Ok((rendered.to_string(), false));
            };
            let servers_entry = root_obj
                .entry("mcpServers")
                .or_insert_with(|| Value::Object(Map::new()));
            if let (Some(dst_servers), Some(src_servers)) = (
                servers_entry.as_object_mut(),
                rendered_val.get("mcpServers").and_then(Value::as_object),
            ) {
                for (k, v) in src_servers {
                    dst_servers.insert(k.clone(), v.clone());
                }
            }
            Ok((
                format!("{}\n", serde_json::to_string_pretty(&existing_val)?),
                true,
            ))
        }
        "merge_opencode_config" => {
            let existing_raw = fs::read_to_string(existing_path)?;
            let mut existing_val: Value = serde_json::from_str(&existing_raw)?;
            let rendered_val: Value = serde_json::from_str(rendered)?;
            let Some(root_obj) = existing_val.as_object_mut() else {
                return Ok((rendered.to_string(), false));
            };

            if let Some(src_plugins) = rendered_val.get("plugin").and_then(Value::as_array) {
                let dst_plugins = root_obj
                    .entry("plugin")
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Some(arr) = dst_plugins.as_array_mut() {
                    for p in src_plugins {
                        if !arr.contains(p) {
                            arr.push(p.clone());
                        }
                    }
                }
            }

            if let Some(src_mcp) = rendered_val.get("mcp").and_then(Value::as_object) {
                let dst_mcp = root_obj
                    .entry("mcp")
                    .or_insert_with(|| Value::Object(Map::new()));
                if let Some(map) = dst_mcp.as_object_mut() {
                    for (k, v) in src_mcp {
                        map.insert(k.clone(), v.clone());
                    }
                }
            }

            if let Some(src_perm) = rendered_val.get("permission").and_then(Value::as_object) {
                let dst_perm = root_obj
                    .entry("permission")
                    .or_insert_with(|| Value::Object(Map::new()));
                if let Some(map) = dst_perm.as_object_mut() {
                    for (k, v) in src_perm {
                        map.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
            }

            Ok((
                format!("{}\n", serde_json::to_string_pretty(&existing_val)?),
                true,
            ))
        }
        "merge_cursor_hooks" => {
            let existing_raw = fs::read_to_string(existing_path)?;
            let mut existing_val: Value = serde_json::from_str(&existing_raw)?;
            let rendered_val: Value = serde_json::from_str(rendered)?;
            let Some(root_obj) = existing_val.as_object_mut() else {
                return Ok((rendered.to_string(), false));
            };
            root_obj
                .entry("version")
                .or_insert_with(|| Value::from(1u64));
            let dst_hooks = root_obj
                .entry("hooks")
                .or_insert_with(|| Value::Object(Map::new()));
            if let (Some(dst_map), Some(src_arr)) = (
                dst_hooks.as_object_mut(),
                rendered_val
                    .pointer("/hooks/afterShellExecution")
                    .and_then(Value::as_array),
            ) {
                let arr = dst_map
                    .entry("afterShellExecution")
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Some(list) = arr.as_array_mut() {
                    list.retain(|entry| {
                        !entry
                            .get("command")
                            .and_then(Value::as_str)
                            .is_some_and(|c| c.contains("post-command-capture"))
                    });
                    for item in src_arr {
                        list.push(item.clone());
                    }
                }
            }
            Ok((
                format!("{}\n", serde_json::to_string_pretty(&existing_val)?),
                true,
            ))
        }
        "merge_claude_hooks" => {
            let existing_raw = fs::read_to_string(existing_path)?;
            let mut existing_val: Value = serde_json::from_str(&existing_raw)?;
            let rendered_val: Value = serde_json::from_str(rendered)?;
            let Some(root_obj) = existing_val.as_object_mut() else {
                return Ok((rendered.to_string(), false));
            };
            let dst_hooks = root_obj
                .entry("hooks")
                .or_insert_with(|| Value::Object(Map::new()));
            if let (Some(dst_map), Some(src_arr)) = (
                dst_hooks.as_object_mut(),
                rendered_val
                    .pointer("/hooks/PostToolUse")
                    .and_then(Value::as_array),
            ) {
                let arr = dst_map
                    .entry("PostToolUse")
                    .or_insert_with(|| Value::Array(Vec::new()));
                if let Some(list) = arr.as_array_mut() {
                    list.retain(|entry| {
                        !serde_json::to_string(entry)
                            .unwrap_or_default()
                            .contains("post-tool-reduce.mjs")
                    });
                    for item in src_arr {
                        list.push(item.clone());
                    }
                }
            }
            Ok((
                format!("{}\n", serde_json::to_string_pretty(&existing_val)?),
                true,
            ))
        }
        "merge_toml_mcp_servers" => {
            let existing_raw = fs::read_to_string(existing_path)?;
            let stripped = remove_toml_section(&existing_raw, "mcp_servers.context_engine");
            let trimmed = stripped.trim_end();
            let merged = if trimmed.is_empty() {
                rendered.to_string()
            } else {
                format!("{trimmed}\n\n{rendered}")
            };
            Ok((merged, true))
        }
        _ => Ok((rendered.to_string(), false)),
    }
}

fn remove_toml_section(raw: &str, target_section: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let mut skipping = false;

    for line in raw.lines() {
        let code = strip_toml_line_comment(line).trim();
        if code.starts_with('[') && code.ends_with(']') {
            let name = code.trim_start_matches('[').trim_end_matches(']').trim();
            skipping = name == target_section;
        }
        if !skipping {
            kept.push(line);
        }
    }
    kept.join("\n")
}

fn sanitize_relative_target(raw_rel: &str) -> Result<PathBuf> {
    let p = Path::new(raw_rel);
    if p.is_absolute() {
        return Err(ContextError::PathEscape {
            path: raw_rel.to_string(),
            workspace_root: "<target>".to_string(),
            reason: "manifest target path must be relative".to_string(),
        });
    }
    let mut clean = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(seg) => clean.push(seg),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ContextError::PathEscape {
                    path: raw_rel.to_string(),
                    workspace_root: "<target>".to_string(),
                    reason: "manifest target path must not contain '..' traversal".to_string(),
                });
            }
        }
    }
    Ok(clean)
}

fn resolve_possibly_new_dir(requested: &Path) -> Result<PathBuf> {
    let abs = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()?.join(requested)
    };

    let mut existing_prefix = abs.as_path();
    let mut missing_suffix: Vec<std::ffi::OsString> = Vec::new();

    while !existing_prefix.exists() {
        let Some(name) = existing_prefix.file_name() else {
            break;
        };
        missing_suffix.push(name.to_os_string());
        let Some(parent) = existing_prefix.parent() else {
            break;
        };
        existing_prefix = parent;
    }

    let mut base = if existing_prefix.exists() {
        dunce::canonicalize(existing_prefix)?
    } else {
        dunce::simplified(&abs).to_path_buf()
    };

    for seg in missing_suffix.into_iter().rev() {
        base.push(seg);
    }
    Ok(base)
}

fn reject_raw_global_syntax(raw: &Path) -> Result<()> {
    let text = raw.to_string_lossy();
    let trimmed = text.trim();
    let lower = trimmed.replace('\\', "/").to_ascii_lowercase();

    if trimmed == "~"
        || lower.starts_with("~/")
        || lower.contains("%appdata%")
        || lower.contains("$appdata")
        || lower.contains("%userprofile%/.cursor")
        || lower.contains("%userprofile%/.claude")
        || lower.contains("%userprofile%/.codex")
    {
        return Err(ContextError::ScopeViolation {
            expected_workspace: "<isolated-project-directory>".to_string(),
            actual_workspace: trimmed.to_string(),
            detail: "setup unconditionally refuses tilde (~) and global user config paths"
                .to_string(),
        });
    }
    Ok(())
}

fn ensure_not_forbidden_global_root(target_root: &Path, env_paths: &HostEnvPaths) -> Result<()> {
    for home in [&env_paths.home, &env_paths.userprofile]
        .into_iter()
        .flatten()
    {
        let canon_home = canonical_or_simplified(home);
        if paths_equal(target_root, &canon_home) {
            return Err(ContextError::ScopeViolation {
                expected_workspace: "<isolated-project-directory>".to_string(),
                actual_workspace: target_root.display().to_string(),
                detail: "setup refuses targeting the user's home directory directly because it would write global ~/.cursor or ~/.claude configs".to_string(),
            });
        }
    }
    ensure_not_forbidden_global_path(target_root, env_paths)
}

fn ensure_not_forbidden_global_path(candidate: &Path, env_paths: &HostEnvPaths) -> Result<()> {
    let mut forbidden_roots: Vec<PathBuf> = Vec::new();

    for home in [&env_paths.home, &env_paths.userprofile]
        .into_iter()
        .flatten()
    {
        let h = canonical_or_simplified(home);
        forbidden_roots.push(h.join(".cursor"));
        forbidden_roots.push(h.join(".claude"));
        forbidden_roots.push(h.join(".codex"));
        forbidden_roots.push(h.join(".config").join("opencode"));
        forbidden_roots.push(h.join("AppData").join("Roaming"));
    }

    if let Some(ref xdg) = env_paths.xdg_config_home {
        let x = canonical_or_simplified(xdg);
        forbidden_roots.push(x.join("opencode"));
    }

    if let Some(ref appdata) = env_paths.appdata {
        forbidden_roots.push(canonical_or_simplified(appdata));
    }

    for forbidden in &forbidden_roots {
        let canon_forbidden = canonical_or_simplified(forbidden);
        if path_starts_with_dir(candidate, &canon_forbidden) {
            return Err(ContextError::ScopeViolation {
                expected_workspace: "<isolated-project-directory>".to_string(),
                actual_workspace: candidate.display().to_string(),
                detail: format!(
                    "setup unconditionally refuses writing inside global user config path '{}'",
                    canon_forbidden.display()
                ),
            });
        }
    }

    Ok(())
}

fn canonical_or_simplified(p: &Path) -> PathBuf {
    if p.exists() {
        dunce::canonicalize(p).unwrap_or_else(|_| dunce::simplified(p).to_path_buf())
    } else {
        dunce::simplified(p).to_path_buf()
    }
}

fn paths_equal(a: &Path, b: &Path) -> bool {
    let a_comps: Vec<Component<'_>> = dunce::simplified(a).components().collect();
    let b_comps: Vec<Component<'_>> = dunce::simplified(b).components().collect();
    if a_comps.len() != b_comps.len() {
        return false;
    }
    a_comps
        .into_iter()
        .zip(b_comps)
        .all(|(ca, cb)| comp_eq(ca, cb))
}

fn path_starts_with_dir(candidate: &Path, dir: &Path) -> bool {
    let mut cand_comps = dunce::simplified(candidate).components();
    for dir_comp in dunce::simplified(dir).components() {
        let Some(c) = cand_comps.next() else {
            return false;
        };
        if !comp_eq(c, dir_comp) {
            return false;
        }
    }
    true
}

fn comp_eq(a: Component<'_>, b: Component<'_>) -> bool {
    #[cfg(windows)]
    {
        a.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

fn write_file_atomic(target_path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let parent_dir = target_path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = TempBuilder::new()
        .prefix(".ce-setup-")
        .suffix(".tmp")
        .tempfile_in(parent_dir)?;
    tmp.write_all(bytes)?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;

    #[cfg(unix)]
    if executable {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755));
    }
    #[cfg(not(unix))]
    let _ = executable;

    tmp.persist(target_path)
        .map_err(|err| ContextError::Io(err.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn embeds_all_23_adapter_files_and_validates_every_client_dry_run() {
        assert_eq!(EMBEDDED_ADAPTER_FILES.len(), 23);

        let ws = TempDir::new().expect("ws");
        let fake_home = TempDir::new().expect("fake_home");
        let fake_appdata = fake_home.path().join("AppData").join("Roaming");
        fs::create_dir_all(&fake_appdata).expect("mkdir appdata");

        let env = HostEnvPaths {
            home: Some(fake_home.path().to_path_buf()),
            userprofile: Some(fake_home.path().to_path_buf()),
            appdata: Some(fake_appdata),
            xdg_config_home: None,
        };

        // Default (neither `--output-dir` nor `--write-project`) MUST be `DryRun` and write 0 files!
        let report = run_setup_with_env(
            &SetupOptions {
                client: "all".to_string(),
                workspace: ws.path().to_path_buf(),
                binary: Some(PathBuf::from(r"D:\tools\context-engine\context-engine.exe")),
                output_dir: None,
                write_project: false,
                dry_run: false,
            },
            &env,
        )
        .expect("dry-run all clients");

        assert!(report.dry_run);
        assert_eq!(report.mode, SetupWriteMode::DryRun);
        assert_eq!(report.clients.len(), 5);
        // 22 client files across cursor(6) + claude-code(6) + opencode(3) + codex(3) + generic-mcp(4)
        assert_eq!(report.files.len(), 22);
        assert!(!ws.path().join(".cursor").exists());
        assert!(!ws.path().join(".mcp.json").exists());

        for f in &report.files {
            assert!(!f.written);
            if f.kind == "template" {
                assert!(
                    !f.content.contains("{{"),
                    "unresolved token in {}",
                    f.source_path
                );
            }
            if f.format == "json" {
                let parsed: Value = serde_json::from_str(&f.content).expect("valid JSON");
                assert!(parsed.is_object());
            } else if f.format == "toml" {
                validate_toml_config(&f.content, &f.source_path).expect("valid TOML");
            }
        }
    }

    #[test]
    fn refuses_forbidden_global_paths_and_supports_output_dir_and_project_merge() {
        let fake_home = TempDir::new().expect("fake_home");
        let dot_cursor = fake_home.path().join(".cursor");
        let dot_claude = fake_home.path().join(".claude");
        let dot_codex = fake_home.path().join(".codex");
        let opencode_cfg = fake_home.path().join(".config").join("opencode");
        let appdata = fake_home.path().join("AppData").join("Roaming");
        for d in [
            &dot_cursor,
            &dot_claude,
            &dot_codex,
            &opencode_cfg,
            &appdata,
        ] {
            fs::create_dir_all(d).expect("mkdir forbidden");
        }

        let env = HostEnvPaths {
            home: Some(fake_home.path().to_path_buf()),
            userprofile: Some(fake_home.path().to_path_buf()),
            appdata: Some(appdata.clone()),
            xdg_config_home: Some(fake_home.path().join(".config")),
        };

        let safe_ws = TempDir::new().expect("safe_ws");

        // 1. Refuse targeting HOME directly or any forbidden global directory
        for bad_target in [
            fake_home.path().to_path_buf(),
            dot_cursor,
            dot_claude,
            dot_codex,
            opencode_cfg,
            appdata,
            PathBuf::from("~/.cursor"),
        ] {
            let err = run_setup_with_env(
                &SetupOptions {
                    client: "cursor".to_string(),
                    workspace: safe_ws.path().to_path_buf(),
                    binary: Some(PathBuf::from("context-engine")),
                    output_dir: Some(bad_target.clone()),
                    write_project: false,
                    dry_run: false,
                },
                &env,
            )
            .expect_err("forbidden global path must be refused");
            assert_eq!(
                err.error_code(),
                "SCOPE_VIOLATION",
                "target={}",
                bad_target.display()
            );
        }

        // 2. Write to explicit `--output-dir`
        let out_dir = TempDir::new().expect("out_dir");
        let out_report = run_setup_with_env(
            &SetupOptions {
                client: "generic".to_string(),
                workspace: safe_ws.path().to_path_buf(),
                binary: Some(PathBuf::from("context-engine")),
                output_dir: Some(out_dir.path().to_path_buf()),
                write_project: false,
                dry_run: false,
            },
            &env,
        )
        .expect("output-dir write");
        assert_eq!(out_report.mode, SetupWriteMode::OutputDir);
        assert!(out_dir.path().join(".mcp.stdio.json").exists());
        assert!(out_dir
            .path()
            .join(".context-engine")
            .join("bin")
            .join("ce-run.ps1")
            .exists());

        // 3. `--write-project` preserves existing unrelated MCP servers via `merge_json_mcp_servers`
        let cursor_dir = safe_ws.path().join(".cursor");
        fs::create_dir_all(&cursor_dir).expect("mkdir .cursor");
        fs::write(
            cursor_dir.join("mcp.json"),
            r#"{"mcpServers":{"existing-tool":{"command":"node","args":["srv.js"]}}}"#,
        )
        .expect("seed mcp.json");

        let proj_report = run_setup_with_env(
            &SetupOptions {
                client: "cursor".to_string(),
                workspace: safe_ws.path().to_path_buf(),
                binary: Some(PathBuf::from("D:/bin/context-engine.exe")),
                output_dir: None,
                write_project: true,
                dry_run: false,
            },
            &env,
        )
        .expect("write-project cursor");
        assert_eq!(proj_report.mode, SetupWriteMode::WriteProject);

        let merged_mcp: Value = serde_json::from_str(
            &fs::read_to_string(cursor_dir.join("mcp.json")).expect("read merged mcp.json"),
        )
        .expect("parse merged JSON");
        assert!(merged_mcp["mcpServers"]["existing-tool"].is_object());
        assert_eq!(
            merged_mcp["mcpServers"]["context-engine"]["command"],
            "D:/bin/context-engine.exe"
        );
    }
}
