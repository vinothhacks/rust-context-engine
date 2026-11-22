//! Deterministic Rust (`rustc` / `cargo check` / `cargo clippy`) and TypeScript (`tsc`)
//! compiler diagnostic reducer (`compiler_diag@1`).
//!
//! Deduplicates identical diagnostics across multi-target workspace builds, surfaces root errors
//! first with diagnostic codes (`E0308`, `TS2322`, etc.) and exact `file:line:col` spans in
//! `failure_identifiers`, and summarizes warning counts.

use std::collections::HashMap;
use std::sync::LazyLock;

use context_core::{ArtifactId, ReductionBudget, StreamKind, ViewKind};
use regex::Regex;

use crate::common::{
    count_lines, dedup_preserve_order, format_exit_badge, format_recovery_hint, DomainReduction,
    RecoveryRange,
};

static RUSTC_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<sev>error|warning)(?:\[(?P<code>[A-Za-z0-9_-]+)\])?:\s+(?P<msg>.+)$")
        .expect("valid RUSTC_HEADER_RE")
});

static RUSTC_SPAN_ARROW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*-->\s+(?P<loc>.+?:[0-9]+:[0-9]+)\s*$").expect("valid RUSTC_SPAN_ARROW_RE")
});

static TSC_PAREN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<file>[^\r\n(]+)\((?P<line>[0-9]+),(?P<col>[0-9]+)\):\s+(?P<sev>error|warning)\s+(?P<code>TS[0-9]+):\s+(?P<msg>.+)$",
    )
    .expect("valid TSC_PAREN_RE")
});

static TSC_COLON_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<file>[^\r\n:]+(?::[^\r\n:0-9][^\r\n:]*)?):(?P<line>[0-9]+):(?P<col>[0-9]+)\s+-\s+(?P<sev>error|warning)\s+(?P<code>TS[0-9]+):\s+(?P<msg>.+)$",
    )
    .expect("valid TSC_COLON_RE")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiagSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone)]
struct ParsedDiagnostic {
    severity: DiagSeverity,
    code: Option<String>,
    message: String,
    primary_span: Option<String>,
    stream: StreamKind,
    start_line: usize,
    end_line: usize,
    body_lines: Vec<String>,
    occurrences: usize,
}

fn is_cargo_summary_boilerplate(sev: &str, msg: &str) -> bool {
    if sev == "error" {
        msg.starts_with("could not compile `")
            || msg.starts_with("aborting due to ")
            || msg.starts_with("build failed")
    } else {
        msg.starts_with("build failed, waiting for other jobs to finish")
            || (msg.starts_with('`') && msg.contains(" generated ") && msg.contains(" warning"))
            || msg.ends_with(" warnings emitted")
            || msg.ends_with(" warning emitted")
    }
}

fn is_cargo_progress_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("Compiling ")
        || trimmed.starts_with("Checking ")
        || trimmed.starts_with("Downloading ")
        || trimmed.starts_with("Downloaded ")
        || trimmed.starts_with("Locking ")
        || trimmed.starts_with("Finished ")
        || trimmed.starts_with("For more information about this error, try ")
        || trimmed.starts_with("Some errors have detailed explanations:")
}

fn format_error_identifier(diag: &ParsedDiagnostic) -> String {
    match (&diag.primary_span, &diag.code) {
        (Some(span), Some(code)) => format!("{span} [{code}]"),
        (Some(span), None) => span.clone(),
        (None, Some(code)) => format!("[{code}] {}", diag.message),
        (None, None) => diag.message.clone(),
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn reduce_compiler_diag(
    exit_code: Option<i32>,
    timed_out: bool,
    stdout_text: &str,
    stderr_text: &str,
    artifact_id: Option<&ArtifactId>,
    originals_available: bool,
    budget: &ReductionBudget,
) -> DomainReduction {
    let mut unique_diags: Vec<ParsedDiagnostic> = Vec::new();
    let mut dedup_map: HashMap<(u8, String, String, String), usize> = HashMap::new();
    let mut checked_crates = 0usize;

    for (stream_kind, stream_text) in [
        (StreamKind::Stderr, stderr_text),
        (StreamKind::Stdout, stdout_text),
    ] {
        let lines: Vec<&str> = stream_text.lines().collect();
        let mut idx = 0usize;

        while idx < lines.len() {
            let line = lines[idx];
            let line_no = idx + 1;
            let trimmed_start = line.trim_start();

            if trimmed_start.starts_with("Checking ") || trimmed_start.starts_with("Compiling ") {
                checked_crates += 1;
                idx += 1;
                continue;
            }

            // 1. TypeScript `file(line,col): error TSxxxx: msg` or `file:line:col - error TSxxxx: msg`
            if let Some(caps) = TSC_PAREN_RE
                .captures(line)
                .or_else(|| TSC_COLON_RE.captures(line))
            {
                let sev = if &caps["sev"] == "error" {
                    DiagSeverity::Error
                } else {
                    DiagSeverity::Warning
                };
                let span = format!(
                    "{}:{}:{}",
                    caps["file"].trim(),
                    &caps["line"],
                    &caps["col"]
                );
                let code = caps["code"].to_string();
                let msg = caps["msg"].trim().to_string();

                let mut body: Vec<String> = Vec::new();
                let mut cursor = idx + 1;
                while cursor < lines.len() {
                    let next_ln = lines[cursor];
                    if TSC_PAREN_RE.is_match(next_ln)
                        || TSC_COLON_RE.is_match(next_ln)
                        || next_ln.starts_with("Found ")
                    {
                        break;
                    }
                    if !next_ln.trim().is_empty() && body.len() < budget.max_trace_lines_per_failure
                    {
                        body.push(next_ln.to_string());
                    }
                    cursor += 1;
                }
                let end_ln = if cursor > idx { cursor } else { line_no };
                let key = (
                    u8::from(sev == DiagSeverity::Warning),
                    code.clone(),
                    span.clone(),
                    msg.clone(),
                );
                if let Some(&existing_idx) = dedup_map.get(&key) {
                    unique_diags[existing_idx].occurrences += 1;
                } else {
                    let pos = unique_diags.len();
                    dedup_map.insert(key, pos);
                    unique_diags.push(ParsedDiagnostic {
                        severity: sev,
                        code: Some(code),
                        message: msg,
                        primary_span: Some(span),
                        stream: stream_kind,
                        start_line: line_no,
                        end_line: end_ln,
                        body_lines: body,
                        occurrences: 1,
                    });
                }
                idx = cursor;
                continue;
            }

            // 2. Rustc / Cargo `error[E0308]: ...` or `warning[...]: ...`
            if let Some(caps) = RUSTC_HEADER_RE.captures(line) {
                let sev_raw = &caps["sev"];
                let msg = caps["msg"].trim().to_string();
                if is_cargo_summary_boilerplate(sev_raw, &msg) {
                    idx += 1;
                    continue;
                }
                let sev = if sev_raw == "error" {
                    DiagSeverity::Error
                } else {
                    DiagSeverity::Warning
                };
                let code = caps.name("code").map(|m| m.as_str().to_string());

                let mut primary_span: Option<String> = None;
                let mut body: Vec<String> = Vec::new();
                let mut cursor = idx + 1;

                while cursor < lines.len() {
                    let next_ln = lines[cursor];
                    if RUSTC_HEADER_RE.is_match(next_ln) || is_cargo_progress_line(next_ln) {
                        break;
                    }
                    if primary_span.is_none() {
                        if let Some(sc) = RUSTC_SPAN_ARROW_RE.captures(next_ln) {
                            primary_span = Some(sc["loc"].trim().to_string());
                        }
                    }
                    if !next_ln.trim().is_empty() && body.len() < budget.max_trace_lines_per_failure
                    {
                        body.push(next_ln.to_string());
                    }
                    cursor += 1;
                }

                let end_ln = if cursor > idx { cursor } else { line_no };
                let key = (
                    u8::from(sev == DiagSeverity::Warning),
                    code.clone().unwrap_or_default(),
                    primary_span.clone().unwrap_or_default(),
                    msg.clone(),
                );
                if let Some(&existing_idx) = dedup_map.get(&key) {
                    unique_diags[existing_idx].occurrences += 1;
                } else {
                    let pos = unique_diags.len();
                    dedup_map.insert(key, pos);
                    unique_diags.push(ParsedDiagnostic {
                        severity: sev,
                        code,
                        message: msg,
                        primary_span,
                        stream: stream_kind,
                        start_line: line_no,
                        end_line: end_ln,
                        body_lines: body,
                        occurrences: 1,
                    });
                }
                idx = cursor;
                continue;
            }

            idx += 1;
        }
    }

    let errors: Vec<&ParsedDiagnostic> = unique_diags
        .iter()
        .filter(|d| d.severity == DiagSeverity::Error)
        .collect();
    let warnings: Vec<&ParsedDiagnostic> = unique_diags
        .iter()
        .filter(|d| d.severity == DiagSeverity::Warning)
        .collect();

    let raw_error_total: usize = errors.iter().map(|d| d.occurrences).sum();
    let raw_warning_total: usize = warnings.iter().map(|d| d.occurrences).sum();

    let failure_identifiers =
        dedup_preserve_order(errors.iter().map(|d| format_error_identifier(d)));

    let has_failed = !errors.is_empty() || exit_code.is_some_and(|c| c != 0) || timed_out;
    let status_word = if has_failed { "FAIL" } else { "OK" };
    let exit_badge = format_exit_badge(exit_code, timed_out);

    let mut out_lines: Vec<String> = Vec::new();
    let mut header = format!(
        "compiler_diag@1: {status_word} ({exit_badge}) | {} unique error(s)",
        errors.len()
    );
    if raw_error_total > errors.len() {
        header.push_str(&format!(" ({raw_error_total} total)"));
    }
    header.push_str(&format!(", {} unique warning(s)", warnings.len()));
    if raw_warning_total > warnings.len() {
        header.push_str(&format!(" ({raw_warning_total} total)"));
    }
    if checked_crates > 0 {
        header.push_str(&format!(" | {checked_crates} target(s) checked"));
    }
    out_lines.push(header);

    // Surface root errors FIRST
    for (rendered, err) in errors.iter().enumerate() {
        if rendered >= budget.max_failure_items {
            let rem = errors.len() - rendered;
            out_lines.push(format!(
                "... +{rem} more unique error(s) retained in failure_identifiers"
            ));
            break;
        }
        let code_str = err
            .code
            .as_deref()
            .map_or("error".to_string(), |c| format!("error[{c}]"));
        let loc_str = err
            .primary_span
            .as_deref()
            .map_or(String::new(), |s| format!(" @ {s}"));
        let dup_str = if err.occurrences > 1 {
            format!(" [x{}]", err.occurrences)
        } else {
            String::new()
        };
        out_lines.push(format!(
            "{code_str}{loc_str}: {}{dup_str} [{} L{}-L{}]",
            err.message,
            err.stream.as_str(),
            err.start_line,
            err.end_line
        ));
        for bl in &err.body_lines {
            out_lines.push(format!("  {bl}"));
        }
    }

    // Summarize top warnings concisely if errors didn't exhaust budget
    if !warnings.is_empty() && errors.len() < 8 {
        let warn_preview_cap = 5usize;
        for warn in warnings.iter().take(warn_preview_cap) {
            let code_str = warn
                .code
                .as_deref()
                .map_or("warning".to_string(), |c| format!("warning[{c}]"));
            let loc_str = warn
                .primary_span
                .as_deref()
                .map_or(String::new(), |s| format!(" @ {s}"));
            let dup_str = if warn.occurrences > 1 {
                format!(" [x{}]", warn.occurrences)
            } else {
                String::new()
            };
            out_lines.push(format!("{code_str}{loc_str}: {}{dup_str}", warn.message));
        }
        if warnings.len() > warn_preview_cap {
            out_lines.push(format!(
                "... +{} additional unique warning(s) omitted",
                warnings.len() - warn_preview_cap
            ));
        }
    }

    let total_stderr_lines = count_lines(stderr_text);
    let total_stdout_lines = count_lines(stdout_text);
    let total_raw_lines = total_stderr_lines + total_stdout_lines;

    if has_failed && errors.is_empty() && total_raw_lines > 0 {
        let (err_stream, err_text, err_total) = if !stderr_text.trim().is_empty() {
            (StreamKind::Stderr, stderr_text, total_stderr_lines)
        } else {
            (StreamKind::Stdout, stdout_text, total_stdout_lines)
        };
        let take = budget.max_trace_lines_per_failure.min(err_total);
        let start_ln = err_total.saturating_sub(take) + 1;
        out_lines.push(format!(
            "unparsed build failure [{} L{}-L{}]:",
            err_stream.as_str(),
            start_ln,
            err_total
        ));
        for ln in err_text.lines().skip(start_ln.saturating_sub(1)) {
            out_lines.push(format!("  {ln}"));
        }
    }

    let omitted = total_raw_lines > out_lines.len()
        || raw_error_total > errors.len()
        || raw_warning_total > 0
        || checked_crates > 0;
    if omitted && total_raw_lines > 0 {
        let (hint_stream, hint_range) = if let Some(first_err) = errors.first() {
            (
                first_err.stream,
                RecoveryRange::Lines {
                    start: first_err.start_line,
                    end: first_err
                        .end_line
                        .min(first_err.start_line + budget.max_get_lines.saturating_sub(1)),
                },
            )
        } else if total_stderr_lines > 0 {
            (
                StreamKind::Stderr,
                RecoveryRange::Lines {
                    start: 1,
                    end: total_stderr_lines.min(budget.max_get_lines),
                },
            )
        } else {
            (
                StreamKind::Stdout,
                RecoveryRange::Lines {
                    start: 1,
                    end: total_stdout_lines.min(budget.max_get_lines),
                },
            )
        };
        out_lines.push(format!(
            "omitted: {total_raw_lines} raw line(s) | {}",
            format_recovery_hint(artifact_id, originals_available, hint_stream, hint_range)
        ));
    }

    DomainReduction {
        kind: ViewKind::CompilerDiagnostics,
        safe_excerpt: out_lines.join("\n"),
        omitted,
        failure_identifiers,
    }
}
