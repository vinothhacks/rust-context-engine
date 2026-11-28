//! Deterministic log severity histogram & parameterized template deduplicator (`log_dedup@1`).
//!
//! Preserves severity counts (`FATAL`/`ERROR`/`WARN`/`INFO`/`DEBUG`), first/last timestamps,
//! 100% of unique `ERROR`/`FATAL` messages (with multi-line / chained stack traces intact),
//! and collapses repetitive operational lines into `<TS>`/`<UUID>`/`<IP>`/`<HEX>`/`<NUM>`
//! templates annotated with `[xN]` counts.

use std::collections::HashMap;
use std::sync::LazyLock;

use context_core::{ArtifactId, ReductionBudget, StreamKind, ViewKind};
use regex::Regex;

use crate::common::{
    count_lines, dedup_preserve_order, format_recovery_hint, DomainReduction, RecoveryRange,
};

static EXTRACT_TS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?P<ts>",
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]{1,9})?(?:Z|[+-][0-9]{2}:?[0-9]{2})?",
        r"|[0-9]{4}/[0-9]{2}/[0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2}",
        r"|[A-Z][a-z]{2}\s+[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}",
        r"|[0-9]{2}/[A-Z][a-z]{2}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}",
        r"|[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.,][0-9]{1,6})?",
        r")",
    ))
    .expect("valid EXTRACT_TS_RE")
});

static ZERO_ERROR_FALSE_POS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:0|no|zero)\s+(?:errors?|fail(?:ed|ing|ures?)?|fatals?)\b|\b(?:errors?|fail(?:ed|ures?)?)\s*[:=]\s*0\b",
    )
    .expect("valid ZERO_ERROR_FALSE_POS_RE")
});

static FATAL_SEV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[\s\[\(:=])(?:FATAL|PANIC|CRITICAL|EMERGENCY|EMERG|ALERT|SEVERE)(?:[\s\]\):,]|$)")
        .expect("valid FATAL_SEV_RE")
});

static ERROR_SEV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[\s\[\(:=])(?:ERROR|ERR)(?:[\s\]\):,]|$)").expect("valid ERROR_SEV_RE")
});

static WARN_SEV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[\s\[\(:=])(?:WARN|WARNING)(?:[\s\]\):,]|$)").expect("valid WARN_SEV_RE")
});

static INFO_SEV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[\s\[\(:=])(?:INFO|NOTICE)(?:[\s\]\):,]|$)").expect("valid INFO_SEV_RE")
});

static DEBUG_SEV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[\s\[\(:=])(?:DEBUG|TRACE|VERBOSE)(?:[\s\]\):,]|$)")
        .expect("valid DEBUG_SEV_RE")
});

static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
        .expect("valid UUID_RE")
});

static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b").expect("valid IPV4_RE")
});

static HEX_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:0x[0-9a-fA-F]{4,}|[0-9a-fA-F]{16,})\b").expect("valid HEX_RE")
});

static NUM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[0-9]+(?:\.[0-9]+)?(?:ms|us|ns|s|B|KB|MB|GB|%)?\b").expect("valid NUM_RE")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum LogLevel {
    Fatal,
    Error,
    Warn,
    Info,
    Debug,
    Other,
}

#[derive(Debug, Clone)]
struct LogEvent {
    level: LogLevel,
    head_line: String,
    start_line: usize,
    continuation_lines: Vec<String>,
}

fn classify_line_severity(line: &str) -> LogLevel {
    let scrubbed = ZERO_ERROR_FALSE_POS_RE.replace_all(line, "");
    if FATAL_SEV_RE.is_match(&scrubbed)
        || scrubbed.starts_with("Traceback (most recent call last):")
        || scrubbed.starts_with("thread '") && scrubbed.contains("' panicked at")
    {
        LogLevel::Fatal
    } else if ERROR_SEV_RE.is_match(&scrubbed) {
        LogLevel::Error
    } else if WARN_SEV_RE.is_match(&scrubbed) {
        LogLevel::Warn
    } else if INFO_SEV_RE.is_match(&scrubbed) {
        LogLevel::Info
    } else if DEBUG_SEV_RE.is_match(&scrubbed) {
        LogLevel::Debug
    } else {
        LogLevel::Other
    }
}

fn is_trace_continuation(line: &str, prev_in_trace: bool) -> bool {
    if line.trim().is_empty() {
        return prev_in_trace;
    }
    line.starts_with("  ")
        || line.starts_with('\t')
        || line.starts_with("Caused by:")
        || line.starts_with("During handling of the above exception")
        || line.starts_with("The above exception was the direct cause")
        || (prev_in_trace
            && !EXTRACT_TS_RE.is_match(line)
            && (line.contains("Error:")
                || line.contains("Exception:")
                || line.starts_with("stack backtrace:")))
}

/// Normalizes timestamps, UUIDs, IPv4 addresses, hex digests, and standalone numbers into
/// `<TS>`, `<UUID>`, `<IP>`, `<HEX>`, and `<NUM>` placeholders while preserving alphanumeric
/// error codes (`E0503`, `TS2322`, `ERR_CONN_REFUSED`).
#[must_use]
pub fn parameterize_log_template(line: &str) -> String {
    let s1 = EXTRACT_TS_RE.replace_all(line, "<TS>");
    let s2 = UUID_RE.replace_all(&s1, "<UUID>");
    let s3 = IPV4_RE.replace_all(&s2, "<IP>");
    let s4 = HEX_RE.replace_all(&s3, "<HEX>");
    let s5 = NUM_RE.replace_all(&s4, "<NUM>");
    s5.into_owned()
}

fn strip_leading_timestamp(line: &str) -> String {
    if let Some(mat) = EXTRACT_TS_RE.find(line) {
        if mat.start() <= 2 {
            let rest = line[mat.end()..].trim_start_matches([']', ' ', '\t', '-', '|']);
            if !rest.is_empty() {
                return rest.to_string();
            }
        }
    }
    line.trim().to_string()
}

#[allow(clippy::too_many_lines)]
pub(crate) fn reduce_logs(
    text: &str,
    stream: StreamKind,
    artifact_id: Option<&ArtifactId>,
    originals_available: bool,
    budget: &ReductionBudget,
) -> DomainReduction {
    let raw_lines: Vec<&str> = text.lines().collect();
    let total_lines = count_lines(text);

    let mut first_ts: Option<String> = None;
    let mut last_ts: Option<String> = None;

    let mut events: Vec<LogEvent> = Vec::new();
    let mut in_trace = false;

    for (idx, &line) in raw_lines.iter().enumerate() {
        let line_no = idx + 1;

        if let Some(mat) = EXTRACT_TS_RE.find(line) {
            let ts = mat.as_str().to_string();
            if first_ts.is_none() {
                first_ts = Some(ts.clone());
            }
            last_ts = Some(ts);
        }

        if line.trim().is_empty() && !in_trace {
            continue;
        }

        if !events.is_empty() && is_trace_continuation(line, in_trace) {
            if let Some(last_ev) = events.last_mut() {
                if !line.trim().is_empty() || in_trace {
                    last_ev.continuation_lines.push(line.to_string());
                }
                if matches!(
                    last_ev.level,
                    LogLevel::Info | LogLevel::Debug | LogLevel::Other
                ) && (line.contains("Traceback")
                    || line.contains("Error:")
                    || line.contains("Exception:"))
                {
                    last_ev.level = LogLevel::Error;
                }
            }
            in_trace = !line.trim().is_empty()
                || raw_lines.get(idx + 1).is_some_and(|nxt| {
                    nxt.starts_with("During handling of the above exception")
                        || nxt.starts_with("The above exception was the direct cause")
                        || nxt.starts_with("Traceback ")
                        || nxt.starts_with("  ")
                });
            continue;
        }

        let level = classify_line_severity(line);
        in_trace = line.contains("Traceback (most recent call last):")
            || (line.starts_with("thread '") && line.contains("' panicked at"));
        events.push(LogEvent {
            level,
            head_line: line.to_string(),
            start_line: line_no,
            continuation_lines: Vec::new(),
        });
    }

    let mut fatal_count = 0usize;
    let mut error_count = 0usize;
    let mut warn_count = 0usize;
    let mut info_count = 0usize;
    let mut debug_count = 0usize;
    let mut other_count = 0usize;

    // 100% of unique ERROR/FATAL messages (deduplicated by timestamp-stripped exact message)
    let mut unique_errors: Vec<(String, usize, usize, Vec<String>)> = Vec::new();
    let mut error_key_map: HashMap<String, usize> = HashMap::new();

    // Parameterized templates for WARN / INFO / DEBUG / OTHER
    let mut templates: Vec<(LogLevel, String, usize, usize)> = Vec::new();
    let mut template_map: HashMap<(LogLevel, String), usize> = HashMap::new();

    for ev in events {
        match ev.level {
            LogLevel::Fatal => fatal_count += 1,
            LogLevel::Error => error_count += 1,
            LogLevel::Warn => warn_count += 1,
            LogLevel::Info => info_count += 1,
            LogLevel::Debug => debug_count += 1,
            LogLevel::Other => other_count += 1,
        }

        if matches!(ev.level, LogLevel::Fatal | LogLevel::Error) {
            let exact_msg = strip_leading_timestamp(&ev.head_line);
            if let Some(&pos) = error_key_map.get(&exact_msg) {
                unique_errors[pos].1 += 1;
            } else {
                let pos = unique_errors.len();
                error_key_map.insert(exact_msg.clone(), pos);
                let mut trace: Vec<String> = ev
                    .continuation_lines
                    .into_iter()
                    .filter(|l| !l.trim().is_empty())
                    .take(budget.max_trace_lines_per_failure)
                    .collect();
                while trace.last().is_some_and(|l| l.trim().is_empty()) {
                    trace.pop();
                }
                unique_errors.push((exact_msg, 1, ev.start_line, trace));
            }
        } else {
            let tpl = parameterize_log_template(&ev.head_line);
            let key = (ev.level, tpl.clone());
            if let Some(&pos) = template_map.get(&key) {
                templates[pos].2 += 1;
            } else {
                let pos = templates.len();
                template_map.insert(key, pos);
                templates.push((ev.level, tpl, 1, ev.start_line));
            }
        }
    }

    let failure_identifiers =
        dedup_preserve_order(unique_errors.iter().map(|(msg, _, _, _)| msg.clone()));

    let mut out_lines: Vec<String> = Vec::new();
    let mut header = format!(
        "log_dedup@1: {total_lines} line(s) | FATAL={fatal_count} ERROR={error_count} WARN={warn_count} INFO={info_count} DEBUG={debug_count}"
    );
    if other_count > 0 {
        header.push_str(&format!(" OTHER={other_count}"));
    }
    out_lines.push(header);

    if let (Some(first), Some(last)) = (&first_ts, &last_ts) {
        if first == last {
            out_lines.push(format!("timestamps: {first}"));
        } else {
            out_lines.push(format!("timestamps: {first} .. {last}"));
        }
    }

    // Surface 100% of unique ERROR/FATAL messages first
    if !unique_errors.is_empty() {
        out_lines.push(format!("unique ERROR/FATAL ({}):", unique_errors.len()));
        for (msg, count, start_ln, trace) in &unique_errors {
            out_lines.push(format!(
                "  [x{count}] {msg} [{} L{start_ln}]",
                stream.as_str()
            ));
            for tl in trace {
                out_lines.push(format!("    {tl}"));
            }
        }
    }

    // Sort templates: WARN first, then highest count descending, then first-seen line
    templates.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| b.2.cmp(&a.2))
            .then_with(|| a.3.cmp(&b.3))
    });

    if !templates.is_empty() {
        let tpl_cap = 15usize;
        out_lines.push(format!("deduplicated templates ({}):", templates.len()));
        for (_, tpl, count, start_ln) in templates.iter().take(tpl_cap) {
            out_lines.push(format!("  [x{count}] {tpl} [L{start_ln}]"));
        }
        if templates.len() > tpl_cap {
            out_lines.push(format!(
                "  ... +{} additional template(s) omitted",
                templates.len() - tpl_cap
            ));
        }
    }

    let omitted = total_lines > unique_errors.len() + templates.len()
        || templates.iter().any(|t| t.2 > 1)
        || unique_errors.iter().any(|e| e.1 > 1);
    if omitted && total_lines > 0 {
        let hint_start = unique_errors.first().map_or(1, |(_, _, ln, _)| *ln);
        let hint_end = (hint_start + budget.max_get_lines.saturating_sub(1)).min(total_lines);
        out_lines.push(format!(
            "omitted: {total_lines} raw line(s) collapsed | {}",
            format_recovery_hint(
                artifact_id,
                originals_available,
                stream,
                RecoveryRange::Lines {
                    start: hint_start,
                    end: hint_end,
                }
            )
        ));
    }

    DomainReduction {
        kind: ViewKind::LogSummary,
        safe_excerpt: out_lines.join("\n"),
        omitted,
        failure_identifiers,
    }
}
