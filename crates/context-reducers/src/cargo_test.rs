//! Deterministic Cargo test & `cargo nextest` reducer (`cargo_test@1`).
//!
//! Preserves exact exit status, aggregated passed/failed/ignored/measured/filtered counts
//! across multi-crate unit/integration/`Doc-tests` suites, 100% of distinct failing test
//! identifiers, `file:line:col` panic/assertion spans, and bounded causal failure blocks.

use std::collections::HashMap;
use std::sync::LazyLock;

use context_core::{ArtifactId, ReductionBudget, StreamKind, ViewKind};
use regex::Regex;

use crate::common::{
    count_lines, dedup_preserve_order, format_exit_badge, format_recovery_hint, DomainReduction,
    RecoveryRange,
};

static TEST_RESULT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^test result:\s+(?P<status>ok|FAILED)\.\s+(?P<passed>[0-9]+)\s+passed;\s+(?P<failed>[0-9]+)\s+failed;\s+(?P<ignored>[0-9]+)\s+ignored;\s+(?P<measured>[0-9]+)\s+measured;\s+(?P<filtered>[0-9]+)\s+filtered out",
    )
    .expect("valid TEST_RESULT_RE")
});

static NEXTEST_SUMMARY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*Summary\s+\[\s*[0-9.]+s\]\s+(?P<run>[0-9]+)\s+tests?\s+run:\s+(?P<rest>.+)$")
        .expect("valid NEXTEST_SUMMARY_RE")
});

static NEXTEST_FAIL_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s*(?P<kind>FAIL|TIMEOUT|LEAK)\s+\[\s*[0-9.]+s\]\s+(?P<bin>\S+)\s+(?P<name>\S.*)$",
    )
    .expect("valid NEXTEST_FAIL_LINE_RE")
});

static LIBTEST_FAILED_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^test\s+(?P<name>.+?)\s+\.\.\.\s+FAILED\s*$")
        .expect("valid LIBTEST_FAILED_LINE_RE")
});

static FAILURE_BLOCK_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^----\s+(?P<name>.+?)\s+(?:stdout|stderr)\s+----\s*$")
        .expect("valid FAILURE_BLOCK_HEADER_RE")
});

static PANIC_MODERN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^thread\s+'(?P<thread>[^']+)'\s+panicked\s+at\s+(?P<loc>[^\r\n:]+(?::[^\r\n:]+)*:[0-9]+:[0-9]+):\s*$",
    )
    .expect("valid PANIC_MODERN_RE")
});

static PANIC_LEGACY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^thread\s+'(?P<thread>[^']+)'\s+panicked\s+at\s+'(?P<msg>[^']*)',\s+(?P<loc>[^\r\n]+:[0-9]+:[0-9]+)\s*$",
    )
    .expect("valid PANIC_LEGACY_RE")
});

static SPAN_ARROW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*-->\s+(?P<loc>\S+:[0-9]+:[0-9]+)").expect("valid SPAN_ARROW_RE")
});

#[derive(Debug, Clone)]
struct FailureDetail {
    location: Option<String>,
    stream: StreamKind,
    start_line: usize,
    end_line: usize,
    trace_lines: Vec<String>,
}

fn canonicalize_libtest_name(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(stripped) = trimmed.strip_suffix(" - should panic") {
        stripped.trim().to_string()
    } else {
        trimmed.to_string()
    }
}

fn is_noise_backtrace_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("note: run with `RUST_BACKTRACE=")
        || trimmed.starts_with("stack backtrace:")
        || trimmed.starts_with("note: Some details are omitted, run with `RUST_BACKTRACE=full`")
        || trimmed.contains("std::panicking::")
        || trimmed.contains("core::panicking::")
        || trimmed.contains("std::sys_common::backtrace")
        || trimmed.contains("test::__rust_begin_short_backtrace")
}

#[allow(clippy::too_many_lines)]
pub(crate) fn reduce_cargo_test(
    exit_code: Option<i32>,
    timed_out: bool,
    stdout_text: &str,
    stderr_text: &str,
    artifact_id: Option<&ArtifactId>,
    originals_available: bool,
    budget: &ReductionBudget,
) -> DomainReduction {
    let mut suites_run = 0usize;
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut ignored = 0usize;
    let mut measured = 0usize;
    let mut filtered = 0usize;
    let mut compiled_crates = 0usize;

    let mut raw_failed_names: Vec<String> = Vec::new();
    let mut details_by_name: HashMap<String, FailureDetail> = HashMap::new();
    let mut ordered_detail_names: Vec<String> = Vec::new();

    for line in stderr_text.lines().chain(stdout_text.lines()) {
        let trimmed = line.trim_start();
        if trimmed.starts_with("Compiling ") || trimmed.starts_with("Checking ") {
            compiled_crates += 1;
        }
    }

    // Parse both streams with accurate per-stream 1-indexed line numbers.
    for (stream_kind, stream_text) in [
        (StreamKind::Stdout, stdout_text),
        (StreamKind::Stderr, stderr_text),
    ] {
        let lines: Vec<&str> = stream_text.lines().collect();
        let mut idx = 0usize;
        let mut in_failures_list = false;

        while idx < lines.len() {
            let line = lines[idx];
            let line_no = idx + 1;

            if line.trim() == "failures:" {
                // Distinguish the first `failures:` header (followed by `---- name stdout ----`)
                // from the bottom `failures:` list (followed by indented test names).
                let next_non_empty = lines[idx + 1..].iter().find(|l| !l.trim().is_empty());
                in_failures_list =
                    next_non_empty.is_some_and(|next| !FAILURE_BLOCK_HEADER_RE.is_match(next));
                idx += 1;
                continue;
            }

            if in_failures_list {
                if line.trim().is_empty() || line.starts_with("test result:") {
                    in_failures_list = false;
                } else if line.starts_with("    ") || line.starts_with('\t') {
                    raw_failed_names.push(canonicalize_libtest_name(line));
                    idx += 1;
                    continue;
                } else {
                    in_failures_list = false;
                }
            }

            if let Some(caps) = TEST_RESULT_RE.captures(line) {
                suites_run += 1;
                passed += caps["passed"].parse::<usize>().unwrap_or(0);
                failed += caps["failed"].parse::<usize>().unwrap_or(0);
                ignored += caps["ignored"].parse::<usize>().unwrap_or(0);
                measured += caps["measured"].parse::<usize>().unwrap_or(0);
                filtered += caps["filtered"].parse::<usize>().unwrap_or(0);
                idx += 1;
                continue;
            }

            if let Some(caps) = NEXTEST_SUMMARY_RE.captures(line) {
                suites_run += 1;
                let rest = &caps["rest"];
                for part in rest.split(',') {
                    let tokens: Vec<&str> = part.split_whitespace().collect();
                    if tokens.len() >= 2 {
                        if let Ok(n) = tokens[0].parse::<usize>() {
                            match tokens[1] {
                                "passed" => passed += n,
                                "failed" | "timed" | "leaky" => failed += n,
                                "skipped" | "ignored" => ignored += n,
                                _ => {}
                            }
                        }
                    }
                }
                idx += 1;
                continue;
            }

            if let Some(caps) = LIBTEST_FAILED_LINE_RE.captures(line) {
                raw_failed_names.push(canonicalize_libtest_name(&caps["name"]));
                idx += 1;
                continue;
            }

            if let Some(caps) = NEXTEST_FAIL_LINE_RE.captures(line) {
                let name = caps["name"].trim().to_string();
                raw_failed_names.push(name.clone());
                details_by_name.entry(name.clone()).or_insert_with(|| {
                    ordered_detail_names.push(name);
                    FailureDetail {
                        location: None,
                        stream: stream_kind,
                        start_line: line_no,
                        end_line: line_no,
                        trace_lines: vec![line.trim().to_string()],
                    }
                });
                idx += 1;
                continue;
            }

            if let Some(caps) = FAILURE_BLOCK_HEADER_RE.captures(line) {
                let name = canonicalize_libtest_name(&caps["name"]);
                raw_failed_names.push(name.clone());

                let block_start = line_no;
                let mut cursor = idx + 1;
                let mut location: Option<String> = None;
                let mut trace: Vec<String> = Vec::new();

                while cursor < lines.len() {
                    let body = lines[cursor];
                    if FAILURE_BLOCK_HEADER_RE.is_match(body)
                        || body.trim() == "failures:"
                        || TEST_RESULT_RE.is_match(body)
                    {
                        break;
                    }

                    if location.is_none() {
                        if let Some(pc) = PANIC_MODERN_RE.captures(body) {
                            location = Some(pc["loc"].to_string());
                        } else if let Some(pc) = PANIC_LEGACY_RE.captures(body) {
                            location = Some(pc["loc"].to_string());
                        } else if let Some(sc) = SPAN_ARROW_RE.captures(body) {
                            location = Some(sc["loc"].to_string());
                        }
                    }

                    if !is_noise_backtrace_line(body)
                        && (!body.trim().is_empty() || !trace.is_empty())
                        && trace.len() < budget.max_trace_lines_per_failure
                    {
                        trace.push(body.to_string());
                    }
                    cursor += 1;
                }

                // Trim trailing empty lines from trace.
                while trace.last().is_some_and(|l| l.trim().is_empty()) {
                    trace.pop();
                }

                let block_end = if cursor > idx { cursor } else { block_start };
                if !details_by_name.contains_key(&name) {
                    ordered_detail_names.push(name.clone());
                }
                details_by_name.insert(
                    name,
                    FailureDetail {
                        location,
                        stream: stream_kind,
                        start_line: block_start,
                        end_line: block_end,
                        trace_lines: trace,
                    },
                );
                idx = cursor;
                continue;
            }

            // Standalone panic outside a `---- name stdout ----` block (e.g., `--nocapture` or harness panic)
            if let Some(pc) = PANIC_MODERN_RE.captures(line) {
                let thread_name = pc["thread"].trim().to_string();
                let loc = pc["loc"].to_string();
                if thread_name != "main" {
                    raw_failed_names.push(thread_name.clone());
                }
                let key = if thread_name == "main" {
                    format!("panic@{loc}")
                } else {
                    thread_name
                };
                details_by_name.entry(key.clone()).or_insert_with(|| {
                    let mut trace = vec![line.to_string()];
                    let mut k = idx + 1;
                    while k < lines.len() && trace.len() < budget.max_trace_lines_per_failure {
                        let next_ln = lines[k];
                        if is_noise_backtrace_line(next_ln)
                            || TEST_RESULT_RE.is_match(next_ln)
                            || LIBTEST_FAILED_LINE_RE.is_match(next_ln)
                        {
                            break;
                        }
                        trace.push(next_ln.to_string());
                        k += 1;
                    }
                    ordered_detail_names.push(key);
                    FailureDetail {
                        location: Some(loc),
                        stream: stream_kind,
                        start_line: line_no,
                        end_line: k.max(line_no),
                        trace_lines: trace,
                    }
                });
            } else if let Some(pc) = PANIC_LEGACY_RE.captures(line) {
                let thread_name = pc["thread"].trim().to_string();
                let loc = pc["loc"].to_string();
                if thread_name != "main" {
                    raw_failed_names.push(thread_name.clone());
                }
                let key = if thread_name == "main" {
                    format!("panic@{loc}")
                } else {
                    thread_name
                };
                details_by_name.entry(key.clone()).or_insert_with(|| {
                    ordered_detail_names.push(key);
                    FailureDetail {
                        location: Some(loc),
                        stream: stream_kind,
                        start_line: line_no,
                        end_line: line_no,
                        trace_lines: vec![line.to_string()],
                    }
                });
            }

            idx += 1;
        }
    }

    let failure_identifiers = dedup_preserve_order(raw_failed_names);
    if failed < failure_identifiers.len() {
        failed = failure_identifiers.len();
    }

    let exit_failed = exit_code.is_some_and(|c| c != 0) || timed_out;
    let overall_failed = failed > 0 || !failure_identifiers.is_empty() || exit_failed;
    let status_word = if overall_failed { "FAIL" } else { "PASS" };
    let exit_badge = format_exit_badge(exit_code, timed_out);

    let total_stdout_lines = count_lines(stdout_text);
    let total_stderr_lines = count_lines(stderr_text);
    let total_raw_lines = total_stdout_lines + total_stderr_lines;

    let mut out_lines: Vec<String> = Vec::new();
    let mut header = format!(
        "cargo_test@1: {status_word} ({exit_badge}) | {passed} passed, {failed} failed, {ignored} ignored"
    );
    if filtered > 0 {
        header.push_str(&format!(", {filtered} filtered"));
    }
    if measured > 0 {
        header.push_str(&format!(", {measured} measured"));
    }
    if suites_run > 1 {
        header.push_str(&format!(" across {suites_run} suites"));
    }
    if compiled_crates > 0 {
        header.push_str(&format!(" ({compiled_crates} crates built)"));
    }
    out_lines.push(header);

    // Render causal failure details up to `budget.max_failure_items`.
    let mut rendered_failures = 0usize;
    let render_order: Vec<String> = if !failure_identifiers.is_empty() {
        failure_identifiers.clone()
    } else {
        ordered_detail_names
    };

    for fail_name in &render_order {
        if rendered_failures >= budget.max_failure_items {
            let remaining = render_order.len() - rendered_failures;
            out_lines.push(format!(
                "... +{remaining} additional failing test(s) retained in failure_identifiers"
            ));
            break;
        }
        rendered_failures += 1;

        if let Some(detail) = details_by_name.get(fail_name) {
            let loc_str = detail
                .location
                .as_deref()
                .map_or(String::new(), |loc| format!(" @ {loc}"));
            out_lines.push(format!(
                "FAIL {fail_name}{loc_str} [{} L{}-L{}]:",
                detail.stream.as_str(),
                detail.start_line,
                detail.end_line
            ));
            for tl in &detail.trace_lines {
                out_lines.push(format!("  {tl}"));
            }
        } else {
            out_lines.push(format!("FAIL {fail_name}"));
        }
    }

    // OQ-01 safety net: nonzero exit with zero parsed failure blocks (e.g. test binary SIGABRT / harness error)
    if overall_failed && rendered_failures == 0 && total_raw_lines > 0 {
        let (err_stream, err_text, err_total) = if !stderr_text.trim().is_empty() {
            (StreamKind::Stderr, stderr_text, total_stderr_lines)
        } else {
            (StreamKind::Stdout, stdout_text, total_stdout_lines)
        };
        let tail_take = budget.max_trace_lines_per_failure.min(err_total);
        let start_ln = err_total.saturating_sub(tail_take) + 1;
        out_lines.push(format!(
            "unparsed failure tail [{} L{}-L{}]:",
            err_stream.as_str(),
            start_ln,
            err_total
        ));
        for ln in err_text.lines().skip(start_ln.saturating_sub(1)) {
            out_lines.push(format!("  {ln}"));
        }
    }

    // Determine whether raw lines were elided and attach exact recovery hint.
    let omitted = total_raw_lines > out_lines.len() || compiled_crates > 0 || passed > 0;
    if omitted && total_raw_lines > 0 {
        let (hint_stream, hint_range) = if let Some(first_fail) = render_order
            .first()
            .and_then(|name| details_by_name.get(name))
        {
            let window_end = first_fail
                .end_line
                .min(first_fail.start_line + budget.max_get_lines.saturating_sub(1));
            (
                first_fail.stream,
                RecoveryRange::Lines {
                    start: first_fail.start_line,
                    end: window_end,
                },
            )
        } else if total_stdout_lines > 0 {
            (
                StreamKind::Stdout,
                RecoveryRange::Lines {
                    start: 1,
                    end: total_stdout_lines.min(budget.max_get_lines),
                },
            )
        } else {
            (
                StreamKind::Stderr,
                RecoveryRange::Lines {
                    start: 1,
                    end: total_stderr_lines.min(budget.max_get_lines),
                },
            )
        };
        out_lines.push(format!(
            "omitted: {total_raw_lines} raw line(s) | {}",
            format_recovery_hint(artifact_id, originals_available, hint_stream, hint_range)
        ));
    }

    DomainReduction {
        kind: ViewKind::TestSummary,
        safe_excerpt: out_lines.join("\n"),
        omitted,
        failure_identifiers,
    }
}
