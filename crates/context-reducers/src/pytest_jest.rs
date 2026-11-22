//! Deterministic `pytest`, `jest`, and `vitest` test-runner reducer (`pytest_jest@1`).
//!
//! Preserves exact exit status (distinguishing pytest exit code `5` = no tests collected from
//! pre-collection crashes), passed/failed/error/skipped/xpass counts, 100% of distinct failing
//! test identifiers, `file:line(:col)` failure spans, and bounded assertion diffs.

use std::collections::HashMap;
use std::sync::LazyLock;

use context_core::{ArtifactId, ReductionBudget, StreamKind, ViewKind};
use regex::Regex;

use crate::common::{
    count_lines, dedup_preserve_order, format_exit_badge, format_recovery_hint, DomainReduction,
    RecoveryRange,
};

static PYTEST_SUMMARY_BAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^=+\s+(?P<body>.+?\bin\s+[0-9.]+s(?:\s*\([^)]*\))?)\s+=+\s*$")
        .expect("valid PYTEST_SUMMARY_BAR_RE")
});

static PYTEST_COUNT_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?P<num>[0-9]+)\s+(?P<kind>passed|failed|errors?|skipped|xfailed|xpassed|warnings?|deselected)",
    )
    .expect("valid PYTEST_COUNT_TOKEN_RE")
});

static PYTEST_SHORT_SUMMARY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<kind>FAILED|ERROR|XPASS)\s+(?:collecting\s+)?(?P<id>[^\s]+)(?:\s+(?:-\s+)?(?P<msg>.+))?$",
    )
    .expect("valid PYTEST_SHORT_SUMMARY_RE")
});

static PYTEST_VERBOSE_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<id>\S+::\S+)\s+(?P<kind>FAILED|ERROR|XPASS)(?:\s+\([^)]*\))?(?:\s+\[\s*[0-9]+%\])?\s*$",
    )
    .expect("valid PYTEST_VERBOSE_LINE_RE")
});

static PYTEST_SECTION_BANNER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^=+\s+(?P<sec>FAILURES|ERRORS|short test summary info|test session starts)\s+=+")
        .expect("valid PYTEST_SECTION_BANNER_RE")
});

static PYTEST_CASE_SEP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^_{3,}\s+(?P<title>.+?)\s+_{3,}\s*$").expect("valid PYTEST_CASE_SEP_RE")
});

static PYTEST_FILE_LOC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<loc>[^\s:][^:]*\.py:[0-9]+):\s*(?P<exc>.*)$")
        .expect("valid PYTEST_FILE_LOC_RE")
});

static JEST_TESTS_SUMMARY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*Tests:\s+(?P<body>.+)$").expect("valid JEST_TESTS_SUMMARY_RE")
});

static JEST_COUNT_PART_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<num>[0-9]+)\s+(?P<kind>failed|passed|skipped|todo|pending|total)")
        .expect("valid JEST_COUNT_PART_RE")
});

static JEST_SUITE_FAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*FAIL\s+(?P<suite>\S+\.(?:test|spec)\.[A-Za-z0-9]+)(?:\s+>\s+(?P<vname>.+))?$")
        .expect("valid JEST_SUITE_FAIL_RE")
});

static JEST_BULLET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*●\s+(?P<name>.+?)\s*$").expect("valid JEST_BULLET_RE"));

static JS_STACK_LOC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:\((?P<p1>[^()\s]+:[0-9]+:[0-9]+)\)|(?:at|❯)\s+(?P<p2>[^\s()]+:[0-9]+:[0-9]+))",
    )
    .expect("valid JS_STACK_LOC_RE")
});

#[derive(Debug, Clone)]
struct RunnerFailureBlock {
    id: String,
    location: Option<String>,
    stream: StreamKind,
    start_line: usize,
    end_line: usize,
    excerpt_lines: Vec<String>,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn reduce_pytest_jest(
    exit_code: Option<i32>,
    timed_out: bool,
    stdout_text: &str,
    stderr_text: &str,
    artifact_id: Option<&ArtifactId>,
    originals_available: bool,
    budget: &ReductionBudget,
) -> DomainReduction {
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut errors = 0usize;
    let mut skipped = 0usize;
    let mut xfailed = 0usize;
    let mut xpassed = 0usize;
    let mut no_tests_collected = exit_code == Some(5);

    let mut raw_failure_ids: Vec<String> = Vec::new();
    let mut blocks: Vec<RunnerFailureBlock> = Vec::new();
    let mut block_index_by_title: HashMap<String, usize> = HashMap::new();

    for (stream_kind, stream_text) in [
        (StreamKind::Stdout, stdout_text),
        (StreamKind::Stderr, stderr_text),
    ] {
        let lines: Vec<&str> = stream_text.lines().collect();
        let mut idx = 0usize;
        let mut in_pytest_failures = false;
        let mut current_jest_file: Option<String> = None;

        while idx < lines.len() {
            let line = lines[idx];
            let line_no = idx + 1;

            if line.contains("no tests ran in ") || line.contains("collected 0 items") {
                no_tests_collected = true;
            }

            if let Some(caps) = PYTEST_SECTION_BANNER_RE.captures(line) {
                let sec = &caps["sec"];
                in_pytest_failures = sec == "FAILURES" || sec == "ERRORS";
                idx += 1;
                continue;
            }

            if let Some(caps) = PYTEST_SUMMARY_BAR_RE.captures(line) {
                in_pytest_failures = false;
                let body = &caps["body"];
                for tok in PYTEST_COUNT_TOKEN_RE.captures_iter(body) {
                    let n = tok["num"].parse::<usize>().unwrap_or(0);
                    match &tok["kind"] {
                        "passed" => passed = passed.max(n),
                        "failed" => failed = failed.max(n),
                        "error" | "errors" => errors = errors.max(n),
                        "skipped" => skipped = skipped.max(n),
                        "xfailed" => xfailed = xfailed.max(n),
                        "xpassed" => xpassed = xpassed.max(n),
                        _ => {}
                    }
                }
                idx += 1;
                continue;
            }

            if let Some(caps) = JEST_TESTS_SUMMARY_RE.captures(line) {
                let body = &caps["body"];
                for tok in JEST_COUNT_PART_RE.captures_iter(body) {
                    let n = tok["num"].parse::<usize>().unwrap_or(0);
                    match &tok["kind"] {
                        "passed" => passed = passed.max(n),
                        "failed" => failed = failed.max(n),
                        "skipped" | "todo" | "pending" => skipped = skipped.max(n),
                        _ => {}
                    }
                }
                idx += 1;
                continue;
            }

            if let Some(caps) = PYTEST_SHORT_SUMMARY_RE.captures(line) {
                let id = caps["id"].trim().to_string();
                raw_failure_ids.push(id.clone());
                if let Some(msg) = caps.name("msg") {
                    let summary_line = format!("{}: {}", &caps["kind"], msg.as_str().trim());
                    if !block_index_by_title.contains_key(&id) {
                        let pos = blocks.len();
                        block_index_by_title.insert(id.clone(), pos);
                        blocks.push(RunnerFailureBlock {
                            id,
                            location: None,
                            stream: stream_kind,
                            start_line: line_no,
                            end_line: line_no,
                            excerpt_lines: vec![summary_line],
                        });
                    }
                }
                idx += 1;
                continue;
            }

            if let Some(caps) = PYTEST_VERBOSE_LINE_RE.captures(line) {
                raw_failure_ids.push(caps["id"].trim().to_string());
                idx += 1;
                continue;
            }

            // Pytest `___ test_name ___` detailed block (handles chained tracebacks with blank lines)
            if in_pytest_failures {
                if let Some(caps) = PYTEST_CASE_SEP_RE.captures(line) {
                    let title = caps["title"].trim().to_string();
                    let start_ln = line_no;
                    let mut cursor = idx + 1;
                    let mut loc: Option<String> = None;
                    let mut e_lines: Vec<String> = Vec::new();
                    let mut tail_context: Vec<String> = Vec::new();

                    while cursor < lines.len() {
                        let body = lines[cursor];
                        if PYTEST_CASE_SEP_RE.is_match(body)
                            || PYTEST_SECTION_BANNER_RE.is_match(body)
                            || PYTEST_SUMMARY_BAR_RE.is_match(body)
                        {
                            break;
                        }
                        if let Some(lc) = PYTEST_FILE_LOC_RE.captures(body.trim()) {
                            loc = Some(lc["loc"].to_string());
                        }
                        if body.starts_with("E   ") || body == "E" {
                            if e_lines.len() < budget.max_trace_lines_per_failure {
                                e_lines.push(body.to_string());
                            }
                        } else if body.contains("During handling of the above exception")
                            || body.contains("The above exception was the direct cause")
                            || body.trim_start().starts_with("File \"")
                            || (!body.trim().is_empty() && !body.starts_with("captured "))
                        {
                            tail_context.push(body.to_string());
                        }
                        cursor += 1;
                    }

                    let end_ln = if cursor > idx { cursor } else { start_ln };
                    let mut excerpt = if !e_lines.is_empty() {
                        e_lines
                    } else {
                        let skip = tail_context
                            .len()
                            .saturating_sub(budget.max_trace_lines_per_failure);
                        tail_context.into_iter().skip(skip).collect()
                    };
                    if excerpt.len() > budget.max_trace_lines_per_failure {
                        excerpt.truncate(budget.max_trace_lines_per_failure);
                    }

                    // Derive canonical node id if location file is known (`path.py::title` fallback)
                    let inferred_id = if let Some(ref l) = loc {
                        let file_only = l.rsplit_once(':').map_or(l.as_str(), |(f, _)| f);
                        let dotted_to_colons = title.replace('.', "::");
                        format!("{file_only}::{dotted_to_colons}")
                    } else {
                        title.clone()
                    };

                    let pos = blocks.len();
                    block_index_by_title.insert(title, pos);
                    block_index_by_title.insert(inferred_id.clone(), pos);
                    blocks.push(RunnerFailureBlock {
                        id: inferred_id,
                        location: loc,
                        stream: stream_kind,
                        start_line: start_ln,
                        end_line: end_ln,
                        excerpt_lines: excerpt,
                    });

                    idx = cursor;
                    continue;
                }
            }

            // Jest / Vitest `FAIL src/foo.test.ts` or `FAIL src/foo.test.ts > suite > test`
            if let Some(caps) = JEST_SUITE_FAIL_RE.captures(line) {
                let suite_file = caps["suite"].trim().to_string();
                if let Some(vname) = caps.name("vname") {
                    let full_id = format!("{suite_file} > {}", vname.as_str().trim());
                    raw_failure_ids.push(full_id.clone());
                    let start_ln = line_no;
                    let mut cursor = idx + 1;
                    let mut loc: Option<String> = None;
                    let mut excerpt: Vec<String> = Vec::new();
                    while cursor < lines.len() {
                        let body = lines[cursor];
                        if JEST_SUITE_FAIL_RE.is_match(body)
                            || body.starts_with("⎯⎯")
                            || body.trim_start().starts_with("Test Files")
                        {
                            break;
                        }
                        if loc.is_none() {
                            if let Some(sc) = JS_STACK_LOC_RE.captures(body) {
                                let candidate = sc
                                    .name("p1")
                                    .or_else(|| sc.name("p2"))
                                    .map(|m| m.as_str().to_string());
                                if candidate
                                    .as_deref()
                                    .is_some_and(|c| !c.contains("node_modules"))
                                {
                                    loc = candidate;
                                }
                            }
                        }
                        if !body.trim().is_empty()
                            && !body.contains("node_modules")
                            && excerpt.len() < budget.max_trace_lines_per_failure
                        {
                            excerpt.push(body.trim_end().to_string());
                        }
                        cursor += 1;
                    }
                    let end_ln = if cursor > idx { cursor } else { start_ln };
                    let pos = blocks.len();
                    block_index_by_title.insert(full_id.clone(), pos);
                    blocks.push(RunnerFailureBlock {
                        id: full_id,
                        location: loc,
                        stream: stream_kind,
                        start_line: start_ln,
                        end_line: end_ln,
                        excerpt_lines: excerpt,
                    });
                    idx = cursor;
                    continue;
                }
                current_jest_file = Some(suite_file);
                idx += 1;
                continue;
            }

            // Jest `● Suite › test name` block
            if let Some(caps) = JEST_BULLET_RE.captures(line) {
                let bullet_name = caps["name"].trim().to_string();
                // Skip Jest's `● Console` log header!
                if bullet_name == "Console" {
                    idx += 1;
                    continue;
                }
                let full_id = match &current_jest_file {
                    Some(f) => format!("{f}::{bullet_name}"),
                    None => bullet_name.clone(),
                };
                raw_failure_ids.push(full_id.clone());

                let start_ln = line_no;
                let mut cursor = idx + 1;
                let mut loc: Option<String> = None;
                let mut excerpt: Vec<String> = Vec::new();
                while cursor < lines.len() {
                    let body = lines[cursor];
                    if JEST_BULLET_RE.is_match(body)
                        || JEST_SUITE_FAIL_RE.is_match(body)
                        || body.starts_with("PASS ")
                        || body.starts_with("Test Suites:")
                    {
                        break;
                    }
                    if loc.is_none() {
                        if let Some(sc) = JS_STACK_LOC_RE.captures(body) {
                            let candidate = sc
                                .name("p1")
                                .or_else(|| sc.name("p2"))
                                .map(|m| m.as_str().to_string());
                            if candidate
                                .as_deref()
                                .is_some_and(|c| !c.contains("node_modules"))
                            {
                                loc = candidate;
                            }
                        }
                    }
                    if !body.trim().is_empty()
                        && !body.contains("node_modules")
                        && excerpt.len() < budget.max_trace_lines_per_failure
                    {
                        excerpt.push(body.trim_end().to_string());
                    }
                    cursor += 1;
                }
                let end_ln = if cursor > idx { cursor } else { start_ln };
                let pos = blocks.len();
                block_index_by_title.insert(full_id.clone(), pos);
                blocks.push(RunnerFailureBlock {
                    id: full_id,
                    location: loc,
                    stream: stream_kind,
                    start_line: start_ln,
                    end_line: end_ln,
                    excerpt_lines: excerpt,
                });
                idx = cursor;
                continue;
            }

            idx += 1;
        }
    }

    // If short summary wasn't enabled (`-q` without `-rA`), populate ids from `blocks`.
    if raw_failure_ids.is_empty() && !blocks.is_empty() {
        for b in &blocks {
            raw_failure_ids.push(b.id.clone());
        }
    }

    let failure_identifiers = dedup_preserve_order(raw_failure_ids);
    let total_fail_like = failed + errors + xpassed;
    if total_fail_like == 0 && !failure_identifiers.is_empty() {
        failed = failure_identifiers.len();
    }

    let exit_badge = format_exit_badge(exit_code, timed_out);
    let pre_collection_crash = exit_code.is_some_and(|c| c != 0 && c != 5)
        && failure_identifiers.is_empty()
        && failed == 0
        && errors == 0;

    let status_word = if no_tests_collected && failed == 0 && errors == 0 && !timed_out {
        "NO_TESTS_COLLECTED"
    } else if pre_collection_crash || timed_out {
        "ERROR"
    } else if failed > 0 || errors > 0 || xpassed > 0 || exit_code.is_some_and(|c| c != 0) {
        "FAIL"
    } else {
        "PASS"
    };

    let mut out_lines: Vec<String> = Vec::new();
    let mut header = format!(
        "pytest_jest@1: {status_word} ({exit_badge}) | {passed} passed, {failed} failed"
    );
    if errors > 0 {
        header.push_str(&format!(", {errors} error(s)"));
    }
    if skipped > 0 {
        header.push_str(&format!(", {skipped} skipped"));
    }
    if xfailed > 0 {
        header.push_str(&format!(", {xfailed} xfailed"));
    }
    if xpassed > 0 {
        header.push_str(&format!(", {xpassed} xpassed"));
    }
    out_lines.push(header);

    // Render causal blocks up to `budget.max_failure_items`
    for (rendered, fid) in failure_identifiers.iter().enumerate() {
        if rendered >= budget.max_failure_items {
            let rem = failure_identifiers.len() - rendered;
            out_lines.push(format!(
                "... +{rem} additional failure(s) retained in failure_identifiers"
            ));
            break;
        }

        // Match exact id or suffix match (for `path.py::Class::method` vs `Class.method` block)
        let matched_block = block_index_by_title
            .get(fid)
            .map(|&i| &blocks[i])
            .or_else(|| {
                blocks
                    .iter()
                    .find(|b| b.id == *fid || fid.ends_with(&b.id) || b.id.ends_with(fid))
            });

        if let Some(b) = matched_block {
            let loc_str = b
                .location
                .as_deref()
                .map_or(String::new(), |l| format!(" @ {l}"));
            out_lines.push(format!(
                "FAIL {fid}{loc_str} [{} L{}-L{}]:",
                b.stream.as_str(),
                b.start_line,
                b.end_line
            ));
            for el in &b.excerpt_lines {
                out_lines.push(format!("  {el}"));
            }
        } else {
            out_lines.push(format!("FAIL {fid}"));
        }
    }

    let total_stdout_lines = count_lines(stdout_text);
    let total_stderr_lines = count_lines(stderr_text);
    let total_raw_lines = total_stdout_lines + total_stderr_lines;

    if pre_collection_crash && total_raw_lines > 0 {
        let (err_stream, err_text, err_total) = if !stderr_text.trim().is_empty() {
            (StreamKind::Stderr, stderr_text, total_stderr_lines)
        } else {
            (StreamKind::Stdout, stdout_text, total_stdout_lines)
        };
        let take = budget.max_trace_lines_per_failure.min(err_total);
        let start_ln = err_total.saturating_sub(take) + 1;
        out_lines.push(format!(
            "collection/runtime crash [{} L{}-L{}]:",
            err_stream.as_str(),
            start_ln,
            err_total
        ));
        for ln in err_text.lines().skip(start_ln.saturating_sub(1)) {
            out_lines.push(format!("  {ln}"));
        }
    }

    let omitted = total_raw_lines > out_lines.len() || passed > 0;
    if omitted && total_raw_lines > 0 {
        let (hint_stream, hint_range) = if let Some(first_block) = blocks.first() {
            (
                first_block.stream,
                RecoveryRange::Lines {
                    start: first_block.start_line,
                    end: first_block
                        .end_line
                        .min(first_block.start_line + budget.max_get_lines.saturating_sub(1)),
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
