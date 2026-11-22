//! Deterministic lexical search (`rg` / `grep`) hit grouper (`search_hits@1`).
//!
//! Groups matches by file path (handling Windows `C:\` drive letters and dashed filenames),
//! ranks files by match count, merges matched line ranges, and emits bounded snippets.

use std::collections::HashMap;

use context_core::{
    truncate_str_utf8_boundary, ArtifactId, ReductionBudget, StreamKind, ViewKind,
};

use crate::common::{
    count_lines, dedup_preserve_order, format_exit_badge, format_recovery_hint, DomainReduction,
    RecoveryRange,
};
use crate::ported::parse_search_result_line;

#[derive(Debug, Clone)]
struct FileSearchGroup {
    path: String,
    first_seen_idx: usize,
    first_raw_line: usize,
    match_lines: Vec<usize>,
    snippets: Vec<(usize, String)>,
}

fn format_line_spans(lines: &[usize]) -> String {
    if lines.is_empty() {
        return String::new();
    }
    let mut sorted = lines.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut ranges: Vec<String> = Vec::new();
    let mut start = sorted[0];
    let mut prev = sorted[0];

    for &ln in &sorted[1..] {
        if ln <= prev + 2 {
            prev = ln;
        } else {
            if start == prev {
                ranges.push(format!("L{start}"));
            } else {
                ranges.push(format!("L{start}-L{prev}"));
            }
            start = ln;
            prev = ln;
        }
    }
    if start == prev {
        ranges.push(format!("L{start}"));
    } else {
        ranges.push(format!("L{start}-L{prev}"));
    }

    if ranges.len() > 8 {
        format!("{}, ... (+{} spans)", ranges[..8].join(", "), ranges.len() - 8)
    } else {
        ranges.join(", ")
    }
}

pub(crate) fn reduce_search_hits(
    exit_code: Option<i32>,
    timed_out: bool,
    stdout_text: &str,
    stderr_text: &str,
    artifact_id: Option<&ArtifactId>,
    originals_available: bool,
    budget: &ReductionBudget,
) -> DomainReduction {
    let mut groups: Vec<FileSearchGroup> = Vec::new();
    let mut group_idx_by_path: HashMap<String, usize> = HashMap::new();
    let mut total_matches = 0usize;
    let mut context_lines = 0usize;

    for (idx, line) in stdout_text.lines().enumerate() {
        let raw_ln_no = idx + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed == "--" {
            continue;
        }
        if let Some(parsed) = parse_search_result_line(line) {
            let g_idx = if let Some(&existing) = group_idx_by_path.get(parsed.path) {
                existing
            } else {
                let pos = groups.len();
                group_idx_by_path.insert(parsed.path.to_string(), pos);
                groups.push(FileSearchGroup {
                    path: parsed.path.to_string(),
                    first_seen_idx: pos,
                    first_raw_line: raw_ln_no,
                    match_lines: Vec::new(),
                    snippets: Vec::new(),
                });
                pos
            };

            if parsed.is_match {
                total_matches += 1;
                groups[g_idx].match_lines.push(parsed.line_number);
                if groups[g_idx].snippets.len() < 3 {
                    let (snip, cut) = truncate_str_utf8_boundary(
                        parsed.snippet.trim(),
                        budget.max_search_snippet_bytes.min(120),
                    );
                    let formatted = if cut {
                        format!("{snip}...")
                    } else {
                        snip.to_string()
                    };
                    groups[g_idx].snippets.push((parsed.line_number, formatted));
                }
            } else {
                context_lines += 1;
            }
        }
    }

    // Note: in `rg` and `grep`, exit code 1 means "0 matches found" (not an error);
    // exit code >= 2 indicates an actual CLI/regex/IO error.
    let mut failure_identifiers: Vec<String> = Vec::new();
    if exit_code.is_some_and(|c| !(0..2).contains(&c)) || timed_out {
        for ln in stderr_text.lines() {
            let t = ln.trim();
            if !t.is_empty() {
                failure_identifiers.push(t.to_string());
            }
        }
    }
    let failure_identifiers = dedup_preserve_order(failure_identifiers);

    // Rank files by match count descending, preserving discovery order on ties
    groups.sort_by(|a, b| {
        b.match_lines
            .len()
            .cmp(&a.match_lines.len())
            .then_with(|| a.first_seen_idx.cmp(&b.first_seen_idx))
    });

    let exit_badge = format_exit_badge(exit_code, timed_out);
    let mut out_lines: Vec<String> = Vec::new();

    if groups.is_empty() {
        out_lines.push(format!("search_hits@1: 0 matches ({exit_badge})"));
        for err_ln in stderr_text.lines().take(5) {
            if !err_ln.trim().is_empty() {
                out_lines.push(format!("stderr: {}", err_ln.trim()));
            }
        }
        return DomainReduction {
            kind: ViewKind::SearchHits,
            safe_excerpt: out_lines.join("\n"),
            omitted: false,
            failure_identifiers,
        };
    }

    out_lines.push(format!(
        "search_hits@1: {total_matches} match(es) across {} file(s) ({exit_badge})",
        groups.len()
    ));

    let max_files = budget.max_search_results.clamp(1, 20);
    let mut snippets_omitted = context_lines > 0;

    for g in groups.iter().take(max_files) {
        let spans = format_line_spans(&g.match_lines);
        out_lines.push(format!(
            "{} ({} hit(s): {spans}) [stdout L{}]:",
            g.path,
            g.match_lines.len(),
            g.first_raw_line
        ));
        for (ln_no, snip) in &g.snippets {
            out_lines.push(format!("  L{ln_no}: {snip}"));
        }
        if g.match_lines.len() > g.snippets.len() {
            snippets_omitted = true;
            out_lines.push(format!(
                "  ... +{} more match(es) in {}",
                g.match_lines.len() - g.snippets.len(),
                g.path
            ));
        }
    }

    if groups.len() > max_files {
        snippets_omitted = true;
        out_lines.push(format!(
            "... +{} additional file(s) omitted",
            groups.len() - max_files
        ));
    }

    let total_raw_lines = count_lines(stdout_text) + count_lines(stderr_text);
    let omitted = snippets_omitted || total_raw_lines > out_lines.len();
    if omitted && total_raw_lines > 0 {
        out_lines.push(format!(
            "omitted: {total_raw_lines} raw line(s) | {}",
            format_recovery_hint(
                artifact_id,
                originals_available,
                StreamKind::Stdout,
                RecoveryRange::Lines {
                    start: 1,
                    end: total_raw_lines.min(budget.max_get_lines),
                }
            )
        ));
    }

    DomainReduction {
        kind: ViewKind::SearchHits,
        safe_excerpt: out_lines.join("\n"),
        omitted,
        failure_identifiers,
    }
}
