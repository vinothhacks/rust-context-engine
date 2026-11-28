//! Deterministic Git (`status`, `diff`, `log`, `show`) output reducer (`git_reducer@1`).
//!
//! Preserves branch/upstream tracking state, staged/unstaged/untracked/conflicted path lists,
//! commit headers, per-file `+/-` diffstats, and hunk headers with exact 1-indexed raw stream
//! line ranges (`[stdout Lstart-Lend]`) so agents can inspect targeted hunks via `context_get`.

use std::sync::LazyLock;

use context_core::{ArtifactId, ReductionBudget, StreamKind, ViewKind};
use regex::Regex;

use crate::common::{
    count_lines, dedup_preserve_order, format_exit_badge, format_recovery_hint, DomainReduction,
    RecoveryRange,
};

static DIFF_GIT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^diff --(?:git a/(?P<a_path>.+?) b/(?P<b_path>.+)|(?:cc|combined) (?P<c_path>.+))$",
    )
    .expect("valid DIFF_GIT_RE")
});

static HUNK_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<hdr>@@+ -[0-9]+(?:,[0-9]+)? (?:\-[0-9]+(?:,[0-9]+)? )*?\+[0-9]+(?:,[0-9]+)? @@+)(?P<ctx>.*)$")
        .expect("valid HUNK_HEADER_RE")
});

static COMMIT_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^commit (?P<sha>[0-9a-f]{7,40})(?:\s+\((?P<refs>[^)]+)\))?\s*$")
        .expect("valid COMMIT_LINE_RE")
});

static STATUS_ENTRY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\s+(?P<kind>new file|modified|deleted|renamed|copied|typechange|both modified|both added|both deleted|added by us|deleted by us|added by them|deleted by them):\s+(?P<path>.+)$",
    )
    .expect("valid STATUS_ENTRY_RE")
});

#[derive(Debug, Clone)]
struct DiffHunk {
    header: String,
    context: String,
    raw_start_line: usize,
    raw_end_line: usize,
}

#[derive(Debug, Clone)]
struct FileDiffStat {
    display_path: String,
    change_note: Option<String>,
    added: usize,
    removed: usize,
    eof_newline_note: bool,
    raw_start_line: usize,
    raw_end_line: usize,
    hunks: Vec<DiffHunk>,
}

#[derive(Debug, Clone)]
struct CommitEntry {
    short_sha: String,
    author: Option<String>,
    date: Option<String>,
    subject: String,
    raw_line: usize,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn reduce_git_output(
    exit_code: Option<i32>,
    timed_out: bool,
    stdout_text: &str,
    stderr_text: &str,
    raw_cr_present: bool,
    artifact_id: Option<&ArtifactId>,
    originals_available: bool,
    budget: &ReductionBudget,
) -> DomainReduction {
    let (primary_stream, primary_text) = if !stdout_text.trim().is_empty() {
        (StreamKind::Stdout, stdout_text)
    } else {
        (StreamKind::Stderr, stderr_text)
    };

    let lines: Vec<&str> = primary_text.lines().collect();
    let total_raw_lines = count_lines(stdout_text) + count_lines(stderr_text);

    // Handle nonzero Git error (e.g. `fatal: not a git repository` or bad revision)
    let exit_failed = exit_code.is_some_and(|c| c != 0) || timed_out;

    // 1. Check if this is `git status` (long or porcelain)
    let is_long_status = lines.first().is_some_and(|first| {
        first.starts_with("On branch ")
            || first.starts_with("HEAD detached at ")
            || first.starts_with("HEAD detached from ")
            || first.starts_with("interactive rebase in progress")
    });
    let is_porcelain_status = lines.first().is_some_and(|first| first.starts_with("## "));

    if is_long_status || is_porcelain_status {
        return reduce_git_status_lines(
            &lines,
            is_porcelain_status,
            exit_code,
            timed_out,
            total_raw_lines,
            primary_stream,
            artifact_id,
            originals_available,
            budget,
        );
    }

    // 2. Parse commits (`git log` / `git show`) and file diffs (`git diff` / `git show` / `git log -p`)
    let mut commits: Vec<CommitEntry> = Vec::new();
    let mut files: Vec<FileDiffStat> = Vec::new();

    let mut idx = 0usize;
    while idx < lines.len() {
        let line = lines[idx];
        let line_no = idx + 1;

        if let Some(caps) = COMMIT_LINE_RE.captures(line) {
            let full_sha = &caps["sha"];
            let short_sha: String = full_sha.chars().take(10).collect();
            let mut author: Option<String> = None;
            let mut date: Option<String> = None;
            let mut subject = String::new();

            let mut cursor = idx + 1;
            while cursor < lines.len() {
                let cl = lines[cursor];
                if COMMIT_LINE_RE.is_match(cl) || DIFF_GIT_RE.is_match(cl) {
                    break;
                }
                if let Some(rest) = cl.strip_prefix("Author:") {
                    author = Some(rest.trim().to_string());
                } else if let Some(rest) = cl.strip_prefix("Date:") {
                    date = Some(rest.trim().to_string());
                } else if subject.is_empty() && cl.starts_with("    ") && !cl.trim().is_empty() {
                    subject = cl.trim().to_string();
                }
                cursor += 1;
            }
            commits.push(CommitEntry {
                short_sha,
                author,
                date,
                subject,
                raw_line: line_no,
            });
            idx = cursor;
            continue;
        }

        if let Some(caps) = DIFF_GIT_RE.captures(line) {
            let display_path =
                if let (Some(a), Some(b)) = (caps.name("a_path"), caps.name("b_path")) {
                    if a.as_str() == b.as_str() {
                        b.as_str().to_string()
                    } else {
                        format!("{} -> {}", a.as_str(), b.as_str())
                    }
                } else if let Some(c) = caps.name("c_path") {
                    c.as_str().to_string()
                } else {
                    line.to_string()
                };

            let file_start = line_no;
            let mut change_note: Option<String> = None;
            let mut added = 0usize;
            let mut removed = 0usize;
            let mut eof_newline_note = false;
            let mut hunks: Vec<DiffHunk> = Vec::new();

            let mut cursor = idx + 1;
            while cursor < lines.len() {
                let dl = lines[cursor];
                let dl_no = cursor + 1;
                if DIFF_GIT_RE.is_match(dl) || COMMIT_LINE_RE.is_match(dl) {
                    break;
                }
                if dl.starts_with("new file mode ") {
                    change_note = Some("new".to_string());
                } else if dl.starts_with("deleted file mode ") {
                    change_note = Some("deleted".to_string());
                } else if dl.starts_with("rename from ") || dl.starts_with("similarity index ") {
                    if change_note.is_none() {
                        change_note = Some("renamed".to_string());
                    }
                } else if dl.starts_with("old mode ") || dl.starts_with("new mode ") {
                    if change_note.is_none() {
                        change_note = Some("mode-change".to_string());
                    }
                } else if dl.starts_with("Binary files ") {
                    change_note = Some("binary".to_string());
                } else if dl.starts_with("index ")
                    || dl.starts_with("--- ")
                    || dl.starts_with("+++ ")
                {
                    // Skip git blob index & file-marker boilerplate
                } else if let Some(hc) = HUNK_HEADER_RE.captures(dl) {
                    if let Some(prev_hunk) = hunks.last_mut() {
                        prev_hunk.raw_end_line =
                            dl_no.saturating_sub(1).max(prev_hunk.raw_start_line);
                    }
                    hunks.push(DiffHunk {
                        header: hc["hdr"].to_string(),
                        context: hc["ctx"].trim().to_string(),
                        raw_start_line: dl_no,
                        raw_end_line: dl_no,
                    });
                } else if dl.starts_with("\\ No newline at end of file") {
                    eof_newline_note = true;
                } else if dl.starts_with('+') && !dl.starts_with("+++") {
                    added += 1;
                } else if dl.starts_with('-') && !dl.starts_with("---") {
                    removed += 1;
                }
                cursor += 1;
            }

            let file_end = if cursor > idx { cursor } else { file_start };
            if let Some(last_hunk) = hunks.last_mut() {
                last_hunk.raw_end_line = file_end.max(last_hunk.raw_start_line);
            }

            if added == 0
                && removed == 0
                && change_note.is_none()
                && (eof_newline_note || raw_cr_present)
            {
                change_note = Some("line-ending/eof-newline".to_string());
            }

            files.push(FileDiffStat {
                display_path,
                change_note,
                added,
                removed,
                eof_newline_note,
                raw_start_line: file_start,
                raw_end_line: file_end,
                hunks,
            });
            idx = cursor;
            continue;
        }

        idx += 1;
    }

    let mut failure_identifiers: Vec<String> = Vec::new();
    if exit_failed {
        for ln in stderr_text.lines().chain(stdout_text.lines()) {
            let trimmed = ln.trim();
            if trimmed.starts_with("fatal:")
                || trimmed.starts_with("error:")
                || trimmed.starts_with("CONFLICT ")
            {
                failure_identifiers.push(trimmed.to_string());
            }
        }
    }
    let failure_identifiers = dedup_preserve_order(failure_identifiers);

    let exit_badge = format_exit_badge(exit_code, timed_out);
    let mut out_lines: Vec<String> = Vec::new();

    // Handle `--oneline` git log when neither `commit <40-hex>` nor `diff --git` appeared
    if commits.is_empty() && files.is_empty() {
        if total_raw_lines == 0 {
            out_lines.push(format!("git_reducer@1: empty output ({exit_badge})"));
            return DomainReduction {
                kind: ViewKind::GitSummary,
                safe_excerpt: out_lines.join("\n"),
                omitted: false,
                failure_identifiers,
            };
        }

        let preview_cap = 20usize.min(budget.max_view_lines.saturating_sub(3).max(1));
        out_lines.push(format!(
            "git_reducer@1: {total_raw_lines} line(s) ({exit_badge})"
        ));
        for ln in lines.iter().take(preview_cap) {
            out_lines.push((*ln).to_string());
        }
        let omitted = lines.len() > preview_cap;
        if omitted {
            out_lines.push(format!(
                "... +{} line(s) omitted | {}",
                lines.len() - preview_cap,
                format_recovery_hint(
                    artifact_id,
                    originals_available,
                    primary_stream,
                    RecoveryRange::Lines {
                        start: 1,
                        end: lines.len().min(budget.max_get_lines),
                    }
                )
            ));
        }
        return DomainReduction {
            kind: ViewKind::GitSummary,
            safe_excerpt: out_lines.join("\n"),
            omitted,
            failure_identifiers,
        };
    }

    let total_added: usize = files.iter().map(|f| f.added).sum();
    let total_removed: usize = files.iter().map(|f| f.removed).sum();

    let mut summary = format!("git_reducer@1: ({exit_badge})");
    if !commits.is_empty() {
        summary.push_str(&format!(" | {} commit(s)", commits.len()));
    }
    if !files.is_empty() {
        summary.push_str(&format!(
            " | {} file(s) changed, +{total_added}/-{total_removed}",
            files.len()
        ));
    }
    out_lines.push(summary);

    // Render commits (bounded)
    let commit_cap = 12usize;
    for c in commits.iter().take(commit_cap) {
        let author_part = c
            .author
            .as_deref()
            .map_or(String::new(), |a| format!(" ({a})"));
        let date_part = c
            .date
            .as_deref()
            .map_or(String::new(), |d| format!(" [{d}]"));
        out_lines.push(format!(
            "commit {}{author_part}{date_part}: {} [L{}]",
            c.short_sha, c.subject, c.raw_line
        ));
    }
    if commits.len() > commit_cap {
        out_lines.push(format!(
            "... +{} earlier commit(s)",
            commits.len() - commit_cap
        ));
    }

    // Render per-file diffstats + hunk headers with exact raw line ranges
    let file_cap = 30usize;
    for f in files.iter().take(file_cap) {
        let mut tag = f
            .change_note
            .as_deref()
            .map_or(String::new(), |n| format!(" ({n})"));
        if f.eof_newline_note && f.change_note.as_deref() != Some("line-ending/eof-newline") {
            tag.push_str(" [no-eof-nl]");
        }
        out_lines.push(format!(
            "file {}{tag}: +{}/-{} [{} L{}-L{}]",
            f.display_path,
            f.added,
            f.removed,
            primary_stream.as_str(),
            f.raw_start_line,
            f.raw_end_line
        ));
        let hunk_cap = 6usize;
        for h in f.hunks.iter().take(hunk_cap) {
            let ctx = if h.context.is_empty() {
                String::new()
            } else {
                format!(" {}", h.context)
            };
            out_lines.push(format!(
                "  {}{} [{} L{}-L{}]",
                h.header,
                ctx,
                primary_stream.as_str(),
                h.raw_start_line,
                h.raw_end_line
            ));
        }
        if f.hunks.len() > hunk_cap {
            out_lines.push(format!(
                "  ... +{} additional hunk(s) in {}",
                f.hunks.len() - hunk_cap,
                f.display_path
            ));
        }
    }
    if files.len() > file_cap {
        out_lines.push(format!(
            "... +{} additional file(s)",
            files.len() - file_cap
        ));
    }

    let omitted = !files.is_empty() || total_raw_lines > out_lines.len();
    if omitted && total_raw_lines > 0 {
        let first_range = files.first().map_or(
            RecoveryRange::Lines {
                start: 1,
                end: total_raw_lines.min(budget.max_get_lines),
            },
            |f| RecoveryRange::Lines {
                start: f.raw_start_line,
                end: f
                    .raw_end_line
                    .min(f.raw_start_line + budget.max_get_lines.saturating_sub(1)),
            },
        );
        out_lines.push(format!(
            "omitted: {total_raw_lines} raw line(s) | {}",
            format_recovery_hint(
                artifact_id,
                originals_available,
                primary_stream,
                first_range
            )
        ));
    }

    DomainReduction {
        kind: ViewKind::GitSummary,
        safe_excerpt: out_lines.join("\n"),
        omitted,
        failure_identifiers,
    }
}

#[allow(clippy::too_many_arguments)]
fn reduce_git_status_lines(
    lines: &[&str],
    porcelain: bool,
    exit_code: Option<i32>,
    timed_out: bool,
    total_raw_lines: usize,
    stream: StreamKind,
    artifact_id: Option<&ArtifactId>,
    originals_available: bool,
    budget: &ReductionBudget,
) -> DomainReduction {
    let mut branch_header = String::new();
    let mut upstream_note = String::new();
    let mut conflicted: Vec<String> = Vec::new();
    let mut staged: Vec<String> = Vec::new();
    let mut unstaged: Vec<String> = Vec::new();
    let mut untracked: Vec<String> = Vec::new();

    if porcelain {
        for &ln in lines {
            if let Some(rest) = ln.strip_prefix("## ") {
                branch_header = rest.trim().to_string();
                continue;
            }
            if ln.len() < 4 {
                continue;
            }
            let status_pair = &ln[..2];
            let path = ln[3..].trim().to_string();
            match status_pair {
                "??" => untracked.push(path),
                "!!" => {}
                "UU" | "AA" | "DD" | "AU" | "UA" | "DU" | "UD" => {
                    conflicted.push(format!("{status_pair} {path}"));
                }
                _ => {
                    let bytes = status_pair.as_bytes();
                    if bytes[0] != b' ' && bytes[0] != b'?' {
                        staged.push(format!("{} {path}", bytes[0] as char));
                    }
                    if bytes[1] != b' ' && bytes[1] != b'?' {
                        unstaged.push(format!("{} {path}", bytes[1] as char));
                    }
                }
            }
        }
    } else {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Section {
            None,
            Staged,
            Unstaged,
            Untracked,
            Unmerged,
        }
        let mut section = Section::None;

        for &ln in lines {
            let trimmed_end = ln.trim_end();
            if branch_header.is_empty()
                && (trimmed_end.starts_with("On branch ")
                    || trimmed_end.starts_with("HEAD detached "))
            {
                branch_header = trimmed_end.to_string();
                continue;
            }
            if trimmed_end.starts_with("Your branch is ") {
                upstream_note = trimmed_end.to_string();
                continue;
            }
            match trimmed_end {
                "Changes to be committed:" => {
                    section = Section::Staged;
                    continue;
                }
                "Changes not staged for commit:" => {
                    section = Section::Unstaged;
                    continue;
                }
                "Untracked files:" => {
                    section = Section::Untracked;
                    continue;
                }
                "Unmerged paths:" => {
                    section = Section::Unmerged;
                    continue;
                }
                _ => {}
            }

            if trimmed_end.is_empty() || trimmed_end.starts_with("  (use ") {
                continue;
            }

            if section == Section::Untracked {
                if let Some(rest) = trimmed_end.strip_prefix('\t') {
                    let p = rest.trim();
                    if !p.is_empty() {
                        untracked.push(p.to_string());
                    }
                }
            } else if let Some(caps) = STATUS_ENTRY_RE.captures(trimmed_end) {
                let entry = format!("{}: {}", &caps["kind"], caps["path"].trim());
                match section {
                    Section::Staged => staged.push(entry),
                    Section::Unstaged => unstaged.push(entry),
                    Section::Unmerged => conflicted.push(entry),
                    Section::None | Section::Untracked => {}
                }
            }
        }
    }

    let failure_identifiers = dedup_preserve_order(conflicted.clone());
    let exit_badge = format_exit_badge(exit_code, timed_out);

    let mut out_lines: Vec<String> = Vec::new();
    let clean_tree =
        conflicted.is_empty() && staged.is_empty() && unstaged.is_empty() && untracked.is_empty();

    let branch_str = if branch_header.is_empty() {
        "status".to_string()
    } else {
        branch_header
    };
    out_lines.push(format!(
        "git_reducer@1: {branch_str} ({exit_badge}) | staged={}, unstaged={}, untracked={}, conflicted={}",
        staged.len(),
        unstaged.len(),
        untracked.len(),
        conflicted.len()
    ));
    if !upstream_note.is_empty() {
        out_lines.push(format!("upstream: {upstream_note}"));
    }
    if clean_tree {
        out_lines.push("working tree clean".to_string());
    }

    let mut any_list_truncated = false;
    for (label, items, cap) in [
        ("conflicted", &conflicted, 25usize),
        ("staged", &staged, 20usize),
        ("unstaged", &unstaged, 20usize),
        ("untracked", &untracked, 15usize),
    ] {
        if items.is_empty() {
            continue;
        }
        out_lines.push(format!("{label} ({}):", items.len()));
        for item in items.iter().take(cap) {
            out_lines.push(format!("  {item}"));
        }
        if items.len() > cap {
            any_list_truncated = true;
            out_lines.push(format!("  ... +{} more {label} path(s)", items.len() - cap));
        }
    }

    let omitted = any_list_truncated || total_raw_lines > out_lines.len() + 2;
    if omitted && total_raw_lines > 0 {
        out_lines.push(format!(
            "omitted: {total_raw_lines} raw line(s) | {}",
            format_recovery_hint(
                artifact_id,
                originals_available,
                stream,
                RecoveryRange::Lines {
                    start: 1,
                    end: total_raw_lines.min(budget.max_get_lines),
                }
            )
        ));
    }

    DomainReduction {
        kind: ViewKind::GitSummary,
        safe_excerpt: out_lines.join("\n"),
        omitted,
        failure_identifiers,
    }
}
