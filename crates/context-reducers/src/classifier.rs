//! Deterministic single-pass stream & command classifier (`classifier.rs`).
//!
//! Combines `argv` metadata priors (`cargo test`, `cargo nextest`, `pytest`, `jest`, `vitest`,
//! `cargo check`/`build`/`clippy`, `rustc`, `tsc`, `git status`/`diff`/`log`/`show`, `rg`/`grep`)
//! with structural content-shape anchors and the `user-rust-anything`-gated `ported` classifier.

use std::sync::LazyLock;

use context_core::{
    StreamEncoding, ViewKind, TRANSFORM_CARGO_TEST_V1, TRANSFORM_COMPILER_DIAG_V1,
    TRANSFORM_GIT_REDUCER_V1, TRANSFORM_LOG_DEDUP_V1, TRANSFORM_PYTEST_JEST_V1,
    TRANSFORM_SEARCH_HITS_V1, TRANSFORM_STRUCTURED_JSON_V1, TRANSFORM_UNKNOWN_SAFE_V1,
};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::ported::{classify_content, extract_bulk_json, parse_search_result_line, TIMESTAMP_ROW_RE};

/// Policy-selected domain reducer target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReducerTarget {
    Passthrough,
    CargoTest,
    PytestJest,
    CompilerDiag,
    GitReducer,
    StructuredJson,
    LogDedup,
    SearchHits,
    UnknownSafe,
}

impl ReducerTarget {
    /// Versioned transformation identifier recorded in [`context_core::TransformationLedger`].
    #[must_use]
    pub const fn transform_id(&self) -> Option<&'static str> {
        match self {
            Self::Passthrough => None,
            Self::CargoTest => Some(TRANSFORM_CARGO_TEST_V1),
            Self::PytestJest => Some(TRANSFORM_PYTEST_JEST_V1),
            Self::CompilerDiag => Some(TRANSFORM_COMPILER_DIAG_V1),
            Self::GitReducer => Some(TRANSFORM_GIT_REDUCER_V1),
            Self::StructuredJson => Some(TRANSFORM_STRUCTURED_JSON_V1),
            Self::LogDedup => Some(TRANSFORM_LOG_DEDUP_V1),
            Self::SearchHits => Some(TRANSFORM_SEARCH_HITS_V1),
            Self::UnknownSafe => Some(TRANSFORM_UNKNOWN_SAFE_V1),
        }
    }

    /// Maps this reducer target to [`ViewKind`].
    #[must_use]
    pub const fn view_kind(&self, is_clean_utf8_document: bool) -> ViewKind {
        match self {
            Self::Passthrough => ViewKind::Passthrough,
            Self::CargoTest | Self::PytestJest => ViewKind::TestSummary,
            Self::CompilerDiag => ViewKind::CompilerDiagnostics,
            Self::GitReducer => ViewKind::GitSummary,
            Self::StructuredJson => ViewKind::StructuredJson,
            Self::LogDedup => ViewKind::LogSummary,
            Self::SearchHits => ViewKind::SearchHits,
            Self::UnknownSafe => {
                if is_clean_utf8_document {
                    ViewKind::DocumentIndex
                } else {
                    ViewKind::UnknownSafe
                }
            }
        }
    }
}

/// Git subcommand hint extracted from `argv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitSubcommandHint {
    Status,
    Diff,
    Log,
    Show,
}

/// Candidate prior derived from command `argv` before structural content confirmation (`OQ-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandPrior {
    None,
    CargoTest,
    PytestJest,
    CompilerDiag,
    Git(GitSubcommandHint),
    SearchHits,
    JsonFlagged,
}

static RUSTC_DIAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(?:error(?:\[E[0-9]{4}\])?|warning(?:\[[A-Za-z0-9_-]+\])?): .+")
        .expect("valid RUSTC_DIAG_RE")
});

static RUSTC_SPAN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*-->\s+\S+:[0-9]+:[0-9]+").expect("valid RUSTC_SPAN_RE"));

static TSC_DIAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^[^\r\n]+?(?:\([0-9]+,[0-9]+\):\s+(?:error|warning)\s+TS[0-9]+:|:[0-9]+:[0-9]+\s+-\s+(?:error|warning)\s+TS[0-9]+:)",
    )
    .expect("valid TSC_DIAG_RE")
});

static CARGO_TEST_ANCHOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^(?:running [0-9]+ tests?|test result: (?:ok|FAILED)\.|Doc-tests [^\r\n]+|\s*Running (?:unittests |tests/)|failures:$|\s*(?:PASS|FAIL|TIMEOUT|LEAK) \[\s*[0-9.]+s\] |\s*Summary \[\s*[0-9.]+s\] [0-9]+ tests? run:)",
    )
    .expect("valid CARGO_TEST_ANCHOR_RE")
});

static PYTEST_JEST_ANCHOR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^(?:=+ (?:test session starts|FAILURES|ERRORS|short test summary info) =+|collected [0-9]+ items?|FAILED [^\r\n]+::[^\r\n]+|(?:PASS|FAIL)\s+\S+\.(?:test|spec)\.[A-Za-z0-9]+|Test Suites:\s+[0-9]+|Tests:\s+[0-9]+|⎯+\s+Failed (?:Tests|Suites))",
    )
    .expect("valid PYTEST_JEST_ANCHOR_RE")
});

static GIT_COMMIT_LOG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^commit [0-9a-f]{7,40}(?: \(.+\))?\n(?:Merge: .+\n)?Author:\s+")
        .expect("valid GIT_COMMIT_LOG_RE")
});

static GIT_PORCELAIN_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A## [A-Za-z0-9._/-]+(?:\.\.\.[A-Za-z0-9._/-]+)?").expect("valid GIT_PORCELAIN_HEADER_RE")
});

static LOG_SEVERITY_LINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?im)^(?:\s*\[?(?:FATAL|PANIC|CRITICAL|ERROR|ERR|WARN|WARNING|INFO|DEBUG|TRACE)\]?[:\s]|\S+\s+\[?(?:FATAL|PANIC|CRITICAL|ERROR|ERR|WARN|WARNING|INFO|DEBUG|TRACE)\]?[:\s]|.*\blevel=(?:fatal|panic|critical|error|err|warn|warning|info|debug|trace)\b)",
    )
    .expect("valid LOG_SEVERITY_LINE_RE")
});

fn normalize_exe_name(raw: &str) -> String {
    let file_part = raw
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase();
    for suffix in [".exe", ".cmd", ".bat", ".com"] {
        if let Some(stripped) = file_part.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    file_part
}

/// Extracts a [`CommandPrior`] from `argv`, accounting for Cargo `+toolchain` prefixes,
/// global flags (`-C`, `--color`, `--manifest-path`, etc.), and Node/Python test-runner wrappers.
#[must_use]
pub fn parse_command_prior(argv: &[String]) -> CommandPrior {
    let Some(first) = argv.first() else {
        return CommandPrior::None;
    };
    let prog = normalize_exe_name(first);
    let args = &argv[1..];

    match prog.as_str() {
        "cargo" => parse_cargo_prior(args),
        "cargo-nextest" => CommandPrior::CargoTest,
        "rustc" | "tsc" => CommandPrior::CompilerDiag,
        "pytest" | "py.test" | "jest" | "vitest" => CommandPrior::PytestJest,
        "python" | "python3" | "py" | "uv" | "poetry" => {
            if args.iter().any(|a| {
                let lower = normalize_exe_name(a);
                lower == "pytest" || lower == "py.test"
            }) {
                CommandPrior::PytestJest
            } else {
                CommandPrior::None
            }
        }
        "npx" | "pnpm" | "yarn" | "npm" | "bun" => {
            for arg in args {
                let lower = normalize_exe_name(arg);
                if lower == "jest" || lower == "vitest" {
                    return CommandPrior::PytestJest;
                }
                if lower == "tsc" {
                    return CommandPrior::CompilerDiag;
                }
            }
            CommandPrior::None
        }
        "git" => parse_git_prior(args),
        "rg" | "ripgrep" | "grep" | "egrep" | "fgrep" => {
            if args.iter().any(|a| a == "--json") {
                CommandPrior::JsonFlagged
            } else {
                CommandPrior::SearchHits
            }
        }
        _ => CommandPrior::None,
    }
}

fn parse_cargo_prior(args: &[String]) -> CommandPrior {
    let has_json_format = args.windows(2).any(|w| {
        w[0] == "--message-format" && w[1].to_ascii_lowercase().starts_with("json")
    }) || args.iter().any(|a| {
        a.to_ascii_lowercase()
            .starts_with("--message-format=json")
    });

    let flags_with_value = [
        "-C",
        "--config",
        "--color",
        "--target",
        "--target-dir",
        "--manifest-path",
        "--lockfile-path",
        "-Z",
        "--features",
        "-p",
        "--package",
        "--bin",
        "--test",
        "--bench",
        "--example",
        "-j",
        "--jobs",
        "--profile",
        "--message-format",
    ];

    let mut idx = 0usize;
    if idx < args.len() && args[idx].starts_with('+') {
        idx += 1;
    }

    let mut subcmd: Option<&str> = None;
    while idx < args.len() {
        let tok = args[idx].as_str();
        if tok == "--" {
            break;
        }
        if flags_with_value.contains(&tok) {
            idx += 2;
            continue;
        }
        if tok.starts_with('-') {
            idx += 1;
            continue;
        }
        subcmd = Some(tok);
        break;
    }

    if has_json_format {
        return CommandPrior::JsonFlagged;
    }

    match subcmd.map(str::to_ascii_lowercase).as_deref() {
        Some("test" | "t" | "bench" | "nextest") => CommandPrior::CargoTest,
        Some("check" | "c" | "build" | "b" | "clippy" | "rustc") => CommandPrior::CompilerDiag,
        _ => CommandPrior::None,
    }
}

fn parse_git_prior(args: &[String]) -> CommandPrior {
    let flags_with_value = [
        "-C",
        "-c",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--super-prefix",
        "--config-env",
    ];
    let mut idx = 0usize;
    while idx < args.len() {
        let tok = args[idx].as_str();
        if flags_with_value.contains(&tok) {
            idx += 2;
            continue;
        }
        if tok.starts_with('-') {
            idx += 1;
            continue;
        }
        return match tok.to_ascii_lowercase().as_str() {
            "status" => CommandPrior::Git(GitSubcommandHint::Status),
            "diff" => CommandPrior::Git(GitSubcommandHint::Diff),
            "log" | "whatchanged" | "shortlog" => CommandPrior::Git(GitSubcommandHint::Log),
            "show" | "format-patch" => CommandPrior::Git(GitSubcommandHint::Show),
            "grep" => CommandPrior::SearchHits,
            _ => CommandPrior::None,
        };
    }
    CommandPrior::None
}

/// Checks whether text contains structural anchors for `cargo test` or `cargo nextest`.
#[must_use]
pub fn has_cargo_test_anchors(text: &str) -> bool {
    CARGO_TEST_ANCHOR_RE.is_match(text)
}

/// Checks whether text contains structural anchors for `pytest`, `jest`, or `vitest`.
#[must_use]
pub fn has_pytest_jest_anchors(text: &str) -> bool {
    PYTEST_JEST_ANCHOR_RE.is_match(text)
}

/// Checks whether text contains `rustc`/`cargo` or `tsc` compiler diagnostics.
#[must_use]
pub fn has_compiler_diag_anchors(text: &str) -> bool {
    if TSC_DIAG_RE.is_match(text) {
        return true;
    }
    if text.contains("error[E") || text.contains("error: could not compile ") {
        return true;
    }
    RUSTC_DIAG_RE.is_match(text) && RUSTC_SPAN_RE.is_match(text)
}

/// Checks whether text looks like `git status`, `git diff`, `git log`, or `git show`.
#[must_use]
pub fn has_git_anchors(text: &str) -> bool {
    let ported_class = classify_content(text);
    if ported_class == "diff" || ported_class == "git_status" {
        return true;
    }
    GIT_COMMIT_LOG_RE.is_match(text) || GIT_PORCELAIN_HEADER_RE.is_match(text)
}

/// Checks whether multi-line text looks like structured or timestamped operational logs.
#[must_use]
pub fn has_log_anchors(text: &str) -> bool {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|ln| !ln.is_empty())
        .take(200)
        .collect();
    if lines.len() < 3 {
        return false;
    }
    let ts_or_sev = lines
        .iter()
        .filter(|ln| TIMESTAMP_ROW_RE.is_match(ln) || LOG_SEVERITY_LINE_RE.is_match(ln))
        .count();
    ts_or_sev * 10 >= lines.len() * 3
}

/// Classifies normalized command output `(argv, exit_code, stdout_text, stderr_text)` into
/// a single [`ReducerTarget`].
#[must_use]
pub fn classify_command_text(
    argv: &[String],
    exit_code: Option<i32>,
    encoding: StreamEncoding,
    stdout_text: &str,
    stderr_text: &str,
) -> ReducerTarget {
    if encoding == StreamEncoding::Binary {
        return ReducerTarget::UnknownSafe;
    }

    let prior = parse_command_prior(argv);
    let combined_owned;
    let combined: &str = if stderr_text.is_empty() {
        stdout_text
    } else if stdout_text.is_empty() {
        stderr_text
    } else {
        combined_owned = format!("{stderr_text}\n{stdout_text}");
        &combined_owned
    };

    match prior {
        CommandPrior::JsonFlagged => {
            if extract_bulk_json(stdout_text).is_some() || extract_bulk_json(combined).is_some() {
                return ReducerTarget::StructuredJson;
            }
        }
        CommandPrior::CargoTest => {
            if has_cargo_test_anchors(stdout_text) || has_cargo_test_anchors(stderr_text) {
                return ReducerTarget::CargoTest;
            }
            // OQ-01: `cargo test` failed during compilation before running any test binary.
            if has_compiler_diag_anchors(stderr_text) || has_compiler_diag_anchors(stdout_text) {
                return ReducerTarget::CompilerDiag;
            }
            // Clean empty `--quiet` exit 0 run.
            if exit_code == Some(0) && combined.trim().is_empty() {
                return ReducerTarget::CargoTest;
            }
        }
        CommandPrior::PytestJest => {
            if has_pytest_jest_anchors(combined)
                || exit_code.is_some()
                || combined.contains("Traceback (most recent call last)")
                || combined.contains("SyntaxError")
                || combined.contains("ImportError")
                || combined.contains("ModuleNotFoundError")
            {
                return ReducerTarget::PytestJest;
            }
        }
        CommandPrior::CompilerDiag => {
            if has_compiler_diag_anchors(combined)
                || stderr_text.contains("Checking ")
                || stderr_text.contains("Compiling ")
                || stderr_text.contains("Finished ")
                || exit_code == Some(0)
            {
                return ReducerTarget::CompilerDiag;
            }
        }
        CommandPrior::Git(_) => {
            return ReducerTarget::GitReducer;
        }
        CommandPrior::SearchHits => {
            if combined.trim().is_empty() {
                return ReducerTarget::SearchHits;
            }
            if combined
                .lines()
                .take(50)
                .any(|ln| parse_search_result_line(ln).is_some())
            {
                return ReducerTarget::SearchHits;
            }
        }
        CommandPrior::None => {}
    }

    classify_unhinted_text(combined, None, None)
}

/// Classifies normalized text with optional document file-path and MIME hints into a
/// [`ReducerTarget`].
#[must_use]
pub fn classify_unhinted_text(
    text: &str,
    path_hint: Option<&str>,
    media_type: Option<&str>,
) -> ReducerTarget {
    if text.trim().is_empty() {
        return ReducerTarget::UnknownSafe;
    }

    // 1. Specialized test-runner outputs
    if has_cargo_test_anchors(text) {
        return ReducerTarget::CargoTest;
    }
    if has_pytest_jest_anchors(text) {
        return ReducerTarget::PytestJest;
    }

    // 2. Compiler diagnostics (`rustc` / `cargo` / `tsc`)
    if has_compiler_diag_anchors(text) {
        return ReducerTarget::CompilerDiag;
    }

    // 3. Git diffs, status, logs
    if has_git_anchors(text) {
        return ReducerTarget::GitReducer;
    }

    // 4. JSON / Concatenated JSON / NDJSON (before generic log checks)
    let is_json_hint = media_type.is_some_and(|m| m.contains("json"))
        || path_hint.is_some_and(|p| {
            let lower = p.to_ascii_lowercase();
            lower.ends_with(".json") || lower.ends_with(".jsonl") || lower.ends_with(".ndjson")
        });
    if extract_bulk_json(text).is_some() {
        return ReducerTarget::StructuredJson;
    }
    if is_json_hint {
        // Check if strict JSON fails; if so fall through to safe handling.
    }

    // 5. Gated `classify_content` for search hits vs logs vs prose/code
    let ported_kind = classify_content(text);
    if ported_kind == "search" {
        return ReducerTarget::SearchHits;
    }

    // 6. Structured / timestamped logs
    let is_log_hint = path_hint.is_some_and(|p| p.to_ascii_lowercase().ends_with(".log"));
    if has_log_anchors(text) || (is_log_hint && ported_kind == "build") {
        return ReducerTarget::LogDedup;
    }
    if ported_kind == "build" && text.lines().count() >= 5 {
        return ReducerTarget::LogDedup;
    }

    ReducerTarget::UnknownSafe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cargo_toolchain_and_flags() {
        let argv: Vec<String> = vec![
            "cargo",
            "+nightly",
            "--color",
            "always",
            "-p",
            "my-crate",
            "test",
            "--",
            "--nocapture",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(parse_command_prior(&argv), CommandPrior::CargoTest);

        let check_argv: Vec<String> = vec!["cargo.exe", "clippy", "--all-targets"]
            .into_iter()
            .map(str::to_string)
            .collect();
        assert_eq!(parse_command_prior(&check_argv), CommandPrior::CompilerDiag);
    }

    #[test]
    fn cargo_test_compile_failure_cascades_to_compiler_diag() {
        let argv = vec!["cargo".to_string(), "test".to_string()];
        let stderr = "   Compiling demo v0.1.0\nerror[E0308]: mismatched types\n  --> src/lib.rs:10:5\n   |\n10 |     \"bad\"\n   |     ^^^^^ expected `u32`, found `&str`\n";
        let target = classify_command_text(&argv, Some(101), StreamEncoding::Utf8, "", stderr);
        assert_eq!(target, ReducerTarget::CompilerDiag);
    }
}
