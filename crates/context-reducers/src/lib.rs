//! Deterministic single-pass command and document output reducers (`crates/context-reducers`).
//!
//! Enforces ADR 0004 single-pass transformation ledgers, pre/post `SecretGuard` sanitization,
//! ECMA-48/xterm ANSI & spinner normalization (`strip_ansi@1`), deterministic classification,
//! bounded `ReductionBudget` views, and panic-free `unknown_safe@1` degradation.

#![forbid(unsafe_code)]

pub mod ansi;
pub(crate) mod cargo_test;
pub mod classifier;
pub(crate) mod common;
pub(crate) mod compiler_diag;
pub(crate) mod git_reducer;
pub(crate) mod log_dedup;
pub mod ported;
pub(crate) mod pytest_jest;
pub(crate) mod search_hits;
pub(crate) mod structured_json;
pub(crate) mod unknown_safe;

use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub use ansi::{
    decode_lossy_lines, detect_stream_encoding, identify_binary_magic, prepare_stream,
    strip_ansi_and_normalize, AnsiStripOutcome, PreparedStream,
};
pub use classifier::{
    classify_command_text, classify_unhinted_text, has_cargo_test_anchors,
    has_compiler_diag_anchors, has_git_anchors, has_log_anchors, has_pytest_jest_anchors,
    parse_command_prior, CommandPrior, GitSubcommandHint, ReducerTarget,
};
pub use context_core::{
    ArtifactId, ArtifactView, ReductionBudget, SecretGuard, StreamEncoding, StreamKind,
    TransformationLedger, ViewKind,
};
pub use log_dedup::parameterize_log_template;
pub use ported::{
    carries_record_array, classify_content, normalize_concatenated_json, reduce_json_structure,
    scan_json_spans,
};

use common::{dedup_preserve_order, DomainReduction};
use context_core::{
    TRANSFORM_SECRET_REDACT_V1, TRANSFORM_STRIP_ANSI_V1, TRANSFORM_UNKNOWN_SAFE_V1,
};
use unknown_safe::{reduce_unknown_safe, UnknownSafeParams};

/// Current reducer contract version string stored in [`ArtifactView::reducer_version`].
pub const REDUCER_VERSION_V1: &str = "1";

/// Structured input for command output reduction (`context_run`).
#[derive(Debug, Clone)]
pub struct CommandReductionInput<'a> {
    pub argv: &'a [String],
    pub exit_code: Option<i32>,
    pub stdout: &'a [u8],
    pub stderr: &'a [u8],
    pub artifact_id: Option<&'a ArtifactId>,
    pub originals_available: bool,
    pub timed_out: bool,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub existing_transforms: &'a [String],
}

impl<'a> CommandReductionInput<'a> {
    /// Creates a standard command reduction request with default flags (`originals_available = true`).
    #[must_use]
    pub const fn new(
        argv: &'a [String],
        exit_code: Option<i32>,
        stdout: &'a [u8],
        stderr: &'a [u8],
    ) -> Self {
        Self {
            argv,
            exit_code,
            stdout,
            stderr,
            artifact_id: None,
            originals_available: true,
            timed_out: false,
            stdout_truncated: false,
            stderr_truncated: false,
            existing_transforms: &[],
        }
    }
}

/// Structured input for document / file reduction (`context_index`).
#[derive(Debug, Clone)]
pub struct DocumentReductionInput<'a> {
    pub bytes: &'a [u8],
    pub path_relative: Option<&'a str>,
    pub label: Option<&'a str>,
    pub media_type: Option<&'a str>,
    pub artifact_id: Option<&'a ArtifactId>,
    pub originals_available: bool,
    pub truncated: bool,
    pub existing_transforms: &'a [String],
}

impl<'a> DocumentReductionInput<'a> {
    /// Creates a standard document reduction request (`originals_available = true`).
    #[must_use]
    pub const fn new(
        bytes: &'a [u8],
        path_relative: Option<&'a str>,
        media_type: Option<&'a str>,
    ) -> Self {
        Self {
            bytes,
            path_relative,
            label: None,
            media_type,
            artifact_id: None,
            originals_available: true,
            truncated: false,
            existing_transforms: &[],
        }
    }
}

/// Structured input for arbitrary single-stream reduction.
#[derive(Debug, Clone)]
pub struct StreamReductionInput<'a> {
    pub stream_kind: StreamKind,
    pub bytes: &'a [u8],
    pub argv: Option<&'a [String]>,
    pub exit_code: Option<i32>,
    pub path_hint: Option<&'a str>,
    pub media_type: Option<&'a str>,
    pub artifact_id: Option<&'a ArtifactId>,
    pub originals_available: bool,
    pub truncated: bool,
    pub existing_transforms: &'a [String],
}

impl<'a> StreamReductionInput<'a> {
    /// Creates a single-stream reduction request (`originals_available = true`).
    #[must_use]
    pub const fn new(bytes: &'a [u8], stream_kind: StreamKind) -> Self {
        Self {
            stream_kind,
            bytes,
            argv: None,
            exit_code: None,
            path_hint: None,
            media_type: None,
            artifact_id: None,
            originals_available: true,
            truncated: false,
            existing_transforms: &[],
        }
    }
}

/// Complete single-pass reduction result including the bounded [`ArtifactView`], detected
/// [`StreamEncoding`], secret redaction telemetry, and byte-reduction metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReductionOutcome {
    /// Compact, sanitized, budget-bounded view ready for `ArtifactEnvelope::view`.
    pub view: ArtifactView,
    /// Detected byte-level encoding across the input stream(s).
    pub encoding: StreamEncoding,
    /// Selected reducer target.
    pub target: ReducerTarget,
    /// Total raw input bytes (`stdout.len() + stderr.len()` or `bytes.len()`).
    pub raw_bytes: usize,
    /// UTF-8 byte length of `view.safe_excerpt`.
    pub reduced_bytes: usize,
    /// Total secret occurrences redacted from text entering `view`.
    pub secrets_redacted: usize,
    /// Deduplicated, sorted rule IDs triggered by `SecretGuard`.
    pub secret_rule_ids: Vec<String>,
    /// `true` when input already carried a `context-engine` transformation marker and was passed through.
    pub already_reduced: bool,
}

impl ReductionOutcome {
    /// Consumes `self` and returns the inner [`ArtifactView`].
    #[must_use]
    pub fn into_view(self) -> ArtifactView {
        self.view
    }

    /// Computes `(raw_bytes - reduced_bytes) / raw_bytes` (`0.0` if `raw_bytes == 0`; can be
    /// negative on tiny inputs whose structured header is slightly longer than raw bytes).
    #[must_use]
    pub fn byte_reduction_ratio(&self) -> f64 {
        if self.raw_bytes == 0 {
            0.0
        } else {
            1.0 - (self.reduced_bytes as f64 / self.raw_bytes as f64)
        }
    }
}

/// Reusable deterministic single-pass reducer engine holding [`ReductionBudget`] and [`SecretGuard`].
#[derive(Debug, Clone, Default)]
pub struct ReducerEngine {
    budget: ReductionBudget,
    secret_guard: SecretGuard,
}

impl ReducerEngine {
    #[must_use]
    pub const fn new(budget: ReductionBudget, secret_guard: SecretGuard) -> Self {
        Self {
            budget,
            secret_guard,
        }
    }

    #[must_use]
    pub const fn budget(&self) -> &ReductionBudget {
        &self.budget
    }

    #[must_use]
    pub const fn secret_guard(&self) -> &SecretGuard {
        &self.secret_guard
    }

    #[must_use]
    pub fn reduce_stream(&self, bytes: &[u8], stream_kind: StreamKind) -> ReductionOutcome {
        reduce_stream(bytes, stream_kind, &self.budget, &self.secret_guard)
    }

    #[must_use]
    pub fn reduce_stream_with_input(&self, input: &StreamReductionInput<'_>) -> ReductionOutcome {
        reduce_stream_with_input(input, &self.budget, &self.secret_guard)
    }

    #[must_use]
    pub fn reduce_command_output(
        &self,
        argv: &[String],
        exit_code: Option<i32>,
        stdout: &[u8],
        stderr: &[u8],
    ) -> ReductionOutcome {
        reduce_command_output(
            argv,
            exit_code,
            stdout,
            stderr,
            &self.budget,
            &self.secret_guard,
        )
    }

    #[must_use]
    pub fn reduce_command_with_input(&self, input: &CommandReductionInput<'_>) -> ReductionOutcome {
        reduce_command_with_input(input, &self.budget, &self.secret_guard)
    }

    #[must_use]
    pub fn reduce_document(
        &self,
        bytes: &[u8],
        path_relative: Option<&str>,
        media_type: Option<&str>,
    ) -> ReductionOutcome {
        reduce_document(
            bytes,
            path_relative,
            media_type,
            &self.budget,
            &self.secret_guard,
        )
    }

    #[must_use]
    pub fn reduce_document_with_input(
        &self,
        input: &DocumentReductionInput<'_>,
    ) -> ReductionOutcome {
        reduce_document_with_input(input, &self.budget, &self.secret_guard)
    }
}

/// Reduces an arbitrary single byte stream in one deterministic pass.
#[must_use]
pub fn reduce_stream(
    bytes: &[u8],
    stream_kind: StreamKind,
    budget: &ReductionBudget,
    secret_guard: &SecretGuard,
) -> ReductionOutcome {
    let input = StreamReductionInput::new(bytes, stream_kind);
    reduce_stream_with_input(&input, budget, secret_guard)
}

/// Reduces a single byte stream with optional provenance metadata (`argv`, `path_hint`, `artifact_id`).
#[must_use]
pub fn reduce_stream_with_input(
    input: &StreamReductionInput<'_>,
    budget: &ReductionBudget,
    secret_guard: &SecretGuard,
) -> ReductionOutcome {
    if let Some(argv) = input.argv {
        let (stdout, stderr) = if input.stream_kind == StreamKind::Stderr {
            (&[][..], input.bytes)
        } else {
            (input.bytes, &[][..])
        };
        let cmd_in = CommandReductionInput {
            argv,
            exit_code: input.exit_code,
            stdout,
            stderr,
            artifact_id: input.artifact_id,
            originals_available: input.originals_available,
            timed_out: false,
            stdout_truncated: input.stream_kind != StreamKind::Stderr && input.truncated,
            stderr_truncated: input.stream_kind == StreamKind::Stderr && input.truncated,
            existing_transforms: input.existing_transforms,
        };
        return reduce_command_with_input(&cmd_in, budget, secret_guard);
    }

    reduce_single_payload(
        input.bytes,
        input.stream_kind,
        input.stream_kind == StreamKind::Document,
        input.path_hint,
        input.media_type,
        input.artifact_id,
        input.originals_available,
        input.truncated,
        input.existing_transforms,
        budget,
        secret_guard,
        None,
    )
}

/// Reduces a command's `(argv, exit_code, stdout, stderr)` in one deterministic pass.
#[must_use]
pub fn reduce_command_output(
    argv: &[String],
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
    budget: &ReductionBudget,
    secret_guard: &SecretGuard,
) -> ReductionOutcome {
    let input = CommandReductionInput::new(argv, exit_code, stdout, stderr);
    reduce_command_with_input(&input, budget, secret_guard)
}

/// Reduces a [`CommandReductionInput`] in one deterministic pass.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn reduce_command_with_input(
    input: &CommandReductionInput<'_>,
    budget: &ReductionBudget,
    secret_guard: &SecretGuard,
) -> ReductionOutcome {
    reduce_command_inner(input, budget, secret_guard, None)
}

/// Reduces a document byte slice (`context_index`) in one deterministic pass.
#[must_use]
pub fn reduce_document(
    bytes: &[u8],
    path_relative: Option<&str>,
    media_type: Option<&str>,
    budget: &ReductionBudget,
    secret_guard: &SecretGuard,
) -> ReductionOutcome {
    let input = DocumentReductionInput::new(bytes, path_relative, media_type);
    reduce_document_with_input(&input, budget, secret_guard)
}

/// Reduces a [`DocumentReductionInput`] in one deterministic pass.
#[must_use]
pub fn reduce_document_with_input(
    input: &DocumentReductionInput<'_>,
    budget: &ReductionBudget,
    secret_guard: &SecretGuard,
) -> ReductionOutcome {
    reduce_single_payload(
        input.bytes,
        StreamKind::Document,
        true,
        input.path_relative,
        input.media_type,
        input.artifact_id,
        input.originals_available,
        input.truncated,
        input.existing_transforms,
        budget,
        secret_guard,
        None,
    )
}

fn payload_is_already_reduced(bytes: &[u8]) -> Option<&str> {
    let Ok(raw_utf8) = std::str::from_utf8(bytes) else {
        return None;
    };
    let nobom = ported::strip_bom(raw_utf8);
    if TransformationLedger::is_already_reduced_payload(nobom) {
        Some(raw_utf8)
    } else {
        None
    }
}

fn split_verified_ledger_banner(raw_text: &str) -> Option<(&str, &str)> {
    let trimmed = ported::strip_bom(raw_text).trim_start();
    if !trimmed.starts_with(context_core::LEDGER_HEADER_PREFIX) {
        return None;
    }
    let close_bracket = trimmed.find(']')?;
    // Banner must sit on a single header line without embedded newlines.
    let header_slice = &trimmed[..=close_bracket];
    if header_slice.contains('\n') || header_slice.contains('\r') {
        return None;
    }
    let inner = &trimmed[context_core::LEDGER_HEADER_PREFIX.len()..close_bracket];
    let mut parts = inner.split_whitespace();
    let art_kv = parts.next()?;
    let transforms_kv = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let art_raw = art_kv.strip_prefix("artifact=")?;
    ArtifactId::parse(art_raw).ok()?;
    let transforms_val = transforms_kv.strip_prefix("transforms=")?;
    if !transforms_val
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'_' | b',' | b'-'))
    {
        return None;
    }

    let prefix_offset = raw_text.len() - trimmed.len();
    let header_end_in_raw = prefix_offset + close_bracket + 1;
    Some((
        &raw_text[..header_end_in_raw],
        &raw_text[header_end_in_raw..],
    ))
}

fn build_passthrough_outcome(
    raw_text: &str,
    raw_bytes: usize,
    encoding: StreamEncoding,
    existing_transforms: &[String],
    capture_truncated: bool,
    budget: &ReductionBudget,
    secret_guard: &SecretGuard,
) -> ReductionOutcome {
    let mut ledger = TransformationLedger::from_entries(existing_transforms.iter().cloned());
    let mut rules: BTreeSet<String> = BTreeSet::new();
    let mut secrets_redacted = 0usize;

    // Preserve a cryptographically/syntactically verified `[context-engine:v1 artifact=a_<64-hex> ...]`
    // header verbatim (preventing `artifact=a_<hex>` from false-positiving `SecretGuard`'s `=` token
    // entropy heuristic), while scanning 100% of the body text through `SecretGuard`.
    let sanitized_full =
        if let Some((verified_banner, body)) = split_verified_ledger_banner(raw_text) {
            let scan = secret_guard.scan_str(body);
            secrets_redacted += scan.redacted_count();
            for r in scan.distinct_rule_ids() {
                rules.insert(r);
            }
            format!("{verified_banner}{}", scan.sanitized_text)
        } else {
            let scan = secret_guard.scan_str(raw_text);
            secrets_redacted += scan.redacted_count();
            for r in scan.distinct_rule_ids() {
                rules.insert(r);
            }
            scan.sanitized_text
        };

    if secrets_redacted > 0 {
        ledger.record(TRANSFORM_SECRET_REDACT_V1);
    }

    let (bounded, was_cut) = budget.bound_view_excerpt(&sanitized_full);
    let reduced_bytes = bounded.len();

    ReductionOutcome {
        view: ArtifactView {
            kind: ViewKind::Passthrough,
            reducer_version: REDUCER_VERSION_V1.to_string(),
            omitted: was_cut || capture_truncated,
            safe_excerpt: bounded,
            transformations: ledger.into_vec(),
            reduction_error: None,
            failure_identifiers: Vec::new(),
        },
        encoding,
        target: ReducerTarget::Passthrough,
        raw_bytes,
        reduced_bytes,
        secrets_redacted,
        secret_rule_ids: rules.into_iter().collect(),
        already_reduced: true,
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn reduce_single_payload(
    bytes: &[u8],
    stream_kind: StreamKind,
    is_document: bool,
    path_hint: Option<&str>,
    media_type: Option<&str>,
    artifact_id: Option<&ArtifactId>,
    originals_available: bool,
    capture_truncated: bool,
    existing_transforms: &[String],
    budget: &ReductionBudget,
    secret_guard: &SecretGuard,
    forced_fault: Option<&str>,
) -> ReductionOutcome {
    let raw_bytes = bytes.len();
    let existing_ledger = TransformationLedger::from_entries(existing_transforms.iter().cloned());

    // 1. Single-pass idempotency check (`TransformationLedger::is_already_reduced_payload` + ledger)
    if let Some(already_str) = payload_is_already_reduced(bytes) {
        return build_passthrough_outcome(
            already_str,
            raw_bytes,
            StreamEncoding::Utf8,
            existing_transforms,
            capture_truncated,
            budget,
            secret_guard,
        );
    }
    if existing_ledger.has_domain_reducer() {
        let prep = prepare_stream(bytes);
        let passthrough_str = prep.normalized_text.as_deref().unwrap_or("");
        return build_passthrough_outcome(
            passthrough_str,
            raw_bytes,
            prep.encoding,
            existing_transforms,
            capture_truncated,
            budget,
            secret_guard,
        );
    }

    let prep = prepare_stream(bytes);
    let mut ledger = existing_ledger;
    let mut rule_ids: BTreeSet<String> = BTreeSet::new();
    let mut secrets_redacted = 0usize;

    // 2. Binary stream short-circuit -> `unknown_safe@1`
    if prep.encoding == StreamEncoding::Binary {
        let lossy_probe = String::from_utf8_lossy(bytes);
        let probe_scan = secret_guard.scan_str(&lossy_probe);
        if probe_scan.has_secrets() {
            secrets_redacted += probe_scan.redacted_count();
            for r in probe_scan.distinct_rule_ids() {
                rule_ids.insert(r);
            }
            ledger.record(TRANSFORM_SECRET_REDACT_V1);
        }
        ledger.record_domain_reducer(TRANSFORM_UNKNOWN_SAFE_V1);

        let domain = reduce_unknown_safe(&UnknownSafeParams {
            view_kind: ViewKind::UnknownSafe,
            stream: stream_kind,
            raw_bytes: bytes,
            secondary_stderr_bytes: None,
            encoding: StreamEncoding::Binary,
            sanitized_text: None,
            secrets_detected_in_binary: probe_scan.has_secrets(),
            exit_code: None,
            timed_out: false,
            capture_truncated,
            artifact_id,
            originals_available,
            reduction_error_note: None,
            budget,
        });

        return finalize_outcome(
            domain,
            StreamEncoding::Binary,
            ReducerTarget::UnknownSafe,
            raw_bytes,
            capture_truncated,
            ledger,
            secrets_redacted,
            rule_ids,
            None,
            budget,
            secret_guard,
        );
    }

    // 3. `strip_ansi@1` + pre-reducer `SecretGuard` scan
    ledger.record(TRANSFORM_STRIP_ANSI_V1);
    let norm_text = prep.normalized_text.as_deref().unwrap_or("");
    // Also check if `strip_ansi@1` uncovered an already-reduced banner wrapped in ANSI color codes
    if TransformationLedger::is_already_reduced_payload(ported::strip_bom(norm_text)) {
        return build_passthrough_outcome(
            norm_text,
            raw_bytes,
            prep.encoding,
            existing_transforms,
            capture_truncated,
            budget,
            secret_guard,
        );
    }

    let scan = secret_guard.scan_str(norm_text);
    if scan.has_secrets() {
        secrets_redacted += scan.redacted_count();
        for r in scan.distinct_rule_ids() {
            rule_ids.insert(r);
        }
        ledger.record(TRANSFORM_SECRET_REDACT_V1);
    }
    let clean_text = &scan.sanitized_text;
    let raw_cr_present = bytes.contains(&b'\r');

    // 4. Classify and execute single domain reducer inside `catch_unwind`
    let selected_target = classify_unhinted_text(clean_text, path_hint, media_type);
    let is_clean_utf8_doc = is_document && prep.encoding == StreamEncoding::Utf8;

    let attempt = catch_unwind(AssertUnwindSafe(|| -> Result<DomainReduction, String> {
        if let Some(fault_reason) = forced_fault {
            return Err(fault_reason.to_string());
        }
        match selected_target {
            ReducerTarget::CargoTest => Ok(cargo_test::reduce_cargo_test(
                None,
                false,
                clean_text,
                "",
                artifact_id,
                originals_available,
                budget,
            )),
            ReducerTarget::PytestJest => Ok(pytest_jest::reduce_pytest_jest(
                None,
                false,
                clean_text,
                "",
                artifact_id,
                originals_available,
                budget,
            )),
            ReducerTarget::CompilerDiag => Ok(compiler_diag::reduce_compiler_diag(
                None,
                false,
                "",
                clean_text,
                artifact_id,
                originals_available,
                budget,
            )),
            ReducerTarget::GitReducer => Ok(git_reducer::reduce_git_output(
                None,
                false,
                clean_text,
                "",
                raw_cr_present,
                artifact_id,
                originals_available,
                budget,
            )),
            ReducerTarget::StructuredJson => structured_json::reduce_structured_json(
                clean_text,
                stream_kind,
                artifact_id,
                originals_available,
                budget,
            ),
            ReducerTarget::LogDedup => Ok(log_dedup::reduce_logs(
                clean_text,
                stream_kind,
                artifact_id,
                originals_available,
                budget,
            )),
            ReducerTarget::SearchHits => Ok(search_hits::reduce_search_hits(
                None,
                false,
                clean_text,
                "",
                artifact_id,
                originals_available,
                budget,
            )),
            ReducerTarget::UnknownSafe | ReducerTarget::Passthrough => {
                Ok(reduce_unknown_safe(&UnknownSafeParams {
                    view_kind: selected_target.view_kind(is_clean_utf8_doc),
                    stream: stream_kind,
                    raw_bytes: bytes,
                    secondary_stderr_bytes: None,
                    encoding: prep.encoding,
                    sanitized_text: Some(clean_text),
                    secrets_detected_in_binary: false,
                    exit_code: None,
                    timed_out: false,
                    capture_truncated,
                    artifact_id,
                    originals_available,
                    reduction_error_note: None,
                    budget,
                }))
            }
        }
    }));

    let (domain, final_target, reduction_error) = match attempt {
        Ok(Ok(dom)) => {
            if let Some(tid) = selected_target.transform_id() {
                ledger.record_domain_reducer(tid);
            }
            (dom, selected_target, None)
        }
        Ok(Err(err_msg)) => {
            let safe_err = secret_guard.redact_str(&err_msg);
            ledger.record_domain_reducer(TRANSFORM_UNKNOWN_SAFE_V1);
            let fallback = reduce_unknown_safe(&UnknownSafeParams {
                view_kind: ViewKind::UnknownSafe,
                stream: stream_kind,
                raw_bytes: bytes,
                secondary_stderr_bytes: None,
                encoding: prep.encoding,
                sanitized_text: Some(clean_text),
                secrets_detected_in_binary: false,
                exit_code: None,
                timed_out: false,
                capture_truncated,
                artifact_id,
                originals_available,
                reduction_error_note: Some(&safe_err),
                budget,
            });
            (fallback, ReducerTarget::UnknownSafe, Some(safe_err))
        }
        Err(panic_payload) => {
            let panic_msg = extract_panic_message(panic_payload.as_ref());
            let safe_err = secret_guard.redact_str(&format!(
                "internal reducer panic in {:?}: {panic_msg}",
                selected_target
            ));
            ledger.record_domain_reducer(TRANSFORM_UNKNOWN_SAFE_V1);
            let fallback = reduce_unknown_safe(&UnknownSafeParams {
                view_kind: ViewKind::UnknownSafe,
                stream: stream_kind,
                raw_bytes: bytes,
                secondary_stderr_bytes: None,
                encoding: prep.encoding,
                sanitized_text: Some(clean_text),
                secrets_detected_in_binary: false,
                exit_code: None,
                timed_out: false,
                capture_truncated,
                artifact_id,
                originals_available,
                reduction_error_note: Some(&safe_err),
                budget,
            });
            (fallback, ReducerTarget::UnknownSafe, Some(safe_err))
        }
    };

    finalize_outcome(
        domain,
        prep.encoding,
        final_target,
        raw_bytes,
        capture_truncated,
        ledger,
        secrets_redacted,
        rule_ids,
        reduction_error,
        budget,
        secret_guard,
    )
}

#[allow(clippy::too_many_lines)]
fn reduce_command_inner(
    input: &CommandReductionInput<'_>,
    budget: &ReductionBudget,
    secret_guard: &SecretGuard,
    forced_fault: Option<&str>,
) -> ReductionOutcome {
    let raw_bytes = input.stdout.len().saturating_add(input.stderr.len());
    let capture_truncated = input.stdout_truncated || input.stderr_truncated;
    let existing_ledger =
        TransformationLedger::from_entries(input.existing_transforms.iter().cloned());

    // 1. Single-pass idempotency check (`TransformationLedger::is_already_reduced_payload` + ledger)
    if input.stderr.is_empty() {
        if let Some(already_str) = payload_is_already_reduced(input.stdout) {
            return build_passthrough_outcome(
                already_str,
                raw_bytes,
                StreamEncoding::Utf8,
                input.existing_transforms,
                capture_truncated,
                budget,
                secret_guard,
            );
        }
    } else if input.stdout.is_empty() {
        if let Some(already_str) = payload_is_already_reduced(input.stderr) {
            return build_passthrough_outcome(
                already_str,
                raw_bytes,
                StreamEncoding::Utf8,
                input.existing_transforms,
                capture_truncated,
                budget,
                secret_guard,
            );
        }
    }

    let prep_out = prepare_stream(input.stdout);
    let prep_err = prepare_stream(input.stderr);

    let combined_encoding = if (!input.stdout.is_empty()
        && prep_out.encoding == StreamEncoding::Binary)
        || (!input.stderr.is_empty() && prep_err.encoding == StreamEncoding::Binary)
    {
        StreamEncoding::Binary
    } else if prep_out.encoding == StreamEncoding::Utf8Lossy
        || prep_err.encoding == StreamEncoding::Utf8Lossy
    {
        StreamEncoding::Utf8Lossy
    } else {
        StreamEncoding::Utf8
    };

    if existing_ledger.has_domain_reducer() {
        let out_s = prep_out.normalized_text.as_deref().unwrap_or("");
        let err_s = prep_err.normalized_text.as_deref().unwrap_or("");
        let merged = if err_s.is_empty() {
            out_s.to_string()
        } else if out_s.is_empty() {
            err_s.to_string()
        } else {
            format!("{err_s}\n{out_s}")
        };
        return build_passthrough_outcome(
            &merged,
            raw_bytes,
            combined_encoding,
            input.existing_transforms,
            capture_truncated,
            budget,
            secret_guard,
        );
    }

    let mut ledger = existing_ledger;
    let mut rule_ids: BTreeSet<String> = BTreeSet::new();
    let mut secrets_redacted = 0usize;

    // 2. Binary stream short-circuit -> `unknown_safe@1`
    if combined_encoding == StreamEncoding::Binary {
        let (primary_stream, primary_bytes, sec_bytes) = if !input.stdout.is_empty() {
            (
                StreamKind::Stdout,
                input.stdout,
                if input.stderr.is_empty() {
                    None
                } else {
                    Some(input.stderr)
                },
            )
        } else {
            (StreamKind::Stderr, input.stderr, None)
        };

        let mut binary_has_secret = false;
        for slice in [input.stdout, input.stderr] {
            if !slice.is_empty() {
                let probe = secret_guard.scan_str(&String::from_utf8_lossy(slice));
                if probe.has_secrets() {
                    binary_has_secret = true;
                    secrets_redacted += probe.redacted_count();
                    for r in probe.distinct_rule_ids() {
                        rule_ids.insert(r);
                    }
                }
            }
        }
        if binary_has_secret {
            ledger.record(TRANSFORM_SECRET_REDACT_V1);
        }
        ledger.record_domain_reducer(TRANSFORM_UNKNOWN_SAFE_V1);

        let domain = reduce_unknown_safe(&UnknownSafeParams {
            view_kind: ViewKind::UnknownSafe,
            stream: primary_stream,
            raw_bytes: primary_bytes,
            secondary_stderr_bytes: sec_bytes,
            encoding: StreamEncoding::Binary,
            sanitized_text: None,
            secrets_detected_in_binary: binary_has_secret,
            exit_code: input.exit_code,
            timed_out: input.timed_out,
            capture_truncated,
            artifact_id: input.artifact_id,
            originals_available: input.originals_available,
            reduction_error_note: None,
            budget,
        });

        return finalize_outcome(
            domain,
            StreamEncoding::Binary,
            ReducerTarget::UnknownSafe,
            raw_bytes,
            capture_truncated,
            ledger,
            secrets_redacted,
            rule_ids,
            None,
            budget,
            secret_guard,
        );
    }

    // 3. `strip_ansi@1` + pre-reducer `SecretGuard` scan on both streams
    ledger.record(TRANSFORM_STRIP_ANSI_V1);
    let norm_out = prep_out.normalized_text.as_deref().unwrap_or("");
    let norm_err = prep_err.normalized_text.as_deref().unwrap_or("");

    if norm_err.is_empty()
        && TransformationLedger::is_already_reduced_payload(ported::strip_bom(norm_out))
    {
        return build_passthrough_outcome(
            norm_out,
            raw_bytes,
            combined_encoding,
            input.existing_transforms,
            capture_truncated,
            budget,
            secret_guard,
        );
    }

    let scan_out = secret_guard.scan_str(norm_out);
    let scan_err = secret_guard.scan_str(norm_err);
    for scan in [&scan_out, &scan_err] {
        if scan.has_secrets() {
            secrets_redacted += scan.redacted_count();
            for r in scan.distinct_rule_ids() {
                rule_ids.insert(r);
            }
        }
    }
    if secrets_redacted > 0 {
        ledger.record(TRANSFORM_SECRET_REDACT_V1);
    }

    let clean_out = &scan_out.sanitized_text;
    let clean_err = &scan_err.sanitized_text;
    let raw_cr_present = input.stdout.contains(&b'\r') || input.stderr.contains(&b'\r');

    // 4. Deterministic classification + single-pass reducer execution inside `catch_unwind`
    let selected_target = classify_command_text(
        input.argv,
        input.exit_code,
        combined_encoding,
        clean_out,
        clean_err,
    );

    let (primary_stream, primary_bytes, sec_bytes, merged_clean_text) =
        if !clean_out.is_empty() || input.stderr.is_empty() {
            let merged = if clean_err.is_empty() {
                clean_out.clone()
            } else if clean_out.is_empty() {
                clean_err.clone()
            } else {
                format!("{clean_err}\n{clean_out}")
            };
            (
                StreamKind::Stdout,
                input.stdout,
                if input.stderr.is_empty() {
                    None
                } else {
                    Some(input.stderr)
                },
                merged,
            )
        } else {
            (StreamKind::Stderr, input.stderr, None, clean_err.clone())
        };

    let attempt = catch_unwind(AssertUnwindSafe(|| -> Result<DomainReduction, String> {
        if let Some(fault_reason) = forced_fault {
            return Err(fault_reason.to_string());
        }
        match selected_target {
            ReducerTarget::CargoTest => Ok(cargo_test::reduce_cargo_test(
                input.exit_code,
                input.timed_out,
                clean_out,
                clean_err,
                input.artifact_id,
                input.originals_available,
                budget,
            )),
            ReducerTarget::PytestJest => Ok(pytest_jest::reduce_pytest_jest(
                input.exit_code,
                input.timed_out,
                clean_out,
                clean_err,
                input.artifact_id,
                input.originals_available,
                budget,
            )),
            ReducerTarget::CompilerDiag => Ok(compiler_diag::reduce_compiler_diag(
                input.exit_code,
                input.timed_out,
                clean_out,
                clean_err,
                input.artifact_id,
                input.originals_available,
                budget,
            )),
            ReducerTarget::GitReducer => Ok(git_reducer::reduce_git_output(
                input.exit_code,
                input.timed_out,
                clean_out,
                clean_err,
                raw_cr_present,
                input.artifact_id,
                input.originals_available,
                budget,
            )),
            ReducerTarget::StructuredJson => {
                let (j_stream, j_text) = if !clean_out.trim().is_empty() {
                    (StreamKind::Stdout, clean_out.as_str())
                } else {
                    (StreamKind::Stderr, clean_err.as_str())
                };
                structured_json::reduce_structured_json(
                    j_text,
                    j_stream,
                    input.artifact_id,
                    input.originals_available,
                    budget,
                )
            }
            ReducerTarget::LogDedup => Ok(log_dedup::reduce_logs(
                &merged_clean_text,
                primary_stream,
                input.artifact_id,
                input.originals_available,
                budget,
            )),
            ReducerTarget::SearchHits => Ok(search_hits::reduce_search_hits(
                input.exit_code,
                input.timed_out,
                clean_out,
                clean_err,
                input.artifact_id,
                input.originals_available,
                budget,
            )),
            ReducerTarget::UnknownSafe | ReducerTarget::Passthrough => {
                Ok(reduce_unknown_safe(&UnknownSafeParams {
                    view_kind: ViewKind::UnknownSafe,
                    stream: primary_stream,
                    raw_bytes: primary_bytes,
                    secondary_stderr_bytes: sec_bytes,
                    encoding: combined_encoding,
                    sanitized_text: Some(&merged_clean_text),
                    secrets_detected_in_binary: false,
                    exit_code: input.exit_code,
                    timed_out: input.timed_out,
                    capture_truncated,
                    artifact_id: input.artifact_id,
                    originals_available: input.originals_available,
                    reduction_error_note: None,
                    budget,
                }))
            }
        }
    }));

    let (domain, final_target, reduction_error) = match attempt {
        Ok(Ok(dom)) => {
            if let Some(tid) = selected_target.transform_id() {
                ledger.record_domain_reducer(tid);
            }
            (dom, selected_target, None)
        }
        Ok(Err(err_msg)) => {
            let safe_err = secret_guard.redact_str(&err_msg);
            ledger.record_domain_reducer(TRANSFORM_UNKNOWN_SAFE_V1);
            let fallback = reduce_unknown_safe(&UnknownSafeParams {
                view_kind: ViewKind::UnknownSafe,
                stream: primary_stream,
                raw_bytes: primary_bytes,
                secondary_stderr_bytes: sec_bytes,
                encoding: combined_encoding,
                sanitized_text: Some(&merged_clean_text),
                secrets_detected_in_binary: false,
                exit_code: input.exit_code,
                timed_out: input.timed_out,
                capture_truncated,
                artifact_id: input.artifact_id,
                originals_available: input.originals_available,
                reduction_error_note: Some(&safe_err),
                budget,
            });
            (fallback, ReducerTarget::UnknownSafe, Some(safe_err))
        }
        Err(panic_payload) => {
            let panic_msg = extract_panic_message(panic_payload.as_ref());
            let safe_err = secret_guard.redact_str(&format!(
                "internal reducer panic in {:?}: {panic_msg}",
                selected_target
            ));
            ledger.record_domain_reducer(TRANSFORM_UNKNOWN_SAFE_V1);
            let fallback = reduce_unknown_safe(&UnknownSafeParams {
                view_kind: ViewKind::UnknownSafe,
                stream: primary_stream,
                raw_bytes: primary_bytes,
                secondary_stderr_bytes: sec_bytes,
                encoding: combined_encoding,
                sanitized_text: Some(&merged_clean_text),
                secrets_detected_in_binary: false,
                exit_code: input.exit_code,
                timed_out: input.timed_out,
                capture_truncated,
                artifact_id: input.artifact_id,
                originals_available: input.originals_available,
                reduction_error_note: Some(&safe_err),
                budget,
            });
            (fallback, ReducerTarget::UnknownSafe, Some(safe_err))
        }
    };

    finalize_outcome(
        domain,
        combined_encoding,
        final_target,
        raw_bytes,
        capture_truncated,
        ledger,
        secrets_redacted,
        rule_ids,
        reduction_error,
        budget,
        secret_guard,
    )
}

#[allow(clippy::too_many_arguments)]
fn finalize_outcome(
    domain: DomainReduction,
    encoding: StreamEncoding,
    target: ReducerTarget,
    raw_bytes: usize,
    capture_truncated: bool,
    mut ledger: TransformationLedger,
    mut secrets_redacted: usize,
    mut rule_ids: BTreeSet<String>,
    reduction_error: Option<String>,
    budget: &ReductionBudget,
    secret_guard: &SecretGuard,
) -> ReductionOutcome {
    // Post-gate SecretGuard scan across `safe_excerpt` and every `failure_identifier`
    let excerpt_scan = secret_guard.scan_str(&domain.safe_excerpt);
    if excerpt_scan.has_secrets() {
        secrets_redacted += excerpt_scan.redacted_count();
        for r in excerpt_scan.distinct_rule_ids() {
            rule_ids.insert(r);
        }
    }

    let mut clean_failures: Vec<String> = Vec::with_capacity(domain.failure_identifiers.len());
    for fid in domain.failure_identifiers {
        let f_scan = secret_guard.scan_str(&fid);
        if f_scan.has_secrets() {
            secrets_redacted += f_scan.redacted_count();
            for r in f_scan.distinct_rule_ids() {
                rule_ids.insert(r);
            }
        }
        clean_failures.push(f_scan.sanitized_text);
    }
    let clean_failures = dedup_preserve_order(clean_failures);

    if secrets_redacted > 0 {
        ledger.record(TRANSFORM_SECRET_REDACT_V1);
    }

    // Strict `ReductionBudget` enforcement on `safe_excerpt`
    let (bounded_excerpt, budget_cut) = budget.bound_view_excerpt(&excerpt_scan.sanitized_text);
    let reduced_bytes = bounded_excerpt.len();
    let omitted = domain.omitted || budget_cut || capture_truncated;

    ReductionOutcome {
        view: ArtifactView {
            kind: domain.kind,
            reducer_version: REDUCER_VERSION_V1.to_string(),
            omitted,
            safe_excerpt: bounded_excerpt,
            transformations: ledger.into_vec(),
            reduction_error,
            failure_identifiers: clean_failures,
        },
        encoding,
        target,
        raw_bytes,
        reduced_bytes,
        secrets_redacted,
        secret_rule_ids: rule_ids.into_iter().collect(),
        already_reduced: false,
    }
}

fn extract_panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(&s) = payload.downcast_ref::<&'static str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unexpected reducer panic".to_string()
    }
}

#[cfg(test)]
pub(crate) fn reduce_command_with_simulated_fault(
    input: &CommandReductionInput<'_>,
    budget: &ReductionBudget,
    secret_guard: &SecretGuard,
    fault_message: &str,
) -> ReductionOutcome {
    reduce_command_inner(input, budget, secret_guard, Some(fault_message))
}

#[cfg(test)]
mod unit_tests {
    use context_core::{
        sha256_hex, ArtifactEnvelope, ArtifactSource, BoundScope, CaptureSummary, RecoveryHandle,
    };
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn simulated_reducer_fault_degrades_safely_to_unknown_safe_without_panicking() {
        let budget = ReductionBudget::default();
        let guard = SecretGuard::default();
        let argv = vec!["cargo".to_string(), "test".to_string()];
        let stdout = b"running 2 tests\ntest alpha ... ok\ntest beta ... FAILED\n\ntest result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n";
        let input = CommandReductionInput::new(&argv, Some(101), stdout, b"");

        let fault_with_secret =
            "synthetic parser failure near token ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD";
        let outcome =
            reduce_command_with_simulated_fault(&input, &budget, &guard, fault_with_secret);

        assert_eq!(outcome.target, ReducerTarget::UnknownSafe);
        assert_eq!(outcome.view.kind, ViewKind::UnknownSafe);
        assert!(outcome.view.omitted);
        let err = outcome
            .view
            .reduction_error
            .as_deref()
            .expect("reduction_error must be populated");
        assert!(err.contains("synthetic parser failure"));
        assert!(!err.contains("ghp_0123456789"));
        assert!(!outcome.view.safe_excerpt.contains("ghp_0123456789"));
        assert!(outcome
            .view
            .transformations
            .contains(&TRANSFORM_UNKNOWN_SAFE_V1.to_string()));
    }

    #[test]
    fn secret_guard_scrubs_both_safe_excerpt_and_failure_identifiers() {
        let budget = ReductionBudget::default();
        let guard = SecretGuard::default();
        let leaked_gh = "ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD";
        let leaked_openai = "sk-proj-0123456789abcdefghijklmnopqrstuvwxyzABCD";

        let log_payload = format!(
            "2026-11-22T12:00:00Z INFO Booting worker\n\
             2026-11-22T12:00:01Z INFO Heartbeat ok\n\
             2026-11-22T12:00:02Z ERROR Auth rejected token {leaked_gh} and key {leaked_openai}\n"
        );

        let out = reduce_stream(log_payload.as_bytes(), StreamKind::Stdout, &budget, &guard);
        assert_eq!(out.target, ReducerTarget::LogDedup);
        assert!(out.secrets_redacted >= 2);
        assert!(out
            .view
            .transformations
            .contains(&TRANSFORM_SECRET_REDACT_V1.to_string()));
        assert!(!out.view.safe_excerpt.contains(leaked_gh));
        assert!(!out.view.safe_excerpt.contains(leaked_openai));
        assert!(!out.view.failure_identifiers.is_empty());
        for fid in &out.view.failure_identifiers {
            assert!(
                !fid.contains(leaked_gh),
                "secret leaked in failure_identifiers: {fid}"
            );
            assert!(
                !fid.contains(leaked_openai),
                "secret leaked in failure_identifiers: {fid}"
            );
            assert!(fid.contains("[REDACTED:"));
        }
    }

    #[test]
    fn single_pass_transformation_ledger_prevents_double_reduction() {
        let tmp = TempDir::new().expect("tempdir");
        let scope = BoundScope::bind(tmp.path(), Some("ledger-test")).expect("bind");
        let budget = ReductionBudget::default();
        let guard = SecretGuard::default();

        let argv = vec!["cargo".to_string(), "test".to_string()];
        let stdout = b"running 1 test\ntest works ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n";
        let first = reduce_command_output(&argv, Some(0), stdout, b"", &budget, &guard);
        assert!(!first.already_reduced);
        assert_eq!(first.view.kind, ViewKind::TestSummary);

        let stdout_sha = sha256_hex(stdout);
        let stderr_sha = sha256_hex(b"");
        let art_id = ArtifactId::mint(
            &scope,
            "2026-11-22T12:00:00.000Z",
            1,
            &stdout_sha,
            Some(&stderr_sha),
        );

        // 1. Banner-prefixed text payload short-circuits to Passthrough
        let banner_payload = format!(
            "{}\n{}",
            TransformationLedger::format_banner(&art_id, &first.view.transformations),
            first.view.safe_excerpt
        );
        let second_banner = reduce_stream(
            banner_payload.as_bytes(),
            StreamKind::Stdout,
            &budget,
            &guard,
        );
        assert!(second_banner.already_reduced);
        assert_eq!(second_banner.view.kind, ViewKind::Passthrough);
        assert_eq!(second_banner.view.safe_excerpt, banner_payload);

        // 2. Serialized ArtifactEnvelope JSON short-circuits to Passthrough (not structured_json@1!)
        let envelope = ArtifactEnvelope::new_v1(
            &scope,
            art_id.clone(),
            ArtifactSource::Command {
                argv: argv.clone(),
                cwd_relative: ".".to_string(),
                exit_code: Some(0),
                duration_ms: Some(10),
                timed_out: None,
                captured_at: "2026-11-22T12:00:00.000Z".to_string(),
            },
            CaptureSummary {
                stdout_sha256: stdout_sha,
                stderr_sha256: stderr_sha,
                stdout_bytes: stdout.len() as u64,
                stderr_bytes: 0,
                stdout_truncated: false,
                stderr_truncated: false,
                complete: true,
                encoding: first.encoding,
                originals_available: true,
                secrets_redacted: 0,
                secret_rule_ids: Vec::new(),
            },
            first.view.clone(),
            RecoveryHandle::for_artifact(art_id, Some(budget.max_get_bytes)),
        );
        let env_json = serde_json::to_string_pretty(&envelope).expect("json");
        let second_env = reduce_document(
            env_json.as_bytes(),
            Some("envelope.json"),
            Some("application/json"),
            &budget,
            &guard,
        );
        assert!(second_env.already_reduced);
        assert_eq!(second_env.view.kind, ViewKind::Passthrough);

        // 3. Passing `existing_transforms` with a domain reducer also short-circuits
        let cmd_repeat = CommandReductionInput {
            argv: &argv,
            exit_code: Some(0),
            stdout: first.view.safe_excerpt.as_bytes(),
            stderr: b"",
            artifact_id: None,
            originals_available: true,
            timed_out: false,
            stdout_truncated: false,
            stderr_truncated: false,
            existing_transforms: &first.view.transformations,
        };
        let third = reduce_command_with_input(&cmd_repeat, &budget, &guard);
        assert!(third.already_reduced);
        assert_eq!(third.view.kind, ViewKind::Passthrough);
    }

    #[test]
    fn pytest_exit_5_vs_precollection_syntax_crash() {
        let budget = ReductionBudget::default();
        let guard = SecretGuard::default();
        let argv = vec!["pytest".to_string()];

        // Exit code 5 = legitimate "no tests collected"
        let out_5 = reduce_command_output(
            &argv,
            Some(5),
            b"=== test session starts ===\ncollected 0 items\n=== no tests ran in 0.01s ===\n",
            b"",
            &budget,
            &guard,
        );
        assert!(out_5
            .view
            .safe_excerpt
            .contains("NO_TESTS_COLLECTED (exit 5)"));

        // Exit code 2 = pre-collection crash (SyntaxError / ImportError) -> must NEVER report PASS
        let crash_stderr = b"ImportError while importing test module 'tests/test_api.py'.\nModuleNotFoundError: No module named 'pydantic'\n";
        let out_2 = reduce_command_output(&argv, Some(2), b"", crash_stderr, &budget, &guard);
        assert!(out_2.view.safe_excerpt.contains("ERROR (exit 2)"));
        assert!(out_2.view.safe_excerpt.contains("ModuleNotFoundError"));
    }

    #[test]
    fn cargo_nextest_and_ndjson_and_git_log_supported() {
        let engine = ReducerEngine::default();

        // cargo nextest
        let nextest_argv = vec!["cargo".into(), "nextest".into(), "run".into()];
        let nextest_stderr = b"    Starting 20 tests across 2 binaries\n        PASS [   0.012s] core::unit budget::ok\n        FAIL [   0.045s] core::unit scope::forged_denied\n     Summary [   0.060s] 20 tests run: 19 passed, 1 failed, 2 skipped\n";
        let r_next = engine.reduce_command_output(&nextest_argv, Some(100), b"", nextest_stderr);
        assert_eq!(r_next.target, ReducerTarget::CargoTest);
        assert_eq!(
            r_next.view.failure_identifiers,
            vec!["scope::forged_denied"]
        );
        assert!(r_next
            .view
            .safe_excerpt
            .contains("19 passed, 1 failed, 2 ignored"));

        // NDJSON stream
        let mut ndjson = String::new();
        for i in 0..30 {
            ndjson.push_str(&format!(
                "{{\"seq\":{i},\"status\":\"ok\",\"bytes\":4096}}\n"
            ));
        }
        ndjson.push_str("{\"seq\":30,\"status\":\"failed\",\"error\":\"disk full\"}\n");
        let r_nd = engine.reduce_document(ndjson.as_bytes(), Some("events.ndjson"), None);
        assert_eq!(r_nd.target, ReducerTarget::StructuredJson);
        assert!(r_nd.view.safe_excerpt.contains("Array(len=31)"));
        assert!(r_nd.view.safe_excerpt.contains("disk full"));
        assert_eq!(r_nd.view.failure_identifiers, vec!["item[30]: disk full"]);

        // git show (commit + diff)
        let git_argv = vec!["git".into(), "show".into(), "HEAD".into()];
        let git_out = b"commit 8f3c2a1b9e4d7c6f5a0b1c2d3e4f5a6b7c8d9e0f\nAuthor: Dev <dev@local>\nDate:   Sun Nov 22 12:00:00 2026 +0000\n\n    feat: add single-pass reducer\n\ndiff --git a/src/lib.rs b/src/lib.rs\nindex 111..222 100644\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1,3 @@\n pub mod a;\n+pub mod b;\n";
        let r_git = engine.reduce_command_output(&git_argv, Some(0), git_out, b"");
        assert_eq!(r_git.target, ReducerTarget::GitReducer);
        assert!(r_git.view.safe_excerpt.contains("commit 8f3c2a1b9e"));
        assert!(r_git
            .view
            .safe_excerpt
            .contains("feat: add single-pass reducer"));
        assert!(r_git.view.safe_excerpt.contains("file src/lib.rs: +1/-0"));
    }
}
