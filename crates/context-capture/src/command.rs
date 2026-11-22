//! Bounded async child process capture (`capture_command`) over `ApprovedCommand`.

use std::process::Stdio;
use std::time::{Duration, Instant};

use context_core::{now_rfc3339_utc, ArtifactSource, CaptureSummary, ContextError, Result};
use context_execution::ApprovedCommand;
use serde::{Deserialize, Serialize};
use tokio::process::{Child, Command};

use crate::stream::{
    combine_stream_encodings, read_stream_bounded, CaptureCancelToken, CapturedStream,
    StreamAccumulator,
};

/// Complete capture record produced by executing an [`ApprovedCommand`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedCommand {
    /// Validated `argv` executed without a shell.
    pub argv: Vec<String>,
    /// Workspace-relative working directory (`"."` for workspace root).
    pub cwd_relative: String,
    /// Process exit status code (`None` when killed by signal, timed out, or cancelled).
    pub exit_code: Option<i32>,
    /// Wall-clock execution duration in milliseconds.
    pub duration_ms: u64,
    /// Configured timeout limit in milliseconds.
    pub timeout_ms: u64,
    /// `true` if the child exceeded `timeout_ms` and was forcefully terminated.
    pub timed_out: bool,
    /// `true` if execution was aborted via [`CaptureCancelToken`].
    pub cancelled: bool,
    /// RFC 3339 UTC timestamp recorded when capture started.
    pub captured_at: String,
    /// Independent bounded capture of `stdout`.
    pub stdout: CapturedStream,
    /// Independent bounded capture of `stderr`.
    pub stderr: CapturedStream,
}

impl CapturedCommand {
    /// Returns `true` if neither stream truncated, nor timed out, nor was cancelled, nor hit pipe read errors.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.timed_out
            && !self.cancelled
            && !self.stdout.truncated
            && !self.stderr.truncated
            && self.stdout.read_error.is_none()
            && self.stderr.read_error.is_none()
    }

    /// Fails closed with [`ContextError::ExecutionTimeout`] if `self.timed_out` is `true`.
    pub fn check_timeout(&self) -> Result<()> {
        if self.timed_out {
            return Err(ContextError::ExecutionTimeout {
                timeout_ms: self.timeout_ms,
            });
        }
        Ok(())
    }

    /// Converts provenance metadata into [`ArtifactSource::Command`].
    #[must_use]
    pub fn to_artifact_source(&self) -> ArtifactSource {
        ArtifactSource::Command {
            argv: self.argv.clone(),
            cwd_relative: self.cwd_relative.clone(),
            exit_code: self.exit_code,
            duration_ms: Some(self.duration_ms),
            timed_out: if self.timed_out { Some(true) } else { None },
            captured_at: self.captured_at.clone(),
        }
    }

    /// Builds a preliminary [`CaptureSummary`] from raw capture metrics.
    #[must_use]
    pub fn to_capture_summary(&self, originals_available: bool) -> CaptureSummary {
        CaptureSummary {
            stdout_sha256: self.stdout.sha256.clone(),
            stderr_sha256: self.stderr.sha256.clone(),
            stdout_bytes: self.stdout.captured_len(),
            stderr_bytes: self.stderr.captured_len(),
            stdout_truncated: self.stdout.truncated,
            stderr_truncated: self.stderr.truncated,
            complete: self.is_complete(),
            encoding: combine_stream_encodings(self.stdout.encoding, self.stderr.encoding),
            originals_available,
            secrets_redacted: 0,
            secret_rule_ids: Vec::new(),
        }
    }
}

/// Executes `approved` asynchronously without a shell, capturing `stdout` and `stderr`
/// concurrently up to `approved.max_stream_bytes()` and enforcing `approved.timeout()`.
///
/// On timeout, terminates the child process and returns `Ok(CapturedCommand)` with
/// `timed_out = true`, `exit_code = None`, and all partial `stdout`/`stderr` bytes captured
/// prior to deadline expiry. Use [`capture_command_strict`] or [`CapturedCommand::check_timeout`]
/// when a hard [`ContextError::ExecutionTimeout`] error is desired.
pub async fn capture_command(approved: &ApprovedCommand) -> Result<CapturedCommand> {
    let token = CaptureCancelToken::new();
    capture_command_with_cancel(approved, &token).await
}

/// Like [`capture_command`], but fails immediately with [`ContextError::ExecutionTimeout`]
/// when the command exceeds `approved.timeout()`.
pub async fn capture_command_strict(approved: &ApprovedCommand) -> Result<CapturedCommand> {
    let captured = capture_command(approved).await?;
    captured.check_timeout()?;
    Ok(captured)
}

/// Executes `approved` with cooperative cancellation via `cancel_token`, deadline timeout via
/// `tokio::time::timeout`, and `kill_on_drop(true)` future-drop safety.
pub async fn capture_command_with_cancel(
    approved: &ApprovedCommand,
    cancel_token: &CaptureCancelToken,
) -> Result<CapturedCommand> {
    let captured_at = now_rfc3339_utc();
    let max_bytes = approved.max_stream_bytes();

    if cancel_token.is_cancelled() {
        return Ok(CapturedCommand {
            argv: approved.argv().to_vec(),
            cwd_relative: approved.cwd_relative().to_string(),
            exit_code: None,
            duration_ms: 0,
            timeout_ms: approved.timeout_ms(),
            timed_out: false,
            cancelled: true,
            captured_at,
            stdout: StreamAccumulator::new(max_bytes).finalize(),
            stderr: StreamAccumulator::new(max_bytes).finalize(),
        });
    }

    let mut cmd = Command::new(approved.program());
    cmd.args(approved.args())
        .current_dir(approved.cwd_canonical())
        .env_clear()
        .envs(
            approved
                .scrubbed_env()
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str())),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let started = Instant::now();
    let mut child = cmd.spawn().map_err(|err| {
        ContextError::Io(std::io::Error::new(
            err.kind(),
            format!("failed to spawn '{}': {err}", approved.program()),
        ))
    })?;

    let mut stdout_pipe = child.stdout.take().ok_or_else(|| {
        ContextError::Io(std::io::Error::other("child stdout pipe was not captured"))
    })?;
    let mut stderr_pipe = child.stderr.take().ok_or_else(|| {
        ContextError::Io(std::io::Error::other("child stderr pipe was not captured"))
    })?;

    let mut stdout_acc = StreamAccumulator::new(max_bytes);
    let mut stderr_acc = StreamAccumulator::new(max_bytes);

    enum RunOutcome {
        Finished(std::io::Result<std::process::ExitStatus>),
        Cancelled,
    }

    let timeout_res = tokio::time::timeout(approved.timeout(), async {
        tokio::select! {
            biased;
            () = cancel_token.cancelled() => RunOutcome::Cancelled,
            ((), (), wait_res) = async {
                tokio::join!(
                    read_stream_bounded(&mut stdout_pipe, &mut stdout_acc),
                    read_stream_bounded(&mut stderr_pipe, &mut stderr_acc),
                    child.wait(),
                )
            } => RunOutcome::Finished(wait_res),
        }
    })
    .await;

    // Explicitly close our read ends before reaping a timed-out or cancelled child.
    drop(stdout_pipe);
    drop(stderr_pipe);

    let (exit_code, timed_out, cancelled) = match timeout_res {
        Ok(RunOutcome::Finished(Ok(status))) => (status.code(), false, false),
        Ok(RunOutcome::Finished(Err(wait_err))) => {
            terminate_child(&mut child).await;
            return Err(ContextError::Io(wait_err));
        }
        Ok(RunOutcome::Cancelled) => {
            terminate_child(&mut child).await;
            (None, false, true)
        }
        Err(_elapsed) => {
            terminate_child(&mut child).await;
            (None, true, false)
        }
    };

    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    Ok(CapturedCommand {
        argv: approved.argv().to_vec(),
        cwd_relative: approved.cwd_relative().to_string(),
        exit_code,
        duration_ms,
        timeout_ms: approved.timeout_ms(),
        timed_out,
        cancelled,
        captured_at,
        stdout: stdout_acc.finalize(),
        stderr: stderr_acc.finalize(),
    })
}

async fn terminate_child(child: &mut Child) {
    let _ = child.start_kill();
    let _ = tokio::time::timeout(Duration::from_millis(500), child.wait()).await;
}
