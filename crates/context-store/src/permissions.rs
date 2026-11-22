//! Private owner-only filesystem permission hardening and `doctor` diagnostics
//! for `.context-engine/store/` (Windows `icacls` DACL + Unix `0700`/`0600`).

#[cfg(unix)]
use std::fs;
use std::path::{Path, PathBuf};

use context_core::{ContextError, Result};
use serde::{Deserialize, Serialize};

/// Diagnostic report returned by [`verify_directory_permissions`] / `BlobStore::verify_store_permissions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorePermissionReport {
    /// Store root directory inspected.
    pub store_dir: PathBuf,
    /// Whether `store_dir` exists on disk.
    pub exists: bool,
    /// `true` when directory permissions are restricted to the current OS owner.
    pub private_only: bool,
    /// OS permission mechanism (`"windows_icacls_dacl"` or `"unix_mode_0700"`).
    pub platform_mechanism: String,
    /// Resolved owner principal name when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// Human-readable diagnostic summary suitable for `context-engine doctor`.
    pub details: String,
}

/// Applies private owner-only permissions to `dir`.
///
/// - **Windows:** Executes `icacls <dir> /inheritance:r /grant:r "<USERNAME>:(OI)(CI)F"`
///   directly via `std::process::Command::new("icacls")` (array args, no shell) and verifies
///   a zero exit status.
/// - **Unix:** Sets mode `0o700` via `std::os::unix::fs::PermissionsExt`.
pub fn apply_private_dir_permissions(dir: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        apply_windows_icacls(dir)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Applies private owner-only file permissions (`0o600` on Unix; inherited `(OI)(CI)F` DACL on Windows).
pub fn apply_private_file_permissions(file_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(file_path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = file_path;
    }
    Ok(())
}

/// Inspects `dir` and verifies that owner-only private permissions are active.
pub fn verify_directory_permissions(dir: &Path) -> Result<StorePermissionReport> {
    if !dir.exists() {
        return Ok(StorePermissionReport {
            store_dir: dir.to_path_buf(),
            exists: false,
            private_only: false,
            platform_mechanism: platform_mechanism_name().to_string(),
            principal: None,
            details: "store directory does not exist yet".to_string(),
        });
    }

    #[cfg(windows)]
    {
        verify_windows_icacls(dir)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(dir)?;
        let mode = meta.permissions().mode() & 0o777;
        let private_only = (mode & 0o077) == 0;
        Ok(StorePermissionReport {
            store_dir: dir.to_path_buf(),
            exists: true,
            private_only,
            platform_mechanism: "unix_mode_0700".to_string(),
            principal: std::env::var("USER").ok(),
            details: format!("directory mode is {mode:04o}"),
        })
    }
    #[cfg(not(any(windows, unix)))]
    {
        Ok(StorePermissionReport {
            store_dir: dir.to_path_buf(),
            exists: true,
            private_only: false,
            platform_mechanism: "unsupported_platform".to_string(),
            principal: None,
            details: "platform ACL verification not supported".to_string(),
        })
    }
}

const fn platform_mechanism_name() -> &'static str {
    #[cfg(windows)]
    {
        "windows_icacls_dacl"
    }
    #[cfg(unix)]
    {
        "unix_mode_0700"
    }
    #[cfg(not(any(windows, unix)))]
    {
        "unknown"
    }
}

#[cfg(windows)]
fn resolve_windows_principal_candidates() -> Result<Vec<String>> {
    let mut candidates: Vec<String> = Vec::new();

    let username = std::env::var("USERNAME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("USERPROFILE").ok().and_then(|profile| {
                Path::new(profile.trim())
                    .file_name()
                    .map(|os| os.to_string_lossy().trim().to_string())
                    .filter(|s| !s.is_empty())
            })
        });

    if let Some(user) = &username {
        candidates.push(user.clone());
        if let Ok(domain) = std::env::var("USERDOMAIN") {
            let dom = domain.trim();
            if !dom.is_empty() {
                candidates.push(format!(r"{dom}\{user}"));
            }
        }
    }

    if candidates.is_empty() {
        let out = std::process::Command::new("whoami")
            .output()
            .map_err(|err| ContextError::Storage {
                message: format!("unable to determine current Windows user via env or whoami: {err}"),
            })?;
        if out.status.success() {
            let who = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !who.is_empty() {
                if let Some((_, short_user)) = who.rsplit_once('\\') {
                    candidates.push(short_user.to_string());
                }
                candidates.push(who);
            }
        }
    }

    if candidates.is_empty() {
        return Err(ContextError::Storage {
            message: "could not determine current Windows principal for icacls".to_string(),
        });
    }

    Ok(candidates)
}

#[cfg(windows)]
fn apply_windows_icacls(dir: &Path) -> Result<()> {
    let simplified = dunce::simplified(dir);
    let candidates = resolve_windows_principal_candidates()?;
    let mut last_error = String::new();

    for principal in candidates {
        let grant_arg = format!("{principal}:(OI)(CI)F");
        let output = std::process::Command::new("icacls")
            .arg(simplified)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(&grant_arg)
            .output()
            .map_err(|err| ContextError::Storage {
                message: format!("failed to invoke icacls on '{}': {err}", simplified.display()),
            })?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        last_error = format!(
            "principal='{principal}' status={} stdout='{}' stderr='{}'",
            output.status,
            stdout.trim(),
            stderr.trim()
        );
    }

    Err(ContextError::Storage {
        message: format!(
            "icacls failed to restrict permissions on '{}': {last_error}",
            simplified.display()
        ),
    })
}

#[cfg(windows)]
fn verify_windows_icacls(dir: &Path) -> Result<StorePermissionReport> {
    let simplified = dunce::simplified(dir);
    let output = std::process::Command::new("icacls")
        .arg(simplified)
        .output()
        .map_err(|err| ContextError::Storage {
            message: format!("failed to query icacls on '{}': {err}", simplified.display()),
        })?;

    if !output.status.success() {
        return Err(ContextError::Storage {
            message: format!(
                "icacls query failed on '{}' with status {}: {}",
                simplified.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }

    let raw_stdout = String::from_utf8_lossy(&output.stdout);
    let path_prefix = simplified.to_string_lossy();
    let acl_body = raw_stdout
        .trim_start()
        .strip_prefix(path_prefix.as_ref())
        .unwrap_or(&raw_stdout);

    // Take ACE lines before the trailing "Successfully processed 1 files..." summary line.
    let ace_lines: Vec<&str> = acl_body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.to_ascii_lowercase().starts_with("successfully "))
        .collect();

    let joined_aces = ace_lines.join("; ");
    let lower_aces = joined_aces.to_ascii_lowercase();

    let has_inherited = joined_aces.contains("(I)");
    let has_broad_principal = lower_aces.contains("everyone:")
        || lower_aces.contains("builtin\\users:")
        || lower_aces.contains("authenticated users:");
    let has_full_grant = joined_aces.contains("(F)");

    let candidates = resolve_windows_principal_candidates().unwrap_or_default();
    let matched_principal = candidates.into_iter().find(|cand| {
        let short = cand.rsplit_once('\\').map_or(cand.as_str(), |(_, u)| u);
        lower_aces.contains(&short.to_ascii_lowercase())
    });

    let private_only =
        !has_inherited && !has_broad_principal && has_full_grant && matched_principal.is_some();

    Ok(StorePermissionReport {
        store_dir: dir.to_path_buf(),
        exists: true,
        private_only,
        platform_mechanism: "windows_icacls_dacl".to_string(),
        principal: matched_principal,
        details: joined_aces,
    })
}
