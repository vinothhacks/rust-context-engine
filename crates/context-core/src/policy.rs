//! Subprocess execution, sensitive path denylist, and environment scrubbing policy contracts.

use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::error::{ContextError, Result};

const SHELL_INTERPRETERS: &[&str] = &[
    "cmd",
    "powershell",
    "pwsh",
    "sh",
    "bash",
    "zsh",
    "fish",
    "ksh",
    "csh",
    "wsl",
];

const DEFAULT_ALLOWED_PROGRAMS: &[&str] = &[
    "cargo", "rustc", "rustup", "git", "pytest", "python", "python3", "node", "npm", "npx",
    "pnpm", "yarn", "tsc", "go", "rg", "dotnet", "mvn", "gradle",
];

const DEFAULT_BLOCKED_PROGRAMS: &[&str] = &[
    "rm",
    "rmdir",
    "del",
    "erase",
    "remove-item",
    "format",
    "diskpart",
    "shred",
    "curl",
    "wget",
    "invoke-webrequest",
    "invoke-restmethod",
    "ssh",
    "scp",
    "sftp",
    "nc",
    "ncat",
    "netcat",
    "telnet",
];

const DEFAULT_PRESERVED_ENV_KEYS: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "SYSTEMDRIVE",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMDATA",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "RUSTFLAGS",
    "CARGO_TERM_COLOR",
    "GOPATH",
    "GOROOT",
    "VIRTUAL_ENV",
    "PYTHONPATH",
    "NODE_ENV",
    "LANG",
    "LC_ALL",
    "TERM",
    "NO_COLOR",
    "CI",
];

const SENSITIVE_DIRECTORIES: &[&str] = &[".ssh", ".aws", ".gnupg", ".kube", ".azure", ".gcloud"];

const SENSITIVE_EXACT_FILENAMES: &[&str] = &[
    ".env",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    "credentials",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
];

const SENSITIVE_EXTENSIONS: &[&str] = &["pem", "key", "pfx", "p12", "kdbx", "jks", "keystore"];

/// Declarative execution confinement policy shared between `context-core` and `context-execution`
/// (ADR 0003).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPolicyConfig {
    /// Whether shell interpreters (`cmd`, `powershell`, `sh`, `bash`) may be invoked.
    /// Defaults to `false`.
    pub allow_shell: bool,
    /// Lowercase normalized base executable names permitted for `context_run`.
    pub allowed_programs: Vec<String>,
    /// Lowercase normalized base executable names explicitly denied even if allowlisted.
    pub blocked_programs: Vec<String>,
    /// Environment variable keys preserved across subprocess scrubbing.
    pub preserved_env_keys: Vec<String>,
    /// Default command execution timeout in milliseconds (`120_000` = 2 minutes).
    pub default_timeout_ms: u64,
    /// Hard maximum command execution timeout in milliseconds (`600_000` = 10 minutes).
    pub max_timeout_ms: u64,
    /// Maximum bytes captured per child stream (`16 MiB` default).
    pub max_stream_bytes: u64,
}

impl Default for ExecutionPolicyConfig {
    fn default() -> Self {
        Self {
            allow_shell: false,
            allowed_programs: DEFAULT_ALLOWED_PROGRAMS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            blocked_programs: DEFAULT_BLOCKED_PROGRAMS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            preserved_env_keys: DEFAULT_PRESERVED_ENV_KEYS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            default_timeout_ms: 120_000,
            max_timeout_ms: 600_000,
            max_stream_bytes: 16 * 1024 * 1024,
        }
    }
}

impl ExecutionPolicyConfig {
    /// Validates `argv` against shell-interpreter, allowlist, blocklist, and destructive-flag rules.
    ///
    /// Returns the normalized base program name (e.g. `"cargo"`) when approved.
    pub fn validate_argv(&self, argv: &[String]) -> Result<String> {
        let Some(program_raw) = argv.first() else {
            return Err(ContextError::ExecutionDenied {
                program: "<empty>".to_string(),
                reason: "argv must contain at least one executable element".to_string(),
            });
        };

        let trimmed = program_raw.trim();
        if trimmed.is_empty() || trimmed.contains('\0') {
            return Err(ContextError::ExecutionDenied {
                program: program_raw.clone(),
                reason: "executable name cannot be empty or contain NUL bytes".to_string(),
            });
        }

        // Reject relative traversal or explicit path components in argv[0] by default so callers
        // cannot bypass allowlists via `./evil/cargo.exe` or `..\..\cmd.exe`.
        if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains(':') {
            return Err(ContextError::ExecutionDenied {
                program: program_raw.clone(),
                reason: "executable must be a bare allowlisted program name without path separators"
                    .to_string(),
            });
        }

        if argv.iter().any(|arg| arg.contains('\0')) {
            return Err(ContextError::ExecutionDenied {
                program: program_raw.clone(),
                reason: "arguments must not contain NUL bytes".to_string(),
            });
        }

        let base = normalize_program_name(trimmed);

        if !self.allow_shell && SHELL_INTERPRETERS.contains(&base.as_str()) {
            return Err(ContextError::ExecutionDenied {
                program: program_raw.clone(),
                reason: "shell interpreters are disabled by execution policy".to_string(),
            });
        }

        if self
            .blocked_programs
            .iter()
            .any(|blocked| normalize_program_name(blocked) == base)
        {
            return Err(ContextError::ExecutionDenied {
                program: program_raw.clone(),
                reason: format!("program '{base}' is blocked by destructive/network policy"),
            });
        }

        if !self
            .allowed_programs
            .iter()
            .any(|allowed| normalize_program_name(allowed) == base)
        {
            return Err(ContextError::ExecutionDenied {
                program: program_raw.clone(),
                reason: format!("program '{base}' is not in the execution allowlist"),
            });
        }

        validate_subcommand_safety(&base, &argv[1..], program_raw)?;

        Ok(base)
    }

    /// Resolves a requested timeout (or `default_timeout_ms`), failing closed if `0` or exceeding
    /// `max_timeout_ms`.
    pub fn resolve_timeout_ms(&self, requested_ms: Option<u64>) -> Result<u64> {
        let timeout = requested_ms.unwrap_or(self.default_timeout_ms);
        if timeout == 0 {
            return Err(ContextError::InvalidConfig {
                field: "timeout_ms",
                reason: "timeout_ms must be greater than 0".to_string(),
            });
        }
        if timeout > self.max_timeout_ms {
            return Err(ContextError::BudgetExceeded {
                resource: "execution.timeout_ms",
                requested: usize::try_from(timeout).unwrap_or(usize::MAX),
                limit: usize::try_from(self.max_timeout_ms).unwrap_or(usize::MAX),
            });
        }
        Ok(timeout)
    }

    /// Checks whether a path matches any sensitive credential/key rule (`.env*`, `*.pem`, `.ssh`, etc.).
    ///
    /// Returns `Some(rule_name)` when blocked, or `None` when permitted.
    #[must_use]
    pub fn classify_sensitive_path(&self, path: &Path) -> Option<&'static str> {
        let components: Vec<String> = path
            .components()
            .filter_map(|c| match c {
                Component::Normal(os) => Some(os.to_string_lossy().to_ascii_lowercase()),
                _ => None,
            })
            .collect();

        for (idx, comp) in components.iter().enumerate() {
            if SENSITIVE_DIRECTORIES.contains(&comp.as_str()) {
                return Some("sensitive_credential_directory");
            }
            if comp == ".git"
                && components
                    .get(idx + 1)
                    .is_some_and(|next| next == "credentials")
            {
                return Some("git_credentials_store");
            }
        }

        if let Some(file_name) = components.last() {
            if file_name == ".env" || file_name.starts_with(".env.") {
                return Some("dotenv_secret_file");
            }
            if SENSITIVE_EXACT_FILENAMES.contains(&file_name.as_str()) {
                return Some("credential_or_private_key_file");
            }
            if (file_name.starts_with("id_rsa")
                || file_name.starts_with("id_ed25519")
                || file_name.starts_with("id_ecdsa")
                || file_name.starts_with("id_dsa"))
                && !file_name.ends_with(".pub")
            {
                return Some("ssh_private_key_file");
            }
            if let Some((_, ext)) = file_name.rsplit_once('.') {
                if SENSITIVE_EXTENSIONS.contains(&ext) {
                    return Some("private_key_or_keystore_extension");
                }
            }
        }

        None
    }

    /// Enforces [`Self::classify_sensitive_path`], returning [`ContextError::SensitivePathBlocked`]
    /// when `path` targets a credential or secret file.
    pub fn ensure_non_sensitive_path(&self, path: &Path) -> Result<()> {
        if let Some(rule) = self.classify_sensitive_path(path) {
            return Err(ContextError::SensitivePathBlocked {
                path: path.display().to_string(),
                rule: rule.to_string(),
            });
        }
        Ok(())
    }

    /// Returns `true` if the environment variable `key` should be scrubbed before spawning
    /// a child process.
    #[must_use]
    pub fn should_scrub_env_var(&self, key: &str) -> bool {
        let upper = key.trim().to_ascii_uppercase();
        if self
            .preserved_env_keys
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&upper))
        {
            return false;
        }

        const SENSITIVE_SUBSTRINGS: &[&str] = &[
            "SECRET",
            "TOKEN",
            "PASSWORD",
            "PASSWD",
            "API_KEY",
            "APIKEY",
            "PRIVATE_KEY",
            "ACCESS_KEY",
            "AUTH_KEY",
            "CREDENTIALS",
            "CONN_STR",
            "CONNECTION_STRING",
        ];

        const SENSITIVE_EXACT_VARS: &[&str] = &[
            "DATABASE_URL",
            "REDIS_URL",
            "MONGODB_URI",
            "AMQP_URL",
            "ANTHROPIC_KEY",
            "OPENAI_KEY",
            "GH_ENTERPRISE_TOKEN",
            "NPM_CONFIG_AUTHTOKEN",
        ];

        if SENSITIVE_EXACT_VARS.contains(&upper.as_str()) {
            return true;
        }
        if upper.starts_with("AWS_") || upper.starts_with("AZURE_") || upper.starts_with("GCP_") {
            return true;
        }
        SENSITIVE_SUBSTRINGS
            .iter()
            .any(|needle| upper.contains(needle))
    }

    /// Filters an environment `(key, value)` iterator down to safe non-sensitive variables.
    pub fn filter_safe_env<I, K, V>(&self, env_vars: I) -> Vec<(String, String)>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        env_vars
            .into_iter()
            .filter_map(|(k, v)| {
                let key = k.into();
                if self.should_scrub_env_var(&key) {
                    None
                } else {
                    Some((key, v.into()))
                }
            })
            .collect()
    }
}

fn normalize_program_name(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    for suffix in [".exe", ".cmd", ".bat", ".com"] {
        if let Some(stripped) = lower.strip_suffix(suffix) {
            return stripped.to_string();
        }
    }
    lower
}

fn validate_subcommand_safety(base: &str, args: &[String], raw_program: &str) -> Result<()> {
    let lower_args: Vec<String> = args.iter().map(|a| a.to_ascii_lowercase()).collect();

    if base == "git" {
        let subcmd = lower_args
            .iter()
            .find(|a| !a.starts_with('-'))
            .map(String::as_str);

        if subcmd == Some("reset") && lower_args.iter().any(|a| a == "--hard") {
            return Err(ContextError::ExecutionDenied {
                program: raw_program.to_string(),
                reason: "'git reset --hard' is blocked as a destructive operation".to_string(),
            });
        }
        if subcmd == Some("clean")
            && lower_args.iter().any(|a| {
                a == "--force"
                    || (a.starts_with('-')
                        && !a.starts_with("--")
                        && (a.contains('f') || a.contains('x')))
            })
        {
            return Err(ContextError::ExecutionDenied {
                program: raw_program.to_string(),
                reason: "'git clean -f/-x' is blocked as a destructive operation".to_string(),
            });
        }
        if subcmd == Some("push")
            && lower_args
                .iter()
                .any(|a| a == "--force" || a == "-f" || a.starts_with("--force-with-lease"))
        {
            return Err(ContextError::ExecutionDenied {
                program: raw_program.to_string(),
                reason: "'git push --force' is blocked by execution policy".to_string(),
            });
        }
        if subcmd == Some("checkout")
            && lower_args.windows(2).any(|w| w[0] == "--" && w[1] == ".")
        {
            return Err(ContextError::ExecutionDenied {
                program: raw_program.to_string(),
                reason: "'git checkout -- .' is blocked as a destructive operation".to_string(),
            });
        }
    }

    // Block inline script evaluation flags on python/node that are commonly used as shell-equivalents
    // if combined with destructive commands? Note: python -m pytest is safe, while `-Recurse` + `-Force`
    // PowerShell-style flags are never valid in confined dev invocations.
    let has_recurse = lower_args
        .iter()
        .any(|a| a == "-recurse" || a == "--recursive");
    let has_force = lower_args.iter().any(|a| a == "-force");
    if has_recurse && has_force {
        return Err(ContextError::ExecutionDenied {
            program: raw_program.to_string(),
            reason: "recursive force flags (-Recurse -Force) are blocked by workspace safety policy"
                .to_string(),
        });
    }

    Ok(())
}
