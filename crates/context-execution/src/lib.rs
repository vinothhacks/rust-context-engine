//! Subprocess execution confinement, canonical path containment, TOCTOU file opening,
//! and `argv` allowlist authorization for the Rust Context Engine.

pub mod confinement;
pub mod gate;

pub use confinement::{
    open_confined_file, open_confined_file_sync, relative_within_workspace, resolve_cwd_in_scope,
    resolve_existing_file_in_scope, resolve_path_in_scope, ConfinedPath,
};
pub use context_core::ExecutionPolicyConfig;
pub use gate::{authorize_command, ApprovedCommand, CommandRequest, ExecutionGate};

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::path::{Path, PathBuf};

    use context_core::BoundScope;
    use proptest::prelude::*;
    use tempfile::TempDir;

    use super::*;

    fn create_dir_link(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
        #[cfg(windows)]
        {
            if std::os::windows::fs::symlink_dir(target, link).is_ok() {
                return true;
            }
            let status = std::process::Command::new("cmd")
                .arg("/c")
                .arg("mklink")
                .arg("/J")
                .arg(link)
                .arg(target)
                .output();
            matches!(status, Ok(out) if out.status.success())
        }
    }

    fn create_file_link(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link).is_ok()
        }
    }

    #[test]
    fn resolves_confined_paths_and_nonexistent_leaves_inside_workspace() {
        let ws = TempDir::new().expect("workspace tempdir");
        let src_dir = ws.path().join("crates").join("demo");
        fs::create_dir_all(&src_dir).expect("create src_dir");
        let main_rs = src_dir.join("main.rs");
        fs::write(&main_rs, "fn main() {}\n").expect("write main.rs");

        let scope = BoundScope::bind(ws.path(), Some("exec-test")).expect("bind scope");
        let gate = ExecutionGate::default();

        let root_cwd = gate.resolve_cwd(&scope, None).expect("default cwd");
        assert_eq!(root_cwd.relative, ".");
        assert_eq!(root_cwd.canonical, scope.workspace_root);

        let sub_cwd = gate
            .resolve_cwd(&scope, Some(Path::new("crates/demo")))
            .expect("subdir cwd");
        assert_eq!(sub_cwd.relative, "crates/demo");

        let resolved_file = gate
            .resolve_file(&scope, Path::new("crates/demo/main.rs"))
            .expect("existing file");
        assert_eq!(resolved_file.relative, "crates/demo/main.rs");

        // Non-existent leaf inside existing or non-existent subdirectory stays confined
        let future_leaf = gate
            .resolve_path(&scope, Path::new("crates/demo/new_mod/future.rs"))
            .expect("non-existent leaf inside workspace");
        assert_eq!(future_leaf.relative, "crates/demo/new_mod/future.rs");

        // Internal `..` normalizing back inside workspace is allowed
        let normalized_internal = gate
            .resolve_file(&scope, Path::new("crates/demo/../demo/main.rs"))
            .expect("internal .. normalization");
        assert_eq!(normalized_internal.relative, "crates/demo/main.rs");
    }

    #[test]
    fn rejects_parent_traversal_outside_workspace_and_sensitive_paths() {
        let outer = TempDir::new().expect("outer tempdir");
        let ws_dir = outer.path().join("workspace");
        let secret_outside = outer.path().join("outside_secret.txt");
        fs::create_dir_all(&ws_dir).expect("create workspace");
        fs::write(&secret_outside, "top-secret").expect("write outside");
        fs::write(ws_dir.join(".env"), "API_TOKEN=secret123\n").expect("write .env");

        let scope = BoundScope::bind(&ws_dir, None).expect("bind workspace");
        let gate = ExecutionGate::default();

        for escape_path in [
            PathBuf::from(".."),
            PathBuf::from("../outside_secret.txt"),
            PathBuf::from("sub/../../outside_secret.txt"),
            PathBuf::from("../nonexistent_outside_leaf.txt"),
            secret_outside.clone(),
        ] {
            let err = gate
                .resolve_path(&scope, &escape_path)
                .expect_err("expected escape path to fail");
            assert_eq!(
                err.error_code(),
                "PATH_ESCAPE",
                "unexpected error for {}: {err:?}",
                escape_path.display()
            );
            assert!(err.is_security_denial());
        }

        for sensitive in [
            ".env",
            ".env.local",
            "config/.env.production",
            "certs/private.pem",
            "keys/service.key",
            ".ssh/id_rsa",
            ".aws/credentials",
            ".git/credentials",
        ] {
            let err = gate
                .resolve_path(&scope, Path::new(sensitive))
                .expect_err("expected sensitive path to be blocked");
            assert_eq!(
                err.error_code(),
                "SENSITIVE_PATH_BLOCKED",
                "unexpected error for {sensitive}: {err:?}"
            );
            assert!(err.is_security_denial());
        }
    }

    #[test]
    fn rejects_symlink_and_junction_escapes_including_nonexistent_leaves() {
        let outer = TempDir::new().expect("outer");
        let ws_dir = outer.path().join("repo");
        let external_dir = outer.path().join("external_target");
        fs::create_dir_all(&ws_dir).expect("create repo");
        fs::create_dir_all(ws_dir.join("docs")).expect("create docs");
        fs::write(ws_dir.join("docs").join("guide.md"), "# Guide\n").expect("write guide");
        fs::write(ws_dir.join(".env"), "SECRET=1\n").expect("write .env");
        fs::create_dir_all(&external_dir).expect("create external");
        fs::write(external_dir.join("leaked.txt"), "leaked").expect("write leaked");

        let scope = BoundScope::bind(&ws_dir, None).expect("bind");
        let gate = ExecutionGate::default();

        let escape_link = ws_dir.join("escape_link");
        assert!(
            create_dir_link(&external_dir, &escape_link),
            "expected directory symlink or NTFS junction creation to succeed"
        );

        // 1. Existing file through escaping symlink/junction -> PATH_ESCAPE
        let err_existing = gate
            .resolve_path(&scope, Path::new("escape_link/leaked.txt"))
            .expect_err("escape via junction/symlink must fail");
        assert_eq!(err_existing.error_code(), "PATH_ESCAPE");

        // 2. Non-existent leaf through escaping symlink/junction -> PATH_ESCAPE
        let err_nonexistent = gate
            .resolve_path(&scope, Path::new("escape_link/future_file.txt"))
            .expect_err("non-existent leaf via escaping junction/symlink must fail");
        assert_eq!(err_nonexistent.error_code(), "PATH_ESCAPE");

        // 3. CWD pointing to escaping symlink/junction -> PATH_ESCAPE
        let err_cwd = gate
            .resolve_cwd(&scope, Some(Path::new("escape_link")))
            .expect_err("cwd escape via junction/symlink must fail");
        assert_eq!(err_cwd.error_code(), "PATH_ESCAPE");

        // 4. Safe internal link pointing inside workspace -> allowed
        let safe_link = ws_dir.join("docs_alias");
        if create_dir_link(&ws_dir.join("docs"), &safe_link) {
            let ok_internal = gate
                .resolve_file(&scope, Path::new("docs_alias/guide.md"))
                .expect("internal workspace link allowed");
            assert_eq!(ok_internal.relative, "docs/guide.md");
            let _ = fs::remove_dir(&safe_link);
        }

        // 5. File symlink inside workspace targeting `.env` -> SENSITIVE_PATH_BLOCKED
        let dotenv_alias = ws_dir.join("harmless_readme.txt");
        if create_file_link(&ws_dir.join(".env"), &dotenv_alias) {
            let err_dotenv = gate
                .resolve_file(&scope, Path::new("harmless_readme.txt"))
                .expect_err("symlink targeting .env must be blocked");
            assert_eq!(err_dotenv.error_code(), "SENSITIVE_PATH_BLOCKED");
            let _ = fs::remove_file(&dotenv_alias);
        }

        // Clean up junction link explicitly before TempDir drops.
        let _ = fs::remove_dir(&escape_link);
    }

    #[tokio::test]
    async fn open_confined_file_sync_and_async_verify_toctou_and_read_contents() {
        let ws = TempDir::new().expect("ws");
        fs::write(ws.path().join("hello.txt"), b"confined content\n").expect("write");
        let scope = BoundScope::bind(ws.path(), None).expect("bind");
        let gate = ExecutionGate::default();

        let (mut sync_file, confined_sync) = gate
            .open_file_sync(&scope, Path::new("hello.txt"))
            .expect("open sync");
        assert_eq!(confined_sync.relative, "hello.txt");
        let mut buf = String::new();
        sync_file.read_to_string(&mut buf).expect("read sync");
        assert_eq!(buf, "confined content\n");

        let (mut async_file, confined_async) = gate
            .open_file(&scope, Path::new("hello.txt"))
            .await
            .expect("open async");
        assert_eq!(confined_async.relative, "hello.txt");
        let mut async_buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut async_file, &mut async_buf)
            .await
            .expect("read async");
        assert_eq!(async_buf, b"confined content\n");
    }

    #[test]
    fn execution_gate_authorizes_safe_commands_scrubs_env_and_blocks_dangerous_invocations() {
        let ws = TempDir::new().expect("ws");
        fs::create_dir_all(ws.path().join("subcrate")).expect("mkdir subcrate");
        let scope = BoundScope::bind(ws.path(), Some("gate-sess")).expect("bind");
        let gate = ExecutionGate::default();

        let synthetic_env = vec![
            ("PATH", "/usr/local/bin:/usr/bin"),
            ("CARGO_HOME", "/home/dev/.cargo"),
            ("OPENAI_API_KEY", "sk-live-secret"),
            ("AWS_SECRET_ACCESS_KEY", "aws-super-secret"),
            ("GITHUB_TOKEN", "ghp_secret"),
            ("DATABASE_URL", "postgres://user:pass@db/prod"),
        ];

        let req = CommandRequest::new(["cargo", "test", "--lib"])
            .with_cwd("subcrate")
            .with_timeout_ms(30_000)
            .with_max_stream_bytes(1024 * 1024)
            .with_extra_env([
                ("RUST_BACKTRACE", "1"),
                ("ANTHROPIC_API_KEY", "sk-ant-AttemptedSmuggle"),
            ]);

        let approved = gate
            .authorize_with_env(&scope, &req, synthetic_env)
            .expect("cargo test authorized");
        assert_eq!(approved.normalized_program(), "cargo");
        assert_eq!(approved.program(), "cargo");
        assert_eq!(approved.args(), &["test".to_string(), "--lib".to_string()]);
        assert_eq!(approved.cwd_relative(), "subcrate");
        assert_eq!(approved.timeout_ms(), 30_000);
        assert_eq!(approved.max_stream_bytes(), 1024 * 1024);

        let env_keys: Vec<&str> = approved
            .scrubbed_env()
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert!(env_keys.contains(&"PATH"));
        assert!(env_keys.contains(&"CARGO_HOME"));
        assert!(env_keys.contains(&"RUST_BACKTRACE"));
        assert!(!env_keys.contains(&"OPENAI_API_KEY"));
        assert!(!env_keys.contains(&"AWS_SECRET_ACCESS_KEY"));
        assert!(!env_keys.contains(&"GITHUB_TOKEN"));
        assert!(!env_keys.contains(&"DATABASE_URL"));
        assert!(!env_keys.contains(&"ANTHROPIC_API_KEY"));

        // Verify empty, shell, destructive, and upload commands are denied
        let denied_cases: Vec<Vec<&str>> = vec![
            vec![],
            vec!["cmd", "/c", "echo hi"],
            vec!["powershell", "-Command", "Get-Process"],
            vec!["pwsh", "-c", "pwd"],
            vec!["sh", "-c", "ls"],
            vec!["bash", "-c", "ls"],
            vec!["git", "reset", "--hard"],
            vec!["git", "clean", "-fd"],
            vec!["git", "clean", "-d"],
            vec!["rm", "-rf", "."],
            vec!["Remove-Item", "-Recurse", "-Force", "foo"],
            vec!["del", "file.txt"],
            vec!["curl", "https://example.com"],
            vec!["wget", "https://example.com"],
        ];

        for argv in denied_cases {
            let bad_req = CommandRequest::new(argv.clone());
            let err = gate
                .authorize_with_env(&scope, &bad_req, std::iter::empty::<(&str, &str)>())
                .expect_err("expected command to be denied");
            assert_eq!(err.error_code(), "EXECUTION_DENIED", "argv={argv:?}");
        }

        // Even if `curl` is explicitly allowlisted by custom policy, upload flags remain blocked
        // unless `with_allow_network_uploads(true)` is also configured.
        let mut curl_policy = ExecutionPolicyConfig::default();
        curl_policy.blocked_programs.retain(|p| p != "curl");
        curl_policy.allowed_programs.push("curl".to_string());

        let readonly_curl_gate = ExecutionGate::new(curl_policy.clone());
        readonly_curl_gate
            .authorize_with_env(
                &scope,
                &CommandRequest::new(["curl", "-s", "http://127.0.0.1:8080/health"]),
                std::iter::empty::<(&str, &str)>(),
            )
            .expect("GET curl allowed when policy enables curl");

        let upload_err = readonly_curl_gate
            .authorize_with_env(
                &scope,
                &CommandRequest::new([
                    "curl",
                    "--upload-file",
                    "Cargo.toml",
                    "http://127.0.0.1:8080/upload",
                ]),
                std::iter::empty::<(&str, &str)>(),
            )
            .expect_err("curl --upload-file must still be blocked");
        assert_eq!(upload_err.error_code(), "EXECUTION_DENIED");

        let upload_enabled_gate =
            ExecutionGate::new(curl_policy).with_allow_network_uploads(true);
        upload_enabled_gate
            .authorize_with_env(
                &scope,
                &CommandRequest::new([
                    "curl",
                    "--upload-file",
                    "Cargo.toml",
                    "http://127.0.0.1:8080/upload",
                ]),
                std::iter::empty::<(&str, &str)>(),
            )
            .expect("explicitly upload-enabled policy permits curl upload");
    }

    proptest! {
        #[test]
        fn prop_confinement_never_panics_or_allows_escape(
            segments in proptest::collection::vec(
                prop_oneof![
                    Just("..".to_string()),
                    Just(".".to_string()),
                    Just(".env".to_string()),
                    "[a-zA-Z0-9_-]{1,12}",
                ],
                1..8
            )
        ) {
            let outer = TempDir::new().expect("outer");
            let ws_dir = outer.path().join("ws");
            fs::create_dir_all(&ws_dir).expect("mkdir ws");
            let scope = BoundScope::bind(&ws_dir, None).expect("bind");
            let gate = ExecutionGate::default();

            let candidate: PathBuf = segments.iter().collect();
            if let Ok(confined) = gate.resolve_path(&scope, &candidate) {
                prop_assert!(
                    relative_within_workspace(&confined.canonical, &scope.workspace_root).is_some()
                );
                prop_assert!(!confined.relative.contains(".."));
                prop_assert!(
                    gate.policy()
                        .ensure_non_sensitive_path(Path::new(&confined.relative))
                        .is_ok()
                );
            }
        }
    }
}
