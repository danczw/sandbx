//! `auth` end to end: the file it writes, the mode it writes it with, and what an
//! operator sees.
//!
//! Spawned rather than called, because the chain reads `XDG_CONFIG_HOME`, `HOME` and
//! `ANTHROPIC_API_KEY` off the real process, and edition 2024 makes setting a variable
//! `unsafe` — which this workspace forbids.
// `Command::new` here spawns sandbx itself, never a command that bypasses it; the
// workspace ban exists to stop code executing *around* the sandbox.
#![allow(clippy::disallowed_methods)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// What a spawned `auth` reported.
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run `auth <action>` against `config` as the config home, with no key in the environment.
fn auth(config: &Path, action: &str, stdin: Option<&str>) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sandbx"));
    command
        .args(["auth", action])
        .env("XDG_CONFIG_HOME", config)
        .env_remove("ANTHROPIC_API_KEY")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("sandbx should start");
    if let Some(key) = stdin {
        let mut pipe = child.stdin.take().expect("stdin was piped");
        pipe.write_all(key.as_bytes())
            .expect("the pipe should take the key");
    }

    let output = child.wait_with_output().expect("sandbx should finish");
    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// `auth status` with a key exported, which must win over whatever is on disk.
fn status_with_env(config: &Path, key: &str) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_sandbx"))
        .args(["auth", "status"])
        .env("XDG_CONFIG_HOME", config)
        .env("ANTHROPIC_API_KEY", key)
        .output()
        .expect("sandbx should start");

    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn credentials(config: &Path) -> PathBuf {
    config.join("sandbx/credentials.toml")
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("{} should exist: {error}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

#[test]
fn login_writes_the_file_and_its_directory_owner_only() {
    let config = tempfile::tempdir().unwrap();
    let run = auth(config.path(), "login", Some("sk-ant-test\n"));

    assert_eq!(run.code, Some(0), "{}", run.stderr);

    let path = credentials(config.path());
    assert_eq!(mode_of(&path), 0o600, "the credential file is not 0600");
    assert_eq!(
        mode_of(path.parent().unwrap()),
        0o700,
        "the directory holding the credential is not 0700"
    );
}

#[test]
fn login_never_echoes_the_key_it_stored() {
    let config = tempfile::tempdir().unwrap();
    let run = auth(config.path(), "login", Some("sk-ant-secret"));

    assert!(
        !run.stdout.contains("sk-ant-secret") && !run.stderr.contains("sk-ant-secret"),
        "login printed the key it stored: {}{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn status_names_the_file_without_printing_the_key() {
    let config = tempfile::tempdir().unwrap();
    auth(config.path(), "login", Some("sk-ant-secret"));

    let run = auth(config.path(), "status", None);

    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        run.stdout.contains("credentials.toml"),
        "status does not say where the key came from: {}",
        run.stdout
    );
    assert!(
        !run.stdout.contains("sk-ant-secret"),
        "status printed the key: {}",
        run.stdout
    );
}

#[test]
fn status_without_a_key_anywhere_exits_one() {
    let config = tempfile::tempdir().unwrap();
    let run = auth(config.path(), "status", None);

    assert_eq!(run.code, Some(1), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.contains("not authenticated"), "{}", run.stdout);
}

/// The precedence an operator relies on: exporting a key is a local override that needs no
/// `auth logout` first.
#[test]
fn an_exported_key_wins_over_the_stored_one() {
    let config = tempfile::tempdir().unwrap();
    auth(config.path(), "login", Some("from-file"));

    let run = status_with_env(config.path(), "from-env");

    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        run.stdout.contains("ANTHROPIC_API_KEY"),
        "the stored key won over the exported one: {}",
        run.stdout
    );
}

#[test]
fn logout_removes_the_file_it_emptied() {
    let config = tempfile::tempdir().unwrap();
    auth(config.path(), "login", Some("sk-ant-test"));

    let run = auth(config.path(), "logout", None);

    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(!credentials(config.path()).exists());
    assert_eq!(auth(config.path(), "status", None).code, Some(1));
}

#[test]
fn logout_with_nothing_stored_says_so_and_succeeds() {
    let config = tempfile::tempdir().unwrap();
    let run = auth(config.path(), "logout", None);

    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(run.stderr.contains("no key"), "{}", run.stderr);
}

#[test]
fn a_second_login_replaces_the_key_and_keeps_the_mode() {
    let config = tempfile::tempdir().unwrap();
    auth(config.path(), "login", Some("first"));
    let run = auth(config.path(), "login", Some("second"));

    assert_eq!(run.code, Some(0), "{}", run.stderr);

    let path = credentials(config.path());
    assert_eq!(mode_of(&path), 0o600);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("second") && !text.contains("first"), "{text}");
}

/// The case the mode check exists for: a file copied, or written under a lax umask, is
/// already disclosed, so it is refused rather than read.
#[test]
fn a_group_readable_file_is_refused_with_the_fix() {
    let config = tempfile::tempdir().unwrap();
    auth(config.path(), "login", Some("sk-ant-test"));

    let path = credentials(config.path());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

    let run = auth(config.path(), "status", None);

    assert_eq!(run.code, Some(1), "a 0640 credential was accepted");
    assert!(
        run.stderr.contains("chmod 600"),
        "the refusal does not say how to fix it: {}",
        run.stderr
    );
}

/// An empty stdin is a `printf` that produced nothing, or a pipe from a command that
/// failed. Storing it would overwrite a working key with a blank one.
#[test]
fn login_refuses_an_empty_stdin() {
    let config = tempfile::tempdir().unwrap();
    let run = auth(config.path(), "login", Some(""));

    assert_eq!(run.code, Some(1));
    assert!(!credentials(config.path()).exists());
}

#[test]
fn login_keeps_a_table_it_did_not_write() {
    let config = tempfile::tempdir().unwrap();
    let path = credentials(config.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "[other]\nkey = \"keep\"\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    auth(config.path(), "login", Some("sk-ant-test"));

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.contains("[other]"),
        "login dropped a table it does not know: {text}"
    );
}

/// With `XDG_CONFIG_HOME` unset and `HOME` relative, there is nowhere to keep a credential
/// — refused rather than resolved against the working directory, which for `agent-run` is
/// the tree the model can write.
#[test]
fn no_absolute_config_home_is_refused_not_guessed() {
    let output = Command::new(env!("CARGO_BIN_EXE_sandbx"))
        .args(["auth", "status"])
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("ANTHROPIC_API_KEY")
        .env("HOME", "relative/path")
        .output()
        .expect("sandbx should start");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("absolute directory"),
        "{stderr} does not say why there was nowhere to look"
    );
}
