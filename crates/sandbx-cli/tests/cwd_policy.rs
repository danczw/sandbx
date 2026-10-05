//! The working-directory default, end to end: the refusals an operator actually sees.
//!
//! Spawned rather than called, because the guard reads `getcwd` and `HOME` off the real
//! process and `set_current_dir` is process-global — under parallel tests one case would
//! decide another's verdict. `PolicyError::EnforcerInside` needs the binary *under* the
//! test's cwd, which cargo's layout prevents, so it is covered inline in `grants.rs` only.
// `Command::new` here spawns sandbx itself, never a command that bypasses it; the
// workspace ban exists to stop code executing *around* the sandbox.
#![allow(clippy::disallowed_methods)]

use std::process::Command;

/// The package root: cargo's own cwd for a test, and what the home cases pretend is `$HOME`.
const PACKAGE: &str = env!("CARGO_MANIFEST_DIR");

/// Whether `sandbox-run` succeeded from `cwd` with `HOME` set to `home`, and its stderr.
fn run(cwd: &str, home: &str, flags: &[&str]) -> (bool, String) {
    spawn(cwd, flags, |command| command.env("HOME", home))
}

/// [`run`], but with `HOME` removed from the child's environment entirely.
fn run_without_home(cwd: &str, flags: &[&str]) -> (bool, String) {
    spawn(cwd, flags, |command| command.env_remove("HOME"))
}

fn spawn(
    cwd: &str,
    flags: &[&str],
    home: impl FnOnce(&mut Command) -> &mut Command,
) -> (bool, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sandbx"));
    command
        .arg("sandbox-run")
        .args(flags)
        .args(["--", "true"])
        .current_dir(cwd);

    let output = home(&mut command).output().expect("sandbx should start");

    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn refuses_to_run_from_the_filesystem_root() {
    let (ok, stderr) = run("/", PACKAGE, &[]);

    assert!(!ok, "a no-flag run from / was allowed: {stderr}");
    assert!(
        stderr.contains("refusing to derive") && stderr.contains("--allow-write"),
        "{stderr} does not say what was refused, or what to type instead"
    );
}

/// The accident the guard exists for: it would hand the command `~/.ssh` and every
/// dotfile, and for `agent-run` that is a prompt injection's blast radius.
#[test]
fn refuses_to_run_from_the_home_directory() {
    let (ok, stderr) = run(PACKAGE, PACKAGE, &[]);

    assert!(!ok, "a no-flag run from $HOME was allowed: {stderr}");
    assert!(
        stderr.contains("refusing to derive") && stderr.contains("--allow-write"),
        "{stderr} does not say what was refused, or what to type instead"
    );
}

/// The reproducer: with `HOME` gone the home rule has nothing to compare, and before the
/// well-known fallback this derived read and write over every user's home.
#[test]
fn refuses_to_run_from_home_with_no_home_set() {
    let (ok, stderr) = run_without_home("/home", &[]);

    assert!(!ok, "a no-flag run from /home with no HOME was allowed");
    assert!(
        stderr.contains("with HOME unset"),
        "{stderr} does not say why /home could not be told apart"
    );
}

/// The container case, through the real binary: an unset `HOME` must not refuse an ordinary
/// directory, or the fallback above has broken the deployment the default exists for.
#[test]
fn an_unset_home_still_runs_from_a_project() {
    let (_, stderr) = run_without_home(PACKAGE, &[]);

    assert!(
        !stderr.contains("refusing to derive"),
        "an unset HOME refused an ordinary project directory: {stderr}"
    );
}

/// The guard must fire on the derived default and never on an explicit one, or adding it
/// made a hand-written policy unrunnable from `$HOME`. Asserts only the refusal's absence:
/// whether the run then succeeds is kernel-dependent, which is the sandbox suite's
/// question.
#[test]
fn a_path_flag_runs_from_the_home_directory() {
    let (_, stderr) = run(PACKAGE, PACKAGE, &["--allow-read", "/usr"]);

    assert!(
        !stderr.contains("refusing to derive"),
        "an explicit policy was refused over a directory it never asked for: {stderr}"
    );
}
