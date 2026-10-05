//! The working-directory default, end to end: the refusals an operator actually sees.
//!
//! Spawned rather than called, because the guard reads `getcwd` and `HOME` off the real
//! process and `set_current_dir` is process-global — under parallel tests one case would
//! decide another's verdict. `PolicyError::EnforcerInside` has no case here: reaching it
//! needs the binary *under* the test's cwd, which cargo's layout prevents, so it is
//! covered inline in `grants.rs` only.
// `Command::new` here spawns sandbx itself, never a command that bypasses it; the
// workspace ban exists to stop code executing *around* the sandbox.
#![allow(clippy::disallowed_methods)]

use std::process::Command;

/// The package root: cargo's own cwd for a test, and what the home cases pretend is `$HOME`.
const PACKAGE: &str = env!("CARGO_MANIFEST_DIR");

/// Whether `sandbox-run` succeeded from `cwd` with `HOME` set to `home`, and its stderr.
fn run(cwd: &str, home: &str, flags: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_sandbx"))
        .arg("sandbox-run")
        .args(flags)
        .args(["--", "true"])
        .current_dir(cwd)
        .env("HOME", home)
        .output()
        .expect("sandbx should start");

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

/// A no-flag run from `$HOME` is the accident the guard exists for: it would hand the
/// command `~/.ssh` and every dotfile, and for `agent-run` that is a prompt injection's
/// blast radius.
#[test]
fn refuses_to_run_from_the_home_directory() {
    let (ok, stderr) = run(PACKAGE, PACKAGE, &[]);

    assert!(!ok, "a no-flag run from $HOME was allowed: {stderr}");
    assert!(
        stderr.contains("refusing to derive") && stderr.contains("--allow-write"),
        "{stderr} does not say what was refused, or what to type instead"
    );
}

/// The guard must fire on the derived default and never on an explicit one — otherwise
/// adding it made a hand-written policy unrunnable from the one directory operators
/// stand in most. Asserts only the absence of the refusal: whether the run then succeeds
/// depends on the kernel, which is the sandbox suite's question rather than this one's.
#[test]
fn a_path_flag_runs_from_the_home_directory() {
    let (_, stderr) = run(PACKAGE, PACKAGE, &["--allow-read", "/usr"]);

    assert!(
        !stderr.contains("refusing to derive"),
        "an explicit policy was refused over a directory it never asked for: {stderr}"
    );
}
