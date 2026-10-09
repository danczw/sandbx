//! The held trail end to end: the shipped subscriber, a real emit, and real stderr.
//!
//! The composition is what was untested, and it is why #266 stood undiagnosable. The
//! other two files each cover half of it: `audit_log.rs` drives `subscriber(…)` over a
//! closure writer, never `Audit`; `logging.rs`'s own tests drive `Audit` and `HELD` with
//! no subscriber installed. Neither reaches `emit` → the global layer → `Audit::write` →
//! `HELD` → `Held::drop` → stderr, which is the path `tui` actually runs.
//!
//! Its own binary, because `logging::init` installs a process-global subscriber — the same
//! reason `audit_log_install.rs` holds exactly one test.
//!
//! Stderr has to be the real descriptor for the ordering to mean anything: `Held::drop`
//! writes to fd 2 directly, where libtest's capture only intercepts the print macros, so
//! a captured run would interleave the two by mechanism rather than by time. So the test
//! re-execs this binary with `--nocapture` and reads fd 2 from the outside.
// `Command::new` here spawns this test binary, never a command that bypasses the sandbox.
#![allow(clippy::disallowed_methods)]

use std::process::Command;

use sandbx_core::AuditEvent;

/// Set on the re-exec, so the one test below runs its other half.
const CHILD: &str = "SANDBX_TEST_AUDIT_HELD_CHILD";

/// Written before the guard drops and after it, so the record's place is asserted against
/// two fixed points rather than against "stderr was not empty".
const HELD: &str = "mark: the guard is still in force";
const RELEASED: &str = "mark: the guard has dropped";

/// A record emitted under a hold reaches stderr, once, after the hold ends.
#[test]
fn a_record_emitted_under_a_hold_reaches_stderr_when_the_hold_ends() {
    if std::env::var_os(CHILD).is_some() {
        return held_run();
    }

    let exe = std::env::current_exe().expect("the test binary should know its own path");
    let output = Command::new(exe)
        .args([
            "--nocapture",
            "--exact",
            "a_record_emitted_under_a_hold_reaches_stderr_when_the_hold_ends",
        ])
        .env(CHILD, "1")
        .output()
        .expect("the re-exec should start");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the child failed: {stderr}");

    let at = |needle: &str| {
        stderr
            .find(needle)
            .unwrap_or_else(|| panic!("{needle:?} never reached stderr: {stderr}"))
    };
    let record = at(r#"decision="allowed""#);

    assert!(record > at(HELD), "the record escaped the hold: {stderr}");
    assert!(
        record < at(RELEASED),
        "the record outlived the hold: {stderr}"
    );
    assert_eq!(
        stderr.matches(r#"decision="allowed""#).count(),
        1,
        "the record was written more than once: {stderr}"
    );
    assert!(stderr.contains("sandbx::audit"), "{stderr}");
}

/// The other half, run in the re-exec: install, hold, emit, release.
fn held_run() {
    sandbx_cli::logging::init().expect("the first install in a process should succeed");

    let held = sandbx_cli::logging::hold();

    // From a blocking task, not from here: a tool emits on whichever thread
    // `spawn_blocking` gave it, and a subscriber scoped to the asking thread would see
    // nothing at all — which is why `init` is global and this test spends a process on it
    // (`guide-logging.md`).
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime for one blocking task")
        .block_on(async {
            tokio::task::spawn_blocking(|| AuditEvent::allowed("ls", "/srv").emit())
                .await
                .expect("the blocking task should finish");
        });

    eprintln!("{HELD}");
    drop(held);
    eprintln!("{RELEASED}");
}
