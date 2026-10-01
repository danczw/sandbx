//! The spawn seam on `ExecutionContext`.
//!
//! `bash` is the only built-in that spawns, and it used to assemble the policy,
//! helper and timeout by hand. These assert the context does it instead, so a
//! second spawning tool cannot forget one — and so no tool needs to be handed
//! the raw policy in order to spawn at all (#56).
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]

use sandbx_core::SandboxPolicy;
use sandbx_tools::ExecutionContext;

fn context(policy: SandboxPolicy) -> ExecutionContext {
    // The test harness does not dispatch helper mode, so point at a binary that
    // does rather than re-executing this one.
    ExecutionContext::new(policy).with_helper(env!("CARGO_BIN_EXE_sandbx-tools-test-helper"))
}

fn rendered(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The seam carries the policy, so a command built through it is confined
/// without the caller passing the policy in.
#[test]
fn a_command_from_the_seam_is_confined_by_the_policy() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, b"SECRET-CONTENTS").unwrap();

    // dir is deliberately not granted.
    let ctx = context(SandboxPolicy::default().allow_system_executables());
    let output = ctx
        .sandboxed_command("/bin/sh")
        .arg("-c")
        .arg(format!("cat {}", secret.display()))
        .output()
        .unwrap();

    assert!(
        !rendered(&output).contains("SECRET-CONTENTS"),
        "ungranted file leaked through the spawn seam: {}",
        rendered(&output)
    );
}

/// Granted paths stay reachable, or the test above would pass on a seam that
/// simply never works.
#[test]
fn a_command_from_the_seam_still_reaches_a_granted_path() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("visible.txt"), b"VISIBLE").unwrap();

    let ctx = context(
        SandboxPolicy::default()
            .allow_system_executables()
            .allow_read(dir.path()),
    );
    let output = ctx
        .sandboxed_command("/bin/sh")
        .arg("-c")
        .arg(format!("cat {}/visible.txt", dir.path().display()))
        .output()
        .unwrap();

    assert!(
        rendered(&output).contains("VISIBLE"),
        "granted path unreachable: {}",
        rendered(&output)
    );
}

/// And it carries the timeout, which the caller would otherwise have to
/// remember on every spawn.
#[test]
fn a_command_from_the_seam_carries_the_context_timeout() {
    let ctx = context(SandboxPolicy::default().allow_system_executables())
        .with_timeout(std::time::Duration::from_millis(200));

    let started = std::time::Instant::now();
    let error = ctx
        .sandboxed_command("/bin/sh")
        .arg("-c")
        .arg("sleep 30")
        .output()
        .unwrap_err();
    let elapsed = started.elapsed();

    assert!(
        matches!(error, sandbx_core::SandboxError::TimedOut { .. }),
        "expected a timeout, got: {error:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "the call stayed blocked for {elapsed:?}"
    );
}
