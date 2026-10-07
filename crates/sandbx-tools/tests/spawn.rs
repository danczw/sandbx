//! The spawn seam on `ExecutionContext`.
//!
//! `bash` is the only built-in that spawns. These assert the context assembles the
//! policy, helper and timeout, so a second spawning tool cannot forget one — and no
//! tool needs the raw policy in order to spawn at all.
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]

use sandbx_core::SandboxPolicy;
use sandbx_tools::ExecutionContext;

fn context(policy: SandboxPolicy) -> ExecutionContext {
    // The test harness does not dispatch helper mode; point at a binary that does.
    ExecutionContext::new(policy).with_helper(env!("CARGO_BIN_EXE_sandbx-tools-test-helper"))
}

fn rendered(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_command_from_the_seam_is_confined_by_the_policy() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, b"SECRET-CONTENTS").unwrap();

    // dir is not granted.
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

/// Without this, the test above would pass on a seam that never works at all.
#[test]
fn a_command_from_the_seam_reaches_a_granted_path() {
    let dir = tempfile::tempdir().unwrap();
    // Resolved: the helper refuses a grant that opens as something else, and `$TMPDIR` is a
    // symlink on some hosts.
    let root = dir.path().canonicalize().unwrap();
    std::fs::write(root.join("visible.txt"), b"VISIBLE").unwrap();

    let ctx = context(
        SandboxPolicy::default()
            .allow_system_executables()
            .allow_read(&root),
    );
    let output = ctx
        .sandboxed_command("/bin/sh")
        .arg("-c")
        .arg(format!("cat {}/visible.txt", root.display()))
        .output()
        .unwrap();

    assert!(
        rendered(&output).contains("VISIBLE"),
        "granted path unreachable: {}",
        rendered(&output)
    );
}

#[test]
fn the_seam_carries_the_context_timeout() {
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
