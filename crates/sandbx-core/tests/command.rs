//! Public contract of [`SandboxedCommand`].

use sandbx_core::{HELPER_FLAG, SandboxPolicy, SandboxedCommand};

/// Without an explicit helper, the command re-runs this executable with the
/// dispatch flag — so a shipped sandbx needs no second binary installed.
#[test]
fn defaults_to_re_executing_the_current_binary() {
    let (helper, argv) = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
        .command_line()
        .unwrap();

    assert_eq!(helper, std::env::current_exe().unwrap());
    assert_eq!(argv.first().map(String::as_str), Some(HELPER_FLAG));
}

/// The policy must reach the helper intact: a grant lost here is a permission
/// the tool silently does not get, and one invented here is one it should not
/// have had.
#[test]
fn carries_the_policy_into_the_command_line() {
    let (_, argv) = SandboxedCommand::new("/bin/sh", SandboxPolicy::default().allow_read("/usr"))
        .arg("-c")
        .arg("true")
        .helper("/nonexistent/helper")
        .command_line()
        .unwrap();

    assert!(argv.windows(2).any(|w| w == ["--ro", "/usr"]));
    assert_eq!(&argv[argv.len() - 3..], &["/bin/sh", "-c", "true"]);
}

/// Every helper is invoked the same way, explicit or not. Two calling
/// conventions meant a binary could implement the wrong one and fail only at
/// runtime.
#[test]
fn explicit_helper_still_takes_the_dispatch_flag() {
    let (helper, argv) = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
        .helper("/some/helper")
        .command_line()
        .unwrap();

    assert_eq!(helper, std::path::Path::new("/some/helper"));
    assert_eq!(argv.first().map(String::as_str), Some(HELPER_FLAG));
}

/// End-to-end through the real helper: the policy is enforced by the kernel,
/// not merely encoded.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn runs_a_command_under_the_policy() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("readable.txt");
    std::fs::write(&file, b"visible").unwrap();

    let policy = SandboxPolicy::default()
        .allow_system_executables()
        .allow_read(dir.path());

    let output = SandboxedCommand::new("/bin/cat", policy)
        .arg(file.to_str().unwrap())
        .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "visible");
}

/// A path the policy never granted stays unreadable through this API too.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn refuses_a_path_the_policy_omits() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    let policy = SandboxPolicy::default()
        .allow_read("/usr")
        .allow_read("/bin")
        .allow_read("/lib")
        .allow_read("/lib64");

    let output = SandboxedCommand::new("/bin/cat", policy)
        .arg(secret.to_str().unwrap())
        .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret"));
}

/// The point of #22: a command that never finishes must not block the caller
/// forever. `std::process::Command::output()` reads both pipes to EOF and then
/// waits, so a hung command wedges the harness with no way to reclaim it.
///
/// The elapsed-time assertion is the real guarantee — returning the right error
/// eventually would be no better than hanging.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn a_command_that_outruns_its_timeout_is_killed() {
    let started = std::time::Instant::now();

    let result = SandboxedCommand::new(
        "/bin/sh",
        SandboxPolicy::default().allow_system_executables(),
    )
    .arg("-c")
    .arg("sleep 30")
    .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
    .timeout(std::time::Duration::from_millis(200))
    .output();

    let elapsed = started.elapsed();

    assert!(
        matches!(result, Err(sandbx_core::SandboxError::TimedOut { .. })),
        "expected a timeout, got: {result:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "returned an error but only after {elapsed:?} — the caller was still blocked"
    );
}

/// Grandchildren inherit the pipes. Killing only the direct child would leave
/// them open, so the reader threads would never see EOF and the call would hang
/// anyway — the bug this is meant to fix, one level down.
///
/// A pipeline rather than `cmd &`: backgrounding in `sh` redirects the job's
/// stdin from `/dev/null`, which the policy does not grant, so the shell would
/// bail out before forking anything.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn a_backgrounded_grandchild_does_not_hold_the_call_open() {
    let started = std::time::Instant::now();

    let result = SandboxedCommand::new(
        "/bin/sh",
        SandboxPolicy::default().allow_system_executables(),
    )
    .arg("-c")
    .arg("sleep 30 | cat")
    .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
    .timeout(std::time::Duration::from_millis(200))
    .output();

    let elapsed = started.elapsed();

    assert!(
        matches!(result, Err(sandbx_core::SandboxError::TimedOut { .. })),
        "expected a timeout, got: {result:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "a backgrounded grandchild kept the call blocked for {elapsed:?}"
    );
}

#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn a_command_within_its_timeout_still_succeeds() {
    let output = SandboxedCommand::new(
        "/bin/echo",
        SandboxPolicy::default().allow_system_executables(),
    )
    .arg("done")
    .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
    .timeout(std::time::Duration::from_secs(30))
    .output()
    .expect("a fast command must not time out");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "done");
}

#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn without_a_timeout_a_command_runs_to_completion() {
    let output = SandboxedCommand::new(
        "/bin/echo",
        SandboxPolicy::default().allow_system_executables(),
    )
    .arg("done")
    .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
    .output()
    .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "done");
}

/// A descendant the command backgrounded dies with it (#28).
///
/// Two things are being pinned here. The call must not block — a descendant
/// inherits the pipe write-ends, so before the deadline was bounded the readers
/// never saw EOF and a command that exited well inside its limit could still
/// wedge the caller. And the descendant must not survive: the command is PID 1
/// of its own namespace, so the kernel tears the namespace down when it exits.
///
/// The canary is what proves the second part, and it cannot race. Writing it
/// requires the descendant to still be alive two seconds after the command
/// returned, so the file existing can only mean it survived; there is no way for
/// the assertion to fail against a sandbox that did reap it.
///
/// Granting `/dev/null` because `sh` redirects a background job's stdin from it.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn a_backgrounded_descendant_dies_with_the_command() {
    let dir = tempfile::tempdir().unwrap();
    let canary = dir.path().join("canary");
    let started = std::time::Instant::now();

    let output = SandboxedCommand::new(
        "/bin/sh",
        SandboxPolicy::default()
            .allow_system_executables()
            .allow_read("/dev/null")
            .allow_write("/dev/null")
            .allow_write(dir.path()),
    )
    .arg("-c")
    // Braces matter: without them `&` would background only the `echo`, and the
    // command itself would do the sleeping and the writing — the canary would
    // then prove nothing about a descendant.
    .arg(format!(
        "{{ sleep 2; echo alive > {}; }} & echo started",
        canary.display()
    ))
    .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
    .timeout(std::time::Duration::from_secs(30))
    .output()
    .expect("the command itself succeeded, so this must not be an error");

    let elapsed = started.elapsed();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "started");
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "a descendant held the call open for {elapsed:?}"
    );

    std::thread::sleep(std::time::Duration::from_secs(4));
    assert!(
        !canary.exists(),
        "a backgrounded descendant outlived the command and kept running"
    );
}

/// A descendant that escaped the process group dies anyway (#28).
///
/// This is the bug itself. A process group is advisory — one `setsid` call leaves
/// it — so the timeout's group kill could never promise the escapee was gone, and
/// the shipped binary left a `sleep` running in its own session after the call
/// returned. A PID namespace is not advisory: nothing can leave the one it was
/// born into, `unshare` and `setns` are denied, and killing PID 1 makes the kernel
/// SIGKILL whatever is left inside.
///
/// The `setsid` is the whole point of the test, so it must stay. The canary proves
/// death without racing: only a survivor can write it. The escapee also keeps
/// holding the pipe (no stdout redirect), so the older guarantee — that the call
/// returns regardless, which bounding the drain wait is what makes true — is still
/// asserted alongside.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn a_descendant_that_escapes_the_process_group_is_killed_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let canary = dir.path().join("canary");
    let started = std::time::Instant::now();

    let result = SandboxedCommand::new(
        "/bin/sh",
        SandboxPolicy::default()
            .allow_system_executables()
            .allow_read("/dev/null")
            .allow_write("/dev/null")
            .allow_write(dir.path()),
    )
    .arg("-c")
    .arg(format!(
        "setsid sh -c 'sleep 2; echo alive > {}' & sleep 30",
        canary.display()
    ))
    .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
    .timeout(std::time::Duration::from_millis(200))
    .output();

    let elapsed = started.elapsed();

    assert!(
        matches!(result, Err(sandbx_core::SandboxError::TimedOut { .. })),
        "expected a timeout, got: {result:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "a setsid escapee held the call open for {elapsed:?}"
    );

    std::thread::sleep(std::time::Duration::from_secs(4));
    assert!(
        !canary.exists(),
        "a setsid descendant escaped the kill and outlived the tool call"
    );
}
