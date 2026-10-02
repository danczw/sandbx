//! Public contract of [`SandboxedCommand`].

use sandbx_core::{HELPER_FLAG, SandboxPolicy, SandboxedCommand};

/// Re-running this executable with the dispatch flag is what lets a shipped sandbx
/// need no second binary installed.
#[test]
fn defaults_to_re_executing_the_current_binary() {
    let (helper, argv) = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
        .command_line()
        .unwrap();

    assert_eq!(helper, std::env::current_exe().unwrap());
    assert_eq!(argv.first().map(String::as_str), Some(HELPER_FLAG));
}

/// Without the flag the helper writes nothing and a weakened sandbox goes
/// unrecorded; with it but no pipe, it would write records into whatever fd 0 is.
/// Positional and ahead of the policy: `HelperArgs::decode` refuses a flag it does
/// not recognise, so `exec_sandboxed` splits this one off before decoding.
#[test]
fn asks_the_helper_to_report_on_the_channel() {
    let (_, argv) = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
        .helper("/nonexistent/helper")
        .command_line()
        .unwrap();

    assert_eq!(
        argv.get(1).map(String::as_str),
        Some("--sandbx-audit-stdin"),
        "the audit flag must directly follow the dispatch flag: {argv:?}"
    );
}

/// A grant lost here is a permission the tool silently does not get; one invented
/// is one it should not have had.
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

/// The clearing happens in a process the helper spawns, which knows only what argv
/// told it.
#[test]
fn carries_the_env_allowlist_into_the_command_line() {
    let (_, argv) = SandboxedCommand::new(
        "/bin/true",
        SandboxPolicy::default().allow_env("GIT_AUTHOR_NAME"),
    )
    .helper("/nonexistent/helper")
    .command_line()
    .unwrap();

    assert!(argv.windows(2).any(|w| w == ["--env", "GIT_AUTHOR_NAME"]));
}

/// One calling convention for every helper: two would let a binary implement the
/// wrong one and fail only at runtime.
#[test]
fn explicit_helper_still_takes_the_dispatch_flag() {
    let (helper, argv) = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
        .helper("/some/helper")
        .command_line()
        .unwrap();

    assert_eq!(helper, std::path::Path::new("/some/helper"));
    assert_eq!(argv.first().map(String::as_str), Some(HELPER_FLAG));
}

/// End-to-end through the real helper: the policy is enforced by the kernel, not
/// merely encoded.
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

/// `std::process::Command::output()` reads both pipes to EOF and then waits, so a
/// hung command wedges the caller with no way to reclaim it. The elapsed-time
/// assertion is the real guarantee: the right error, eventually, is still a hang.
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

/// Grandchildren inherit the pipes, so killing only the direct child leaves the
/// reader threads waiting on an EOF that never comes. A pipeline rather than
/// `cmd &`: backgrounding in `sh` redirects the job's stdin from `/dev/null`, which
/// this policy does not grant, so the shell would bail out before forking anything.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn a_backgrounded_grandchild_frees_the_call() {
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

/// The helper supervises the command rather than becoming it, so the status the
/// caller sees is reassembled here; a relay that flattened a crash into an exit code
/// would make a killed tool look like a clean one.
///
/// A real fault rather than `kill -9 $$`: the command is PID 1 of its namespace, and
/// the kernel discards an ordinary signal sent to a namespace's init from inside it.
/// Either encoding is accepted — the relay re-raises the signal, but Rust's runtime
/// installs its own `SIGSEGV` handler to detect stack overflow, so raising that signal
/// at ourselves does not kill us and the `128 + n` form comes out instead.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn a_command_killed_by_a_signal_reports_signalled() {
    use std::os::unix::process::ExitStatusExt;

    let faulting = std::path::Path::new("/usr/bin/python3");
    if !faulting.exists() {
        // Recorded rather than skipped silently: without an interpreter to fault
        // there is nothing on this host to observe.
        eprintln!("no /usr/bin/python3 to fault; signal relay not observed here");
        return;
    }

    let output = SandboxedCommand::new(
        "/usr/bin/python3",
        SandboxPolicy::default().allow_system_executables(),
    )
    .arg("-c")
    .arg("import ctypes; ctypes.string_at(0)")
    .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
    .timeout(std::time::Duration::from_secs(30))
    .output()
    .expect("a crashing command is still a command that ran");

    let signalled = output.status.signal() == Some(libc::SIGSEGV);
    let numbered = output.status.code() == Some(128 + libc::SIGSEGV);

    assert!(
        signalled || numbered,
        "a crash must stay identifiable as SIGSEGV, got: {:?}",
        output.status
    );
}

#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn a_command_exit_code_survives_the_relay() {
    let output = SandboxedCommand::new(
        "/bin/sh",
        SandboxPolicy::default().allow_system_executables(),
    )
    .arg("-c")
    .arg("exit 42")
    .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
    .timeout(std::time::Duration::from_secs(30))
    .output()
    .unwrap();

    assert_eq!(output.status.code(), Some(42));
}

/// Two claims: a descendant inherits the pipe write-ends, so it must not keep the
/// call blocked, and it must not outlive the command — which holds because the
/// command is PID 1 of its own namespace and the kernel tears that down on exit. The
/// canary cannot race: writing it needs the descendant alive two seconds after the
/// command returned. `/dev/null` is granted because `sh` redirects a background job's
/// stdin from it.
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

/// `output()` without a timeout reads both pipes to EOF, and no deadline or kill
/// fires on this path. The namespace is what closes them: the command is PID 1, so
/// everything it left behind goes the moment it exits. Ten seconds rather than a
/// minute, so a regression costs a slow test instead of a hung suite.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn without_a_timeout_a_descendant_does_not_block() {
    let started = std::time::Instant::now();

    let output = SandboxedCommand::new(
        "/bin/sh",
        SandboxPolicy::default()
            .allow_system_executables()
            .allow_read("/dev/null")
            .allow_write("/dev/null"),
    )
    .arg("-c")
    .arg("sleep 10 & echo started")
    .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
    .output()
    .expect("the command itself succeeded, so this must not be an error");

    let elapsed = started.elapsed();

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "started");
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "a descendant held the untimed call open for {elapsed:?}"
    );
}

/// A process group is advisory — one `setsid` leaves it — so the timeout's group
/// kill cannot promise the escapee is gone. A PID namespace is not: nothing leaves
/// the one it was born into, `unshare` and `setns` are denied, and killing PID 1
/// makes the kernel SIGKILL whatever is left inside. The escapee also keeps holding
/// the pipe (no stdout redirect), so the call returning at all is asserted alongside.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn a_descendant_that_leaves_the_group_is_still_killed() {
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

/// Only the non-helper paths are exercised in-process: passing `HELPER_FLAG` here
/// would restrict this test process and `exec`, so the enforcement suite covers
/// that path with a real helper.
#[test]
fn an_ordinary_invocation_is_not_helper_mode() {
    let argv = ["sandbx", "sandbox-run", "--", "/bin/true"].map(std::ffi::OsString::from);

    assert!(matches!(
        sandbx_core::dispatch_helper_mode(argv),
        sandbx_core::HelperDispatch::NotHelperMode
    ));
}

#[test]
fn an_argv_with_no_arguments_is_not_helper_mode() {
    for argv in [vec![], vec![std::ffi::OsString::from("sandbx")]] {
        assert!(
            matches!(
                sandbx_core::dispatch_helper_mode(argv),
                sandbx_core::HelperDispatch::NotHelperMode
            ),
            "a too-short argv must be reported as an ordinary run"
        );
    }
}
