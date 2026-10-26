//! Does a real helper run enforce the policy [`SandboxedCommand`] encoded?
//!
//! The end-to-end half of `sandbx-core`'s `command.rs`: every test here spawns the helper
//! binary, so it lives beside it where `CARGO_BIN_EXE_sandbx-helper` resolves (#328
//! decision 5). The encode-and-parse half, which needs no binary, stayed in `sandbx-core`.
//!
//! One file-level gate rather than one per test, as every other gated file here has: with
//! per-test gates the imports and the two fixtures below are unused when the feature is
//! off, which `-D warnings` refuses.
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]

use sandbx_core::{SandboxPolicy, SandboxedCommand};

/// `path`, pinned to the object it names — the shape every grant takes (#212).
fn vetted(path: impl AsRef<std::path::Path>) -> sandbx_core::VettedPath {
    sandbx_core::VettedPath::vet(path).expect("an existing path to pin the grant to")
}

/// A scratch directory whose own path is already resolved, so granting it grants a path that
/// opens as itself — which the helper requires. `$TMPDIR` is a symlink on some hosts.
fn scratch() -> tempfile::TempDir {
    let root = std::env::temp_dir()
        .canonicalize()
        .expect("the temporary directory exists");
    tempfile::Builder::new()
        .tempdir_in(root)
        .expect("a temporary directory")
}

/// End-to-end through the real helper: the policy is enforced, not merely encoded.
#[test]
fn runs_a_command_under_the_policy() {
    let dir = scratch();
    let file = dir.path().join("readable.txt");
    std::fs::write(&file, b"visible").unwrap();

    let policy = SandboxPolicy::default()
        .allow_system_executables()
        .allow_read(vetted(dir.path()));

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

/// #191 end-to-end, and through [`SandboxedCommand::output`] because that is the only thing
/// that applies the start directory — `tests/support` builds the helper argv itself.
#[test]
fn starts_the_command_in_a_granted_root() {
    let dir = scratch();
    let root = dir.path().canonicalize().unwrap();

    let policy = SandboxPolicy::default()
        .allow_system_executables()
        .allow_read(vetted(&root))
        .allow_write(vetted(&root));

    let output = SandboxedCommand::new("/bin/pwd", policy)
        .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        root.to_str().unwrap(),
        "the command started somewhere other than the root it was granted"
    );
}

#[test]
fn refuses_a_path_the_policy_omits() {
    let dir = scratch();
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    let policy = SandboxPolicy::default().allow_system_executables();

    let output = SandboxedCommand::new("/bin/cat", policy)
        .arg(secret.to_str().unwrap())
        .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
        .output()
        .unwrap();

    // A helper that never execed satisfies both assertions below, so this would pass
    // without the kernel having been asked.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("sandbox helper failed") && !stderr.contains("sandbx-helper:"),
        "setup failed, so the denial was never tested: {stderr}"
    );

    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret"));
}

/// `std::process::Command::output()` reads both pipes to EOF and then waits, so a hung
/// command wedges the caller. The elapsed time is the guarantee: the right error,
/// eventually, is still a hang.
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

/// Grandchildren inherit the pipes, so killing only the direct child leaves the reader
/// threads waiting on an EOF that never comes. A pipeline rather than `cmd &`:
/// backgrounding in `sh` redirects the job's stdin from `/dev/null`, which this policy
/// does not grant, so the shell would bail out before forking anything.
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

/// The helper supervises the command rather than becoming it, so the status the caller
/// sees is reassembled here. Either encoding is accepted; what comes out is `128 + n`,
/// because the namespace's init cannot die by a signal it raises at itself.
#[test]
fn a_command_killed_by_a_signal_reports_signalled() {
    use std::os::unix::process::ExitStatusExt;

    let faulting = std::path::Path::new("/usr/bin/python3");
    if !faulting.exists() {
        // Skipped, not failed: without an interpreter to fault there is nothing on this
        // host to observe.
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

/// Two claims: a descendant inherits the pipe write-ends, so it must not keep the call
/// blocked, and it must not outlive the command — which holds because the init exits with
/// the command and the kernel tears the namespace down when it does. The canary cannot race:
/// writing it needs the descendant alive two seconds after the command returned.
/// `/dev/null` is granted because `sh` redirects a background job's stdin from it.
#[test]
fn a_backgrounded_descendant_dies_with_the_command() {
    let dir = scratch();
    let canary = dir.path().join("canary");
    let started = std::time::Instant::now();

    let output = SandboxedCommand::new(
        "/bin/sh",
        SandboxPolicy::default()
            .allow_system_executables()
            .allow_read(vetted("/dev/null"))
            .allow_write(vetted("/dev/null"))
            .allow_write(vetted(dir.path())),
    )
    .arg("-c")
    // Braces matter: without them `&` backgrounds only the `echo`, and the command
    // itself does the sleeping and the writing.
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

/// `output()` without a timeout reads both pipes to EOF, and no deadline or kill fires on
/// this path. The namespace is what closes them: the init exits with the command, so
/// everything it left behind goes the moment it does. Ten seconds rather than a minute, so a
/// regression costs a slow test instead of a hung suite.
#[test]
fn without_a_timeout_a_descendant_does_not_block() {
    let started = std::time::Instant::now();

    let output = SandboxedCommand::new(
        "/bin/sh",
        SandboxPolicy::default()
            .allow_system_executables()
            .allow_read(vetted("/dev/null"))
            .allow_write(vetted("/dev/null")),
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

/// A process group is advisory — one `setsid` leaves it — so the timeout's group kill
/// cannot promise the escapee is gone. A PID namespace is not: nothing leaves the one it
/// was born into, `unshare` and `setns` are denied, and killing PID 1 makes the kernel
/// SIGKILL whatever is left inside. The escapee also keeps holding the pipe (no stdout
/// redirect), so the call returning at all is asserted alongside.
#[test]
fn a_descendant_that_leaves_the_group_is_still_killed() {
    let dir = scratch();
    let canary = dir.path().join("canary");
    let started = std::time::Instant::now();

    let result = SandboxedCommand::new(
        "/bin/sh",
        SandboxPolicy::default()
            .allow_system_executables()
            .allow_read(vetted("/dev/null"))
            .allow_write(vetted("/dev/null"))
            .allow_write(vetted(dir.path())),
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

/// An `exec` from a second thread sheds the parent death signal; the init still dies, timed.
#[test]
fn a_command_that_sheds_its_lifetime_still_dies() {
    let probe = env!("CARGO_BIN_EXE_sandbx-orphan-probe");
    let dir = scratch();
    let (report, canary) = (dir.path().join("report"), dir.path().join("canary"));
    let parent = std::path::Path::new(probe).parent();

    let result = SandboxedCommand::new(
        probe,
        SandboxPolicy::default()
            .allow_system_executables()
            .allow_read_execute(vetted(parent.expect("the probe has a directory")))
            .allow_write(vetted(dir.path())),
    )
    .arg(report.display().to_string())
    .arg(canary.display().to_string())
    .helper(env!("CARGO_BIN_EXE_sandbx-helper"))
    .timeout(std::time::Duration::from_secs(2))
    .output();

    assert!(
        matches!(result, Err(sandbx_core::SandboxError::TimedOut { .. })),
        "expected a timeout, got: {result:?}"
    );

    std::thread::sleep(std::time::Duration::from_secs(5));
    assert!(
        !canary.exists(),
        "a command that left the group and execed from a thread outlived the call"
    );

    // The re-exec'd image reporting is what tells a kill apart from a probe that never ran.
    let started = std::fs::read_to_string(&report).expect("the probe re-exec'd and reported");
    assert!(started.starts_with("STARTED"), "got: {started}");
}

/// Untimed, so no group kill fires: the init's parent death signal is the only path.
#[test]
fn a_killed_supervisor_takes_an_untimed_command_with_it() {
    let probe = env!("CARGO_BIN_EXE_sandbx-orphan-probe");
    let dir = scratch();
    let (report, canary) = (dir.path().join("report"), dir.path().join("canary"));
    let parent = std::path::Path::new(probe).parent();

    let policy = SandboxPolicy::default()
        .allow_system_executables()
        .allow_read_execute(vetted(parent.expect("the probe has a directory")))
        .allow_write(vetted(dir.path()));
    let command = SandboxedCommand::new(probe, policy)
        .arg(report.display().to_string())
        .arg(canary.display().to_string())
        .helper(env!("CARGO_BIN_EXE_sandbx-helper"));
    let call = std::thread::spawn(move || command.output());

    // The probe's report is what says the command is past its `exec` from a thread.
    let started = std::time::Instant::now();
    while !report.exists() && started.elapsed() < std::time::Duration::from_secs(10) {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(report.exists(), "the probe never reported");

    let marker = canary.display().to_string();
    let supervisor = std::fs::read_dir("/proc")
        .expect("/proc is mounted")
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .find(|pid| {
            let argv = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            let argv: Vec<_> = argv.split(|byte| *byte == 0).collect();
            argv.get(1) == Some(&sandbx_core::HELPER_FLAG.as_bytes())
                && argv.contains(&marker.as_bytes())
        })
        .expect("the supervisor is running");

    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(supervisor),
        nix::sys::signal::Signal::SIGKILL,
    )
    .expect("the supervisor can be killed");

    let _ = call
        .join()
        .expect("the call returns once the supervisor is gone");

    std::thread::sleep(std::time::Duration::from_secs(5));
    assert!(
        !canary.exists(),
        "a command that shed its own lifetime outlived a killed supervisor"
    );
}
