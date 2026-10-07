//! Public contract of [`SandboxedCommand`].

use sandbx_core::{HELPER_FLAG, SandboxPolicy, SandboxedCommand};

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

/// What lets a shipped sandbx need no second binary installed.
#[test]
fn defaults_to_re_executing_this_image_by_inode() {
    let (helper, argv) = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
        .command_line()
        .unwrap();

    assert_eq!(helper, std::path::Path::new("/proc/self/exe"));
    assert_eq!(argv.first().map(String::as_str), Some(HELPER_FLAG));

    let image = std::fs::metadata(&helper).expect("/proc must be mounted for the re-exec");

    assert!(
        image.is_file(),
        "the default helper path does not resolve to the running image"
    );
}

/// Positional and ahead of the policy: `HelperArgs::decode` refuses a flag it does not
/// recognise, so `exec_sandboxed` splits this one off before decoding.
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

/// A grant lost here is a permission the tool silently does not get; one invented is one
/// it should not have had.
#[test]
fn carries_the_policy_into_the_command_line() {
    let (_, argv) = SandboxedCommand::new(
        "/bin/sh",
        SandboxPolicy::default().allow_read(vetted("/usr")),
    )
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

/// The obligation `command_line` documents: the start directory is not in the argv, so a
/// caller that spawns this itself gets its own working directory and not the policy's.
#[test]
fn the_start_directory_is_not_in_the_command_line() {
    let dir = scratch();
    let root = dir.path().to_str().unwrap().to_string();

    let policy = SandboxPolicy::default().allow_write(vetted(dir.path()));
    let (_, argv) = SandboxedCommand::new("/bin/true", policy.clone())
        .helper("/nonexistent/helper")
        .command_line()
        .unwrap();

    assert_eq!(
        policy.working_root(),
        Some(dir.path()),
        "the policy this asserts about does not name a start directory"
    );
    assert_eq!(
        argv.iter().filter(|arg| **arg == root).count(),
        1,
        "the start directory crossed in the argv as well: {argv:?}"
    );
}

/// End-to-end through the real helper: the policy is enforced, not merely encoded.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
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
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
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

#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
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
        !stderr.contains("sandbx-helper:"),
        "setup failed, so the denial was never tested: {stderr}"
    );

    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret"));
}

/// `std::process::Command::output()` reads both pipes to EOF and then waits, so a hung
/// command wedges the caller. The elapsed time is the guarantee: the right error,
/// eventually, is still a hang.
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

/// Grandchildren inherit the pipes, so killing only the direct child leaves the reader
/// threads waiting on an EOF that never comes. A pipeline rather than `cmd &`:
/// backgrounding in `sh` redirects the job's stdin from `/dev/null`, which this policy
/// does not grant, so the shell would bail out before forking anything.
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

/// The helper supervises the command rather than becoming it, so the status the caller
/// sees is reassembled here.
///
/// A real fault rather than `kill -9 $$`: the command is PID 1 of its namespace, and the
/// kernel discards an ordinary signal sent to a namespace's init from inside it. Either
/// encoding is accepted — the relay re-raises the signal, but Rust's runtime installs its
/// own `SIGSEGV` handler to detect stack overflow, so raising that signal at ourselves
/// does not kill us and the `128 + n` form comes out instead.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
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

/// Two claims: a descendant inherits the pipe write-ends, so it must not keep the call
/// blocked, and it must not outlive the command — which holds because the command is PID 1
/// of its own namespace and the kernel tears that down on exit. The canary cannot race:
/// writing it needs the descendant alive two seconds after the command returned.
/// `/dev/null` is granted because `sh` redirects a background job's stdin from it.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
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
/// this path. The namespace is what closes them: the command is PID 1, so everything it
/// left behind goes the moment it exits. Ten seconds rather than a minute, so a
/// regression costs a slow test instead of a hung suite.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
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
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
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

/// Only the non-helper paths are exercised in-process: passing `HELPER_FLAG` here would
/// restrict this test process and `exec`.
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

/// `command_line` and not `output`: this argv is the one an embedder may spawn itself.
#[test]
fn a_policy_that_bounds_no_name_cannot_be_turned_into_an_argv() {
    let policy = SandboxPolicy::default()
        .allow_dns("example.com")
        .allow_unix_sockets();

    let refusal = SandboxedCommand::new("/bin/true", policy)
        .command_line()
        .expect_err("an argv was built for a policy whose allowlist bounds nothing");

    assert_eq!(refusal.label(), "unbounded_resolution", "got {refusal:?}");
}

/// At this level and not the CLI's: an embedder spawning the argv itself would otherwise reach
/// the helper, where the pin is measured against the copy sandbx bound and the run refuses as
/// a substituted object — a false `GrantReplaced` on a legitimate pair.
#[test]
fn a_policy_granting_a_file_its_own_resolver_replaces_cannot_be_turned_into_an_argv() {
    let policy = SandboxPolicy::default()
        .allow_dns("example.com")
        .allow_network_port(443)
        .allow_read(vetted("/etc/hosts"));

    let refusal = SandboxedCommand::new("/bin/true", policy)
        .command_line()
        .expect_err("an argv was built for a grant the run's own resolver binds over");

    assert_eq!(
        refusal.label(),
        "grant_bound_by_resolver",
        "got {refusal:?}"
    );

    // The remedy and not only the refusal: `--allow-dns` beside a grant on the directory is
    // legal, so a message naming no way forward leaves a library caller to find it by reading
    // the source. The CLI's `DnsGrantsBoundFile` says the same thing at the flag.
    let message = refusal.to_string();
    assert!(
        message.contains("/etc/hosts") && message.contains("directory"),
        "the refusal names no path to go and look at, or no way forward: {message}"
    );
}
