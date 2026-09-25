//! Does the kernel actually block an escape?
//!
//! Everything else in this crate tests our own logic. These tests spawn real
//! processes and assert the *kernel* refuses them, which is the only evidence
//! that the sandbox does anything at all.
//!
//! Gated behind `--features sandbox-integration` because they need a Linux
//! kernel with Landlock available (5.13+, enabled at boot).
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]
// Both `Command::new` uses below spawn the sandbox helper itself — never a
// command that bypasses it. The workspace ban exists to stop code executing
// *around* the sandbox; launching the sandbox is the subject of these tests.
#![allow(clippy::disallowed_methods)]

use std::path::Path;
use std::process::Command;

use sandbx_core::{HelperArgs, SandboxPolicy};

/// Paths the helper itself needs in order to `exec` anything at all.
///
/// `exec` happens *after* the restrictions are applied, so the interpreter and
/// shared libraries must stay reachable or nothing can start — including the
/// commands these tests use to probe the sandbox.
///
/// The program directories need read *and* execute; `ld.so.cache` is a plain
/// file the loader only reads, so it gets the narrower grant.
fn runtime_paths(policy: SandboxPolicy) -> SandboxPolicy {
    let policy = ["/usr", "/bin", "/lib", "/lib64"]
        .iter()
        .filter(|p| Path::new(p).exists())
        .fold(policy, |acc, p| acc.allow_read_execute(p));

    ["/etc/ld.so.cache"]
        .iter()
        .filter(|p| Path::new(p).exists())
        .fold(policy, |acc, p| acc.allow_read(p))
}

/// Grant execute access to a probe binary so it can be `exec`ed.
///
/// Probes live under `target/`, which `runtime_paths` does not cover. Without
/// this the probe fails to start, and a denial test would pass because nothing
/// ran — not because the kernel refused anything.
fn allow_probe(policy: SandboxPolicy, probe: &str) -> SandboxPolicy {
    let dir = std::path::Path::new(probe)
        .parent()
        .expect("probe path has a parent");
    policy.allow_read_execute(dir)
}

fn run(policy: &SandboxPolicy, program: &str, args: &[&str]) -> std::process::Output {
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    Command::new(env!("CARGO_BIN_EXE_sandbx-helper"))
        .arg(sandbx_core::HELPER_FLAG)
        .args(HelperArgs::encode(policy, program, &owned))
        .output()
        .expect("helper should start")
}

/// Baseline: with the path allowed, the command works. Without this the denial
/// tests below would pass even if the sandbox broke everything indiscriminately.
#[test]
fn allowed_path_can_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("readable.txt");
    std::fs::write(&file, b"visible").unwrap();

    let policy = runtime_paths(SandboxPolicy::default()).allow_read(dir.path());
    let output = run(&policy, "/bin/cat", &[file.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "reading an allowed path failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "visible");
}

/// The point of the whole crate: a path the policy never granted is unreadable,
/// enforced by the kernel rather than by our own checks.
#[test]
fn unallowed_path_cannot_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    // Note the temp dir is deliberately NOT granted.
    let policy = runtime_paths(SandboxPolicy::default());
    let output = run(&policy, "/bin/cat", &[secret.to_str().unwrap()]);

    assert!(
        !output.status.success(),
        "kernel allowed a read the policy never granted"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("secret"),
        "secret contents leaked through the sandbox"
    );
}

/// Read access must not carry write access, at the kernel level and not merely
/// in `FsGuard`.
#[test]
fn read_only_grant_cannot_write() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("readonly.txt");
    std::fs::write(&file, b"original").unwrap();

    let policy = runtime_paths(SandboxPolicy::default()).allow_read(dir.path());
    let output = run(
        &policy,
        "/bin/sh",
        &["-c", &format!("echo overwritten > {}", file.display())],
    );

    assert!(!output.status.success(), "wrote to a read-only grant");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "original",
        "file was modified despite a read-only grant"
    );
}

#[test]
fn write_grant_can_write() {
    let dir = tempfile::tempdir().unwrap();

    let policy = runtime_paths(SandboxPolicy::default()).allow_write(dir.path());
    let created = dir.path().join("created.txt");
    let output = run(
        &policy,
        "/bin/sh",
        &["-c", &format!("echo written > {}", created.display())],
    );

    assert!(
        output.status.success(),
        "writing to an allowed path failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(&created).unwrap(), "written\n");
}

/// A helper that cannot enforce must not run the command anyway.
#[test]
fn malformed_arguments_do_not_run_the_command() {
    let marker = tempfile::tempdir().unwrap().path().join("should-not-exist");

    let output = Command::new(env!("CARGO_BIN_EXE_sandbx-helper"))
        .args([
            sandbx_core::HELPER_FLAG,
            "--not-a-flag",
            "--",
            "/bin/touch",
            marker.to_str().unwrap(),
        ])
        .output()
        .expect("helper should start");

    assert!(!output.status.success());
    assert!(
        !marker.exists(),
        "helper ran the command despite refusing its arguments"
    );
}

/// Network denial comes from an empty network namespace, not from Landlock.
///
/// A fresh netns has only the loopback interface, so reading the caller's own
/// interface list is a hermetic check — no external network required.
#[test]
fn network_is_denied_by_default() {
    let policy = runtime_paths(SandboxPolicy::default()).allow_read("/proc");
    let output = run(&policy, "/bin/cat", &["/proc/self/net/dev"]);

    assert!(
        output.status.success(),
        "could not read the interface list: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let interfaces = String::from_utf8_lossy(&output.stdout);
    let named: Vec<&str> = interfaces
        .lines()
        .skip(2) // two header lines
        .filter_map(|l| l.split(':').next())
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect();

    assert_eq!(
        named,
        vec!["lo"],
        "a sandbox denying network must see only loopback, found: {named:?}"
    );
}

/// The opposite direction: granting network must actually grant it, or the flag
/// is decorative.
#[test]
fn allowed_network_keeps_host_interfaces() {
    let policy = runtime_paths(SandboxPolicy::default())
        .allow_read("/proc")
        .allow_network();
    let output = run(&policy, "/bin/cat", &["/proc/self/net/dev"]);

    assert!(output.status.success());
    let interfaces = String::from_utf8_lossy(&output.stdout);
    assert!(
        interfaces.lines().skip(2).count() > 1,
        "granting network should leave the host interfaces visible, got: {interfaces}"
    );
}

/// A seccomp filter must actually be installed, not merely constructed.
///
/// `/proc/self/status` reports `Seccomp: 2` once a BPF filter is in force, so
/// the sandboxed process can confirm its own state without needing a tool that
/// attempts a blocked syscall.
#[test]
fn seccomp_filter_is_installed() {
    let policy = runtime_paths(SandboxPolicy::default()).allow_read("/proc");
    let output = run(&policy, "/bin/cat", &["/proc/self/status"]);

    assert!(
        output.status.success(),
        "could not read process status: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let status = String::from_utf8_lossy(&output.stdout);
    let mode = status
        .lines()
        .find_map(|l| l.strip_prefix("Seccomp:"))
        .map(str::trim);

    assert_eq!(
        mode,
        Some("2"),
        "expected seccomp filter mode (2); process reported {mode:?}"
    );
}

/// Truncation is a write. Landlock leaves *unhandled* access types unrestricted
/// everywhere, so a ruleset that never handles `Truncate` permits zeroing any
/// file on the machine — including one granted read-only.
///
/// Uses a dedicated probe: `: > file` and `truncate(1)` both go through
/// `open(O_TRUNC)`/`ftruncate`, which `WriteFile` already covers. Only
/// `truncate(2)` on a path exercises the right under test.
#[test]
fn truncate_on_read_only_grant_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim.txt");
    std::fs::write(&victim, b"original contents").unwrap();

    let probe = env!("CARGO_BIN_EXE_sandbx-truncate-probe");
    let policy = allow_probe(
        runtime_paths(SandboxPolicy::default()).allow_read(dir.path()),
        probe,
    );
    let output = run(&policy, probe, &[victim.to_str().unwrap()]);

    assert!(!output.status.success(), "truncated a read-only grant");
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "original contents",
        "file was truncated despite a read-only grant"
    );
}

/// The same with no grant of any kind — the reviewer's demonstrated escape.
#[test]
fn truncate_on_ungranted_path_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim.txt");
    std::fs::write(&victim, b"original contents").unwrap();

    // dir is deliberately NOT granted.
    let probe = env!("CARGO_BIN_EXE_sandbx-truncate-probe");
    let policy = allow_probe(runtime_paths(SandboxPolicy::default()), probe);
    let output = run(&policy, probe, &[victim.to_str().unwrap()]);

    assert!(!output.status.success(), "truncated an ungranted path");
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "original contents",
        "ungranted file was truncated"
    );
}

/// Truncating a path the policy grants for writing must still work.
#[test]
fn truncate_on_write_grant_is_permitted() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("scratch.txt");
    std::fs::write(&target, b"original contents").unwrap();

    let probe = env!("CARGO_BIN_EXE_sandbx-truncate-probe");
    let policy = allow_probe(
        runtime_paths(SandboxPolicy::default()).allow_write(dir.path()),
        probe,
    );
    let output = run(&policy, probe, &[target.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "truncate was refused on a writable grant: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "");
}

/// A network namespace isolates only *abstract* unix sockets. Pathname sockets
/// live in the filesystem and cross it freely, so denying network is not enough
/// on its own — without a further control a command can still dial host daemons
/// (systemd's bus, docker.sock, an ssh-agent) and have them act outside the cage.
#[test]
fn unix_socket_connect_to_ungranted_path_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("host.sock");

    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let accepting = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            use std::io::Write;
            let _ = stream.write_all(b"HOST-SIDE-SECRET");
        }
    });

    // The socket's directory is deliberately NOT granted, and network is denied.
    let probe = env!("CARGO_BIN_EXE_sandbx-unix-probe");
    let policy = allow_probe(runtime_paths(SandboxPolicy::default()), probe);
    let output = run(&policy, probe, &[socket.to_str().unwrap()]);

    // Unblock the accept thread whether or not the connect got through.
    let _ = std::os::unix::net::UnixStream::connect(&socket);
    let _ = accepting.join();

    assert!(
        !output.status.success(),
        "connected to a unix socket outside every grant with network denied"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("HOST-SIDE-SECRET"),
        "data crossed the sandbox boundary over a unix socket"
    );
}

/// A symlinked policy root grants its resolved target, and both enforcement
/// layers must agree on that.
///
/// `FsGuard` canonicalizes its roots; the helper must too, or the same policy
/// means different things in-process and in the kernel. Resolving rather than
/// rejecting is deliberate: `/bin`, `/lib` and `/lib64` are symlinks on ordinary
/// systems, so refusing symlinked roots would refuse every realistic policy.
#[test]
fn symlinked_policy_root_resolves_consistently() {
    let real = tempfile::tempdir().unwrap();
    let staging = tempfile::tempdir().unwrap();
    std::fs::write(real.path().join("s.txt"), b"target-side").unwrap();

    let link = staging.path().join("granted");
    std::os::unix::fs::symlink(real.path(), &link).unwrap();

    let policy = runtime_paths(SandboxPolicy::default()).allow_read(&link);

    // Reachable through the link — the path actually granted.
    let via_link = run(&policy, "/bin/cat", &[link.join("s.txt").to_str().unwrap()]);
    assert!(via_link.status.success());

    // The in-process guard must reach the same verdict for the resolved path,
    // rather than denying what the kernel permits.
    let guard = sandbx_core::FsGuard::new(&policy).unwrap();
    assert!(
        guard.check_read(&real.path().join("s.txt")).is_ok(),
        "FsGuard denies a path the kernel layer permits: the two layers disagree"
    );
}

/// A read grant must not let the process *run* what it can read.
///
/// `AccessFs::from_read` bundles `Execute` alongside `ReadFile`/`ReadDir`, so
/// for a long time every read grant silently carried it. Nothing about the name
/// `allow_read` suggests that, and a caller granting a data directory would not
/// infer it. Regression test for #19.
#[test]
fn a_read_grant_does_not_make_files_executable() {
    let dir = tempfile::tempdir().unwrap();
    let program = dir.path().join("true");
    std::fs::copy("/bin/true", &program).unwrap();

    let policy = runtime_paths(SandboxPolicy::default()).allow_read(dir.path());
    let output = run(&policy, program.to_str().unwrap(), &[]);

    assert!(
        !output.status.success(),
        "a binary under an allow_read path was executed; the grant is wider than its name"
    );
}

/// The mirror of the above. Without it, the denial test would also pass if the
/// sandbox simply refused to execute anything at all.
#[test]
fn a_read_execute_grant_does_make_files_executable() {
    let dir = tempfile::tempdir().unwrap();
    let program = dir.path().join("true");
    std::fs::copy("/bin/true", &program).unwrap();

    let policy = runtime_paths(SandboxPolicy::default()).allow_read_execute(dir.path());
    let output = run(&policy, program.to_str().unwrap(), &[]);

    assert!(
        output.status.success(),
        "an explicit read+execute grant failed to run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The scenario #19 actually describes: write a binary, then run it. Write
/// grants mapped to `from_all`, which also contains `Execute`, so fixing only
/// the read side would have left this open.
#[test]
fn a_write_grant_does_not_make_files_executable() {
    let dir = tempfile::tempdir().unwrap();
    let program = dir.path().join("planted");

    let policy = runtime_paths(SandboxPolicy::default())
        .allow_read(dir.path())
        .allow_write(dir.path());

    // Plant it from inside the sandbox, the way an agent would.
    let plant = run(
        &policy,
        "/bin/sh",
        &[
            "-c",
            &format!(
                "cp /bin/true {} && chmod +x {}",
                program.display(),
                program.display()
            ),
        ],
    );
    assert!(
        plant.status.success(),
        "could not stage the test: {}",
        String::from_utf8_lossy(&plant.stderr)
    );

    let output = run(&policy, program.to_str().unwrap(), &[]);

    assert!(
        !output.status.success(),
        "a binary written into a writable path was then executed from it"
    );
}
