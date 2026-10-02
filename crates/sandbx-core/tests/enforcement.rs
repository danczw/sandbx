//! Does the kernel actually block an escape?
//!
//! Everything else in this crate tests our own logic; these spawn real processes
//! and assert the *kernel* refuses them, which is the only evidence the sandbox
//! does anything at all. Gated behind `--features sandbox-integration`: they need
//! Landlock available (5.13+, enabled at boot).
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]
// Every `Command::new` below spawns the sandbox helper itself, never a command that
// bypasses it; the workspace ban exists to stop code executing *around* the sandbox.
#![allow(clippy::disallowed_methods)]

use std::path::Path;
use std::process::Command;

use sandbx_core::{HelperArgs, SandboxPolicy};

/// Paths the helper itself needs in order to `exec` anything at all: `exec` happens
/// *after* the restrictions are applied, so the interpreter and shared libraries must
/// stay reachable. Program directories need read *and* execute; `ld.so.cache` the
/// loader only reads.
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

/// Grant execute on a probe binary: probes live under `target/`, which
/// `runtime_paths` does not cover, and without this a denial test passes because
/// nothing ran rather than because the kernel refused.
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

/// Baseline: without it the denials below would pass on a sandbox that broke
/// everything indiscriminately.
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

/// The point of the whole crate, enforced by the kernel rather than our own checks.
#[test]
fn unallowed_path_cannot_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    // The temp dir is not granted.
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

/// At the kernel level, not merely in `FsGuard`.
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

/// Between the supervisor spawning this stage and the stage arming its parent death
/// signal, the supervisor can die with the signal never armed, leaving the command
/// PID 1 of a namespace nothing watches — confined, but unreaped — so the stage checks
/// that the pid it was told to expect is still its parent. It reads `/proc/self/stat`
/// and not `getppid`, which returns 0 inside a PID namespace whose parent lives
/// outside it; `/proc` is the host's, so its ppid field still names the supervisor in
/// host numbering. Pid 1 is a claim no stage can legally receive.
#[test]
fn the_inner_stage_refuses_a_foreign_supervisor() {
    // Bound, not a temporary: `tempdir().path()` drops the directory at the end of
    // the statement, which would leave `!marker.exists()` below asserting nothing.
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("should-not-exist");

    let output = Command::new(env!("CARGO_BIN_EXE_sandbx-helper"))
        .args([
            sandbx_core::HELPER_INNER_FLAG,
            "1",
            "--",
            "/bin/touch",
            marker.to_str().unwrap(),
        ])
        .output()
        .expect("helper should start");

    assert!(
        !output.status.success(),
        "the inner stage ran without a supervisor watching it"
    );
    assert!(
        !marker.exists(),
        "the inner stage ran the command despite having no supervisor"
    );
    // Named in the refusal, so this cannot pass merely because the pid token was
    // rejected as an unrecognised flag.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("supervisor"),
        "the refusal must say the supervisor is the reason, got: {stderr}"
    );
}

/// The only test that reaches this check: every other path arrives at `exec_inner`
/// with the environment already narrowed, so without this the check could be deleted
/// with the suite staying green.
///
/// Reaching it needs the liveness check to pass, so the supervisor named must really
/// be this process's parent — the harness spawns the helper directly. The variable is
/// planted with `Command::env`, since `set_var` is `unsafe` on edition 2024. The
/// policy grants everything `/bin/touch` needs, so with the check removed each
/// assertion fails on its own; under a `default()` policy the exec would be denied and
/// the test would stay green for the wrong reason.
#[test]
fn the_inner_stage_refuses_an_unnarrowed_environment() {
    // Bound, not a temporary: `tempdir().path()` drops the directory at the end of
    // the statement, and `!marker.exists()` would then assert nothing.
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("should-not-exist");

    // Nothing in the environment allowlist, so the planted variable is outside it —
    // as is every variable cargo handed this process.
    let policy = runtime_paths(SandboxPolicy::default()).allow_write(dir.path());
    let args = [marker.to_str().unwrap().to_string()];

    let output = Command::new(env!("CARGO_BIN_EXE_sandbx-helper"))
        .arg(sandbx_core::HELPER_INNER_FLAG)
        .arg(std::process::id().to_string())
        .args(HelperArgs::encode(&policy, "/bin/touch", &args))
        .env("SANDBX_SHOULD_NOT_SURVIVE", "leaked-abc123")
        .output()
        .expect("helper should start");

    assert!(
        !output.status.success(),
        "the inner stage ran with an environment the policy never named"
    );
    assert!(
        !marker.exists(),
        "the inner stage ran the command despite a leaked environment"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Named in the refusal, so this cannot pass merely because the supervisor check
    // or the decode rejected something first.
    assert!(
        stderr.contains("environment"),
        "the refusal must say the environment is the reason, got: {stderr}"
    );
    // And not named: a refusal is a diagnostic an operator reads, so naming the
    // variable would walk back what the audit trail already refuses to record.
    assert!(
        !stderr.contains("SANDBX_SHOULD_NOT_SURVIVE"),
        "the refusal must not name the variable it found, got: {stderr}"
    );
}

/// Asserted on its own, ahead of everything that depends on it, because the answer is
/// a property of the host: a box without AppArmor grants capabilities inside a fresh
/// user namespace that Ubuntu 24.04+ and GitHub's runners strip
/// (`kernel.apparmor_restrict_unprivileged_userns`). Red here means the PID-namespace
/// approach is dead. A probe binary rather than an in-process `unshare`, which would
/// strip the harness of its own namespaces for every test that follows.
#[test]
fn unprivileged_pid_namespace_is_available() {
    #[allow(clippy::disallowed_methods)]
    let output = Command::new(env!("CARGO_BIN_EXE_sandbx-pidns-probe"))
        .output()
        .expect("probe should start");

    assert!(
        output.status.success(),
        "this host cannot create an unprivileged PID namespace\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("CHILD PID 1"),
        "the child of an unsharing process must be pid 1 of the new namespace, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// Everything about process lifetime rests on this: a process cannot leave the PID
/// namespace it was born into, and `unshare`/`setns` are denied, so killing PID 1
/// makes the kernel reap the rest unconditionally — where a process group is advisory.
/// `$$` is the shell's own pid as the kernel reports it.
#[test]
fn the_command_is_pid_one_of_its_own_namespace() {
    let policy = runtime_paths(SandboxPolicy::default());
    let output = run(&policy, "/bin/sh", &["-c", "echo $$"]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "1",
        "the command must be pid 1 of a new namespace, not a process in ours"
    );
}

/// Pid resolution is namespace-relative, so a host pid does not exist as far as the
/// command is concerned. Without the namespace this succeeds: the command runs as the
/// caller's uid, so it can signal the caller's processes — the harness included.
/// `kill -0` sends nothing; it asks whether the signal could be delivered.
#[test]
fn the_command_cannot_signal_outside_its_namespace() {
    let policy = runtime_paths(SandboxPolicy::default());
    let ours = std::process::id();
    let output = run(&policy, "/bin/sh", &["-c", &format!("kill -0 {ours}")]);

    assert!(
        !output.status.success(),
        "the command reached a process outside its namespace (pid {ours})"
    );
}

/// Network denial comes from an empty network namespace, not from Landlock. A fresh
/// netns has only loopback, so reading the interface list needs no external network.
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

/// The opposite direction, or the flag is decorative.
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

/// Installed, not merely constructed: `/proc/self/status` reports `Seccomp: 2` once a
/// BPF filter is in force, which needs no tool that attempts a blocked syscall.
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

fn status_field<'a>(status: &'a str, name: &str) -> &'a str {
    status
        .lines()
        .find_map(|l| l.strip_prefix(name))
        .map(str::trim)
        .unwrap_or_else(|| panic!("no {name} line in /proc/self/status"))
}

/// The four sets the helper can always clear, since shrinking them needs no
/// capability. Hex bitmasks; a fully dropped process reports each as
/// `0000000000000000`. `CapBnd` is absent — see
/// [`the_bounding_set_is_cleared_or_left_inherited`].
const ALWAYS_CLEARED: [&str; 4] = ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"];

/// Can this machine drop the capability bounding set at all? It needs `CAP_SETPCAP`,
/// held only inside a self-created user namespace — and not even there when an LSM
/// strips capabilities from one. AppArmor's `restrict_unprivileged_userns` (default on
/// Ubuntu 24.04+ and GitHub's runners) lets the `unshare` succeed but makes
/// `PR_CAPBSET_DROP` return `EPERM`, so the helper treats the drop as best-effort and
/// this assertion is conditional in step. Repeated in `audit_channel.rs`, because cargo
/// gives each `tests/*.rs` its own binary; keep the two copies identical.
fn bounding_set_is_droppable() -> bool {
    use std::os::unix::fs::MetadataExt;

    // The restriction covers *unprivileged* userns only, so a run as root holds
    // `CAP_SETPCAP` in the new namespace whatever the sysctl says. Off `/proc/self`'s
    // owner because `libc::geteuid` is `unsafe` and this crate forbids that.
    let root = std::fs::metadata("/proc/self")
        .map(|proc_self| proc_self.uid() == 0)
        .unwrap_or(false);

    root || std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .map(|value| value.trim() != "1")
        .unwrap_or(true)
}

/// `no_new_privs` is checked here too, off the same `/proc/self/status` read.
#[test]
fn capabilities_are_dropped() {
    let policy = runtime_paths(SandboxPolicy::default()).allow_read("/proc");
    let output = run(&policy, "/bin/cat", &["/proc/self/status"]);

    assert!(
        output.status.success(),
        "could not read process status: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let status = String::from_utf8_lossy(&output.stdout);
    for name in ALWAYS_CLEARED {
        assert_eq!(
            status_field(&status, name),
            "0000000000000000",
            "{name} was not fully dropped"
        );
    }
    assert_eq!(
        status_field(&status, "NoNewPrivs:"),
        "1",
        "no_new_privs was not set"
    );
}

/// Both paths enter a user namespace, since the PID namespace requires one whatever
/// the policy says, so this pins `CLONE_NEWNET` as the only thing the flag changes.
#[test]
fn capabilities_are_dropped_when_network_is_allowed() {
    let policy = runtime_paths(SandboxPolicy::default().allow_network()).allow_read("/proc");
    let output = run(&policy, "/bin/cat", &["/proc/self/status"]);

    assert!(
        output.status.success(),
        "could not read process status: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let status = String::from_utf8_lossy(&output.stdout);
    for name in ALWAYS_CLEARED {
        assert_eq!(
            status_field(&status, name),
            "0000000000000000",
            "{name} was not dropped on the network-allowed path"
        );
    }
}

/// Both branches assert rather than one returning early, which would report `ok`
/// without checking anything on every CI run. `caps::clear(Bounding)` issues one
/// `PR_CAPBSET_DROP` per capability, so a mid-loop `EPERM` leaves a partial drop — a
/// different failure from the documented fallback.
#[test]
fn the_bounding_set_is_cleared_or_left_inherited() {
    let policy = runtime_paths(SandboxPolicy::default()).allow_read("/proc");
    let output = run(&policy, "/bin/cat", &["/proc/self/status"]);

    assert!(
        output.status.success(),
        "could not read process status: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let status = String::from_utf8_lossy(&output.stdout);
    let sandboxed = status_field(&status, "CapBnd:");

    if bounding_set_is_droppable() {
        assert_eq!(
            sandboxed, "0000000000000000",
            "CapBnd was not dropped although this kernel allows it"
        );
        return;
    }

    // This process is the helper's parent, so its bounding set is the one the helper
    // inherits — the only correct value when the kernel refuses the drop.
    let host = std::fs::read_to_string("/proc/self/status")
        .expect("could not read this process's own status");

    assert_eq!(
        sandboxed,
        status_field(&host, "CapBnd:"),
        "this kernel strips capabilities from an unprivileged userns, so CapBnd \
         should have been left exactly as inherited — a value differing from \
         the parent's means the drop partly succeeded, which is neither the \
         enforced guarantee nor the documented fallback"
    );
}

/// `RLIMIT_CORE` must be zero so a crash inside the sandboxed command cannot
/// write a core dump to disk.
#[test]
fn core_dumps_are_disabled() {
    let policy = runtime_paths(SandboxPolicy::default()).allow_read("/proc");
    let output = run(&policy, "/bin/cat", &["/proc/self/limits"]);

    assert!(
        output.status.success(),
        "could not read process limits: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let limits = String::from_utf8_lossy(&output.stdout);
    let line = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .expect("no core file size line in /proc/self/limits");
    let mut fields = line.split_whitespace();
    let soft = fields.nth(4).expect("no soft limit field");
    let hard = fields.next().expect("no hard limit field");

    assert_eq!(soft, "0", "soft RLIMIT_CORE was not zero");
    assert_eq!(hard, "0", "hard RLIMIT_CORE was not zero");
}

/// Landlock leaves *unhandled* access types unrestricted everywhere, so a ruleset that
/// never handles `Truncate` permits zeroing any file on the machine, read-only grant
/// included. Needs the probe: only `truncate(2)` on a path exercises that right.
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

#[test]
fn truncate_on_ungranted_path_is_denied() {
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim.txt");
    std::fs::write(&victim, b"original contents").unwrap();

    // `dir` is not granted.
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

/// Reaching a host daemon over a unix socket is not IP egress: one grant covering
/// both turns "let it talk to the internet" into "let it ask systemd to run something
/// outside the cage".
#[test]
fn granting_network_does_not_grant_unix_sockets() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("host.sock");

    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let accepting = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            use std::io::Write;
            let _ = stream.write_all(b"HOST-SIDE-SECRET");
        }
    });

    let probe = env!("CARGO_BIN_EXE_sandbx-unix-probe");
    let policy = allow_probe(
        runtime_paths(SandboxPolicy::default().allow_network()),
        probe,
    );
    let output = run(&policy, probe, &[socket.to_str().unwrap()]);

    let _ = std::os::unix::net::UnixStream::connect(&socket);
    let _ = accepting.join();

    assert!(
        !output.status.success(),
        "granting network also granted a unix socket to a host daemon"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("HOST-SIDE-SECRET"),
        "read from a host daemon the policy never granted"
    );
}

/// The grant that does allow it, so the denial above is not the sandbox refusing
/// everything.
#[test]
fn an_explicit_unix_grant_permits_the_connection() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("host.sock");

    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let accepting = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            use std::io::Write;
            let _ = stream.write_all(b"HOST-SIDE-SECRET");
        }
    });

    let probe = env!("CARGO_BIN_EXE_sandbx-unix-probe");
    // The socket's directory must be readable too: the grant lifts the seccomp denial,
    // it does not bypass the filesystem policy.
    let policy = allow_probe(
        runtime_paths(SandboxPolicy::default().allow_unix_sockets()),
        probe,
    )
    .allow_read(dir.path())
    .allow_write(dir.path());
    let output = run(&policy, probe, &[socket.to_str().unwrap()]);

    let _ = std::os::unix::net::UnixStream::connect(&socket);
    let _ = accepting.join();

    assert!(
        output.status.success(),
        "an explicit grant failed to connect: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A network namespace isolates only *abstract* unix sockets; pathname sockets live in
/// the filesystem and cross it freely, so without a further control a command can dial
/// host daemons (systemd's bus, docker.sock, an ssh-agent) and have them act for it.
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

    // The socket's directory is not granted, and network is denied.
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

/// `FsGuard` canonicalizes its roots; the helper must too, or one policy means
/// different things in-process and in the kernel. Resolved rather than rejected
/// because `/bin`, `/lib` and `/lib64` are symlinks on ordinary systems.
#[test]
fn symlinked_policy_root_resolves_consistently() {
    let real = tempfile::tempdir().unwrap();
    let staging = tempfile::tempdir().unwrap();
    std::fs::write(real.path().join("s.txt"), b"target-side").unwrap();

    let link = staging.path().join("granted");
    std::os::unix::fs::symlink(real.path(), &link).unwrap();

    let policy = runtime_paths(SandboxPolicy::default()).allow_read(&link);

    // Through the link — the path actually granted.
    let via_link = run(&policy, "/bin/cat", &[link.join("s.txt").to_str().unwrap()]);
    assert!(via_link.status.success());

    let guard = sandbx_core::FsGuard::new(&policy);
    assert!(
        guard.check_read(&real.path().join("s.txt")).is_ok(),
        "FsGuard denies a path the kernel layer permits: the two layers disagree"
    );
}

/// The kernel gets read alongside execute, since `AccessFs::from_read` bundles
/// `ReadFile`/`ReadDir` in with `Execute`. If `FsGuard` reads only the read and write
/// axes, `bash` can `cat` a file the native `read` tool refuses under one policy.
#[test]
fn an_execute_grant_reads_the_same_in_both_layers() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("data.txt");
    std::fs::write(&file, b"exec-axis-readable").unwrap();

    let policy = runtime_paths(SandboxPolicy::default()).allow_read_execute(dir.path());

    let output = run(&policy, "/bin/cat", &[file.to_str().unwrap()]);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("exec-axis-readable"),
        "kernel layer denies a read on the execute axis: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let guard = sandbx_core::FsGuard::new(&policy);
    assert!(
        guard.check_read(&file).is_ok(),
        "FsGuard denies a read the kernel layer permits: the two layers disagree \
         on the execute axis"
    );
}

/// `SandboxPolicy::writable_paths` promises a write-only drop directory stays
/// unreadable, and `AccessFs::from_all` bundles `ReadFile`/`ReadDir` — so the kernel
/// side needs more than `Execute` subtracted. Both layers are asserted on one policy.
#[test]
fn a_write_grant_does_not_make_files_readable() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("dropped.txt");
    std::fs::write(&secret, b"WRITE-ONLY-SECRET").unwrap();

    let policy = runtime_paths(SandboxPolicy::default()).allow_write(dir.path());

    let output = run(&policy, "/bin/cat", &[secret.to_str().unwrap()]);
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("WRITE-ONLY-SECRET"),
        "a write-only grant let the command read the file back"
    );

    let guard = sandbx_core::FsGuard::new(&policy);
    assert!(
        guard.check_read(&secret).is_err(),
        "FsGuard permits a read the kernel layer denies: the two layers disagree \
         on the write axis"
    );
}

/// `AccessFs::from_read` bundles `Execute` alongside `ReadFile`/`ReadDir`, so a read
/// grant mapped straight onto it carries execute — which nothing about the name
/// `allow_read` would suggest to a caller granting a data directory.
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

/// Without this mirror, the denial above would pass on a sandbox that refused to
/// execute anything at all.
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

/// Write a binary, then run it: write grants map to `from_all`, which also contains
/// `Execute`, so fixing only the read side leaves this open.
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

/// io_uring runs operations from a submission queue without issuing the syscalls, so a
/// ring inside the sandbox sidesteps the whole denylist, the `socket(AF_UNIX)` rule
/// included. Denying `io_uring_setup` is what keeps the ring from existing.
#[test]
fn io_uring_setup_is_denied() {
    let probe = env!("CARGO_BIN_EXE_sandbx-iouring-probe");
    let policy = allow_probe(runtime_paths(SandboxPolicy::default()), probe);
    let output = run(&policy, probe, &[]);

    assert!(
        !output.status.success(),
        "io_uring_setup succeeded inside the sandbox: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// `memfd_create` returns a descriptor backed by RAM with no path anywhere, so
/// Landlock — which binds its rules to inodes and paths — has nothing to match on.
/// Asserts the errno and not just the exit status: any value other than `EPERM` means
/// the call failed for an unrelated reason.
#[test]
fn memfd_create_is_denied() {
    let probe = env!("CARGO_BIN_EXE_sandbx-memfd-probe");
    let policy = allow_probe(runtime_paths(SandboxPolicy::default()), probe);
    let output = run(&policy, probe, &[]);

    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        libc::EPERM.to_string(),
        "memfd_create should have been refused with EPERM by the seccomp filter"
    );
}

/// Reach a syscall through perl's `syscall` builtin and return what the kernel
/// answered: the raw errno, or `"0"` when the call succeeded.
///
/// The only way this suite can probe a syscall with no safe Rust wrapper, since the
/// crate forbids `unsafe`. Pass `nr` from `libc` and never a literal: syscall numbers
/// are per-architecture, and x86_64's `userfaultfd` number is aarch64's `signalfd`, so
/// a literal probes a different call. `$!` is cleared first so a stale errno from
/// perl's startup cannot be read back as this call's result.
fn perl_syscall_errno(nr: libc::c_long, args: &str) -> String {
    let program = format!(
        "$! = 0; my $r = syscall({nr}, {args}); print +(defined $r && $r >= 0) ? 0 : $! + 0;"
    );

    // perl opens /dev/null read-write on startup, so it needs both axes or it never
    // reaches the syscall at all.
    let policy = runtime_paths(SandboxPolicy::default())
        .allow_read("/dev/null")
        .allow_write("/dev/null");
    let output = run(&policy, "/usr/bin/perl", &["-e", &program]);

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        !stdout.is_empty(),
        "perl produced no errno — it likely never ran: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

/// `pidfd_open` is how a process gets the handle `pidfd_getfd` below needs.
#[test]
fn pidfd_open_is_denied() {
    assert_eq!(
        perl_syscall_errno(libc::SYS_pidfd_open, "$$ + 0, 0"),
        libc::EPERM.to_string(),
        "pidfd_open should have been refused with EPERM; it succeeds outside the \
         sandbox, so a different answer means the filter did not stop it"
    );
}

/// `pidfd_getfd` lifts an open descriptor *out* of another process — a socket, a file
/// above the policy. Not filesystem access, so Landlock cannot express it, and denying
/// `ptrace` does not cover it.
#[test]
fn pidfd_getfd_is_denied() {
    assert_eq!(
        perl_syscall_errno(libc::SYS_pidfd_getfd, "0 + 1, 0 + 1, 0"),
        libc::EPERM.to_string(),
        "pidfd_getfd should have been refused with EPERM by the seccomp filter"
    );
}

/// `userfaultfd` gets no end-to-end probe: `vm.unprivileged_userfaultfd` returns
/// `EPERM` for an unprivileged caller when it is `0`, the default on many hosts, so an
/// `EPERM` assertion would pass identically with the filter removed. Where the sysctl
/// permits it, the filter must be what refuses.
#[test]
fn userfaultfd_denial_rests_on_the_list_not_a_probe() {
    let sysctl = std::fs::read_to_string("/proc/sys/vm/unprivileged_userfaultfd")
        .map(|raw| raw.trim().to_string())
        .unwrap_or_default();

    assert!(
        sandbx_core::BLOCKED_SYSCALLS.contains(&libc::SYS_userfaultfd),
        "userfaultfd must stay in the denylist; nothing else covers it"
    );

    if sysctl == "0" {
        // The kernel denies it here regardless, so there is no filter-specific
        // observation to make on this host.
        return;
    }

    assert_eq!(
        perl_syscall_errno(libc::SYS_userfaultfd, "0"),
        libc::EPERM.to_string(),
        "on a host where unprivileged userfaultfd is permitted, the filter must \
         be what refuses it"
    );
}

/// A fresh user namespace reports the overflow `nobody` until a uid_map is written,
/// while the command still *acts* as the real uid on the host — a mismatch that
/// `getuid()`-based logic trips over.
///
/// Both paths create a user namespace, since the PID namespace needs one regardless of
/// policy, so each is checked against the same two answers rather than one being the
/// other's reference: the identity map is best-effort, and where the platform refuses
/// it the command runs as the overflow uid. A third value must never appear.
#[test]
fn the_command_sees_a_consistent_real_uid() {
    // std exposes no getuid and nix's `user` feature is not worth pulling in for one
    // test; ask the host directly.
    let host_value = |args: &[&str]| {
        String::from_utf8(
            std::process::Command::new("/usr/bin/id")
                .args(args)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string()
    };
    let real = host_value(&["-u"]);
    let overflow = std::fs::read_to_string("/proc/sys/kernel/overflowuid")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "65534".to_string());

    for (label, policy) in [
        ("network-denied", SandboxPolicy::default()),
        ("network-allowed", SandboxPolicy::default().allow_network()),
    ] {
        let output = run(&runtime_paths(policy), "/usr/bin/id", &["-u"]);
        assert!(
            output.status.success(),
            "id did not run on the {label} path: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let seen = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(
            seen == real || seen == overflow,
            "{label} path reported {seen:?}, expected the real uid ({real:?}) or \
             the overflow fallback ({overflow:?})"
        );
    }
}

/// A variable the harness holds does not travel through the filesystem — `fork`/`exec`
/// hands it over before Landlock or seccomp have any say — so no path policy can
/// express "not this" about it.
///
/// `CARGO_MANIFEST_DIR` rather than a planted variable: `std::env::set_var` is `unsafe`
/// on edition 2024. Goes through `run`, which spawns the helper without clearing
/// anything first, so what is under test is the helper stages doing it themselves.
#[test]
fn a_variable_the_policy_omits_never_reaches_it() {
    let policy = runtime_paths(SandboxPolicy::default());

    let output = run(&policy, "/usr/bin/env", &[]);

    assert!(
        output.status.success(),
        "env did not run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let seen = String::from_utf8_lossy(&output.stdout);
    assert!(
        !seen.contains("CARGO_MANIFEST_DIR"),
        "a variable no policy granted reached the command: {seen}"
    );
}

/// Baseline: without it the denial above would pass on a helper that dropped the
/// environment wholesale and ignored the allowlist.
#[test]
fn a_granted_variable_reaches_it_with_its_value() {
    let expected = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets this for a test");
    let policy = runtime_paths(SandboxPolicy::default()).allow_env("CARGO_MANIFEST_DIR");

    let output = run(&policy, "/usr/bin/env", &[]);

    assert!(
        output.status.success(),
        "env did not run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let seen = String::from_utf8_lossy(&output.stdout);
    assert!(
        seen.contains(&format!("CARGO_MANIFEST_DIR={expected}")),
        "a granted variable did not arrive with its value: {seen}"
    );
}

/// A second variable arriving alongside the one asked for means the clear is
/// filtering rather than clearing.
#[test]
fn granting_one_variable_passes_only_that_one() {
    let policy = runtime_paths(SandboxPolicy::default()).allow_env("CARGO_MANIFEST_DIR");

    let output = run(&policy, "/usr/bin/env", &[]);

    let seen = String::from_utf8_lossy(&output.stdout);
    let names: Vec<&str> = seen
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name))
        .collect();

    assert_eq!(
        names,
        ["CARGO_MANIFEST_DIR"],
        "the command's environment was not exactly the allowlist: {seen}"
    );
}

/// Absent, not present and empty: a command branching on whether a variable is *set*
/// reads a blank value as "configured, to nothing".
#[test]
fn granting_what_the_harness_lacks_passes_nothing() {
    let policy = runtime_paths(SandboxPolicy::default()).allow_env("SANDBX_DEFINITELY_NOT_SET_98");

    let output = run(&policy, "/usr/bin/env", &[]);

    assert!(
        output.status.success(),
        "env did not run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "",
        "an unset name produced an entry"
    );
}
