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

/// The inner stage refuses to run when its supervisor is already gone (#28).
///
/// Between the supervisor spawning this stage and this stage arming its parent
/// death signal there is a window — short, but real — in which the supervisor could
/// be killed and the signal never armed. The command would then run to completion
/// as PID 1 of a namespace nothing is watching: still fully confined, but unreaped,
/// which is the exact weakness being closed. So the stage checks that the pid the
/// supervisor told it to expect is still its parent, and refuses if it is not.
///
/// The check reads `/proc/self/stat` rather than calling `getppid`, which returns 0
/// inside a PID namespace whose parent lives outside it. `/proc` is the host's, so
/// its ppid field still names the supervisor in host numbering.
///
/// Passing pid 1 as the claimed supervisor is a value the stage can never legally
/// have: the real supervisor is an ordinary process, and host pid 1 never spawns
/// one of these.
#[test]
fn the_inner_stage_refuses_a_supervisor_it_is_not_a_child_of() {
    let marker = tempfile::tempdir().unwrap().path().join("should-not-exist");

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
    // Named in the refusal, so this test cannot pass merely because the pid token
    // was rejected as an unrecognised flag — which is what it would prove if the
    // liveness check were absent.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("supervisor"),
        "the refusal must say the supervisor is the reason, got: {stderr}"
    );
}

/// The inner stage refuses an environment an earlier stage should have narrowed,
/// rather than narrowing it again and carrying on.
///
/// This is what pins the check itself. Every other path reaches `exec_inner` with
/// the environment already narrowed, where the check is trivially satisfied, and
/// `the_inner_stage_refuses_a_supervisor_it_is_not_a_child_of` above never gets
/// that far — so without this test the check could be deleted with the suite
/// staying green, which is the exact class of unobservable line it was added to
/// close (#98).
///
/// Reaching it needs the liveness check to pass, which means naming a supervisor
/// that really is this process's parent. That is the test harness: it spawns the
/// helper directly, so its own pid is the one `/proc/self/stat` will report. The
/// liveness check accepting it is by design — `HELPER_INNER_FLAG` is documented as
/// not a trust boundary — and is what leaves the environment to be caught here.
///
/// The variable is planted with `Command::env` rather than `set_var`, which is
/// `unsafe` on edition 2024 and would poison the whole harness besides.
#[test]
fn the_inner_stage_refuses_an_environment_an_earlier_stage_did_not_narrow() {
    let marker = tempfile::tempdir().unwrap().path().join("should-not-exist");

    // Nothing allowed, so the planted variable is outside the allowlist — as is
    // every variable cargo handed this process, which is the harness-wide
    // environment a real stage 1 would have cleared.
    let policy = SandboxPolicy::default();
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
    // Named in the refusal, so this cannot pass merely because the supervisor
    // check or the decode rejected something first — which is what it would prove
    // if the environment check were absent.
    assert!(
        stderr.contains("environment"),
        "the refusal must say the environment is the reason, got: {stderr}"
    );
    // And not named: a refusal is a diagnostic an operator reads, and
    // `records_how_many_variables_a_spawn_passed_not_which` in `audit.rs` makes the
    // same argument about the audit trail. Naming the variable here would walk it
    // back one seam over.
    assert!(
        !stderr.contains("SANDBX_SHOULD_NOT_SURVIVE"),
        "the refusal must not name the variable it found, got: {stderr}"
    );
}

/// The precondition for #28: this host lets an unprivileged process create a PID
/// namespace, and the next child is born as PID 1 of it.
///
/// Asserted on its own, ahead of anything that depends on it, because the answer
/// is a property of the *host* rather than of our code and it cannot be read off
/// a developer machine. A box without AppArmor grants capabilities inside a fresh
/// user namespace that Ubuntu 24.04+ and GitHub's runners strip
/// (`kernel.apparmor_restrict_unprivileged_userns`), and #39 already learned the
/// hard way that "it passes locally" is not evidence about namespace or
/// capability behaviour. If this test is red on CI, the PID-namespace approach is
/// dead before anything is built on it.
///
/// A probe binary rather than an in-process `unshare`: calling it here would
/// strip the *test harness* of its own namespaces for every test that follows.
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

/// The command runs as PID 1 of a namespace of its own (#28).
///
/// This is the fact everything else about process lifetime rests on: a process
/// cannot leave the PID namespace it was born into, and `unshare`/`setns` are
/// denied, so killing PID 1 makes the kernel reap the rest unconditionally. A
/// process group, which is what the timeout kill used to target on its own, is
/// advisory by comparison.
///
/// `$$` in `sh` is the shell's own pid as the kernel reports it to the shell, so
/// reading it back is the command's own view of where it lives.
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

/// A PID namespace also takes away the ability to signal anything outside it.
///
/// Pid resolution is namespace-relative, so a pid from the host simply does not
/// exist as far as the command is concerned. Without the namespace this succeeds:
/// the command runs as the same uid as the caller, so it can signal every one of
/// the caller's processes — including the harness that is testing it.
///
/// `kill -0` sends nothing; it asks whether the signal *could* be delivered,
/// which is the permission question on its own.
#[test]
fn the_command_cannot_signal_a_process_outside_its_namespace() {
    let policy = runtime_paths(SandboxPolicy::default());
    let ours = std::process::id();
    let output = run(&policy, "/bin/sh", &["-c", &format!("kill -0 {ours}")]);

    assert!(
        !output.status.success(),
        "the command reached a process outside its namespace (pid {ours})"
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

/// Read a named field out of the `/proc/self/status` a sandboxed command sees.
fn status_field<'a>(status: &'a str, name: &str) -> &'a str {
    status
        .lines()
        .find_map(|l| l.strip_prefix(name))
        .map(str::trim)
        .unwrap_or_else(|| panic!("no {name} line in /proc/self/status"))
}

/// The four sets the helper can always clear, whatever privilege it holds:
/// shrinking them needs no capability at all.
///
/// `Cap{Eff,Prm,Inh,Amb}` are hex bitmasks; a fully dropped process reports each
/// as `0000000000000000`. `CapBnd` is deliberately absent — see
/// [`the_bounding_set_is_cleared_or_left_exactly_as_inherited`].
const ALWAYS_CLEARED: [&str; 4] = ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"];

/// Can this machine drop the capability bounding set at all?
///
/// Doing so needs `CAP_SETPCAP`, which an unprivileged process holds only inside
/// a user namespace it created itself — and not even there when an LSM strips
/// capabilities from such a namespace. AppArmor's
/// `restrict_unprivileged_userns` (default on Ubuntu 24.04+, and set on GitHub's
/// runners) does exactly that: the `unshare` succeeds but `PR_CAPBSET_DROP`
/// returns `EPERM`.
///
/// The helper treats that as a best-effort step rather than a refusal, so the
/// assertion has to be conditional in the same way — otherwise this suite would
/// demand a guarantee the kernel is refusing to give.
fn bounding_set_is_droppable() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .map(|value| value.trim() != "1")
        .unwrap_or(true)
}

/// The unprivileged capability sets must be gone on the default
/// (network-denied) path, and `no_new_privs` must be set — piggybacked here
/// since it reads from the same `/proc/self/status` output and has no dedicated
/// test of its own yet.
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

/// Granting the network must not cost any of the unprivileged capability sets.
///
/// They are cleared on both paths, since shrinking them needs no privilege. Both
/// paths now enter a user namespace — the PID namespace of #28 requires one
/// whatever the policy says — so what this pins is that the *conditional* part,
/// `CLONE_NEWNET`, is the only thing the network flag changes.
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

/// The bounding set is cleared where the kernel permits it, and left *exactly*
/// as inherited where it does not.
///
/// Both branches assert, deliberately. An earlier version returned early on
/// hosts that strip capabilities from a fresh user namespace, which meant this
/// test reported `ok` there without checking anything — indistinguishable from a
/// run that actually verified the guarantee, and on CI that was every run.
/// Asserting the fallback instead pins it too: a *partial* drop is a different
/// failure from the documented one, and `caps::clear(Bounding)` issues one
/// `PR_CAPBSET_DROP` per capability, so a partial drop is exactly what a
/// mid-loop `EPERM` would leave behind.
#[test]
fn the_bounding_set_is_cleared_or_left_exactly_as_inherited() {
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

    // This process is the helper's parent, so its bounding set is the one the
    // helper inherits — the only correct value when the kernel refuses the drop.
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

/// The same with no grant of any kind.
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

/// Reaching a host daemon over a unix socket is not IP egress, so granting
/// network must not grant it. This is #8: `--allow-network` used to lift the
/// unix-socket denial too, which turned "let it talk to the internet" into "let
/// it ask systemd to run something outside the cage".
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

/// The grant that does allow it, so the denial above is not just the sandbox
/// refusing everything.
#[test]
fn an_explicit_unix_socket_grant_permits_the_connection() {
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
    // The socket's directory must be readable too: the grant lifts the seccomp
    // denial, it does not bypass the filesystem policy.
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
    let guard = sandbx_core::FsGuard::new(&policy);
    assert!(
        guard.check_read(&real.path().join("s.txt")).is_ok(),
        "FsGuard denies a path the kernel layer permits: the two layers disagree"
    );
}

/// The two layers must also agree about the *execute* axis, not just read.
///
/// `allow_read_execute` grants read alongside execute, and the kernel gets
/// exactly that: `AccessFs::from_read` bundles `ReadFile`/`ReadDir` in with
/// `Execute`. `FsGuard` consulted only the read and write axes, so under the
/// identical policy `bash` could `cat` a file that the native `read` tool
/// refused — one policy, two answers. Regression test for #50.
#[test]
fn execute_grant_reads_consistently_across_both_layers() {
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

/// A write grant must not let the process *read* what it can write.
///
/// `SandboxPolicy::writable_paths` promises a write-only drop directory stays
/// unreadable. `FsGuard` always kept that promise; the kernel did not, because
/// `AccessFs::from_all` bundles `ReadFile`/`ReadDir` and only `Execute` was
/// subtracted. Both layers are asserted here, on one policy, so they cannot
/// drift apart again. Regression test for #49.
#[test]
fn a_write_grant_does_not_make_files_readable() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("dropped.txt");
    std::fs::write(&secret, b"WRITE-ONLY-SECRET").unwrap();

    let policy = runtime_paths(SandboxPolicy::default()).allow_write(dir.path());

    // The kernel layer: the command may write here, but not read it back.
    let output = run(&policy, "/bin/cat", &[secret.to_str().unwrap()]);
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("WRITE-ONLY-SECRET"),
        "a write-only grant let the command read the file back"
    );

    // The in-process layer must reach the same verdict for the same policy.
    let guard = sandbx_core::FsGuard::new(&policy);
    assert!(
        guard.check_read(&secret).is_err(),
        "FsGuard permits a read the kernel layer denies: the two layers disagree \
         on the write axis"
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

/// seccomp filters syscalls, and io_uring runs equivalent operations from a
/// submission queue without issuing them — so a ring set up inside the sandbox
/// sidesteps the denylist, including the `socket(AF_UNIX)` rule that #8 relies
/// on. `io_uring_setup` must be denied so the ring cannot be created (#30).
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

/// `memfd_create` returns a file descriptor backed by RAM with no path anywhere
/// on the filesystem, so Landlock — which binds its rules to inodes and paths —
/// has nothing to match on. That makes it the standard way to stage a payload
/// inside a sandbox that governs the filesystem, which is why container runtimes
/// and OpenShell's profile both deny it (#40).
///
/// Asserts the errno, not just the exit status: `EPERM` is what this filter
/// returns, so any other value means the call failed for an unrelated reason and
/// the test would have passed without proving anything.
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
/// This is the only way this suite can probe a syscall with no safe Rust wrapper
/// in the dependency set. `sandbx-core` forbids `unsafe`, so a probe binary
/// cannot issue a raw syscall, and the alternative was three new crates for
/// test-only code — one of which drags in bindgen. Running a host interpreter as
/// the sandboxed command is already how `the_command_sees_a_consistent_real_uid`
/// works, so this adds no new kind of dependency.
///
/// `nr` comes from `libc` rather than being written out, deliberately: syscall
/// numbers are per-architecture, and x86_64's `userfaultfd` number is aarch64's
/// `signalfd`. A hardcoded number silently probes a different call and the
/// assertion passes for the wrong reason.
///
/// `$!` is cleared first so a stale errno from perl's own startup cannot be read
/// back as this call's result.
fn perl_syscall_errno(nr: libc::c_long, args: &str) -> String {
    let program = format!(
        "$! = 0; my $r = syscall({nr}, {args}); print +(defined $r && $r >= 0) ? 0 : $! + 0;"
    );

    // perl opens /dev/null read-write on startup, so it needs both axes or it
    // never reaches the syscall at all. Until #49 the write grant alone was
    // enough, because the kernel layer handed out read with it — this call site
    // is the evidence that the divergence was load-bearing, not theoretical.
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

/// `pidfd_open` is how a process gets a handle on another process, and the
/// handle is what `pidfd_getfd` below needs. Denying it costs nothing a coding
/// tool does (#40).
#[test]
fn pidfd_open_is_denied() {
    assert_eq!(
        perl_syscall_errno(libc::SYS_pidfd_open, "$$ + 0, 0"),
        libc::EPERM.to_string(),
        "pidfd_open should have been refused with EPERM; it succeeds outside the \
         sandbox, so a different answer means the filter did not stop it"
    );
}

/// The one that matters most of the pair: `pidfd_getfd` lifts an open descriptor
/// *out* of another process — a socket, a file above the policy — which is not
/// filesystem access, so Landlock cannot express it and denying `ptrace` does
/// not cover it (#40).
#[test]
fn pidfd_getfd_is_denied() {
    assert_eq!(
        perl_syscall_errno(libc::SYS_pidfd_getfd, "0 + 1, 0 + 1, 0"),
        libc::EPERM.to_string(),
        "pidfd_getfd should have been refused with EPERM by the seccomp filter"
    );
}

/// `userfaultfd` gets no end-to-end probe, and the reason is worth stating where
/// someone looks for one.
///
/// It is denied — `BLOCKED_SYSCALLS` carries it, pinned by `tests/denylist.rs` —
/// but an `EPERM` assertion here would be close to worthless: the kernel's own
/// `vm.unprivileged_userfaultfd` sysctl returns `EPERM` for an unprivileged
/// caller when it is `0`, which is the default on many hosts including this
/// project's dev box. The assertion would pass identically with the filter
/// removed, which is the definition of a test proving nothing.
///
/// So this test records the situation instead of faking evidence: where the
/// sysctl already denies it, note that the filter is not what was observed.
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
        // Documented outcome, not a skip: the kernel denies it here regardless, so
        // there is no filter-specific observation to make on this host.
        return;
    }

    assert_eq!(
        perl_syscall_errno(libc::SYS_userfaultfd, "0"),
        libc::EPERM.to_string(),
        "on a host where unprivileged userfaultfd is permitted, the filter must \
         be what refuses it"
    );
}

/// The command should see its real uid, not the overflow `nobody` that a fresh
/// user namespace reports when no uid_map is written. It already *acts* as the
/// real uid on the host (files it writes are owned by it), so reporting 65534 is
/// a lie that `getuid()`-based logic trips over. #35.
///
/// Both paths create a user namespace now: the PID namespace of #28 needs one
/// regardless of policy, so granting network no longer means skipping the
/// unshare. Each path is therefore checked against the same two acceptable
/// answers rather than one being used as the other's reference — the identity map
/// is best-effort by design, and where the platform refuses it (AppArmor's
/// `restrict_unprivileged_userns`, default on Ubuntu 24.04+ and set on GitHub's
/// runners) the command runs as the overflow `nobody` instead. What must never
/// happen is a third value.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn the_command_sees_a_consistent_real_uid() {
    // std exposes no getuid, and pulling nix's `user` feature in for one test is
    // not worth it; ask the host directly.
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

/// #98's reproducer, inverted.
///
/// A variable the harness holds does not travel through the filesystem — it is
/// handed over by `fork`/`exec` before Landlock or seccomp have any say — so no
/// path policy can express "not this" about it. Before the fix, the whole
/// environment arrived and the suite could not see it.
///
/// `CARGO_MANIFEST_DIR` rather than a variable this test plants: `std::env::set_var`
/// is `unsafe` on the 2024 edition and `unsafe` is forbidden workspace-wide, so
/// the test cannot mutate its own environment. Cargo sets this one for us, which
/// is as good — it is in the parent's environment and in no policy below.
///
/// Note this goes through `run`, which spawns the helper *without* clearing
/// anything first. So what is under test is the helper stages doing it on their
/// own, which is the case a library consumer invoking the helper directly gets.
#[test]
fn a_variable_the_policy_omits_does_not_reach_the_command() {
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

/// Baseline for the test above: with the variable granted it does arrive.
///
/// Without this, the denial would pass even if the environment were dropped
/// wholesale and the allowlist did nothing — which is a different bug, not a fix.
#[test]
fn a_granted_variable_reaches_the_command_with_its_value() {
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

/// Nothing *but* what was granted. The allowlist is the whole statement, so a
/// second variable arriving alongside the one asked for would mean the clear is
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

/// A name the harness does not hold is absent, not present and empty.
///
/// The distinction is load-bearing for a command that branches on whether a
/// variable is *set* — a blank value would read as "configured, to nothing".
#[test]
fn granting_a_variable_the_harness_lacks_passes_nothing() {
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
