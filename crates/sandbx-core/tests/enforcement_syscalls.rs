//! Does the kernel refuse a syscall the denylist names?
//!
//! The seccomp half of the enforcement suite: calls Landlock cannot express, because they
//! touch no path — unix sockets, io_uring, memfd, pidfd, userfaultfd. `enforcement.rs` is
//! the filesystem half, and states the kernel floor both files run on.
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]

mod support;

use sandbx_core::SandboxPolicy;
use support::{allow_probe, run, runtime_paths, vetted};

/// Reaching a host daemon over a unix socket is not IP egress: one grant covering both
/// turns "let it talk to the internet" into "let it ask systemd to run something".
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
    .allow_read(vetted(dir.path()))
    .allow_write(vetted(dir.path()));
    let output = run(&policy, probe, &[socket.to_str().unwrap()]);

    let _ = std::os::unix::net::UnixStream::connect(&socket);
    let _ = accepting.join();

    assert!(
        output.status.success(),
        "an explicit grant failed to connect: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A network namespace isolates only *abstract* unix sockets; pathname sockets live in the
/// filesystem and cross it freely, so without a further control a command can dial host
/// daemons (systemd's bus, docker.sock, an ssh-agent) and have them act for it.
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
/// io_uring runs operations from a submission queue without issuing the syscalls, so a ring
/// inside the sandbox sidesteps the whole denylist; denying setup keeps it from existing.
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

/// `memfd_create` returns a descriptor backed by RAM with no path, so Landlock has nothing
/// to match on. The errno and not the exit status: anything but `EPERM` is an unrelated
/// failure.
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

/// The raw errno the kernel answered with, or `"0"` when the call succeeded — the only way
/// this suite can probe a syscall with no safe Rust wrapper, the crate forbidding `unsafe`.
///
/// Pass `nr` from `libc` and never a literal: syscall numbers are per-architecture, and
/// x86_64's `userfaultfd` number is aarch64's `signalfd`. `$!` is cleared first so a stale
/// errno from perl's startup cannot be read back as this call's result.
fn perl_syscall_errno(nr: libc::c_long, args: &str) -> String {
    let program = format!(
        "$! = 0; my $r = syscall({nr}, {args}); print +(defined $r && $r >= 0) ? 0 : $! + 0;"
    );

    // perl opens /dev/null read-write on startup, so it needs both axes or it never
    // reaches the syscall at all.
    let policy = runtime_paths(SandboxPolicy::default())
        .allow_read(vetted("/dev/null"))
        .allow_write(vetted("/dev/null"));
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

/// `pidfd_getfd` lifts an open descriptor *out* of another process — a socket, a file above
/// the policy. Not filesystem access, so Landlock cannot express it; `ptrace` does not cover
/// it either.
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
        // The kernel denies it here regardless, so there is nothing to observe.
        return;
    }

    assert_eq!(
        perl_syscall_errno(libc::SYS_userfaultfd, "0"),
        libc::EPERM.to_string(),
        "on a host where unprivileged userfaultfd is permitted, the filter must \
         be what refuses it"
    );
}
