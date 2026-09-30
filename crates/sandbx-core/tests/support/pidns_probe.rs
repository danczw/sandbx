//! Tries to create an unprivileged PID namespace and reports whether the next
//! child was born as PID 1 of it.
//!
//! Test-only (`required-features = ["sandbox-integration"]`), so it is never
//! part of a normal build.
//!
//! This is the precondition the #28 fix rests on. `CLONE_NEWPID` needs
//! `CAP_SYS_ADMIN`, which an unprivileged process only ever holds inside a user
//! namespace it created itself — so the two flags go in one `unshare`. The
//! process that unshares does *not* enter the new namespace; only its children
//! do, which is exactly what makes a second re-exec enough and a `fork` of our
//! own unnecessary.
//!
//! Both halves are asserted, because they can fail independently: a kernel could
//! permit the `unshare` and still not place the child where we expect. Prints the
//! raw errno on refusal so a CI log says *why* rather than only that something
//! went wrong — the AppArmor case (`restrict_unprivileged_userns`, default on
//! Ubuntu 24.04+ and set on GitHub's runners) permits the namespace but strips
//! its capabilities, and `EPERM` here is what would prove the approach dead.
//!
//! Re-execs itself rather than spawning a shell: it mirrors how the helper
//! reaches its inner stage, and it does not depend on `/bin/sh` existing.

/// Argument that marks the re-executed child half of this probe.
const CHILD_FLAG: &str = "--child";

fn main() -> std::process::ExitCode {
    if std::env::args().nth(1).as_deref() == Some(CHILD_FLAG) {
        println!("{}", std::process::id());
        return std::process::ExitCode::SUCCESS;
    }

    use nix::sched::{CloneFlags, unshare};

    let Ok(exe) = std::env::current_exe() else {
        eprintln!("PIDNS PROBE FAILED: could not locate this executable");
        return std::process::ExitCode::FAILURE;
    };

    if let Err(errno) = unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWPID) {
        println!("UNSHARE DENIED {}", errno as i32);
        eprintln!("PIDNS PROBE FAILED: unshare(CLONE_NEWUSER|CLONE_NEWPID): {errno}");
        return std::process::ExitCode::FAILURE;
    }

    // The workspace bans `Command::new`; this probe is the sandbox's own test
    // scaffolding, and what it spawns is itself.
    #[allow(clippy::disallowed_methods)]
    let spawned = std::process::Command::new(exe).arg(CHILD_FLAG).output();

    let Ok(output) = spawned else {
        eprintln!("PIDNS PROBE FAILED: could not re-exec into the new namespace");
        return std::process::ExitCode::FAILURE;
    };

    let pid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("CHILD PID {pid}");

    if pid == "1" {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("PIDNS PROBE FAILED: the child was not pid 1 of a new namespace");
        std::process::ExitCode::FAILURE
    }
}
