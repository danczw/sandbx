//! Tries to create an unprivileged PID namespace and reports whether the next
//! child was born as PID 1 of it; test-only
//! (`required-features = ["sandbox-integration"]`).
//!
//! `CLONE_NEWPID` needs `CAP_SYS_ADMIN`, which an unprivileged process only holds
//! inside a user namespace it created, so both flags go in one `unshare`. The
//! unsharing process does not enter the namespace; only its children do, which is
//! why a re-exec is enough and a `fork` unnecessary. Both halves are checked: a
//! kernel can permit the `unshare` and still not place the child where we expect.
//! AppArmor's `restrict_unprivileged_userns` (default on Ubuntu 24.04+ and
//! GitHub's runners) permits the namespace but strips its capabilities, so the raw
//! errno is printed — `EPERM` here is what proves the approach dead.

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

    // The workspace bans `Command::new`; what this probe spawns is itself.
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
