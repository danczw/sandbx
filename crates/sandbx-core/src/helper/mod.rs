//! The two-stage re-exec that turns a plain process into a sandboxed command.
//!
//! Stage 1 ([`exec_sandboxed`]) makes the namespaces and hardens the state inherited
//! across `exec`; stage 2 ([`exec_inner`]) is PID 1 of the new PID namespace and
//! becomes the command. [`apply`] sequences [`ruleset`], [`seccomp`] and
//! [`hardening`] in the order they have to happen in.

mod hardening;
mod ruleset;
mod seccomp;

pub use seccomp::BLOCKED_SYSCALLS;

use hardening::{
    bind_lifetime_to_supervisor, confirm_supervisor, prepare_supervisor, set_no_new_privs,
};
use ruleset::{Requested, enforcement_verdict, landlock_failed, requested};
use seccomp::deny_dangerous_syscalls;

use crate::degradation::Degradation;
use crate::{HelperArgs, SandboxError};

/// Argument telling the first stage that its stdin is the audit channel.
///
/// Opt-in, and not implied by [`HELPER_FLAG`](crate::HELPER_FLAG): without it a
/// hand-invoked helper would write audit records into whatever fd 0 happens to be — a
/// terminal is writable, so they would appear as the command's own output, and a
/// read-only pipe gives `EBADF`. A degradation then goes unrecorded, which is the honest
/// outcome when there is nowhere to record it.
pub(crate) const AUDIT_STDIN_FLAG: &str = "--sandbx-audit-stdin";

/// Write what degraded to the parent, on the pipe it put in our stdin slot.
///
/// Every failure is swallowed: this reports that the sandbox is *weaker* than advertised,
/// and a channel that cannot be written is a lost record rather than a reason to refuse a
/// command the parent has already been told is running.
///
/// The write end arrives in the stdin slot because it is the only descriptor std can hand
/// a child without `unsafe`, which this crate forbids. `try_clone_to_owned` turns the
/// inherited fd into something writable — `Stdin` is a reader, but the descriptor was
/// opened for writing. See `context/decision-helper-audit-channel.md`.
fn report_degradations(degraded: &[(Degradation, String)]) {
    use std::io::Write;
    use std::os::fd::AsFd;

    let records = crate::degradation::encode(degraded);
    if records.is_empty() {
        return;
    }

    let Ok(channel) = std::io::stdin().as_fd().try_clone_to_owned() else {
        return;
    };

    // One `write_all` for the whole batch: a short write would split a record across
    // two, and the parent skips a line it cannot parse.
    let _ = std::fs::File::from(channel).write_all(records.as_bytes());
}

/// Supervise a sandboxed command: build the namespaces, then run the inner stage
/// inside them.
///
/// Stage 1 of two. Creates the namespaces, hardens the process state inherited
/// across `exec`, then re-execs this same binary into [`exec_inner`].
///
/// The second re-exec exists for one reason: `unshare(CLONE_NEWPID)` does not move the
/// caller into the new PID namespace, only its children, so the *next* process is PID 1
/// of it. Letting `Command::spawn` do that forking keeps every call here safe — `fork`
/// would mean `unsafe` and an async-signal-safety hazard in the `fork`/`exec` window — so
/// `unsafe_code = "forbid"` still holds.
///
/// Intended to run in a freshly executed helper process, never inside sandbx: the
/// namespaces and the capability drops are irreversible for this process, so doing them
/// in sandbx would cage the harness itself.
///
/// On success this never returns: it exits with whatever the command exited with. Any
/// return is an error, and the caller must exit non-zero rather than continue — a helper
/// that fell through to running the command unrestricted would be the exact failure the
/// sandbox exists to prevent.
pub(crate) fn exec_sandboxed(argv: &[String]) -> Result<std::convert::Infallible, SandboxError> {
    // Split off before `decode`, which refuses a flag it does not recognise. Not
    // part of the policy grammar, for the same reason the supervisor pid is not (see
    // `exec_inner`): it describes how to report, not what the command may do.
    let (audit_on_stdin, argv) = match argv.split_first() {
        Some((flag, rest)) if flag == AUDIT_STDIN_FLAG => (true, rest),
        _ => (false, argv),
    };

    // Decoded for this stage's own use: it needs to know whether the policy grants
    // network before choosing the unshare flags. The argv it was given is passed on
    // verbatim — a re-encode would be a second chance for the policy to drift on its way
    // to the stage that enforces it.
    let request = HelperArgs::decode(argv)?;

    // Resolved before the namespaces exist, so a failure to find our own binary
    // happens while nothing has been changed yet.
    let exe = crate::command::current_exe()?;

    let degraded = prepare_supervisor(&request.policy)?;

    // Before the spawn below, so the write end is gone by the time any other process
    // exists. Nothing is read back: a best-effort channel carrying a best-effort
    // record must not be able to fail a run that is otherwise fine.
    if audit_on_stdin {
        report_degradations(&degraded);
    }

    // This same binary in inner mode, which restricts itself before becoming the command.
    // `spawn::command` narrows its environment as it builds it: ordinarily a no-op, since
    // sandbx already narrowed ours, and load-bearing for the helper invoked directly,
    // which has no sandbx above it to have done that.
    let mut inner = crate::spawn::command(exe, &request.policy);
    inner
        .arg(crate::HELPER_INNER_FLAG)
        // So the inner stage can confirm we are still here before it hands control
        // to the command. Host numbering, which is what it reads back from `/proc`.
        .arg(std::process::id().to_string())
        .args(argv);

    // The security half of the audit channel, not a tidy-up. Our stdin is the write end
    // of a pipe the parent reads audit records from; the stage below becomes the sandboxed
    // command, which must not inherit a descriptor it could write forged records into —
    // or hold open, leaving the parent waiting on an EOF that never comes. Pinned by
    // `the_command_cannot_write_the_audit_channel`.
    //
    // Conditional on the same flag as the write, because the flag is what says fd 0 *is* a
    // channel. Without it nothing was written there, so stdin stays inherited — which a
    // hand-invoked `sandbx-helper` needs for a command that reads its own input.
    if audit_on_stdin {
        inner.stdin(std::process::Stdio::null());
    }

    let mut child = inner.spawn().map_err(|source| SandboxError::SpawnFailed {
        detail: "could not start the inner sandbox stage",
        source,
    })?;

    let status = child.wait().map_err(|source| SandboxError::SpawnFailed {
        detail: "could not wait for the sandboxed command",
        source,
    })?;

    relay(status)
}

/// Exit the way the inner stage exited.
///
/// The caller reads this process's status as the command's, and `sandbx-cli` and the
/// `bash` tool both branch on signalled-versus-exited, so anything less than a faithful
/// relay misreports what happened.
///
/// Re-raising rather than exiting with `128 + signal` is what makes the status genuinely
/// *signalled* rather than merely numbered like one. It cannot always work, because two
/// dispositions are not ours: Rust's runtime sets `SIGPIPE` to `SIG_IGN`, and handles
/// `SIGSEGV`/`SIGBUS` to report stack overflow. Raising one of those at ourselves returns
/// instead of killing us, and the caller sees the numbered form — which is how a shell
/// encodes the same fact. Resetting the disposition first would need `sigaction`, which
/// is `unsafe`.
fn relay(status: std::process::ExitStatus) -> Result<std::convert::Infallible, SandboxError> {
    use std::os::unix::process::ExitStatusExt;

    // Re-raised before the numbered form, so a signalled status stays signalled. When the
    // raise returns anyway — the `SIGPIPE`/`SIGSEGV` cases above — the fallback below
    // encodes it the way a shell would.
    if status.code().is_none()
        && let Some(signal) = status.signal()
        && let Ok(signal) = nix::sys::signal::Signal::try_from(signal)
    {
        let _ = nix::sys::signal::raise(signal);
    }

    std::process::exit(exit_code(&status))
}

/// Translate a child's fate into an exit code, the way a shell does.
///
/// A command the sandbox killed dies by signal and has no exit code of its own; reporting
/// 0 there would say "succeeded" about a process seccomp shot. A status that is neither is
/// refused with 1 rather than given an invented success.
///
/// Lives beside the helper that relays a status by exiting with it, so the encoding exists
/// once: `sandbx-cli` reports the same number without deriving it again.
pub fn exit_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;

    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

/// Apply a policy to *this* process, then become the requested command.
///
/// Stage 2 of two, the first child of [`exec_sandboxed`] and therefore PID 1 of the PID
/// namespace it created. Everything here is irreversible and inherited across `exec`,
/// which is what makes the restrictions stick to the real command rather than to this
/// process alone. This process is fresh and so single-threaded: no `fork`/`exec` window,
/// hence no async-signal-safety constraint and no `unsafe`.
///
/// On success this never returns: the process image is replaced. Any return is an error,
/// and the caller must exit non-zero rather than continue — a helper that fell through to
/// running the command unrestricted would be the exact failure the sandbox exists to
/// prevent.
pub(crate) fn exec_inner(argv: &[String]) -> Result<std::convert::Infallible, SandboxError> {
    // A positional token ahead of the policy, not part of it: `HelperArgs` describes what
    // the command may do, this describes who is watching. Keeping them apart leaves the
    // policy grammar and its round-trip untouched, and means a caller reaching
    // `exec_inner` directly cannot pass a policy that smuggles one in.
    let (supervisor, argv) = argv.split_first().ok_or(SandboxError::BadHelperArgs {
        detail: "inner helper mode without a supervisor pid",
    })?;

    let request = HelperArgs::decode(argv)?;

    bind_lifetime_to_supervisor()?;
    confirm_supervisor(supervisor)?;

    // A check, not a re-narrowing. `spawn::command` is the only thing in the crate that
    // builds a `Command` and it narrows by construction, so there is nothing left here to
    // clear; what is worth establishing is whether the stage above really went through it.
    // Clearing again would answer that with silence — the command's `environ` would come
    // out identical either way.
    //
    // Not folded into `confirm_supervisor`, which is a liveness check and explicitly not a
    // trust boundary (see `HELPER_INNER_FLAG`): a caller invoking the inner stage directly
    // arrives with a full environment and is refused here rather than narrowed.
    //
    // A returned error and not an `assert!`: `dispatch_helper_mode` is exhaustive so that a
    // helper run cannot end without either running the command or reporting why not, and a
    // panic leaves through neither. The message names no variable, for the reason
    // `records_how_many_variables_passed_not_which` gives.
    let allowed_env = request.policy.allowed_env();
    if std::env::vars_os()
        .any(|(name, _)| !allowed_env.iter().any(|allowed| name == allowed.as_str()))
    {
        return Err(SandboxError::ProcessHardening {
            detail: "the inner stage inherited a variable the policy does not name; \
                     an earlier stage did not narrow the environment"
                .to_string(),
        });
    }

    apply(&request.policy)?;

    // After `apply`, so the command inherits the cage rather than escaping it: this
    // process is already restricted, and `exec` keeps every one of those restrictions.
    //
    // The load-bearing spawn — where the real command is born, so `spawn::command`
    // narrowing its environment here is what decides what the command can read out of its
    // own `environ`. Nothing here depends on the earlier stages having narrowed the same
    // environment; the check above is what reports a stage that stopped.
    let error = {
        use std::os::unix::process::CommandExt;
        let mut command = crate::spawn::command(&request.program, &request.policy);
        command.args(&request.args);

        command.exec()
    };

    Err(SandboxError::SpawnFailed {
        detail: "could not execute the sandboxed command",
        source: error,
    })
}

fn apply(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    use landlock::{
        CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    };

    // The namespaces and the capability drops already happened in the supervisor that
    // spawned this process — see `prepare_supervisor` — and both are inherited. What is
    // left here is everything that must apply to the command itself and could not be done
    // in a process that still had to spawn one.

    // Installing a seccomp filter requires either CAP_SYS_ADMIN or no_new_privs, and this
    // process holds no capabilities at all, the supervisor having dropped them.
    // Irreversible and inherited across exec, which makes the filter stick to the command.
    set_no_new_privs()?;

    deny_dangerous_syscalls(policy)?;

    // Settles on one ABI and hard-requires all of it, rather than pinning a floor and
    // taking whatever else the kernel offers. Everything handled is therefore enforced,
    // which is what lets `enforcement_verdict` refuse a partial result. The negotiation
    // happens inside `requested`, so no ABI is in scope here and the handled set cannot
    // be derived from a different one than the rules. Destructured for the reason
    // `Requested` gives.
    let Requested { handled, rules } = requested(policy)?;

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled)
        .map_err(landlock_failed)?
        .create()
        .map_err(landlock_failed)?;

    // `Requested` decides what to install; this loop only opens the paths. The axis is
    // for the tests that assert the mapping — the kernel is told the rights and nothing
    // else.
    for (_, path, rights) in rules {
        let fd = PathFd::new(path).map_err(landlock_failed)?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, rights))
            .map_err(landlock_failed)?;
    }

    let status = ruleset.restrict_self().map_err(landlock_failed)?;

    enforcement_verdict(status.ruleset)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `wait(2)` status as the kernel encodes one for a process that exited of its own
    /// accord with `code`. `ExitStatus::from_raw` takes exactly that encoding and is safe,
    /// so the shapes below need no spawned process.
    fn exited(code: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt;

        std::process::ExitStatus::from_raw(code << 8)
    }

    /// The same, for a process killed by `signal`. The signal number occupies the low
    /// seven bits, which is why an exit code sits in the byte above them.
    fn killed_by(signal: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt;

        std::process::ExitStatus::from_raw(signal)
    }

    #[test]
    fn an_exit_code_is_reported_as_itself() {
        for code in [0, 1, 42, 255] {
            assert_eq!(
                exit_code(&exited(code)),
                code,
                "an exit code must survive the translation unchanged"
            );
        }
    }

    #[test]
    fn a_signalled_death_reports_128_plus_the_signal() {
        for signal in [libc::SIGKILL, libc::SIGSEGV, libc::SIGPIPE] {
            assert_eq!(
                exit_code(&killed_by(signal)),
                128 + signal,
                "a command killed by {signal} must report 128 + the signal"
            );
        }
    }

    /// A stop is the only status that is neither an exit nor a death, so the only way to
    /// reach that arm. The premise is asserted first: if a future libc or std decodes this
    /// encoding differently, the test says so instead of quietly re-testing the signal arm
    /// above.
    #[test]
    fn a_status_that_is_neither_exit_nor_death_fails() {
        use std::os::unix::process::ExitStatusExt;

        // 0x7f in the low byte is `WSTOPPED`; the signal that stopped it sits above,
        // where an exit code would.
        let stopped = std::process::ExitStatus::from_raw((libc::SIGSTOP << 8) | 0x7f);

        assert!(
            stopped.code().is_none() && stopped.signal().is_none(),
            "this raw status was meant to be neither an exit nor a death: {stopped:?}"
        );
        assert_eq!(
            exit_code(&stopped),
            1,
            "a status with no verdict of its own must report failure: {stopped:?}"
        );
    }
}
