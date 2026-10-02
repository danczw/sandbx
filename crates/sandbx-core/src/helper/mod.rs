//! The two-stage re-exec that turns a plain process into a sandboxed command.
//!
//! Stage 1 ([`exec_sandboxed`]) builds the namespaces and hardens the state that
//! is inherited across `exec`; stage 2 ([`exec_inner`]) is PID 1 of the new PID
//! namespace and applies the restrictions that must not touch stage 1, then
//! becomes the command. Why it takes two processes is explained on
//! [`exec_sandboxed`].
//!
//! The mechanisms themselves live one per module — [`ruleset`] for Landlock,
//! [`seccomp`] for the syscall filter, [`hardening`] for the process state that
//! neither can express — and [`apply`] is the one place that sequences all three,
//! in the order they have to happen in.

mod hardening;
mod ruleset;
mod seccomp;

pub use seccomp::BLOCKED_SYSCALLS;

use hardening::{
    bind_lifetime_to_supervisor, confirm_supervisor, prepare_supervisor, set_no_new_privs,
};
use ruleset::{enforcement_verdict, fs_rules, landlock_failed, negotiated_abi};
use seccomp::deny_dangerous_syscalls;

use crate::{HelperArgs, SandboxError};

/// Supervise a sandboxed command: build the namespaces, then run the inner stage
/// inside them.
///
/// This is stage 1 of two. It creates the kernel namespaces the command will live
/// in, hardens the process state that is inherited across `exec`, and then re-execs
/// this same binary once more — into [`exec_inner`], which applies the restrictions
/// that must not touch this process and becomes the command.
///
/// The second re-exec exists for one reason: `unshare(CLONE_NEWPID)` does not move
/// the caller into the new PID namespace, only its children. So the *next* process
/// is PID 1 of it, and spawning one is what the fix for #28 needs. Doing that with
/// `fork` would mean `unsafe` and an async-signal-safety hazard in the
/// `fork`/`exec` window; letting `Command::spawn` do the forking keeps every call
/// here a safe one, which is why `unsafe_code = "forbid"` still holds.
///
/// Intended to run in a freshly executed helper process, never inside sandbx:
/// the namespaces and the capability drops are irreversible for this process, so
/// doing them in sandbx would cage the harness itself.
///
/// On success this never returns: it exits with whatever the command exited with.
/// Any return is an error, and the caller must exit non-zero rather than continue —
/// a helper that fell through to running the command unrestricted would be the
/// exact failure the sandbox exists to prevent.
pub(crate) fn exec_sandboxed(argv: &[String]) -> Result<std::convert::Infallible, SandboxError> {
    // Decoded for this stage's own use — it needs to know whether the policy
    // grants network before choosing the unshare flags. What gets passed on is the
    // argv it was given, verbatim: a re-encode here would be a second chance for
    // the policy to drift on its way to the stage that enforces it.
    let request = HelperArgs::decode(argv)?;

    // Resolved before the namespaces exist, so a failure to find our own binary
    // happens while nothing has been changed yet.
    let exe = crate::command::current_exe()?;

    prepare_supervisor(&request.policy)?;

    // The workspace bans `Command::new` so nothing can spawn around the sandbox.
    // This is sanctioned: what it spawns is this same binary in inner mode, which
    // restricts itself before becoming the command.
    let spawned = {
        #[allow(clippy::disallowed_methods)]
        let mut inner = std::process::Command::new(exe);
        inner
            .arg(crate::HELPER_INNER_FLAG)
            // So the inner stage can confirm we are still here before it hands
            // control to the command. Our own pid, in host numbering, which is
            // what the inner stage will read back out of `/proc`.
            .arg(std::process::id().to_string())
            .args(argv);
        // Ordinarily a no-op: sandbx already narrowed our own environment to the
        // allowlist, so there is nothing left to drop. It is here for the helper
        // invoked directly, which has no sandbx above it to have done that.
        crate::env::restrict(&mut inner, &request.policy);

        inner.spawn()
    };

    let mut child = spawned.map_err(|source| SandboxError::SpawnFailed {
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
/// The caller reads this process's status as the command's, so anything less than
/// a faithful relay would misreport what happened: a signalled death reported as
/// an exit code loses the fact that it was killed, and `sandbx-cli` and the `bash`
/// tool both branch on that distinction.
///
/// Re-raising rather than exiting with `128 + signal` is what makes the status
/// genuinely *signalled* rather than merely numbered like one. It cannot always
/// work, because two dispositions are not ours: Rust's runtime sets `SIGPIPE` to
/// `SIG_IGN`, and installs a `SIGSEGV`/`SIGBUS` handler to report stack overflow.
/// Raising one of those at ourselves therefore returns instead of killing us, and
/// the numbered form is what the caller sees — which is how a shell encodes the
/// same fact, and what `sandbx-cli` derives from a signalled status regardless.
/// Resetting the disposition first would make it exact, and needs `sigaction`,
/// which is `unsafe` and so not available to this crate.
fn relay(status: std::process::ExitStatus) -> Result<std::convert::Infallible, SandboxError> {
    use std::os::unix::process::ExitStatusExt;

    // Re-raised before the numbered form, so a signalled status stays signalled.
    // When the raise returns anyway — the `SIGPIPE`/`SIGSEGV` cases above — the
    // fallback below encodes it the way a shell would.
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
/// A command killed by the sandbox dies by signal and has no exit code of its
/// own; reporting 0 there would say "succeeded" about a process seccomp shot. A
/// status that is neither is refused with 1 rather than given an invented
/// success.
///
/// Lives here, beside the helper that relays a status by exiting with it, so the
/// encoding exists once: `sandbx-cli` reports the same number for the same child
/// without deriving it a second time.
pub fn exit_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;

    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

/// Apply a policy to *this* process, then become the requested command.
///
/// Stage 2 of two, running as the first child of [`exec_sandboxed`] and therefore
/// as PID 1 of the PID namespace it created. Everything here is irreversible and
/// inherited across `exec`, which is what makes the restrictions stick to the real
/// command rather than to this process alone.
///
/// Because this process is fresh, it is single-threaded, and the restriction code
/// runs in an ordinary context — no `fork`/`exec` window, so no
/// async-signal-safety constraint and no `unsafe`.
///
/// On success this never returns: the process image is replaced. Any return is an
/// error, and the caller must exit non-zero rather than continue — a helper that
/// fell through to running the command unrestricted would be the exact failure the
/// sandbox exists to prevent.
pub(crate) fn exec_inner(argv: &[String]) -> Result<std::convert::Infallible, SandboxError> {
    // The supervisor's pid is a positional token ahead of the policy, not part of
    // it: `HelperArgs` describes what the command may do, and this describes who is
    // watching. Keeping them apart leaves the policy grammar and its round-trip
    // untouched, and means a caller reaching `exec_inner` directly cannot pass a
    // policy that smuggles one in.
    let (supervisor, argv) = argv.split_first().ok_or(SandboxError::BadHelperArgs {
        detail: "inner helper mode without a supervisor pid",
    })?;

    let request = HelperArgs::decode(argv)?;

    bind_lifetime_to_supervisor()?;
    confirm_supervisor(supervisor)?;

    // Stage 1 narrowed this process's environment before spawning it, so on every
    // supported path there is nothing here outside the allowlist. Checked rather
    // than trusted, and deliberately not folded into `confirm_supervisor`: that is
    // a liveness check and explicitly not a trust boundary (see
    // `HELPER_INNER_FLAG`), so a caller invoking the inner stage directly can
    // arrive with a full environment and is refused here rather than narrowed.
    //
    // A check and not a second `restrict` because both stages narrow the same
    // environment: either call could be deleted and the other would cover for it,
    // leaving the command's `environ` identical and no test able to tell. This is
    // what makes the stage-1 clear a thing that can fail (#98).
    //
    // A returned error and not an `assert!`: `dispatch_helper_mode` is exhaustive
    // so that a helper run cannot end without either running the command or
    // reporting why not, and a panic leaves through neither — it reports a broken
    // harness invariant as a crash on the command's own stderr. The message names
    // no variable, for the reason
    // `records_how_many_variables_a_spawn_passed_not_which` gives.
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

    // The workspace bans `Command::new` so nothing can spawn around the sandbox.
    // This is the one sanctioned call: `apply` has already restricted this
    // process, so the command inherits the cage rather than escaping it. The
    // allow is per-call-site, not crate-wide, so any other use still fails the
    // lint.
    let error = {
        use std::os::unix::process::CommandExt;
        #[allow(clippy::disallowed_methods)]
        let mut command = std::process::Command::new(&request.program);
        command.args(&request.args);
        // The load-bearing one: this is where the real command is born, so this
        // is the call that decides what it can read out of its own `environ`.
        // The earlier stages narrowing the same environment makes this a no-op
        // on the ordinary path, which is the point — nothing here depends on
        // them having done it. What the check above adds is that a stage which
        // stopped doing it is reported rather than silently covered for.
        crate::env::restrict(&mut command, &request.policy);

        command.exec()
    };

    Err(SandboxError::SpawnFailed {
        detail: "could not execute the sandboxed command",
        source: error,
    })
}

fn apply(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    use landlock::{
        Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr,
    };

    // The namespaces and the capability drops already happened, in the supervisor
    // that spawned this process — see `prepare_supervisor`. Both are inherited, so
    // what is left here is everything that must apply to the command itself and
    // could not be done in a process that still had to spawn one.

    // Installing a seccomp filter requires either CAP_SYS_ADMIN or no_new_privs.
    // Set it explicitly: this process holds no capabilities at all, the supervisor
    // having dropped them. It is irreversible and inherited across exec, which is
    // what makes the filter stick to the real command.
    set_no_new_privs()?;

    deny_dangerous_syscalls(policy)?;

    // Settle on one ABI and hard-require all of it, rather than pinning a floor
    // and taking whatever else the kernel happens to offer. Everything handled is
    // therefore enforced, which is what lets `enforcement_verdict` refuse a
    // partial result instead of accepting it as routine.
    let abi = negotiated_abi()?;

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(landlock_failed)?
        .create()
        .map_err(landlock_failed)?;

    // `fs_rules` decides what to install; this loop only opens the paths. The
    // axis each rule came from is for the tests that assert the mapping — the
    // kernel is told the rights and nothing else.
    //
    // The same `abi` the ruleset handles: a rule carrying a right outside the
    // handled set would be narrowed by `PathBeneath` and take the whole ruleset
    // to `PartiallyEnforced`, which is now a refusal.
    for (_, path, rights) in fs_rules(policy, abi) {
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

    /// A `wait(2)` status as the kernel encodes one, for a process that exited of
    /// its own accord with `code`. `ExitStatus::from_raw` takes exactly that
    /// encoding, and it is safe — so the three shapes below can be built here
    /// rather than reached by spawning a process, which is what kept [`exit_code`]
    /// testable only behind `sandbox-integration` until now (#91).
    fn exited(code: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt;

        std::process::ExitStatus::from_raw(code << 8)
    }

    /// The same, for a process killed by `signal`. The signal number occupies the
    /// low seven bits, which is why an exit code occupies the byte above them.
    fn killed_by(signal: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt;

        std::process::ExitStatus::from_raw(signal)
    }

    /// An exit code is reported as itself, so a command's own verdict reaches the
    /// caller unaltered.
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

    /// A command the sandbox killed dies by signal and has no exit code of its
    /// own. `128 + signal` is how a shell encodes that, and both callers —
    /// [`relay`] and `sandbx-cli` — depend on the number being that and not 0,
    /// which would report "succeeded" about a process seccomp shot.
    #[test]
    fn a_signalled_death_is_reported_as_128_plus_the_signal() {
        for signal in [libc::SIGKILL, libc::SIGSEGV, libc::SIGPIPE] {
            assert_eq!(
                exit_code(&killed_by(signal)),
                128 + signal,
                "a command killed by {signal} must report 128 + the signal"
            );
        }
    }

    /// A status that is neither an exit nor a death is refused with 1 rather than
    /// given an invented success. A stop is the shape the low byte reserves for
    /// one, and it is the only way to reach that arm.
    ///
    /// The premise is asserted first and deliberately: if a future libc or std
    /// changes what this encoding decodes to, this says "the input stopped being
    /// the case it was written for" instead of quietly re-testing the signal arm
    /// above.
    #[test]
    fn a_status_that_is_neither_an_exit_nor_a_death_reports_failure() {
        use std::os::unix::process::ExitStatusExt;

        // 0x7f in the low byte is `WSTOPPED`; the signal that stopped it sits
        // above, where an exit code would.
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
