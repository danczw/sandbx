//! The two-stage re-exec that turns a plain process into a sandboxed command.
//!
//! Stage 1 ([`exec_sandboxed`]) makes the namespaces and hardens the state inherited
//! across `exec`; stage 2 ([`exec_inner`]) is PID 1 of the new PID namespace and becomes
//! the command. [`apply`] sequences [`ruleset`], [`seccomp`] and [`hardening`] in the
//! order they have to happen in — one ordered syscall sequence, so one module
//! (`context/guide-module-layout.md`).

mod hardening;
mod ruleset;
mod seccomp;

pub use seccomp::BLOCKED_SYSCALLS;

use hardening::{
    bind_lifetime_to_supervisor, confirm_supervisor, prepare_supervisor, set_no_new_privs,
};
use ruleset::{Requested, RequestedNet, enforcement_verdict, landlock_failed, requested};
use seccomp::deny_dangerous_syscalls;

use crate::{HelperArgs, SandboxError};

/// Argument telling a helper stage that its stdin is the audit channel.
///
/// Opt-in, and not implied by [`HELPER_FLAG`](crate::HELPER_FLAG): without it a
/// hand-invoked helper would write records into whatever fd 0 happens to be — a terminal is
/// writable, so they appear as the command's own output, and a read-only pipe gives `EBADF`.
/// A degradation then goes unrecorded, the honest outcome with nowhere to record it.
///
/// Stage 1 passes it on to stage 2, both stages reporting their own refusals on it.
pub(crate) const AUDIT_STDIN_FLAG: &str = "--sandbx-audit-stdin";

/// Write already-encoded records to the parent, on the pipe it put in our stdin slot.
///
/// Every failure is swallowed: a lost record, not a reason to refuse a command the parent
/// has already been told is running — a refusal included, the parent still having the
/// relayed exit status.
///
/// The stdin slot because it is the only descriptor std can hand a child without `unsafe`,
/// which this crate forbids; `try_clone_to_owned` makes the inherited fd writable, `Stdin`
/// being a reader over a descriptor opened for writing. See
/// `context/decision-helper-audit-channel.md`.
fn report(records: &str) {
    use std::io::Write;
    use std::os::fd::AsFd;

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

/// Narrow this process into the supervisor and start the stage below it, or say why it
/// could not.
///
/// One region, so one site reports every refusal of stage 1's (#160). Both edges are load
/// bearing: stage 2 does not exist anywhere inside here, so at most one refusal reaches the
/// channel, and every refusal inside here is one
/// [`REPORTED_BY_HELPER`](SandboxError::REPORTED_BY_HELPER) admits, so the write needs no
/// second check.
fn start_inner_stage(
    exe: std::path::PathBuf,
    argv: &[String],
    audit_on_stdin: bool,
) -> Result<std::process::Child, SandboxError> {
    // Decoded for this stage's own use: the unshare flags depend on whether the policy
    // grants network. The argv is passed on verbatim — a re-encode would be a second chance
    // for the policy to drift on its way to the stage that enforces it.
    let request = HelperArgs::decode(argv)?;

    let degraded = prepare_supervisor(&request.policy)?;

    // Before the spawn below, so this stage's records reach the channel ahead of anything
    // the stage below reports. Nothing is read back: a best-effort record must not fail a
    // run that is otherwise fine.
    if audit_on_stdin {
        report(&crate::degradation::encode(&degraded));
    }

    // This same binary in inner mode, which restricts itself before becoming the command.
    // `spawn::command` narrows the environment as it builds it: ordinarily a no-op, sandbx
    // having narrowed ours, and load-bearing for a helper invoked directly with no sandbx
    // above it.
    let mut inner = crate::spawn::command(exe, &request.policy);
    inner
        .arg(crate::HELPER_INNER_FLAG)
        // So the inner stage can confirm we are still here before it hands control
        // to the command. Host numbering, which is what it reads back from `/proc`.
        .arg(std::process::id().to_string());

    // Handed down rather than nulled here: a command that could not be `exec`ed is a fact
    // only the stage below has, so taking fd 0 away is its job — see `claim_audit_channel`.
    // Without the flag stdin stays inherited, which a hand-invoked `sandbx-helper` needs
    // for a command that reads its own input.
    if audit_on_stdin {
        inner.arg(AUDIT_STDIN_FLAG);
    }

    inner.args(argv);

    // Not `SpawnFailed`, which the channel does not admit: two callers return it, so it
    // names no single decider.
    inner
        .spawn()
        .map_err(|source| SandboxError::InnerStageFailed {
            detail: "could not start the inner sandbox stage",
            source,
        })
}

/// Supervise a sandboxed command: build the namespaces, then run the inner stage
/// inside them.
///
/// Stage 1 of two. The second re-exec exists for one reason: `unshare(CLONE_NEWPID)` does
/// not move the caller into the new PID namespace, only its children, so the *next* process
/// is PID 1 of it. Letting `Command::spawn` do that forking keeps every call here safe —
/// `fork` would mean `unsafe` and an async-signal-safety hazard in the `fork`/`exec` window
/// — so `unsafe_code = "forbid"` still holds.
///
/// Must run in a freshly executed helper process, never inside sandbx: the namespaces and
/// the capability drops are irreversible for this process, so doing them in sandbx would
/// cage the harness itself.
///
/// On success this never returns: it exits with whatever the command exited with. Any
/// return is an error, and the caller must exit non-zero rather than fall through to
/// running the command unrestricted.
pub(crate) fn exec_sandboxed(argv: &[String]) -> Result<std::convert::Infallible, SandboxError> {
    // Split off before `decode`, which refuses a flag it does not recognise. Not part of
    // the policy grammar, for the reason the supervisor pid is not (see `exec_inner`): it
    // describes how to report, not what the command may do.
    let (audit_on_stdin, argv) = match argv.split_first() {
        Some((flag, rest)) if flag == AUDIT_STDIN_FLAG => (true, rest),
        _ => (false, argv),
    };

    // Before anything has changed, and outside the region that reports: its `spawn_failed`
    // is a label the channel does not admit. It is `/proc/self/exe` unresolved, which the
    // forked child reads as the image it inherited rather than as a second lookup.
    let exe = crate::command::self_exe()?;

    let started = start_inner_stage(exe, argv, audit_on_stdin);

    // Without this the trail cannot tell a refusal from a command that ran and exited 1:
    // this stage exits non-zero and the parent has only that status (#160).
    if let (true, Err(error)) = (audit_on_stdin, &started) {
        report(&crate::degradation::encode_refusal(error.label()));
    }

    let mut child = started?;

    // Off the channel: stage 2 exists by now and may have reported its own, more specific
    // refusal, and the parent's last record wins — so a record here would displace it.
    let status = child.wait().map_err(|source| SandboxError::SpawnFailed {
        detail: "could not wait for the sandboxed command",
        source,
    })?;

    relay(status)
}

/// Exit the way the inner stage exited.
///
/// The caller reads this process's status as the command's, and `sandbx-cli` and the `bash`
/// tool both branch on signalled-versus-exited.
///
/// Re-raising rather than exiting with `128 + signal` is what makes the status genuinely
/// *signalled*. It cannot always work: Rust's runtime sets `SIGPIPE` to `SIG_IGN` and
/// handles `SIGSEGV`/`SIGBUS` to report stack overflow, so raising one of those at ourselves
/// returns instead of killing us and the caller sees the numbered form — which is how a
/// shell encodes the same fact. Resetting the disposition first would need `sigaction`,
/// which is `unsafe`.
fn relay(status: std::process::ExitStatus) -> Result<std::convert::Infallible, SandboxError> {
    use std::os::unix::process::ExitStatusExt;

    // Re-raised before the numbered form, so a signalled status stays signalled. When the
    // raise returns anyway — the `SIGPIPE`/`SIGSEGV` cases above — the fallback encodes it
    // the way a shell would.
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
/// A command the sandbox killed dies by signal and has no exit code of its own; reporting 0
/// there would say "succeeded" about a process seccomp shot. A status that is neither is
/// refused with 1 rather than given an invented success. Lives beside `relay`, so
/// `sandbx-cli` reports the same number without deriving it again.
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
/// On success this never returns: the process image is replaced. Any return is an error, and
/// the caller must exit non-zero rather than fall through to running the command
/// unrestricted.
pub(crate) fn exec_inner(argv: &[String]) -> Result<std::convert::Infallible, SandboxError> {
    // A positional token ahead of the policy, not part of it: `HelperArgs` describes what
    // the command may do, this who is watching. Apart, the policy grammar and its
    // round-trip stay untouched and a caller reaching `exec_inner` directly cannot pass a
    // policy that smuggles one in.
    let (supervisor, argv) = argv.split_first().ok_or(SandboxError::BadHelperArgs {
        detail: "inner helper mode without a supervisor pid",
    })?;

    // Split off for the reason the pid above is, and in the order stage 1 wrote them.
    let (audit_on_stdin, argv) = match argv.split_first() {
        Some((flag, rest)) if flag == AUDIT_STDIN_FLAG => (true, rest),
        _ => (false, argv),
    };

    // Early, so every refusal below is reportable, and before `apply`, so no filter it
    // installs can be what refuses the `dup` or `/dev/null`. Unreportable above here: a
    // missing supervisor pid, and this call's own failure.
    let mut channel = match audit_on_stdin {
        true => Some(claim_audit_channel()?),
        false => None,
    };

    let refusal = restrict_and_exec(supervisor, argv);

    // Without this the trail cannot tell a refusal from a command that ran and exited 1:
    // this stage exits non-zero and stage 1 relays that status on the command's behalf.
    // Swallowed — a lost record must not fail a run the parent was already told about.
    if let (Some(channel), Err(error)) = (&mut channel, &refusal) {
        use std::io::Write;

        let _ = channel.write_all(crate::degradation::encode_refusal(error.label()).as_bytes());
    }

    refusal
}

/// Restrict this process and become the command, or say why it could not.
///
/// The channel is claimed before this is called; nothing here may claim it again.
fn restrict_and_exec(
    supervisor: &str,
    argv: &[String],
) -> Result<std::convert::Infallible, SandboxError> {
    let request = HelperArgs::decode(argv)?;

    bind_lifetime_to_supervisor()?;
    confirm_supervisor(supervisor)?;

    // A check, not a re-narrowing: `spawn::command` is the only `Command` builder in the
    // crate and narrows by construction, so clearing again would answer with silence — the
    // command's `environ` comes out identical either way. Not folded into
    // `confirm_supervisor`, a liveness check and explicitly not a trust boundary (see
    // `HELPER_INNER_FLAG`): a caller reaching the inner stage directly arrives with a full
    // environment and is refused here rather than narrowed.
    //
    // An error and not an `assert!`: `dispatch_helper_mode` is exhaustive so a helper run
    // cannot end without either running the command or reporting why not, and a panic
    // leaves through neither. The message names no variable, for the reason
    // `records_how_many_variables_passed_not_which` gives.
    //
    // `permits_env` and not `allowed_env`: it is the predicate `spawn::command` builds
    // from, so a variable the policy *imposes* cannot refuse the run.
    if std::env::vars_os().any(|(name, _)| !request.policy.permits_env(&name)) {
        return Err(SandboxError::ProcessHardening {
            detail: "the inner stage inherited a variable the policy does not permit; \
                     an earlier stage did not narrow the environment"
                .to_string(),
        });
    }

    apply(&request.policy)?;

    // After `apply`, so the descriptor is provably one the policy authorizes: opening first
    // would hash a file no grant covers and report a mismatch where the honest answer is a
    // denied read. The command below inherits the cage for the same reason — `exec` keeps
    // every restriction `apply` installed, and `spawn::command` narrowing the environment
    // there is what decides what the real command reads out of its own `environ`.
    let image = request
        .pin
        .map(|expected| crate::digest::open_verified(&request.program, expected))
        .transpose()?;

    let error = {
        use std::os::unix::process::CommandExt;
        // The descriptor that was hashed, named so the kernel opens that same inode; the
        // handle outlives the `exec` below, which is what keeps the name valid.
        let program = image.as_ref().map(crate::digest::fd_path);
        let program = program.as_deref().unwrap_or(request.program.as_ref());

        let mut command = crate::spawn::command(program, &request.policy);
        // Unconditional, so a matching pin changes nothing the command can observe: without
        // it `$0` would be the procfs path, which `ps` and a multi-call binary both read.
        command.arg0(&request.program);
        command.args(&request.args);

        // Returns only on failure, and the channel duplicate is close-on-exec, so the
        // caller's record can only be written where the command does not exist.
        command.exec()
    };

    Err(SandboxError::ExecFailed { source: error })
}

/// Take the audit channel out of the stdin slot, leaving the command a null one.
///
/// The duplicate is `F_DUPFD_CLOEXEC`, so a successful `exec` closes it and the command
/// inherits `/dev/null`. Both halves matter: a command holding the write end could forge
/// records, or hold the channel open and leave the parent waiting on an EOF that never
/// comes. One half each: `the_command_cannot_write_the_audit_channel` pins the slot,
/// `the_command_inherits_no_other_end_of_the_channel` the duplicate.
///
/// Fails closed — becoming the command with the channel still on fd 0 is the worse outcome.
fn claim_audit_channel() -> Result<std::fs::File, SandboxError> {
    use std::os::fd::AsFd;

    let refused = |step: &str, source: &dyn std::fmt::Display| SandboxError::ProcessHardening {
        detail: format!("{step}: {source}"),
    };

    let channel = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|source| refused("could not take the audit channel off stdin", &source))?;

    let null = std::fs::File::open("/dev/null")
        .map_err(|source| refused("could not open /dev/null for the command", &source))?;

    nix::unistd::dup2_stdin(&null)
        .map_err(|source| refused("could not put /dev/null in the stdin slot", &source))?;

    Ok(std::fs::File::from(channel))
}

fn apply(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    use landlock::{
        CompatLevel, Compatible, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr,
    };

    // The namespaces and the capability drops already happened in the supervisor — see
    // `prepare_supervisor` — and both are inherited. What is left is everything that must
    // apply to the command itself and could not be done in a process that still had to
    // spawn one.

    // Installing a seccomp filter requires either CAP_SYS_ADMIN or no_new_privs, and this
    // process holds no capabilities at all, the supervisor having dropped them.
    // Irreversible and inherited across exec, which makes the filter stick to the command.
    set_no_new_privs()?;

    deny_dangerous_syscalls(policy)?;

    // One ABI, hard-required in full, so everything handled is enforced and
    // `enforcement_verdict` can refuse a partial result. The negotiation happens inside
    // `requested`, so no ABI is in scope here and the handled set cannot come from a
    // different one than the rules. Destructured for the reason `Requested` gives.
    let Requested {
        handled,
        rules,
        net,
    } = requested(policy)?;

    // Landlock splits `handle_access`, which must precede `create`, from `add_rule`, which
    // must follow it. Decided once so both uses below are gated on the same `Option` and no
    // path installs a port rule without handling the axis.
    let (net_axis, net_ports) = match net {
        RequestedNet::Unhandled => (None, &[][..]),
        RequestedNet::Ports {
            handled,
            granted,
            ports,
        } => (Some((handled, granted)), ports),
    };

    let mut builder = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled)
        .map_err(landlock_failed)?;

    if let Some((handled, _)) = net_axis {
        builder = builder.handle_access(handled).map_err(landlock_failed)?;
    }

    let mut ruleset = builder.create().map_err(landlock_failed)?;

    // `Requested` decides what to install; this loop only opens the paths. The axis is for
    // the tests that assert the mapping — the kernel is told the rights and nothing else.
    for (_, path, rights) in rules {
        let fd = PathFd::new(path).map_err(landlock_failed)?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, rights))
            .map_err(landlock_failed)?;
    }

    // Under the `HardRequirement` set above, a port rule carrying a right the ruleset does
    // not handle is an error rather than a right the kernel quietly drops.
    if let Some((_, granted)) = net_axis {
        for port in net_ports {
            ruleset = ruleset
                .add_rule(NetPort::new(*port, granted))
                .map_err(landlock_failed)?;
        }
    }

    let status = ruleset.restrict_self().map_err(landlock_failed)?;

    enforcement_verdict(status.ruleset)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `wait(2)` status as the kernel encodes one for a process that exited with `code`.
    /// `ExitStatus::from_raw` takes exactly that encoding, so nothing here spawns.
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
    /// reach that arm. The premise is asserted first: a future libc or std decoding this
    /// encoding differently says so, rather than quietly re-testing the signal arm above.
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
