//! `prctl(PR_SET_PDEATHSIG)`, the call that would unbind the command from its supervisor.

use super::*;

/// The verdict for `prctl(option, arg2, …)`.
fn prctl_verdict(program: seccompiler::BpfProgramRef<'_>, option: u64, arg2: u64) -> u32 {
    verdict_with_args(program, libc::SYS_prctl, [option, arg2, 0, 0, 0, 0])
}

/// Every value but `SIGKILL` disarms the parent death signal: 0 clears it, and anything else
/// reaches PID 1 of a namespace with the default disposition, which the kernel ignores.
#[test]
fn the_command_cannot_disarm_its_parent_death_signal() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();
    let option = libc::PR_SET_PDEATHSIG as u64;

    for signal in [0, libc::SIGTERM, libc::SIGCHLD, libc::SIGHUP] {
        assert_eq!(
            prctl_verdict(&program, option, signal as u64),
            EPERM,
            "prctl(PR_SET_PDEATHSIG, {signal}) is permitted, so a command that leaves the \
             process group outlives the supervisor's death"
        );
    }
}

/// Re-arming with `SIGKILL` costs nothing, and a runtime arming its own children — Go's
/// `Pdeathsig` — fails the spawn if refused. Also what makes the test above not vacuous: a
/// filter denying `prctl` outright would pass it.
#[test]
fn arming_sigkill_and_other_prctl_calls_are_allowed() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();

    for (what, option, arg2) in [
        (
            "PR_SET_PDEATHSIG, SIGKILL",
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL,
        ),
        ("PR_SET_NAME", libc::PR_SET_NAME, 0),
        ("PR_GET_PDEATHSIG", libc::PR_GET_PDEATHSIG, 0),
    ] {
        assert_eq!(
            prctl_verdict(&program, option as u64, arg2 as u64),
            ALLOW,
            "prctl({what}) is refused, so the rule has widened past disarming"
        );
    }
}

/// `prctl` takes `option` as an `int`, so the kernel never sees its high half and a `Qword`
/// rule would let `0xdead_beef_0000_0001` through.
#[test]
fn the_prctl_option_comparison_ignores_the_high_half() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();
    let option = 0xdead_beef_0000_0000 | libc::PR_SET_PDEATHSIG as u64;

    assert_eq!(
        prctl_verdict(&program, option, 0),
        EPERM,
        "garbage in the high half of prctl's option escapes the rule"
    );
}
