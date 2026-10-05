//! The architecture gates: a foreign ABI, and on x86_64 the x32 one that shares this
//! architecture's audit value.

use super::*;

/// x32 syscalls reach the kernel with [`X32_SYSCALL_BIT`] set in `nr`, under the same
/// `AUDIT_ARCH_X86_64` the filter gates on, so the denylist's native numbers never
/// match them (#117).
#[cfg(target_arch = "x86_64")]
#[test]
fn the_x32_abi_is_killed_whatever_the_syscall() {
    let program = x32_gate();

    // `unshare` is the demonstration: a `common` syscall, so x32 reaches it at the
    // native number with the bit set. `ptrace` sits at a *different* x32 number
    // (521), which is why the gate is a mask rather than a list.
    for (what, nr) in [
        (
            "unshare",
            X32_SYSCALL_BIT as libc::c_long | libc::SYS_unshare,
        ),
        (
            "ptrace at its x32 number",
            X32_SYSCALL_BIT as libc::c_long | 521,
        ),
        (
            "an x32 syscall sandbx does not denylist",
            X32_SYSCALL_BIT as libc::c_long | libc::SYS_getpid,
        ),
    ] {
        assert_eq!(
            verdict(&program, nr),
            KILL,
            "{what} survives the x32 gate, so the whole denylist can be bypassed \
             by setting one bit in the syscall number"
        );
    }
}

/// The gate keys on one bit, so it must leave every native syscall alone — otherwise
/// it would kill the command outright and the test above would still pass.
#[cfg(target_arch = "x86_64")]
#[test]
fn the_x32_gate_lets_native_syscalls_through() {
    let program = x32_gate();

    for nr in [libc::SYS_getpid, libc::SYS_ptrace, libc::SYS_clone] {
        assert_eq!(
            verdict(&program, nr),
            ALLOW,
            "the x32 gate judges native syscall {nr}, which is the denylist \
             filter's job"
        );
    }
}

/// A negative `nr` carries bit 30 like an x32 number does, but is not one.
///
/// `syscall(-1)` is legal to pass and every kernel answers `ENOSYS`; a bare mask over
/// bit 30 kills it instead, by a signal and with nothing on stderr. The rest of this
/// file assumes that call is survivable — `seccomp_data` passes `nr` through as a
/// signed `int` for exactly this reason.
#[cfg(target_arch = "x86_64")]
#[test]
fn the_x32_gate_never_kills_a_negative_number() {
    let program = x32_gate();

    for nr in [-1, -2, libc::c_long::from(i32::MIN)] {
        assert_eq!(
            verdict(&program, nr),
            ALLOW,
            "syscall({nr}) is killed by the x32 gate, but the sign bit means it is \
             not an x32 number — the kernel would answer ENOSYS"
        );
    }
}

/// `CLONE_NEWNET` and [`X32_SYSCALL_BIT`] are both `0x4000_0000`, in different fields.
/// Pinned because the two rules added together read as if one constant could serve
/// both, and a shared constant would couple a syscall number to a clone flag.
#[cfg(target_arch = "x86_64")]
#[test]
fn the_x32_bit_and_clone_newnet_only_share_a_value() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();

    assert_eq!(
        verdict(&program, X32_SYSCALL_BIT as libc::c_long | libc::SYS_getpid),
        ALLOW,
        "the denylist filter reacts to the x32 bit in `nr`, so a clone flag has \
         leaked into a syscall-number comparison"
    );
}

/// A process reporting a different architecture is killed, not refused.
///
/// Syscall numbers are per-architecture, so a filter built for one cannot say anything
/// safe about calls arriving from another; `seccomp_data.arch` is how the kernel
/// tells, and seccompiler gates every filter on it before the first comparison. So an
/// i386 binary on x86_64, or AArch32 on aarch64, dies rather than seeing `EPERM`,
/// unlike every other denial these tests make.
///
/// Uses a *blocked* number, so the test shows the gate short-circuits the chain.
#[test]
fn a_syscall_from_another_architecture_is_killed() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();

    assert_eq!(
        verdict_from_arch(&program, libc::SYS_ptrace, AUDIT_ARCH ^ 1),
        KILL,
        "a syscall from another architecture is not killed, so the filter is \
         applying this architecture's syscall numbers to a foreign ABI"
    );
}

/// A diagnostic, not evidence about the filter. [`AUDIT_ARCH`] is transcribed from
/// `linux/audit.h`, and if it stops matching seccompiler's
/// `TargetArch::get_audit_value` then most tests across these modules fail as
/// "expected ALLOW, got 0x80000000" and name nothing. This localizes that failure.
///
/// Positionless: that the gate is the program's *first* instruction is seccompiler's
/// codegen, not ABI.
#[test]
fn the_filter_gates_on_the_arch_this_test_models() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();

    assert!(
        program
            .iter()
            .any(|insn| insn.code == JEQ_K && insn.k == AUDIT_ARCH),
        "the filter never compares against {AUDIT_ARCH:#x}, so `AUDIT_ARCH` in \
         this test no longer matches seccompiler's audit value for this \
         architecture. Fix that constant before reading anything into the other \
         failures here."
    );
}
