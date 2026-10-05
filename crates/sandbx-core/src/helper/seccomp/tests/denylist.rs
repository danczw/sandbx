//! The unconditional denylist, the filter's polarity, and whether the program is one
//! the kernel would load at all.

use super::*;

#[test]
fn blocked_syscalls_covers_the_whole_denylist() {
    let blocked = blocked_syscalls(&SandboxPolicy::default()).unwrap();

    for nr in BLOCKED_SYSCALLS {
        let rules = blocked
            .get(nr)
            .unwrap_or_else(|| panic!("{nr} missing from the filter"));

        // An entry with rules matches only those argument values, leaving the syscall
        // reachable for every other — narrower than the list claims.
        assert!(
            rules.is_empty(),
            "{nr} is filtered conditionally, but the denylist claims it outright"
        );
    }
}

/// This is a denylist, so a syscall the filter does not name has to be allowed. Swap
/// the two actions in [`compiled_filter`] and this becomes `EPERM` — a sandbox that
/// refuses every syscall and permits the dangerous ones.
///
/// Evaluated rather than read off the program's last instruction, where seccompiler
/// happens to emit the mismatch action but is not required to.
#[test]
fn a_syscall_the_filter_does_not_name_is_allowed() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();

    assert_eq!(
        verdict(&program, libc::SYS_getpid),
        ALLOW,
        "an unlisted syscall is refused, so the filter's polarity is inverted \
         and the sandbox blocks everything except the denylist"
    );
}

/// The other half of the polarity, needed alongside the fallthrough because either
/// alone admits one of the two broken filters.
///
/// What the kernel then does with the program is out of reach here: its effective
/// action is the most severe across *every* installed filter, so "the program returns
/// `ALLOW`" is not "the syscall runs". The `sandbox-integration` suite establishes
/// that; this pins what sandbx asked for.
#[test]
fn every_denylisted_syscall_is_refused_with_eperm() {
    let program = compiled_filter(&SandboxPolicy::default()).unwrap();

    // Or the loop below asserts nothing at all.
    assert!(
        !BLOCKED_SYSCALLS.is_empty(),
        "the denylist is empty, so this test is vacuous"
    );

    for nr in BLOCKED_SYSCALLS {
        assert_eq!(
            verdict(&program, *nr),
            EPERM,
            "syscall {nr} is on the denylist but the filter does not refuse it"
        );
    }
}

/// `compiled_filter` with its two actions swapped, built from the same
/// `blocked_syscalls` data.
///
/// A twin, not the real path: if `compiled_filter` does more than call
/// `SeccompFilter::new`, this stops being a mutation of it. Change both.
fn inverted_filter(policy: &crate::SandboxPolicy) -> seccompiler::BpfProgram {
    use seccompiler::{SeccompAction, SeccompFilter};

    let filter = SeccompFilter::new(
        blocked_syscalls(policy).unwrap(),
        // Swapped: in `deny_with` the first is `Allow`, the second `Errno(errno)`.
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into().unwrap(),
    )
    .unwrap();

    filter.try_into().unwrap()
}

/// Would the other tests notice if the filter pointed the other way?
///
/// Proves their assertions have mutation-killing power, and says nothing about
/// production polarity: if [`compiled_filter`] were inverted this test would still
/// pass and they would fail, because this one asserts about [`inverted_filter`],
/// a copy.
///
/// Three verdicts, because the inversion has three distinguishable effects: the
/// denylist opens, the fallthrough closes, and the conditional rule inverts with the
/// unconditional ones.
#[test]
fn inverting_the_two_actions_inverts_every_verdict() {
    let program = inverted_filter(&SandboxPolicy::default());

    assert_eq!(
        verdict(&program, libc::SYS_ptrace),
        ALLOW,
        "swapping the actions left the denylist refused, so the real tests \
         would not notice the swap"
    );
    assert_eq!(
        verdict(&program, libc::SYS_getpid),
        EPERM,
        "swapping the actions left the fallthrough allowed, so the real tests \
         would not notice the swap"
    );
    assert_eq!(
        socket_verdict(&program, libc::AF_UNIX as u64),
        ALLOW,
        "swapping the actions left socket(AF_UNIX) refused, so the real tests \
         would not notice the swap"
    );
}

/// Is the program one the kernel would load at all?
///
/// Evaluation covers only the paths its data takes, and a wrong jump offset passes
/// unnoticed. These checks close the rest, and every one is `bpf_check_classic()`
/// restated rather than anything about seccompiler's codegen — the last-instruction
/// check included.
///
/// Asked of the widest policy as well as the default one, because that is the one whose
/// program grows: a port allowlist adds seventeen rules on `socket` alone, and the kernel
/// refuses a filter over 4096 instructions.
#[test]
fn the_program_is_one_the_kernel_would_accept() {
    let widest = SandboxPolicy::default()
        .allow_network_port(443)
        .allow_unix_sockets();

    for policy in [SandboxPolicy::default(), widest] {
        let filters = installed_filters(&policy).unwrap();

        // Or the loop below checks nothing, and `x32_gate` — the one hand-assembled
        // program here, and so the one most likely to be malformed — goes unexamined.
        assert_eq!(
            filters.len(),
            if cfg!(target_arch = "x86_64") { 3 } else { 2 },
            "a filter was added or dropped without this test being told which"
        );

        for program in filters {
            check_program_is_well_formed(&program);
        }
    }
}

fn check_program_is_well_formed(program: seccompiler::BpfProgramRef<'_>) {
    let len = program.len();

    // `bpf_check_classic` refuses `flen == 0 || flen > BPF_MAXINSNS`, so 4096 is the
    // largest filter the kernel loads. seccompiler's own `BPF_MAX_LEN` guard is
    // stricter (it errors at `>=` 4096), so a program can only fail this by being
    // empty — stated as the kernel's bound anyway, for whoever chases a real
    // `FilterTooLarge`.
    assert!(
        (1..=4096).contains(&len),
        "a filter the kernel would load holds 1 to 4096 instructions, this one \
         holds {len}"
    );

    // `BPF_CLASS(code)`, linux/filter.h.
    const CLASS: u16 = 0x07;
    let last = &program[len - 1];
    assert_eq!(
        last.code & CLASS,
        libc::BPF_RET as u16,
        "the program does not end in a return, so the kernel would refuse the \
         filter: {last:?}"
    );

    let mut verdicts = std::collections::BTreeSet::new();
    for (pc, insn) in program.iter().enumerate() {
        assert!(
            KNOWN_OPCODES.contains(&insn.code),
            "opcode {:#x} at pc {pc} is outside the set `eval` interprets: {insn:?}",
            insn.code
        );

        let next = pc + 1;
        if insn.code == LD_W_ABS {
            assert!(
                insn.k % 4 == 0 && insn.k < 64,
                "the load at pc {pc} is unaligned or reaches outside the 64-byte \
                 seccomp_data: {insn:?}"
            );
        } else if insn.code == JA {
            let target = next + usize::try_from(insn.k).unwrap();
            assert!(
                target < len,
                "the jump at pc {pc} targets {target}, outside a program of {len}: \
                 {insn:?}"
            );
        } else if insn.code == JEQ_K || insn.code == JGT_K || insn.code == JGE_K {
            for target in [next + usize::from(insn.jt), next + usize::from(insn.jf)] {
                assert!(
                    target < len,
                    "a branch at pc {pc} targets {target}, outside a program of \
                     {len}: {insn:?}"
                );
            }
        } else if insn.code == RET_K {
            verdicts.insert(insn.k);
        }
    }

    let expected = std::collections::BTreeSet::from([ALLOW, EPERM, ENOSYS, KILL]);
    assert!(
        verdicts.is_subset(&expected),
        "the filter can return a verdict it was never asked for: {verdicts:x?}"
    );
}
