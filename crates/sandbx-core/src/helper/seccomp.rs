//! The seccomp syscall filter applied to the sandboxed command.
//!
//! Covers the escapes Landlock cannot see: a syscall that reaches the kernel
//! without naming a path. The denylist is a constant so a test can assert the
//! installed filter still matches it, and `super::apply` installs it.

use crate::SandboxError;

/// Syscalls blocked for every sandboxed command, regardless of policy.
///
/// A denylist, not an allowlist. An allowlist is the stronger shape, but sandbx
/// runs arbitrary commands — shells, compilers, package managers — whose syscall
/// use is unbounded, so enumerating it would break real tools constantly. This
/// mirrors what container runtimes settle on for the same reason.
///
/// Landlock cannot express any of these: they are not filesystem access. That is
/// why both layers exist rather than one.
///
/// Lifted out of `deny_dangerous_syscalls` so a test can assert the list still
/// contains what `SECURITY.md` claims it does. The filter is built from this and
/// nothing else, so the two cannot drift.
pub const BLOCKED_SYSCALLS: &[libc::c_long] = &[
    // Inspect or modify other processes.
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    // Reshape the filesystem out from under Landlock.
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    // Escape or re-create namespaces, including the netns just entered.
    libc::SYS_setns,
    libc::SYS_unshare,
    // Load code into the kernel.
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_bpf,
    libc::SYS_kexec_load,
    // Kernel keyring: credentials live here.
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_keyctl,
    // Tracing infrastructure, a known side-channel surface.
    libc::SYS_perf_event_open,
    // Handles on another process. `pidfd_getfd` takes a descriptor *out* of a
    // process that holds one — a socket, an open file above the policy — which is
    // not filesystem access, so Landlock cannot express it and `ptrace` being
    // denied does not cover it. `pidfd_open` is how the handle is obtained in the
    // first place, so both go.
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_getfd,
    // userfaultfd hands the faulting process control over when a page fault
    // resolves, which turns any check-then-use in the kernel into an arbitrarily
    // wide window. It is a recurring ingredient in kernel exploits and no coding
    // tool needs it.
    libc::SYS_userfaultfd,
    // io_uring runs operations from a submission queue without issuing the
    // matching syscalls, so a ring set up here would be a route around every
    // rule in this filter — including the `socket(AF_UNIX)` denial that
    // `deny_dangerous_syscalls` adds on top of this list.
    // Deny the ring itself. A coding agent has no need for it, and container
    // runtimes disable it in their default profiles for the same reason.
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    // An anonymous in-memory file has no path on any filesystem, and Landlock
    // binds its rules to inodes and paths — so a payload staged in a memfd sits
    // outside everything the filesystem layer can see. Denying the syscall is the
    // only layer that reaches it.
    //
    // This one has a real compatibility cost, unlike the rest of this list, though
    // a narrower one than it first looked: the heavy users are container runtimes
    // (runc keeps a sealed memfd copy of its own binary and re-execs it from
    // `/proc/self/fd/<n>` as its CVE-2019-5736 self-protection), systemd and snapd.
    // A coding tool does none of that, and running a container runtime in here is
    // already impossible — `unshare` is denied above. An ordinary program can still
    // call it deliberately, which is the case to watch.
    //
    // It is denied because no caller needs it yet, so the restrictive default is
    // the one to start from and loosen on evidence — if a real tool turns out to
    // break, that evidence is a reason to revisit this, possibly as its own policy
    // axis.
    libc::SYS_memfd_create,
    // Whole-machine effects.
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
];

/// The seccomp denylist [`deny_dangerous_syscalls`] will install, as data.
///
/// Split out for the same reason as `fs_rules` in [`super::ruleset`] (#52).
///
/// An empty rule vector means "match this syscall unconditionally", so every
/// listed number takes the filter's match action and everything else is allowed.
fn blocked_syscalls(
    policy: &crate::SandboxPolicy,
) -> Result<std::collections::BTreeMap<libc::c_long, Vec<seccompiler::SeccompRule>>, SandboxError> {
    use std::collections::BTreeMap;

    use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompRule};

    let mut rules = BLOCKED_SYSCALLS
        .iter()
        .copied()
        .map(|nr| (nr, Vec::new()))
        .collect::<BTreeMap<_, _>>();

    // Unix sockets are their own axis, not a sub-case of network. A netns
    // isolates only *abstract* unix sockets; pathname sockets live in the
    // filesystem and cross it freely, so a command that can dial systemd's bus,
    // docker.sock or an ssh-agent can have them act outside the sandbox — which
    // is an escape, not egress. Deliberately not tied to `allows_network`, so
    // granting the internet does not grant this (#8).
    //
    // All-or-nothing: seccomp compares register values, and the path passed to
    // `connect` is behind a pointer it cannot follow. Landlock gained a
    // path-scoped right in ABI V9 (Linux 7.1), which no kernel reports in
    // practice yet. `negotiated_abi` settles on a single ABI the kernel accepts
    // in full, so below V9 that right is simply not in the handled set — there
    // is nothing best-effort left to lean on. A per-socket grant can follow
    // once V9 exists.
    //
    // `socketpair` is deliberately left alone: it creates an anonymous pair with
    // no filesystem path, cannot reach a host daemon, and is used routinely by
    // shells. Blocking it would break real tools for no security gain.
    if !policy.allows_unix_sockets() {
        let af_unix = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_UNIX as u64,
        )
        .map_err(seccomp_failed)?;
        rules.insert(
            libc::SYS_socket,
            vec![SeccompRule::new(vec![af_unix]).map_err(seccomp_failed)?],
        );
    }

    Ok(rules)
}

/// Compile [`blocked_syscalls`] into the BPF program [`deny_dangerous_syscalls`]
/// installs.
///
/// Split out for the same reason as [`blocked_syscalls`] above, and to make the
/// filter's *polarity* assertable without a kernel: the two actions below are
/// positional and of the same type, so the compiler cannot tell them apart, and
/// swapping them yields a filter that allows the denylist and `EPERM`s
/// everything else. Only the kernel-backed suite noticed that — as nine failures
/// naming nothing — hence the named bindings and the tests below (#91).
///
/// `mod tests` keeps a twin of this function with the two actions swapped, which
/// is what proves those tests would notice. It only mutates the real path as long
/// as this body does nothing but call `SeccompFilter::new` — if that changes,
/// change the twin too (#99).
///
/// Blocked calls return `EPERM` rather than killing the process. The syscall does
/// not execute either way; `EPERM` is what tools already expect on hardened
/// systems, so they fail that operation instead of dying mid-run.
fn compiled_filter(policy: &crate::SandboxPolicy) -> Result<seccompiler::BpfProgram, SandboxError> {
    use seccompiler::{SeccompAction, SeccompFilter};

    // `SeccompFilter::new` takes the mismatch action before the match one: every
    // syscall the filter does not name, then the ones it does.
    let unlisted = SeccompAction::Allow;
    let listed = SeccompAction::Errno(libc::EPERM as u32);

    let filter = SeccompFilter::new(
        blocked_syscalls(policy)?,
        unlisted,
        listed,
        std::env::consts::ARCH.try_into().map_err(seccomp_failed)?,
    )
    .map_err(seccomp_failed)?;

    filter.try_into().map_err(seccomp_failed)
}

/// Install the filter [`compiled_filter`] builds.
pub(super) fn deny_dangerous_syscalls(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    seccompiler::apply_filter(&compiled_filter(policy)?).map_err(seccomp_failed)
}

fn seccomp_failed(source: impl std::fmt::Display) -> SandboxError {
    SandboxError::Seccomp {
        detail: source.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxPolicy;

    // The three verdicts this filter can produce, taken from `libc` rather than
    // from `u32::from(SeccompAction::…)`.
    //
    // The tests replaced here used the latter, which left expected and actual
    // sharing a source: a change to seccompiler's `From<SeccompAction> for u32`
    // would move both, and the assertion would go on holding. These are kernel
    // ABI, so they cannot move together with the thing under test (#99).
    const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    const KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;

    // The classic-BPF opcodes `compiled_filter`'s program is built from, composed
    // from `libc`'s field constants rather than written as folded literals.
    //
    // Not quite for the reason the replaced tests gave. `BPF_LD`, `BPF_W`, `BPF_K`
    // and `BPF_JA` are all `0x00`, so dropping or adding a zero-valued term yields
    // the same number and composing cannot catch it. What composing does catch is
    // a *wrong* term — `BPF_LDX` is `0x01`, `BPF_X` is `0x08` — which produces a
    // value no instruction matches, so `eval` hits its panic arm loudly instead of
    // mis-evaluating in silence.
    //
    // This set is closed only as long as seccompiler's codegen is; see `eval`.
    const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const ALU_AND_K: u16 = (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16;
    const JA: u16 = (libc::BPF_JMP | libc::BPF_JA) as u16;
    const JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const JGT_K: u16 = (libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K) as u16;
    const JGE_K: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
    const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

    /// Every opcode [`eval`] implements, for the structural check below.
    const KNOWN_OPCODES: &[u16] = &[LD_W_ABS, ALU_AND_K, JA, JEQ_K, JGT_K, JGE_K, RET_K];

    // `AUDIT_ARCH_*` for the architecture the test runs on: the `EM_*` machine
    // number from `linux/elf-em.h`, or'd with `__AUDIT_ARCH_64BIT` and
    // `__AUDIT_ARCH_LE` from `linux/audit.h`.
    //
    // Transcribed because `libc` does not export these and seccompiler keeps its
    // own copies private (`backend/bpf.rs`). A transcription would normally be the
    // hazard this issue is about, but this one cannot pass silently: the filter's
    // first act is to compare `seccomp_data.arch` and kill on a mismatch, so a
    // wrong value turns every verdict below into a loud failure rather than a
    // false pass. `the_filter_gates_on_the_arch_this_test_models` is what names
    // the drift when it happens.
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 62 | 0x8000_0000 | 0x4000_0000;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 183 | 0x8000_0000 | 0x4000_0000;
    #[cfg(target_arch = "riscv64")]
    const AUDIT_ARCH: u32 = 243 | 0x8000_0000 | 0x4000_0000;
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    compile_error!(
        "this architecture needs its AUDIT_ARCH_* from linux/audit.h here, or the \
         filter's arch gate kills every syscall the tests evaluate"
    );

    #[cfg(target_endian = "big")]
    compile_error!(
        "the seccomp_data word model in `seccomp_data` below assumes little-endian; \
         see the note there on why the load is native-endian"
    );

    /// Build one instruction. seccompiler's `bpf_stmt`/`bpf_jump` are private, so
    /// the interpreter's own tests compose `sock_filter` directly.
    fn insn(code: u16, jt: u8, jf: u8, k: u32) -> seccompiler::sock_filter {
        seccompiler::sock_filter { code, jt, jf, k }
    }

    /// `struct seccomp_data` as the sixteen 32-bit words a
    /// `BPF_LD | BPF_W | BPF_ABS` instruction addresses.
    ///
    /// 64 bytes: `nr` at 0, `arch` at 4, `instruction_pointer` at 8, `args[6]` at
    /// 16 (`seccompiler/backend/bpf.rs`). Each argument's *least* significant half
    /// sits at the lower offset, so word `4 + 2 * i` is `args[i]`'s low word and
    /// `5 + 2 * i` its high word.
    ///
    /// Little-endian, and worth pinning why, because it is the claim a reader is
    /// most likely to "fix" wrongly: in *socket* classic BPF an absolute word load
    /// is a big-endian packet read, but in *seccomp* it is not.
    /// `seccomp_check_filter()` rewrites every `BPF_LD | BPF_W | BPF_ABS` to
    /// `BPF_LDX | BPF_MEM | BPF_W` before the program ever runs, which makes it a
    /// plain native-endian field read out of the struct. A `[u32; 16]` is
    /// therefore the right model — and only because every architecture seccompiler
    /// supports is little-endian.
    fn seccomp_data(nr: libc::c_long, args: [u64; 6]) -> [u32; 16] {
        let mut data = [0u32; 16];

        // Not `u32::try_from(nr).unwrap()`: `nr` is a signed `int`, every
        // comparison the filter makes against it is `jeq` and so sign-agnostic,
        // and a negative number is a legal thing for a process to pass
        // (`syscall(-1)`). The cast keeps that case expressible.
        data[0] = nr as u32;
        data[1] = AUDIT_ARCH;
        // `instruction_pointer` stays zero; no rule sandbx builds looks at it.
        for (i, arg) in args.iter().enumerate() {
            data[4 + 2 * i] = *arg as u32;
            data[5 + 2 * i] = (*arg >> 32) as u32;
        }

        data
    }

    /// Run `program` over `data` and return the verdict it yields.
    ///
    /// This is the point of #99. The tests replaced here asserted over the
    /// program's instruction *layout* — that the mismatch action was the last
    /// instruction, that the match action was the first `RET` after a syscall's
    /// comparison. Both held against seccompiler 0.5.0 and neither was ABI, so a
    /// dependency bump could turn them red with the polarity unchanged. Worse,
    /// they checked that instructions *existed*, not that control flow reached
    /// them, so a wrong jump offset passed.
    ///
    /// The coupling is relocated here, not eliminated: the opcode set above is
    /// closed only as long as seccompiler's codegen is. What keeps the relocation
    /// honest is the panic at the bottom — an unimplemented opcode must never
    /// produce a verdict, because a mis-evaluation returning `ALLOW` would be
    /// worse than the layout coupling it replaces.
    ///
    /// Takes `BpfProgramRef` rather than `&BpfProgram`, which is a `&Vec` and
    /// trips `clippy::ptr_arg`; it is also what `apply_filter` takes.
    /// This loop cannot spin, and it is worth saying why rather than guarding it:
    /// every arm below derives its target as `pc + 1 + <unsigned offset>`, so `pc`
    /// strictly increases, and once it reaches `program.len()` the `get` at the top
    /// panics by name. Termination is a property of the arms, so an added guard
    /// would be unreachable code claiming to catch something. An arm that *could*
    /// jump backwards would have to subtract — which is where to put a check, if a
    /// future opcode ever needs one.
    fn eval(program: seccompiler::BpfProgramRef<'_>, data: &[u32; 16]) -> u32 {
        let mut acc = 0u32;
        let mut pc = 0usize;

        loop {
            let insn = program.get(pc).unwrap_or_else(|| {
                panic!(
                    "control flow ran off the end of the program at pc {pc} of {}",
                    program.len()
                )
            });
            let next = pc + 1;

            // Compared with `==`, not matched. In a pattern, an uppercase path
            // that fails to resolve to a constant becomes a fresh binding rather
            // than an error: the first arm would swallow every opcode, every
            // verdict here would be garbage, and the only signal would be
            // `unreachable_patterns` — a warning. `==` makes that a type error.
            let target = if insn.code == LD_W_ABS {
                let offset = usize::try_from(insn.k)
                    .unwrap_or_else(|_| panic!("load offset {} does not fit a usize", insn.k));
                // The kernel's own install-time checks on this instruction,
                // restated: `seccomp_check_filter()` refuses a filter whose
                // absolute load is unaligned or outside `struct seccomp_data`.
                assert_eq!(
                    offset % 4,
                    0,
                    "unaligned load at pc {pc}; the kernel would refuse this filter: {insn:?}"
                );
                acc = *data.get(offset / 4).unwrap_or_else(|| {
                    panic!(
                        "the load at pc {pc} reads byte {offset}, outside the 64-byte \
                         seccomp_data; the kernel would refuse this filter: {insn:?}"
                    )
                });
                next
            } else if insn.code == ALU_AND_K {
                acc &= insn.k;
                next
            } else if insn.code == JA {
                // The offset is in `k`, not in `jt`.
                next + usize::try_from(insn.k)
                    .unwrap_or_else(|_| panic!("jump offset {} does not fit a usize", insn.k))
            } else if insn.code == JEQ_K {
                next + usize::from(if acc == insn.k { insn.jt } else { insn.jf })
            } else if insn.code == JGT_K {
                // Unsigned, as classic BPF specifies. Both sides are `u32`, so
                // this is the comparison the kernel makes.
                next + usize::from(if acc > insn.k { insn.jt } else { insn.jf })
            } else if insn.code == JGE_K {
                next + usize::from(if acc >= insn.k { insn.jt } else { insn.jf })
            } else if insn.code == RET_K {
                return insn.k;
            } else {
                panic!(
                    "seccompiler emitted opcode {:#x} at pc {pc}, which this interpreter \
                     does not implement. It was verified against seccompiler 0.5.0 \
                     `backend/bpf.rs`, `condition.rs`, `rule.rs` and `filter.rs`. Re-read \
                     those and extend `eval` — do not add an arm that returns a default \
                     verdict: {insn:?}",
                    insn.code
                )
            };

            pc = target;
        }
    }

    /// The verdict for `nr` called with all-zero arguments.
    fn verdict(program: seccompiler::BpfProgramRef<'_>, nr: libc::c_long) -> u32 {
        eval(program, &seccomp_data(nr, [0; 6]))
    }

    /// The verdict for `nr` called with `args`.
    ///
    /// Every test goes through this rather than touching a word index, because
    /// `data[4]` is `args[0]`'s low half while `data[5]` is its high half and
    /// `data[6]` is `args[1]` — an off-by-one would silently assert about the
    /// wrong field, which is the class of mistake #99 exists to remove.
    fn verdict_with_args(
        program: seccompiler::BpfProgramRef<'_>,
        nr: libc::c_long,
        args: [u64; 6],
    ) -> u32 {
        eval(program, &seccomp_data(nr, args))
    }

    /// The verdict for `nr` as seen from a process reporting `arch`.
    fn verdict_from_arch(
        program: seccompiler::BpfProgramRef<'_>,
        nr: libc::c_long,
        arch: u32,
    ) -> u32 {
        let mut data = seccomp_data(nr, [0; 6]);
        data[1] = arch;
        eval(program, &data)
    }

    /// The verdict for `socket(domain, 0, 0)`.
    ///
    /// `domain` is wider than the `int` the kernel reads so that a test can put
    /// something in the half the comparison must ignore.
    fn socket_verdict(program: seccompiler::BpfProgramRef<'_>, domain: u64) -> u32 {
        verdict_with_args(program, libc::SYS_socket, [domain, 0, 0, 0, 0, 0])
    }

    /// The filter is built from `BLOCKED_SYSCALLS` and nothing else, so the two
    /// cannot drift.
    #[test]
    fn blocked_syscalls_covers_the_whole_denylist() {
        let blocked = blocked_syscalls(&SandboxPolicy::default()).unwrap();

        for nr in BLOCKED_SYSCALLS {
            let rules = blocked
                .get(nr)
                .unwrap_or_else(|| panic!("{nr} missing from the filter"));

            // An entry with rules is matched only for those argument values, so
            // the syscall stays reachable for every other. A listed number must
            // be blocked unconditionally, or the denial is narrower than the
            // list claims.
            assert!(
                rules.is_empty(),
                "{nr} is filtered conditionally, but the denylist claims it outright"
            );
        }
    }

    /// `socket` is blocked conditionally — on the `AF_UNIX` argument — and only
    /// when the policy withholds unix sockets. Until now that was verifiable
    /// only by spawning a real sandboxed process.
    #[test]
    fn socket_is_blocked_only_while_unix_sockets_are_withheld() {
        let denied = blocked_syscalls(&SandboxPolicy::default()).unwrap();
        assert!(
            denied.contains_key(&libc::SYS_socket),
            "socket() must be filtered when unix sockets are not granted"
        );
        assert_eq!(
            denied[&libc::SYS_socket].len(),
            1,
            "the socket entry must be conditional, not an unconditional block"
        );

        let granted = blocked_syscalls(&SandboxPolicy::default().allow_unix_sockets()).unwrap();
        assert!(
            !granted.contains_key(&libc::SYS_socket),
            "granting unix sockets must lift the socket() filter"
        );
    }

    /// Does the interpreter implement the opcodes it claims to?
    ///
    /// [`eval`] is itself untested code whose failure mode is the silent pass —
    /// the bug the `EPERM` assertion already had once on the #91 branch, fixed in
    /// `54fa2ac`. These cases are the ones that catch the classic
    /// mis-implementations, over hand-written programs rather than the compiled
    /// filter.
    ///
    /// `ALU|AND`, `JGT` and `JGE` are unreachable from [`compiled_filter`] today:
    /// sandbx builds only `Dword`/`Eq` rules, which compile to loads and `jeq`.
    /// They are implemented anyway, because the alternative is three arms that
    /// panic on a program seccompiler can legitimately emit — and they are
    /// covered here so they are not untested code waiting for the first rule that
    /// reaches them (#99).
    #[test]
    fn eval_implements_the_opcodes_seccompiler_can_emit() {
        // Every program loads word 0, `nr`, so the case's `nr` is the value the
        // comparison sees. `jt`, `jf` and `JA`'s `k` are offsets from the
        // *following* instruction, so 1 skips exactly one.
        let cases: &[(&str, Vec<seccompiler::sock_filter>, libc::c_long, u32)] = &[
            (
                "jgt is strict, so an equal value does not take the greater branch",
                vec![
                    insn(LD_W_ABS, 0, 0, 0),
                    insn(JGT_K, 1, 0, 5),
                    insn(RET_K, 0, 0, ALLOW),
                    insn(RET_K, 0, 0, EPERM),
                ],
                5,
                ALLOW,
            ),
            (
                "jgt does fire on a greater value",
                vec![
                    insn(LD_W_ABS, 0, 0, 0),
                    insn(JGT_K, 1, 0, 5),
                    insn(RET_K, 0, 0, ALLOW),
                    insn(RET_K, 0, 0, EPERM),
                ],
                6,
                EPERM,
            ),
            (
                "jge takes the branch on an equal value",
                vec![
                    insn(LD_W_ABS, 0, 0, 0),
                    insn(JGE_K, 1, 0, 5),
                    insn(RET_K, 0, 0, ALLOW),
                    insn(RET_K, 0, 0, EPERM),
                ],
                5,
                EPERM,
            ),
            (
                // An `i32` interpretation inverts this one: -1 is not > 1 signed,
                // but 0xffff_ffff is unsigned, and the kernel compares unsigned.
                "the comparison is unsigned",
                vec![
                    insn(LD_W_ABS, 0, 0, 0),
                    insn(JGT_K, 1, 0, 1),
                    insn(RET_K, 0, 0, ALLOW),
                    insn(RET_K, 0, 0, EPERM),
                ],
                -1,
                EPERM,
            ),
            (
                // Without the mask 0x19 does not equal 0x10 and this falls to
                // ALLOW, so the case discriminates.
                "alu-and masks the accumulator before the comparison",
                vec![
                    insn(LD_W_ABS, 0, 0, 0),
                    insn(ALU_AND_K, 0, 0, 0xf0),
                    insn(JEQ_K, 1, 0, 0x10),
                    insn(RET_K, 0, 0, ALLOW),
                    insn(RET_K, 0, 0, EPERM),
                ],
                0x19,
                EPERM,
            ),
            (
                // Reading the offset from `jt` (0) instead of `k` lands on ALLOW,
                // so the case discriminates.
                "an unconditional jump takes its offset from k",
                vec![
                    insn(LD_W_ABS, 0, 0, 0),
                    insn(JA, 0, 0, 1),
                    insn(RET_K, 0, 0, ALLOW),
                    insn(RET_K, 0, 0, EPERM),
                ],
                0,
                EPERM,
            ),
        ];

        for (property, program, nr, expected) in cases {
            assert_eq!(
                eval(program, &seccomp_data(*nr, [0; 6])),
                *expected,
                "the interpreter is wrong about {property}, so every verdict it \
                 reports below is unreliable"
            );
        }
    }

    /// An opcode the interpreter does not implement must stop the test, never
    /// produce a verdict.
    ///
    /// The issue's first design constraint, and what keeps relocating the codegen
    /// coupling into [`eval`] honest: a mis-evaluation that returned `ALLOW` for
    /// an unhandled instruction would be worse than the layout coupling it
    /// replaces (#99).
    ///
    /// `expected` is not optional here. Without it the test also passes on the
    /// off-the-end panic, on the alignment assertion, or on an `unwrap` elsewhere
    /// in the body — any of which would leave the panic arm itself unexercised.
    /// The opcode is one seccompiler could plausibly grow into
    /// (`BPF_LDX | BPF_MEM | BPF_W`, a scratch-memory load) rather than a value no
    /// BPF dialect uses, so the test also says what the canary is for.
    #[test]
    #[should_panic(expected = "does not implement")]
    fn eval_refuses_an_opcode_it_does_not_implement() {
        let ldx_mem_w = (libc::BPF_LDX | libc::BPF_MEM | libc::BPF_W) as u16;

        eval(
            &[insn(ldx_mem_w, 0, 0, 0)],
            &seccomp_data(libc::SYS_getpid, [0; 6]),
        );
    }

    /// Does [`seccomp_data`] put every field where the kernel puts it?
    ///
    /// Nothing else here would notice if it did not. Every other test passes
    /// either all-zero arguments or a value in `args[0]` alone, and the array
    /// starts zeroed — so the stride `4 + 2 * i` could map arguments 1 through 5
    /// onto each other's words, or onto the unused tail, and all of them would
    /// still pass. Verified by mutation: swapping the words `args[1]` and `args[2]`
    /// land in leaves the rest of this module green.
    ///
    /// That matters for the next rule rather than for today's. sandbx gates only
    /// on `socket`'s argument 0, but `clone`'s flags, `socket`'s `type` and an
    /// `ioctl` request are all at an index above zero (#118), and a rule on one of
    /// those would be evaluated against the wrong word — reporting a verdict the
    /// kernel would not produce, silently, which is the failure mode #99 exists to
    /// remove.
    ///
    /// Each half is checked separately, with distinct values, because an argument
    /// written as one 64-bit store to the right *pair* in the wrong order would
    /// otherwise pass.
    #[test]
    fn seccomp_data_puts_each_field_where_the_kernel_does() {
        let args = std::array::from_fn::<u64, 6, _>(|i| {
            let i = i as u64;
            (0x2000_0000 | i) << 32 | (0x1000_0000 | i)
        });
        let data = seccomp_data(libc::SYS_socket, args);

        // Byte offsets into `struct seccomp_data`, read off its definition rather
        // than off `seccomp_data`'s own arithmetic: `nr` @0, `arch` @4, the 64-bit
        // `instruction_pointer` @8, `args[6]` @16.
        let mut fields = vec![
            ("nr".to_owned(), 0, libc::SYS_socket as u32),
            ("arch".to_owned(), 4, AUDIT_ARCH),
            ("instruction_pointer low".to_owned(), 8, 0),
            ("instruction_pointer high".to_owned(), 12, 0),
        ];
        for (i, arg) in args.iter().enumerate() {
            fields.push((format!("args[{i}] low"), 16 + 8 * i, *arg as u32));
            fields.push((format!("args[{i}] high"), 20 + 8 * i, (*arg >> 32) as u32));
        }

        for (field, offset, expected) in fields {
            // `eval` has no way to return the accumulator — classic BPF's
            // `BPF_RET | BPF_A` is not an opcode seccompiler emits — so the
            // comparison is the program: load the field, and return `ALLOW` only
            // if it holds what it should.
            let program = [
                insn(LD_W_ABS, 0, 0, u32::try_from(offset).unwrap()),
                insn(JEQ_K, 0, 1, expected),
                insn(RET_K, 0, 0, ALLOW),
                insn(RET_K, 0, 0, EPERM),
            ];

            assert_eq!(
                eval(&program, &data),
                ALLOW,
                "a load at byte {offset} does not read {field}, so `seccomp_data` \
                 does not model the kernel's struct and a rule on that field would \
                 be evaluated against the wrong word"
            );
        }
    }

    /// This is a denylist, so a syscall the filter does not name has to be
    /// allowed. Swap the two actions in [`compiled_filter`] and this becomes
    /// `EPERM` — a sandbox that refuses every syscall and permits the dangerous
    /// ones (#91).
    ///
    /// Evaluated rather than read off the program's last instruction, which is
    /// where seccompiler happens to emit the mismatch action but is not ABI
    /// (#99).
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

    /// The other half of the polarity: a syscall the filter *does* name gets
    /// `EPERM`. Needed alongside the fallthrough because either alone admits one
    /// of the two broken filters — allowing everywhere is as wrong as refusing
    /// everywhere, and only the pair rules both out (#91).
    ///
    /// Covers the whole list rather than `ptrace` alone, which evaluation makes
    /// free: the replaced test could only afford one syscall because it had to
    /// locate that syscall's comparison and scan forward from it (#99).
    ///
    /// What the kernel then does with the program is not in reach here. Its
    /// effective action is the most severe across *every* installed filter, so
    /// "the program returns `ALLOW`" is not "the syscall runs". The
    /// `sandbox-integration` suite spawns a process to establish that; this pins
    /// what sandbx asked for.
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

    /// `socket` is blocked on the value of its first argument, and nothing until
    /// now pinned what that comparison compares against — only that the entry
    /// carried exactly one rule. The argument-comparison path had no kernel-free
    /// test at all (#99, #8).
    #[test]
    fn socket_is_refused_for_af_unix_and_allowed_for_af_inet() {
        let program = compiled_filter(&SandboxPolicy::default()).unwrap();

        assert_eq!(
            socket_verdict(&program, libc::AF_UNIX as u64),
            EPERM,
            "socket(AF_UNIX) is permitted, so a command can reach a pathname socket \
             outside the sandbox"
        );
        assert_eq!(
            socket_verdict(&program, libc::AF_INET as u64),
            ALLOW,
            "socket(AF_INET) is refused, so the unix-socket rule has widened into \
             every address family — the netns is what bounds IP egress, not this"
        );
    }

    /// The comparison must look at the low half of `domain` only.
    ///
    /// `socket`'s `domain` is an `int`, so the kernel truncates it and a 64-bit
    /// comparison would be looking at register bits the kernel discards. That
    /// makes a `Dword`-to-`Qword` change a real bypass rather than a cosmetic
    /// one: `socket(0x1_0000_0001, …)` has the kernel see `AF_UNIX` while a
    /// `Qword` filter sees a non-zero high half, finds no match, and allows it.
    ///
    /// Without this case the test above passes identically against either
    /// comparison width, because it leaves the high half zero (#99).
    #[test]
    fn the_af_unix_comparison_ignores_the_high_half_of_the_domain_argument() {
        let program = compiled_filter(&SandboxPolicy::default()).unwrap();
        let noise = 0xdead_beef_0000_0000 | libc::AF_UNIX as u64;

        assert_eq!(
            socket_verdict(&program, noise),
            EPERM,
            "garbage in the high half of `domain` escapes the AF_UNIX rule, so the \
             comparison is 64-bit where the kernel's is 32-bit"
        );
    }

    /// Granting unix sockets must lift the `socket` rule and nothing else.
    ///
    /// The second assertion is the one worth having: a grant that also widened
    /// the denylist would otherwise be invisible here (#99).
    #[test]
    fn granting_unix_sockets_lifts_only_the_socket_rule() {
        let program = compiled_filter(&SandboxPolicy::default().allow_unix_sockets()).unwrap();

        assert_eq!(
            socket_verdict(&program, libc::AF_UNIX as u64),
            ALLOW,
            "the policy grants unix sockets but the filter still refuses them"
        );
        assert_eq!(
            verdict(&program, libc::SYS_ptrace),
            EPERM,
            "granting unix sockets also lifted the denylist, which no policy may do"
        );
    }

    /// A process reporting a different architecture is killed, not refused.
    ///
    /// Syscall numbers are per-architecture, so a filter built for one of them
    /// cannot say anything safe about calls arriving from another — the kernel's
    /// `seccomp_data.arch` is how it tells, and seccompiler gates every filter on
    /// it before the first comparison. The product consequence is worth naming:
    /// an i386 binary on x86_64, or AArch32 on aarch64, dies rather than seeing
    /// `EPERM`, unlike every other denial in this file.
    ///
    /// Uses a *blocked* number so the test shows the gate short-circuits the
    /// chain, not merely that an unlisted syscall dies (#99).
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

    /// `compiled_filter` with its two actions swapped, built from the same
    /// `blocked_syscalls` data.
    ///
    /// A twin, not the real path: if `compiled_filter` ever does more than call
    /// `SeccompFilter::new`, this stops being a mutation of it. Change both.
    fn inverted_filter(policy: &crate::SandboxPolicy) -> seccompiler::BpfProgram {
        use seccompiler::{SeccompAction, SeccompFilter};

        let filter = SeccompFilter::new(
            blocked_syscalls(policy).unwrap(),
            // Swapped. In `compiled_filter` the first is `Allow` and the second
            // `Errno(EPERM)`.
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            std::env::consts::ARCH.try_into().unwrap(),
        )
        .unwrap();

        filter.try_into().unwrap()
    }

    /// Would the tests above notice if the filter pointed the other way?
    ///
    /// This mechanizes the check the polarity tests were verified by hand against
    /// on the #91 branch, and it is worth being exact about what it proves: that
    /// the assertions above have mutation-killing power. It is **not** evidence
    /// about production polarity. If [`compiled_filter`] were inverted, this test
    /// would still pass and the ones above would fail — which is the right way
    /// round, but means this one is asserting about [`inverted_filter`], a copy.
    ///
    /// Three verdicts, because the inversion has three distinguishable effects:
    /// the denylist opens, the fallthrough closes, and the conditional rule
    /// inverts along with the unconditional ones (#99).
    #[test]
    fn inverting_the_filters_two_actions_inverts_every_verdict() {
        let program = inverted_filter(&SandboxPolicy::default());

        assert_eq!(
            verdict(&program, libc::SYS_ptrace),
            ALLOW,
            "swapping the actions left the denylist refused, so the tests above \
             would not notice the swap"
        );
        assert_eq!(
            verdict(&program, libc::SYS_getpid),
            EPERM,
            "swapping the actions left the fallthrough allowed, so the tests above \
             would not notice the swap"
        );
        assert_eq!(
            socket_verdict(&program, libc::AF_UNIX as u64),
            ALLOW,
            "swapping the actions left socket(AF_UNIX) refused, so the tests above \
             would not notice the swap"
        );
    }

    /// Is the program one the kernel would load at all?
    ///
    /// Evaluation only covers the paths its data takes, and #99's complaint is
    /// that a wrong jump offset passes unnoticed. These checks close the rest,
    /// and every one of them is `bpf_check_classic()` restated rather than
    /// anything about seccompiler's codegen — including the last-instruction
    /// check, which the kernel genuinely requires, unlike the *value* the
    /// replaced test read off it.
    #[test]
    fn the_program_is_one_the_kernel_would_accept() {
        let program = compiled_filter(&SandboxPolicy::default()).unwrap();
        let len = program.len();

        // `bpf_check_classic` refuses `flen == 0 || flen > BPF_MAXINSNS`, so 4096
        // is the largest filter the kernel loads, not the first one it refuses.
        // seccompiler's own `BPF_MAX_LEN` guard is stricter — it errors at `>=`
        // 4096 — so a program can only fail this assertion by being empty. Stated
        // as the kernel's bound anyway, because that is the one a reader chasing a
        // real `FilterTooLarge` needs to have right.
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

        let expected = std::collections::BTreeSet::from([ALLOW, EPERM, KILL]);
        assert!(
            verdicts.is_subset(&expected),
            "the filter can return a verdict it was never asked for: {verdicts:x?}"
        );
    }

    /// Does the filter gate on the architecture this test models?
    ///
    /// A diagnostic, not evidence about the filter. `AUDIT_ARCH` above is
    /// transcribed from `linux/audit.h` because neither `libc` nor seccompiler
    /// exposes it, and if it ever stops matching seccompiler's
    /// `TargetArch::get_audit_value` then most of the tests in this file fail as
    /// "expected ALLOW, got 0x80000000" and name nothing — exactly the confusion
    /// #99 set out to remove. This localizes that one failure.
    ///
    /// Deliberately positionless: that the gate is the program's *first*
    /// instruction is seccompiler's codegen, which is what this issue stopped
    /// asserting.
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
}
