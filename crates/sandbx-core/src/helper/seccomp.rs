//! The seccomp syscall filter applied to the sandboxed command.
//!
//! Covers the escapes Landlock cannot see: a syscall that reaches the kernel without
//! naming a path. The denylist is a constant so a test can assert the installed
//! filter still matches it, and `super::apply` installs it.
//!
//! Three stacked filters, not one: a seccompiler filter carries a single match action,
//! and `clone3` must answer `ENOSYS` while everything else answers `EPERM`. The kernel
//! takes the most severe verdict across every installed filter.

use crate::SandboxError;

/// Syscalls blocked for every sandboxed command, regardless of policy.
///
/// A denylist: sandbx runs arbitrary commands — shells, compilers, package managers —
/// whose syscall use is unbounded, so the stronger allowlist shape would break real tools
/// constantly. Landlock can express none of these; they are not filesystem access.
///
/// The filter is built from this and nothing else, so a test can assert the list still
/// contains what `SECURITY.md` claims.
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
    // Handles on another process. `pidfd_getfd` takes a descriptor *out* of a process that
    // holds one — a socket, an open file above the policy — which is not filesystem
    // access, so Landlock cannot express it and denying `ptrace` does not cover it.
    // `pidfd_open` is how the handle is obtained.
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_getfd,
    // userfaultfd hands the faulting process control over when a page fault resolves,
    // turning any check-then-use in the kernel into an arbitrarily wide window. A
    // recurring ingredient in kernel exploits, and no coding tool needs it.
    libc::SYS_userfaultfd,
    // io_uring runs operations from a submission queue without issuing the matching
    // syscalls, so a ring set up here would be a route around every rule in this
    // filter — including the `socket(AF_UNIX)` denial added on top of this list.
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    // An anonymous in-memory file has no path on any filesystem, and Landlock binds its
    // rules to inodes and paths, so a payload staged in a memfd sits outside everything
    // the filesystem layer can see.
    //
    // The one entry with a real compatibility cost, but a narrow one: the heavy users are
    // container runtimes (runc re-execs a sealed memfd copy of itself as its
    // CVE-2019-5736 self-protection), systemd and snapd — and running a container runtime
    // in here is already impossible, `unshare` being denied above. An ordinary program
    // calling it deliberately is the case to watch.
    libc::SYS_memfd_create,
    // Whole-machine effects.
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
];

/// Namespace-creating `clone` flags, refused one bit at a time.
///
/// `unshare` is on the denylist above, but `clone` reaches every one of these namespaces
/// through its flags argument, so denying only `unshare` leaves the escape open (#118).
///
/// `CLONE_NEWTIME` is absent: it collides with `clone`'s exit-signal byte and the kernel
/// refuses it for this syscall. `unshare` and `clone3`, the two calls that do accept it,
/// are denied outright.
const NAMESPACE_CLONE_FLAGS: &[libc::c_int] = &[
    libc::CLONE_NEWNS,
    libc::CLONE_NEWCGROUP,
    libc::CLONE_NEWUTS,
    libc::CLONE_NEWIPC,
    libc::CLONE_NEWUSER,
    libc::CLONE_NEWPID,
    libc::CLONE_NEWNET,
];

/// `__X32_SYSCALL_BIT` from `asm/unistd.h`: the bit an x32 syscall number carries.
///
/// x32 reports `AUDIT_ARCH_X86_64`, so it passes the filter's architecture gate, but its
/// numbers are the native ones with this bit set — and four denylisted calls (`ptrace`,
/// `kexec_load`, `process_vm_readv`, `process_vm_writev`) sit at *different* numbers again
/// in the x32 table. So the whole ABI is refused rather than enumerated (#117).
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The seccomp denylist [`deny_dangerous_syscalls`] will install, as data.
///
/// Split out so it is assertable without a kernel. An empty rule vector means "match
/// this syscall unconditionally", so every listed number takes the filter's match
/// action and everything else is allowed.
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

    // One rule per flag, because rules for a syscall are OR'd while conditions inside a
    // rule are AND'd — a single `MaskedEq` over the union would only fire when *every*
    // flag was set. `Dword`, like the socket rule below: `clone`'s flags live in the low
    // half and the kernel ignores the high one, so a `Qword` compare would miss
    // `clone(0x1_0000_0000 | CLONE_NEWUSER)`.
    rules.insert(
        libc::SYS_clone,
        NAMESPACE_CLONE_FLAGS
            .iter()
            .map(|flag| {
                let flag = *flag as u64;
                let has_flag = SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::MaskedEq(flag),
                    flag,
                )
                .map_err(seccomp_failed)?;
                SeccompRule::new(vec![has_flag]).map_err(seccomp_failed)
            })
            .collect::<Result<Vec<_>, _>>()?,
    );

    // Unix sockets are their own axis, not a sub-case of network. A netns isolates only
    // *abstract* unix sockets; pathname sockets live in the filesystem and cross it
    // freely, so a command that can dial systemd's bus, docker.sock or an ssh-agent can
    // have them act outside the sandbox — an escape, not egress. Not tied to
    // `allows_network`, so granting the internet does not grant this.
    //
    // All-or-nothing: seccomp compares register values, and the path passed to `connect`
    // is behind a pointer it cannot follow. Landlock gained a path-scoped right in ABI V9
    // (Linux 7.1), which no kernel reports in practice yet, and `negotiated_abi` settles
    // on a single ABI the kernel accepts in full — so below V9 that right is not in the
    // handled set at all. A per-socket grant can follow once V9 exists.
    //
    // `socketpair` is left alone: an anonymous pair with no filesystem path cannot reach
    // a host daemon, and shells use it routinely.
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
/// Blocked calls return `EPERM` rather than killing the process: the syscall does not
/// execute either way, and `EPERM` is what tools already expect on hardened systems, so
/// they fail that operation instead of dying mid-run.
fn compiled_filter(policy: &crate::SandboxPolicy) -> Result<seccompiler::BpfProgram, SandboxError> {
    deny_with(blocked_syscalls(policy)?, libc::EPERM)
}

/// Compile `rules` into a program that answers `errno` for what it names and allows the
/// rest.
///
/// Takes an `errno` rather than a `SeccompAction`, so no caller can pass `Allow` here and
/// invert the filter.
///
/// Split out to make the filter's *polarity* assertable without a kernel: the two actions
/// below are positional and of the same type, so swapping them yields a filter that
/// allows the denylist and `EPERM`s everything else. Hence the named bindings.
///
/// `mod tests` keeps a twin of this function with the two actions swapped, which is what
/// proves those tests would notice. It only mutates the real path as long as this body
/// does nothing but call `SeccompFilter::new` — if that changes, change the twin.
fn deny_with(
    rules: std::collections::BTreeMap<libc::c_long, Vec<seccompiler::SeccompRule>>,
    errno: libc::c_int,
) -> Result<seccompiler::BpfProgram, SandboxError> {
    use seccompiler::{SeccompAction, SeccompFilter};

    // `SeccompFilter::new` takes the mismatch action before the match one: every
    // syscall the filter does not name, then the ones it does.
    let unlisted = SeccompAction::Allow;
    let listed = SeccompAction::Errno(errno as u32);

    let filter = SeccompFilter::new(
        rules,
        unlisted,
        listed,
        std::env::consts::ARCH.try_into().map_err(seccomp_failed)?,
    )
    .map_err(seccomp_failed)?;

    filter.try_into().map_err(seccomp_failed)
}

/// `clone3` answered with `ENOSYS`, which is what makes the `clone` flag rules reachable.
///
/// Its flags sit in a struct behind a pointer, so seccomp cannot read them and the syscall
/// has to go. `ENOSYS` and not `EPERM`: glibc 2.34+ calls `clone3` from `pthread_create`
/// and falls back to `clone` only on `ENOSYS`, so `EPERM` here breaks every threaded
/// program instead of routing it through the filtered `clone`.
fn clone3_filter() -> Result<seccompiler::BpfProgram, SandboxError> {
    deny_with(
        std::collections::BTreeMap::from([(libc::SYS_clone3, Vec::new())]),
        libc::ENOSYS,
    )
}

/// Kill anything arriving over the x32 ABI, identified by [`X32_SYSCALL_BIT`] in `nr`.
///
/// Hand-assembled because seccompiler's conditions address syscall *arguments*; `nr` is
/// reachable only as a filter key, and this rule is a mask over it rather than one number.
///
/// Killed, not `EPERM`'d, for the same reason the architecture gate kills: this is a
/// foreign ABI whose syscall numbers mean something else, so no verdict per call is
/// meaningful. Needs no architecture gate of its own — the denylist filter already kills
/// every non-native architecture, and the kernel takes the most severe verdict.
#[cfg(target_arch = "x86_64")]
fn x32_gate() -> seccompiler::BpfProgram {
    let insn = |code: u16, jt: u8, jf: u8, k: u32| seccompiler::sock_filter { code, jt, jf, k };

    vec![
        // `nr` is the first word of `struct seccomp_data`.
        insn((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0, 0, 0),
        insn(
            (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16,
            0,
            0,
            X32_SYSCALL_BIT,
        ),
        insn(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            0,
            1,
            X32_SYSCALL_BIT,
        ),
        insn(
            (libc::BPF_RET | libc::BPF_K) as u16,
            0,
            0,
            libc::SECCOMP_RET_KILL_PROCESS,
        ),
        insn(
            (libc::BPF_RET | libc::BPF_K) as u16,
            0,
            0,
            libc::SECCOMP_RET_ALLOW,
        ),
    ]
}

/// Every filter [`deny_dangerous_syscalls`] installs, in the order it installs them.
fn installed_filters(
    policy: &crate::SandboxPolicy,
) -> Result<Vec<seccompiler::BpfProgram>, SandboxError> {
    let filters = vec![
        compiled_filter(policy)?,
        clone3_filter()?,
        #[cfg(target_arch = "x86_64")]
        x32_gate(),
    ];

    Ok(filters)
}

/// Install the filters [`installed_filters`] builds.
///
/// Order carries no meaning: the kernel evaluates every installed filter and takes the
/// most severe verdict, so a later filter cannot loosen an earlier one.
pub(super) fn deny_dangerous_syscalls(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    for filter in installed_filters(policy)? {
        seccompiler::apply_filter(&filter).map_err(seccomp_failed)?;
    }

    Ok(())
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

    // The three verdicts this filter can produce, taken from `libc` and not from
    // `u32::from(SeccompAction::…)`, which would leave expected and actual sharing a
    // source. These are kernel ABI and cannot move with the thing under test.
    const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
    const EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    const ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;
    const KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;

    // The classic-BPF opcodes `compiled_filter`'s program is built from, composed from
    // `libc`'s field constants rather than written as folded literals.
    //
    // `BPF_LD`, `BPF_W`, `BPF_K` and `BPF_JA` are all `0x00`, so composing cannot catch a
    // dropped zero-valued term. It does catch a *wrong* term — `BPF_LDX` is `0x01`,
    // `BPF_X` is `0x08` — which produces a value no instruction matches, so `eval` hits
    // its panic arm loudly instead of mis-evaluating.
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

    // `AUDIT_ARCH_*` for the architecture the test runs on: the `EM_*` machine number
    // from `linux/elf-em.h`, or'd with `__AUDIT_ARCH_64BIT` and `__AUDIT_ARCH_LE` from
    // `linux/audit.h`. Transcribed because `libc` does not export these and seccompiler
    // keeps its own copies private (`backend/bpf.rs`).
    //
    // The transcription cannot pass silently: the filter's first act is to compare
    // `seccomp_data.arch` and kill on a mismatch, so a wrong value turns every verdict
    // below into a loud failure, and `the_filter_gates_on_the_arch_this_test_models`
    // names the drift.
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
    /// `sock_filter` is composed directly.
    fn insn(code: u16, jt: u8, jf: u8, k: u32) -> seccompiler::sock_filter {
        seccompiler::sock_filter { code, jt, jf, k }
    }

    /// `struct seccomp_data` as the sixteen 32-bit words a `BPF_LD | BPF_W | BPF_ABS`
    /// instruction addresses.
    ///
    /// 64 bytes: `nr` at 0, `arch` at 4, `instruction_pointer` at 8, `args[6]` at 16
    /// (`seccompiler/backend/bpf.rs`). Each argument's *least* significant half sits at
    /// the lower offset, so word `4 + 2 * i` is `args[i]`'s low word and `5 + 2 * i` its
    /// high word.
    ///
    /// Little-endian, and worth pinning, because it is the claim a reader is most likely
    /// to "fix" wrongly: in *socket* classic BPF an absolute word load is a big-endian
    /// packet read, but in *seccomp* it is not. `seccomp_check_filter()` rewrites every
    /// `BPF_LD | BPF_W | BPF_ABS` to `BPF_LDX | BPF_MEM | BPF_W` before the program runs,
    /// making it a plain native-endian field read out of the struct. A `[u32; 16]` is
    /// therefore the right model — and only because every architecture seccompiler
    /// supports is little-endian.
    fn seccomp_data(nr: libc::c_long, args: [u64; 6]) -> [u32; 16] {
        let mut data = [0u32; 16];

        // Not `u32::try_from(nr).unwrap()`: `nr` is a signed `int`, every comparison the
        // filter makes against it is `jeq` and so sign-agnostic, and `syscall(-1)` is a
        // legal thing for a process to pass.
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
    /// Evaluating rather than asserting over the program's instruction *layout*: the
    /// layout is seccompiler's codegen rather than ABI, and a layout check sees that
    /// instructions exist, not that control flow reaches them, so a wrong jump offset
    /// passes.
    ///
    /// The codegen coupling is relocated here, not eliminated: the opcode set above is
    /// closed only as long as seccompiler's codegen is. What keeps that honest is the
    /// panic at the bottom — an unimplemented opcode must never produce a verdict, because
    /// a mis-evaluation returning `ALLOW` would be worse than the layout coupling it
    /// replaces.
    ///
    /// Takes `BpfProgramRef` rather than `&BpfProgram`, which is a `&Vec` and trips
    /// `clippy::ptr_arg`; it is also what `apply_filter` takes.
    ///
    /// This loop cannot spin, so it carries no guard: every arm derives its target as
    /// `pc + 1 + <unsigned offset>`, so `pc` strictly increases and the `get` at the top
    /// panics by name once it reaches `program.len()`. An arm that *could* jump backwards
    /// would have to subtract — which is where to put a check if a future opcode needs
    /// one.
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

            // Compared with `==`, not matched: in a pattern, an uppercase path that fails
            // to resolve to a constant becomes a fresh binding rather than an error, so
            // the first arm would swallow every opcode and the only signal would be
            // `unreachable_patterns` — a warning. `==` makes that a type error.
            let target = if insn.code == LD_W_ABS {
                let offset = usize::try_from(insn.k)
                    .unwrap_or_else(|_| panic!("load offset {} does not fit a usize", insn.k));
                // `seccomp_check_filter()` refuses a filter whose absolute load is
                // unaligned or outside `struct seccomp_data`; restated here.
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
                // Unsigned, as classic BPF specifies; both sides are `u32`, so this is the
                // comparison the kernel makes.
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
    /// Every test goes through this rather than touching a word index, because `data[4]`
    /// is `args[0]`'s low half while `data[5]` is its high half and `data[6]` is `args[1]`
    /// — an off-by-one would silently assert about the wrong field.
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
    /// `domain` is wider than the `int` the kernel reads, so a test can put something in
    /// the half the comparison must ignore.
    fn socket_verdict(program: seccompiler::BpfProgramRef<'_>, domain: u64) -> u32 {
        verdict_with_args(program, libc::SYS_socket, [domain, 0, 0, 0, 0, 0])
    }

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

    #[test]
    fn socket_is_blocked_only_while_unix_is_withheld() {
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

    /// [`eval`] is itself untested code whose failure mode is the silent pass, so these
    /// cases cover the classic mis-implementations over hand-written programs rather than
    /// the compiled filter.
    ///
    /// `ALU|AND`, `JGT` and `JGE` are unreachable from [`compiled_filter`] today: sandbx
    /// builds only `Dword`/`Eq` rules, which compile to loads and `jeq`. They are
    /// implemented anyway, because the alternative is three arms that panic on a program
    /// seccompiler can legitimately emit.
    #[test]
    fn eval_implements_the_opcodes_seccompiler_can_emit() {
        // Every program loads word 0, `nr`, so the case's `nr` is what the comparison
        // sees. `jt`, `jf` and `JA`'s `k` are offsets from the *following* instruction,
        // so 1 skips exactly one.
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
                // An `i32` interpretation inverts this one: -1 is not > 1 signed, but
                // 0xffff_ffff is unsigned, and the kernel compares unsigned.
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
                // Without the mask 0x19 does not equal 0x10 and this falls to ALLOW,
                // so the case discriminates.
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
                // Reading the offset from `jt` (0) instead of `k` lands on ALLOW, so
                // the case discriminates.
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

    /// `expected` is not optional: without it the test also passes on the off-the-end
    /// panic, on the alignment assertion, or on an `unwrap` elsewhere in the body — any of
    /// which would leave the panic arm itself unexercised. The opcode is one seccompiler
    /// could plausibly grow into (`BPF_LDX | BPF_MEM | BPF_W`, a scratch-memory load)
    /// rather than a value no BPF dialect uses.
    #[test]
    #[should_panic(expected = "does not implement")]
    fn eval_refuses_an_opcode_it_does_not_implement() {
        let ldx_mem_w = (libc::BPF_LDX | libc::BPF_MEM | libc::BPF_W) as u16;

        eval(
            &[insn(ldx_mem_w, 0, 0, 0)],
            &seccomp_data(libc::SYS_getpid, [0; 6]),
        );
    }

    /// Nothing else here would notice if [`seccomp_data`] misplaced a field: every other
    /// test passes all-zero arguments or a value in `args[0]` alone, and the array starts
    /// zeroed — so the stride `4 + 2 * i` could map arguments 1 through 5 onto each
    /// other's words with all of them still passing.
    ///
    /// That matters for the next rule rather than today's: sandbx gates only on `socket`'s
    /// argument 0, but `clone`'s flags, `socket`'s `type` and an `ioctl` request all sit
    /// above index zero (#118), and a rule on one of those would be evaluated against the
    /// wrong word.
    ///
    /// Each half is checked separately, with distinct values, because an argument written
    /// as one 64-bit store to the right *pair* in the wrong order would otherwise pass.
    #[test]
    fn seccomp_data_puts_each_field_where_the_kernel_does() {
        let args = std::array::from_fn::<u64, 6, _>(|i| {
            let i = i as u64;
            (0x2000_0000 | i) << 32 | (0x1000_0000 | i)
        });
        let data = seccomp_data(libc::SYS_socket, args);

        // Byte offsets read off `struct seccomp_data`'s definition rather than off
        // `seccomp_data`'s own arithmetic: `nr` @0, `arch` @4, the 64-bit
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
            // `eval` has no way to return the accumulator — `BPF_RET | BPF_A` is not an
            // opcode seccompiler emits — so the comparison is the program: load the
            // field, return `ALLOW` only if it holds what it should.
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

    #[test]
    fn socket_refuses_af_unix_and_allows_af_inet() {
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

    /// `socket`'s `domain` is an `int`, so the kernel truncates it and a 64-bit comparison
    /// would look at register bits the kernel discards. That makes a `Dword`-to-`Qword`
    /// change a real bypass: `socket(0x1_0000_0001, …)` has the kernel see `AF_UNIX` while
    /// a `Qword` filter sees a non-zero high half, finds no match, and allows it. The test
    /// above leaves the high half zero and so passes against either width.
    #[test]
    fn the_af_unix_test_ignores_the_domains_high_half() {
        let program = compiled_filter(&SandboxPolicy::default()).unwrap();
        let noise = 0xdead_beef_0000_0000 | libc::AF_UNIX as u64;

        assert_eq!(
            socket_verdict(&program, noise),
            EPERM,
            "garbage in the high half of `domain` escapes the AF_UNIX rule, so the \
             comparison is 64-bit where the kernel's is 32-bit"
        );
    }

    /// The verdict for `clone(flags, …)`.
    fn clone_verdict(program: seccompiler::BpfProgramRef<'_>, flags: u64) -> u32 {
        verdict_with_args(program, libc::SYS_clone, [flags, 0, 0, 0, 0, 0])
    }

    /// Every namespace `unshare` is denied for is denied through `clone`'s flags too
    /// (#118), one flag at a time.
    ///
    /// Per flag rather than over the union: the rules are OR'd, so a filter that only
    /// fired when every flag was set would pass a union-only test.
    #[test]
    fn clone_cannot_create_a_namespace_unshare_is_denied_for() {
        let program = compiled_filter(&SandboxPolicy::default()).unwrap();

        for flag in NAMESPACE_CLONE_FLAGS {
            // `SIGCHLD` in the exit-signal byte, as a real caller passes it, so the test
            // would catch a rule that matched the flags word exactly instead of masking.
            let flags = *flag as u64 | libc::SIGCHLD as u64;

            assert_eq!(
                clone_verdict(&program, flags),
                EPERM,
                "clone({flag:#x}) is permitted, so the command can create a namespace \
                 that `unshare` is denied for"
            );
        }
    }

    /// The flag rules must not cost an ordinary `fork`, which is `clone` carrying no
    /// namespace flag at all. Without this, denying `clone` outright would pass the test
    /// above.
    #[test]
    fn clone_without_a_namespace_flag_is_allowed() {
        let program = compiled_filter(&SandboxPolicy::default()).unwrap();

        for (what, flags) in [
            ("a bare fork", libc::SIGCHLD as u64),
            (
                "a thread",
                (libc::CLONE_VM | libc::CLONE_FS | libc::CLONE_FILES | libc::CLONE_THREAD) as u64,
            ),
        ] {
            assert_eq!(
                clone_verdict(&program, flags),
                ALLOW,
                "clone() for {what} is refused, so the namespace rules have widened \
                 into every process creation"
            );
        }
    }

    /// `clone`'s flags are an `unsigned long`, but the kernel reads namespace bits out of
    /// the low half only, so the comparison has to ignore the high one — exactly as the
    /// socket rule does. A `Qword` rule would let `clone(0x1_0000_0000 | CLONE_NEWUSER)`
    /// through.
    #[test]
    fn the_clone_flag_comparison_ignores_the_high_half() {
        let program = compiled_filter(&SandboxPolicy::default()).unwrap();
        let flags = 0xdead_beef_0000_0000 | libc::CLONE_NEWUSER as u64;

        assert_eq!(
            clone_verdict(&program, flags),
            EPERM,
            "garbage in the high half of `clone`'s flags escapes the namespace rules, \
             so the comparison is 64-bit where the kernel's is 32-bit"
        );
    }

    /// `clone3` carries its flags in a struct seccomp cannot read, so it is refused
    /// outright — and with `ENOSYS`, which is what makes the `clone` rules reachable.
    ///
    /// glibc 2.34+ calls `clone3` from `pthread_create` and falls back to `clone` only on
    /// `ENOSYS`. `EPERM` here would break every threaded program rather than routing it
    /// onto the filtered `clone`, so the errno is load-bearing, not cosmetic.
    #[test]
    fn clone3_is_refused_with_enosys_so_callers_fall_back_to_clone() {
        let program = clone3_filter().unwrap();

        assert_eq!(
            verdict(&program, libc::SYS_clone3),
            ENOSYS,
            "clone3 does not answer ENOSYS, so either it is reachable — and its flags \
             are unreadable to seccomp — or glibc cannot fall back and threading breaks"
        );
        assert_eq!(
            verdict(&program, libc::SYS_clone),
            ALLOW,
            "the clone3 filter also answers for clone, which must reach the flag rules \
             in the denylist filter instead"
        );
    }

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

    /// `CLONE_NEWNET` and [`X32_SYSCALL_BIT`] are both `0x4000_0000`, in different fields.
    /// Pinned because the two rules added together read as if one constant could serve
    /// both, and a shared constant would couple a syscall number to a clone flag.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_x32_bit_and_clone_newnet_are_unrelated_despite_sharing_a_value() {
        let program = compiled_filter(&SandboxPolicy::default()).unwrap();

        assert_eq!(
            verdict(&program, X32_SYSCALL_BIT as libc::c_long | libc::SYS_getpid),
            ALLOW,
            "the denylist filter reacts to the x32 bit in `nr`, so a clone flag has \
             leaked into a syscall-number comparison"
        );
    }

    /// The second assertion is the one worth having: a grant that also widened the
    /// denylist would otherwise be invisible here.
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
    /// Syscall numbers are per-architecture, so a filter built for one cannot say anything
    /// safe about calls arriving from another; `seccomp_data.arch` is how the kernel
    /// tells, and seccompiler gates every filter on it before the first comparison. So an
    /// i386 binary on x86_64, or AArch32 on aarch64, dies rather than seeing `EPERM`,
    /// unlike every other denial in this file.
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

    /// Would the tests above notice if the filter pointed the other way?
    ///
    /// Proves the assertions above have mutation-killing power, and says nothing about
    /// production polarity: if [`compiled_filter`] were inverted this test would still
    /// pass and the ones above would fail, because this one asserts about
    /// [`inverted_filter`], a copy.
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
    /// Evaluation covers only the paths its data takes, and a wrong jump offset passes
    /// unnoticed. These checks close the rest, and every one is `bpf_check_classic()`
    /// restated rather than anything about seccompiler's codegen — the last-instruction
    /// check included.
    #[test]
    fn the_program_is_one_the_kernel_would_accept() {
        let filters = installed_filters(&SandboxPolicy::default()).unwrap();

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

    /// A diagnostic, not evidence about the filter. `AUDIT_ARCH` above is transcribed from
    /// `linux/audit.h`, and if it stops matching seccompiler's
    /// `TargetArch::get_audit_value` then most tests in this file fail as "expected ALLOW,
    /// got 0x80000000" and name nothing. This localizes that failure.
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
}
