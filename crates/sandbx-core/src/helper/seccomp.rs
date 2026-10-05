//! The seccomp syscall filter applied to the sandboxed command.
//!
//! Covers the escapes Landlock cannot see: a syscall that reaches the kernel without
//! naming a path. The denylist is a constant so a test can assert the installed
//! filter still matches it, and `super::apply` installs it.
//!
//! Stacked filters, not one: a seccompiler filter carries a single match action, and
//! `clone3` must answer `ENOSYS` while everything else answers `EPERM`. Three on x86_64,
//! where the x32 gate also applies; two elsewhere. The kernel takes the most severe
//! verdict across every installed filter.

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
/// `CLONE_NEWTIME` is absent, and not because it is safe: `0x80` falls inside `CSIGNAL`,
/// and `SYSCALL_DEFINE5(clone)` takes `lower_32_bits(flags) & ~CSIGNAL`, so `clone`
/// silently drops the bit and creates no time namespace. Do not read a refusal into it —
/// the call succeeds. `unshare` and `clone3`, which do honour the flag, are denied
/// outright.
const NAMESPACE_CLONE_FLAGS: &[libc::c_int] = &[
    libc::CLONE_NEWNS,
    libc::CLONE_NEWCGROUP,
    libc::CLONE_NEWUTS,
    libc::CLONE_NEWIPC,
    libc::CLONE_NEWUSER,
    libc::CLONE_NEWPID,
    libc::CLONE_NEWNET,
];

/// `SOCK_TYPE_MASK` from `include/linux/net.h`: `__sys_socket` reads the socket type as
/// `type & 0xf` and takes the bits above it as `SOCK_NONBLOCK`/`SOCK_CLOEXEC`.
///
/// Which is why the rule below masks rather than compares: `SOCK_DGRAM | SOCK_CLOEXEC` is
/// `0x8_0002`, so an `Eq` against `SOCK_DGRAM` never fires while the kernel still hands back
/// a datagram socket.
const SOCK_TYPE_MASK: u64 = 0xf;

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
        // Appended, not inserted: `insert` would make a second producer of `SYS_socket`
        // rules wipe this one with no trace, and rules for one syscall are OR'd, so
        // appending is what "and also deny this" means.
        rules
            .entry(libc::SYS_socket)
            .or_default()
            .push(SeccompRule::new(vec![af_unix]).map_err(seccomp_failed)?);
    }

    // A port allowlist claims egress reaches the ports it names and nowhere else. Landlock's
    // network rules police TCP alone, so a command left holding a UDP or raw socket could
    // carry traffic to any host on any port and the claim would be false — `SECURITY.md` may
    // not overstate the sandbox, so the cheaper half of the promise is the one that goes.
    //
    // Matched exhaustively, and true for one state only. `Denied` is already in an empty
    // netns, where a datagram has nowhere to go, and needs `AF_NETLINK` — a `SOCK_DGRAM`
    // socket — for `getaddrinfo`. `AnyPort` asked for unrestricted egress, which this would
    // narrow. `context/decision-port-allowlist.md` records what the denial costs.
    let confine_to_tcp = match policy.network() {
        crate::NetworkPolicy::Denied | crate::NetworkPolicy::AnyPort => false,
        crate::NetworkPolicy::Ports(_) => true,
    };

    if confine_to_tcp {
        // Every value of the 4-bit type field but `SOCK_STREAM`, rather than the two named
        // constants: sixteen rules also close `SOCK_SEQPACKET` (SCTP, which `ConnectTcp`
        // does not police), `SOCK_RDM`, `SOCK_PACKET` and whatever a future kernel assigns,
        // where a denylist of `SOCK_DGRAM` and `SOCK_RAW` is a guess about what exists.
        //
        // `SOCK_RAW` also needs `CAP_NET_RAW`, which the supervisor drops, so it is mostly
        // unreachable already — kept because the allowlist's integrity must not rest on
        // another subsystem having succeeded.
        for socket_type in 0..=SOCK_TYPE_MASK {
            if socket_type == libc::SOCK_STREAM as u64 {
                continue;
            }

            // Unix sockets are a separate axis, granted or withheld by the rule above.
            // Without this condition a type denial aimed at IP egress would also refuse
            // `socket(AF_UNIX, SOCK_DGRAM)`, silently narrowing a grant it never mentions.
            let not_unix = SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Ne,
                libc::AF_UNIX as u64,
            )
            .map_err(seccomp_failed)?;
            // `Dword` for the reason the `clone` rule above gives: `type` is an `int` and
            // the kernel discards the register's high half, so a `Qword` compare misses
            // `socket(AF_INET, 0x1_0000_0002, 0)`.
            let is_type = SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                socket_type,
            )
            .map_err(seccomp_failed)?;

            rules
                .entry(libc::SYS_socket)
                .or_default()
                .push(SeccompRule::new(vec![not_unix, is_type]).map_err(seccomp_failed)?);
        }
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
/// `seccomp/tests/denylist.rs` keeps a twin of this function with the two actions swapped,
/// which is what proves those tests would notice. It only mutates the real path as long as
/// this body does nothing but call `SeccompFilter::new` — if that changes, change the twin.
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
///
/// A negative `nr` is excluded before the mask, or `syscall(-1)` — `0xffff_ffff`, bit 30
/// among the rest — would die by signal where every kernel answers `ENOSYS`. `do_syscall_64`
/// special-cases `nr == -1`, and x32 dispatch is `nr - BIT < X32_NR_syscalls`, so nothing
/// with the sign bit set is x32. A positive number past the end of the x32 table is still
/// killed rather than refused: matching the table exactly would mean pinning its size here,
/// and only an x32 caller reaches for those numbers at all.
#[cfg(target_arch = "x86_64")]
fn x32_gate() -> seccompiler::BpfProgram {
    let insn = |code: u16, jt: u8, jf: u8, k: u32| seccompiler::sock_filter { code, jt, jf, k };

    // `jt`/`jf` count from the *following* instruction. Laid out so the two returns sit
    // last: both jumps forward, and the fallthrough is the allow.
    vec![
        // `nr` is the first word of `struct seccomp_data`.
        insn((libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, 0, 0, 0),
        // Sign bit set? Not x32 — skip to the allow.
        insn(
            (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16,
            3,
            0,
            0x8000_0000,
        ),
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
mod tests;
