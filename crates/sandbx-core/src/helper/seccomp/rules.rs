//! Which syscalls the filter denies, and under which policy.
//!
//! The data half of `super`: a constant denylist every command gets, plus the
//! conditional rules a grant widens or narrows. Nothing here touches the kernel —
//! `super` compiles what this returns and installs it, which is the other reason this
//! file would change and why it is not the same file.

use crate::SandboxError;

use super::seccomp_failed;

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
pub(super) const NAMESPACE_CLONE_FLAGS: &[libc::c_int] = &[
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
pub(super) const SOCK_TYPE_MASK: u64 = 0xf;

/// The seccomp denylist [`super::deny_dangerous_syscalls`] will install, as data.
///
/// Split out so it is assertable without a kernel. An empty rule vector means "match
/// this syscall unconditionally", so every listed number takes the filter's match
/// action and everything else is allowed.
pub(super) fn blocked_syscalls(
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
        // Appended, not inserted: rules for one syscall are OR'd, and `insert` would make a
        // second producer of `SYS_socket` rules wipe this one with no trace.
        rules
            .entry(libc::SYS_socket)
            .or_default()
            .push(SeccompRule::new(vec![af_unix]).map_err(seccomp_failed)?);
    }

    // A port allowlist claims egress reaches the ports it names and nowhere else, and
    // Landlock polices TCP alone — a UDP or raw socket would carry traffic anywhere and make
    // the claim false. True for `Ports` only: `Denied` is already in an empty netns and needs
    // `AF_NETLINK`, a `SOCK_DGRAM` socket, for `getaddrinfo`; `AnyPort` asked for
    // unrestricted egress. `context/decision-port-allowlist.md` records what this costs.
    let confine_to_tcp = match policy.network() {
        crate::NetworkPolicy::Denied | crate::NetworkPolicy::AnyPort => false,
        crate::NetworkPolicy::Ports(_) => true,
    };

    if confine_to_tcp {
        // Every value of the 4-bit type field but `SOCK_STREAM`: fifteen rules also close
        // `SOCK_SEQPACKET` (SCTP, which `ConnectTcp` does not police), `SOCK_RDM`,
        // `SOCK_PACKET` and whatever a future kernel assigns, where a denylist of
        // `SOCK_DGRAM` and `SOCK_RAW` is a guess about what exists. `SOCK_RAW` stays in
        // despite needing a `CAP_NET_RAW` the supervisor drops: the allowlist's integrity
        // must not rest on another subsystem having succeeded.
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

        // `SOCK_STREAM` is not TCP: `hook_socket_connect` asks for `CONNECT_TCP` only where
        // `sk_is_tcp` holds — `sk_type == SOCK_STREAM && sk_protocol == IPPROTO_TCP`
        // (`include/net/sock.h`) — and returns 0, unrestricted, for every other socket. So
        // `socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)` is a stream socket no port rule sees.
        //
        // Scoped per family rather than AND'ing `Ne AF_UNIX` as above, because `sk_is_inet`
        // is exactly these two: AF_VSOCK and AF_BLUETOOTH streams, which no port rule speaks
        // about either way, stay reachable.
        for family in [libc::AF_INET, libc::AF_INET6] {
            let is_family =
                SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, family as u64)
                    .map_err(seccomp_failed)?;
            // Protocol 0 is "this family's default for this type", which for a stream
            // socket is TCP, so it has to pass alongside the explicit number.
            let not_default =
                SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, 0)
                    .map_err(seccomp_failed)?;
            let not_tcp = SeccompCondition::new(
                2,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Ne,
                libc::IPPROTO_TCP as u64,
            )
            .map_err(seccomp_failed)?;

            rules.entry(libc::SYS_socket).or_default().push(
                SeccompRule::new(vec![is_family, not_default, not_tcp]).map_err(seccomp_failed)?,
            );
        }
    }

    Ok(rules)
}
