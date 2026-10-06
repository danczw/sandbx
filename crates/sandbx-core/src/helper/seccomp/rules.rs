//! Which syscalls the filter denies, and under which policy.
//!
//! The data half of `super`: a constant denylist every command gets, plus the conditional
//! rules a grant widens or narrows. Nothing here touches the kernel — `super` compiles what
//! this returns and installs it.

use crate::SandboxError;

use super::seccomp_failed;

/// Syscalls blocked for every sandboxed command, regardless of policy.
///
/// A denylist: sandbx runs arbitrary commands — shells, compilers, package managers — whose
/// syscall use is unbounded, so the stronger allowlist shape would break real tools
/// constantly. Landlock can express none of these; they are not filesystem access. The filter
/// is built from this and nothing else, so a test can assert it still covers `SECURITY.md`.
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
    // holds one — a socket, an open file above the policy — which is not filesystem access,
    // so Landlock cannot express it and denying `ptrace` does not cover it. `pidfd_open` is
    // how the handle is obtained.
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_getfd,
    // userfaultfd hands the faulting process control over when a page fault resolves, turning
    // any check-then-use in the kernel into an arbitrarily wide window.
    libc::SYS_userfaultfd,
    // io_uring runs operations from a submission queue without issuing the matching syscalls,
    // so a ring set up here would route around every rule in this filter — including the
    // `socket(AF_UNIX)` denial added on top of this list.
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    // An anonymous in-memory file has no path, and Landlock binds its rules to inodes and
    // paths, so a payload staged in a memfd sits outside the filesystem layer entirely.
    //
    // The one entry with a real compatibility cost, and a narrow one: the heavy users are
    // container runtimes (runc re-execs a sealed memfd copy of itself against CVE-2019-5736),
    // systemd and snapd — and a container runtime cannot run in here anyway, `unshare` being
    // denied above.
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
/// `CLONE_NEWTIME` is absent, and not because it is safe: `0x80` falls inside `CSIGNAL`, and
/// `SYSCALL_DEFINE5(clone)` takes `lower_32_bits(flags) & ~CSIGNAL`, so `clone` silently
/// drops the bit and creates no time namespace — do not read a refusal into it, the call
/// succeeds. `unshare` and `clone3`, which do honour the flag, are denied outright.
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
/// Hence masking rather than comparing: `SOCK_DGRAM | SOCK_CLOEXEC` is `0x8_0002`, so an `Eq`
/// against `SOCK_DGRAM` never fires while the kernel still hands back a datagram socket.
pub(super) const SOCK_TYPE_MASK: u64 = 0xf;

/// One comparison against one syscall argument.
///
/// Always `Dword`, because every argument the rules below examine is read by the kernel as a
/// 32-bit value — `socket`'s three `int`s, `clone`'s flags through `lower_32_bits`,
/// `sendmsg`'s `int flags`. A `Qword` compare would consult register bits no kernel check
/// sees, so `socket(AF_INET, 0x1_0000_0002, 0)` would escape a rule that named `SOCK_DGRAM`.
fn arg(
    index: u8,
    op: seccompiler::SeccompCmpOp,
    value: u64,
) -> Result<seccompiler::SeccompCondition, SandboxError> {
    seccompiler::SeccompCondition::new(index, seccompiler::SeccompCmpArgLen::Dword, op, value)
        .map_err(seccomp_failed)
}

/// Deny `syscall` for the calls matching all of `conditions`, unless it is already denied
/// unconditionally.
///
/// Two things make the guard load-bearing. Rules for one syscall are OR'd, so `insert` would
/// let a second producer wipe the first with no trace; and an empty rule vector means "match
/// every call", so appending to one would turn a total denial into a partial one — the filter
/// getting weaker because a number was added to [`BLOCKED_SYSCALLS`]. Skipping is fail-closed:
/// the unconditional denial already covers everything the rule would.
pub(super) fn deny_when(
    rules: &mut std::collections::BTreeMap<libc::c_long, Vec<seccompiler::SeccompRule>>,
    syscall: libc::c_long,
    conditions: Vec<seccompiler::SeccompCondition>,
) -> Result<(), SandboxError> {
    if rules.get(&syscall).is_some_and(Vec::is_empty) {
        return Ok(());
    }

    let rule = seccompiler::SeccompRule::new(conditions).map_err(seccomp_failed)?;
    rules.entry(syscall).or_default().push(rule);
    Ok(())
}

/// The seccomp denylist [`super::deny_dangerous_syscalls`] will install, as data.
///
/// Split out so it is assertable without a kernel. An empty rule vector means "match this
/// syscall unconditionally", so every listed number takes the filter's match action and
/// everything else is allowed.
pub(super) fn blocked_syscalls(
    policy: &crate::SandboxPolicy,
) -> Result<std::collections::BTreeMap<libc::c_long, Vec<seccompiler::SeccompRule>>, SandboxError> {
    use std::collections::BTreeMap;

    use seccompiler::SeccompCmpOp::{Eq, MaskedEq, Ne};

    let mut rules = BLOCKED_SYSCALLS
        .iter()
        .copied()
        .map(|nr| (nr, Vec::new()))
        .collect::<BTreeMap<_, _>>();

    // One rule per flag, because rules for a syscall are OR'd while conditions inside a rule
    // are AND'd — one `MaskedEq` over the union would fire only when *every* flag was set.
    for flag in NAMESPACE_CLONE_FLAGS {
        let flag = *flag as u64;
        deny_when(
            &mut rules,
            libc::SYS_clone,
            vec![arg(0, MaskedEq(flag), flag)?],
        )?;
    }

    // Unix sockets are their own axis, not a sub-case of network: a netns isolates only
    // *abstract* unix sockets, while pathname sockets live in the filesystem and cross it
    // freely, so a command that can dial systemd's bus, docker.sock or an ssh-agent has them
    // act outside the sandbox. An escape, not egress, so granting the internet does not
    // grant this.
    //
    // All or nothing: seccomp compares register values and cannot follow the pointer to
    // `connect`'s path. Per-socket grants need Landlock ABI V9 (Linux 7.1), which
    // `negotiated_abi` cannot settle on until a kernel accepts it in full. `socketpair` is
    // left alone: an anonymous pair has no path to reach a host daemon with, and shells use
    // it routinely.
    if !policy.allows_unix_sockets() {
        deny_when(
            &mut rules,
            libc::SYS_socket,
            vec![arg(0, Eq, libc::AF_UNIX as u64)?],
        )?;
    }

    // A port allowlist claims egress reaches the ports it names and nowhere else, and Landlock
    // polices TCP alone — a UDP or raw socket would carry traffic anywhere and make the claim
    // false. For `Ports` only: `Denied` is already in an empty netns and needs `AF_NETLINK`
    // — `SOCK_RAW`, how glibc's `__check_pf` opens it — for `getaddrinfo`, and `AnyPort` asked
    // for unrestricted egress. `context/decision-port-allowlist.md` for what this costs.
    let confine_to_tcp = match policy.network() {
        crate::NetworkPolicy::Denied | crate::NetworkPolicy::AnyPort => false,
        crate::NetworkPolicy::Ports(_) => true,
    };

    if confine_to_tcp {
        // Unix sockets are the separate axis above: without this condition a denial aimed at
        // IP egress would also refuse `socket(AF_UNIX, SOCK_DGRAM)`, silently narrowing a
        // grant it never mentions.
        let not_unix = arg(0, Ne, libc::AF_UNIX as u64)?;
        let is_stream = arg(1, MaskedEq(SOCK_TYPE_MASK), libc::SOCK_STREAM as u64)?;

        // Every value of the 4-bit type field but `SOCK_STREAM`: fifteen rules also close
        // `SOCK_SEQPACKET` (SCTP, which `ConnectTcp` does not police), `SOCK_RDM`,
        // `SOCK_PACKET` and whatever a future kernel assigns, where a denylist of `SOCK_DGRAM`
        // and `SOCK_RAW` is a guess about what exists. `SOCK_RAW` stays in despite needing a
        // `CAP_NET_RAW` the supervisor drops: this allowlist's integrity must not rest on
        // another subsystem having succeeded.
        for socket_type in 0..=SOCK_TYPE_MASK {
            if socket_type == libc::SOCK_STREAM as u64 {
                continue;
            }

            let is_type = arg(1, MaskedEq(SOCK_TYPE_MASK), socket_type)?;
            deny_when(
                &mut rules,
                libc::SYS_socket,
                vec![not_unix.clone(), is_type],
            )?;
        }

        // A stream socket outside the IP families, because a family that tunnels IP dials its
        // inner socket with `kernel_connect`, which calls `sock->ops->connect` without
        // `security_socket_connect` — so no Landlock hook runs. `smc_connect`
        // (`net/smc/af_smc.c`) is the reachable one: `socket(AF_SMC, SOCK_STREAM, …)`
        // autoloads `net-pf-43` unprivileged and reaches any TCP port. `AF_TIPC` and `AF_IB`
        // have the same shape, hence an allowlist of the families a port rule can speak about
        // rather than a denylist of the ones known to tunnel.
        deny_when(
            &mut rules,
            libc::SYS_socket,
            vec![
                is_stream.clone(),
                not_unix.clone(),
                arg(0, Ne, libc::AF_INET as u64)?,
                arg(0, Ne, libc::AF_INET6 as u64)?,
            ],
        )?;

        // The rule above guards `socket`, where the family is not yet settled for good:
        // `setsockopt(fd, SOL_TCP, TCP_ULP, "smc")` runs `smc_ulp_init`, which assigns
        // `file->private_data = smcsock`, so `sock_from_file` sends a later `connect` to
        // `smc_connect` and `sk_is_tcp` is false for the result. Nothing privileged is
        // involved — `__tcp_ulp_find_autoload`'s `CAP_NET_ADMIN` gates the module autoload,
        // not the lookup of a resident ULP.
        //
        // 31 is `TCP_ULP` (`include/uapi/linux/tcp.h`), which `libc` does not name; level 6 is
        // the only route into `do_tcp_setsockopt`. The option and not the ULP name, `optval`
        // being behind a pointer — so this costs kTLS too.
        deny_when(
            &mut rules,
            libc::SYS_setsockopt,
            vec![arg(1, Eq, libc::IPPROTO_TCP as u64)?, arg(2, Eq, 31)?],
        )?;

        // `SOCK_STREAM` is not TCP: `hook_socket_connect` asks for `CONNECT_TCP` only where
        // `sk_is_tcp` holds — `sk_type == SOCK_STREAM && sk_protocol == IPPROTO_TCP`
        // (`include/net/sock.h`) — and returns 0, unrestricted, for anything else. So
        // `socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)` is a stream socket no port rule sees.
        for family in [libc::AF_INET, libc::AF_INET6] {
            deny_when(
                &mut rules,
                libc::SYS_socket,
                vec![
                    arg(0, Eq, family as u64)?,
                    // Protocol 0 is "this family's default for this type", which for a stream
                    // socket is TCP, so it has to pass alongside the explicit number.
                    arg(2, Ne, 0)?,
                    arg(2, Ne, libc::IPPROTO_TCP as u64)?,
                ],
            )?;
        }

        // TCP Fast Open connects without `connect`: `tcp_sendmsg_locked` routes a send with
        // `MSG_FASTOPEN` into `tcp_sendmsg_fastopen`, which calls `__inet_stream_connect`
        // directly (`net/ipv4/tcp.c`). `security_socket_connect` is reached only from
        // `__sys_connect_file`, so the port in `msg_name` is one Landlock never sees, and
        // `net.ipv4.tcp_fastopen` has client mode on by default. The flag is a register value,
        // so seccomp can refuse it, and an ordinary send never sets it.
        for (syscall, flags_arg) in [
            (libc::SYS_sendto, 3),
            (libc::SYS_sendmsg, 2),
            (libc::SYS_sendmmsg, 3),
        ] {
            let fastopen = libc::MSG_FASTOPEN as u64;
            deny_when(
                &mut rules,
                syscall,
                vec![arg(flags_arg, MaskedEq(fastopen), fastopen)?],
            )?;
        }
    }

    Ok(rules)
}
