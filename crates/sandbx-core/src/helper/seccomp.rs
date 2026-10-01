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
/// Lifted out of [`deny_dangerous_syscalls`] so a test can assert the list still
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
/// Split out for the same reason as [`fs_rules`] (#52).
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
    // path-scoped right in ABI V9 (Linux 6.15), which `apply` already handles
    // best-effort; a per-socket grant can follow once that exists in practice.
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

/// Compile [`blocked_syscalls`] into a seccomp filter and install it.
///
/// Blocked calls return `EPERM` rather than killing the process. The syscall
/// does not execute either way; `EPERM` is what tools already expect on hardened
/// systems, so they fail that operation instead of dying mid-run.
pub(super) fn deny_dangerous_syscalls(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

    let filter = SeccompFilter::new(
        blocked_syscalls(policy)?,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH.try_into().map_err(seccomp_failed)?,
    )
    .map_err(seccomp_failed)?;

    let program: BpfProgram = filter.try_into().map_err(seccomp_failed)?;
    seccompiler::apply_filter(&program).map_err(seccomp_failed)
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
}
