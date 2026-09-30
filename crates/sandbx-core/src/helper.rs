use crate::{HelperArgs, SandboxError};

/// Apply a policy to *this* process, then become the requested command.
///
/// Intended to run in a freshly executed helper process, never inside sandbx:
/// Landlock restrictions are irreversible and inherited, so applying them here
/// would cage sandbx itself.
///
/// Because this process is fresh, it is single-threaded, and the restriction
/// code runs in an ordinary context — no `fork`/`exec` window, so no
/// async-signal-safety constraint and no `unsafe`.
///
/// On success this never returns: the process image is replaced. Any return is
/// an error, and the caller must exit non-zero rather than continue — a helper
/// that fell through to running the command unrestricted would be the exact
/// failure the sandbox exists to prevent.
pub fn exec_sandboxed(argv: &[String]) -> Result<std::convert::Infallible, SandboxError> {
    let request = HelperArgs::decode(argv)?;

    apply(&request.policy)?;

    // The workspace bans `Command::new` so nothing can spawn around the sandbox.
    // This is the one sanctioned call: `apply` has already restricted this
    // process, so the command inherits the cage rather than escaping it. The
    // allow is per-call-site, not crate-wide, so any other use still fails the
    // lint.
    let error = {
        use std::os::unix::process::CommandExt;
        #[allow(clippy::disallowed_methods)]
        std::process::Command::new(&request.program)
            .args(&request.args)
            .exec()
    };

    Err(SandboxError::SpawnFailed {
        detail: "could not execute the sandboxed command",
        source: error,
    })
}

#[cfg(target_os = "linux")]
fn apply(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };

    // Network first, while this process still has the privileges to do it:
    // Landlock's restrict_self is irreversible, so anything needing capabilities
    // must happen before it.
    if !policy.allows_network() {
        deny_network()?;
    }

    // After, not before: `deny_network` may have just entered a fresh user
    // namespace, which grants this process the full capability set *within
    // it* — dropping capabilities earlier would be undone by that unshare.
    harden_process_state()?;

    // Installing a seccomp filter requires either CAP_SYS_ADMIN or no_new_privs.
    // Set it explicitly rather than relying on the user namespace above, which
    // only exists when network is denied. It is irreversible and inherited
    // across exec, which is what makes the filter stick to the real command.
    nix::sys::prctl::set_no_new_privs().map_err(|errno| SandboxError::Seccomp {
        detail: format!("could not set no_new_privs: {errno}"),
    })?;

    deny_dangerous_syscalls(policy)?;

    // Landlock leaves access types that are NOT in the handled set unrestricted
    // *everywhere*. Pinning a low ABI therefore does not mean "enforce less"; it
    // means whole categories go completely unguarded — which is how `truncate(2)`
    // was permitted on any file regardless of policy.
    //
    // So negotiate rather than pin. `handle_access` accumulates (`|=`), so the
    // baseline can be a hard requirement while newer rights are best-effort.
    const BASELINE: ABI = ABI::V5; // Linux 6.10: adds Truncate, Refer, IoctlDev
    const LATEST: ABI = ABI::V9; // Linux 6.15: adds ResolveUnix

    // `from_read` bundles `Execute` in with `ReadFile`/`ReadDir`, and `from_all`
    // inherits it. Granting either would otherwise hand out the right to *run*
    // whatever the path contains, which neither `allow_read` nor `allow_write`
    // says (#19). Execute comes from one axis, named for it.
    let read_execute = AccessFs::from_read(LATEST);
    let read_only = read_execute & !AccessFs::Execute;
    let read_write = AccessFs::from_all(LATEST) & !AccessFs::Execute;

    let mut ruleset = Ruleset::default()
        // Refuse a kernel that cannot enforce the baseline, rather than running
        // with a silent hole in it.
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(BASELINE))
        .map_err(landlock_failed)?
        // Anything newer is a bonus: handled where the kernel has it, dropped
        // where it does not.
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(LATEST))
        .map_err(landlock_failed)?
        .create()
        .map_err(landlock_failed)?;

    // Directory-only rights (ReadDir, MakeDir, …) are invalid on a regular file
    // and the kernel rejects the whole ruleset if one is attached to it. A
    // policy may name either, so narrow the rights to what the target can
    // actually carry. Intersecting rather than substituting keeps this a
    // restriction: a file can never end up with more than the directory case.
    let file_rights = AccessFs::from_file(LATEST);
    for (paths, rights) in [
        (policy.readable_paths(), read_only),
        (policy.writable_paths(), read_write),
        (policy.executable_paths(), read_execute),
    ] {
        for path in paths {
            let rights = if path.is_dir() {
                rights
            } else {
                rights & file_rights
            };
            let fd = PathFd::new(path).map_err(landlock_failed)?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, rights))
                .map_err(landlock_failed)?;
        }
    }

    let status = ruleset.restrict_self().map_err(landlock_failed)?;

    // The kernel may accept a ruleset and enforce only part of it. Partial
    // enforcement is treated as failure: it would leave the caller believing in
    // restrictions that are not actually in place.
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(SandboxError::Unsupported {
            detail: "kernel accepted the ruleset but enforced none of it",
        });
    }

    Ok(())
}

/// Drop capabilities and disable core dumps.
///
/// Landlock and seccomp bound what the sandboxed command can *do*; this bounds
/// what a descendant that somehow survives the kill (#28) can still reach.
/// None of it needs privilege to apply in the general case: every one of these
/// calls only ever removes a right this process already holds, never grants
/// one.
///
/// Deliberately does NOT set `PR_SET_DUMPABLE`: the kernel resets that flag to
/// dumpable on every `execve` of an ordinary (non-setuid, no file-capability)
/// binary — see `setup_new_exec` in `fs/exec.c` — so setting it here would
/// only affect this process's own brief pre-exec window, not the command it
/// is about to become. Applying it would be a claim `SECURITY.md` cannot back
/// up, not real hardening; core dumps are already fully covered below via
/// `RLIMIT_CORE`, which — unlike the dumpable flag — does persist across exec.
///
/// The capability *bounding* set is best-effort, and deliberately so. Dropping
/// it needs `CAP_SETPCAP`, which an unprivileged process holds only inside a
/// user namespace it created itself — and not even there when an LSM strips
/// capabilities from such a namespace. AppArmor's
/// `restrict_unprivileged_userns` (default on Ubuntu 24.04+, and set on
/// GitHub's runners) does exactly that: `deny_network`'s `unshare` succeeds,
/// but `PR_CAPBSET_DROP` then returns `EPERM`. Treating that as a refusal
/// would take the sandbox away entirely on the most common Linux desktop and
/// CI hosts, in exchange for a bit that cannot be spent: once the four sets
/// below are empty and `no_new_privs` is set, the kernel caps the permitted
/// set of an `execve`d binary at the old one and refuses to raise inheritable
/// or ambient, so a leftover bounding bit can never become privilege. So it is
/// attempted and logged, not enforced — and `SECURITY.md` claims it as
/// best-effort rather than as part of the boundary.
///
/// Order matters within this function: the bounding set is dropped *before*
/// the effective set, not after. `PR_CAPBSET_DROP` itself requires
/// `CAP_SETPCAP` in the effective set — clearing effective first would remove
/// the very right this function needs to drop the bounding set at all.
#[cfg(target_os = "linux")]
fn harden_process_state() -> Result<(), SandboxError> {
    use caps::CapSet;

    if let Err(error) = caps::clear(None, CapSet::Bounding) {
        tracing::debug!(
            target: crate::AUDIT_TARGET,
            "could not drop the capability bounding set, leaving it as inherited: {error}"
        );
    }

    for set in [
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
        CapSet::Ambient,
    ] {
        caps::clear(None, set).map_err(hardening_failed)?;
    }

    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0).map_err(
        |errno| SandboxError::ProcessHardening {
            detail: format!("could not set RLIMIT_CORE: {errno}"),
        },
    )?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn hardening_failed(source: impl std::fmt::Display) -> SandboxError {
    SandboxError::ProcessHardening {
        detail: source.to_string(),
    }
}

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
/// contains what `SECURITY.md` and `context/SANDBOXING.md` claim it does. The
/// filter is built from this and nothing else, so the two cannot drift.
#[cfg(target_os = "linux")]
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
    // This one has a real compatibility cost, unlike the rest of this list: Go's
    // runtime and some loaders and package managers use `memfd_create` legitimately.
    // It is denied anyway because no caller needs it yet, so the restrictive
    // default is the one to start from and loosen on evidence — if a common tool
    // turns out to break, that evidence is a reason to revisit this, possibly as
    // its own policy axis.
    libc::SYS_memfd_create,
    // Whole-machine effects.
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
];

/// Compile [`BLOCKED_SYSCALLS`] into a seccomp filter and install it.
///
/// Blocked calls return `EPERM` rather than killing the process. The syscall
/// does not execute either way; `EPERM` is what tools already expect on hardened
/// systems, so they fail that operation instead of dying mid-run.
#[cfg(target_os = "linux")]
fn deny_dangerous_syscalls(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    use std::collections::BTreeMap;

    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule,
    };

    // An empty rule vector means "match this syscall unconditionally", so every
    // listed number takes `match_action` and everything else is allowed.
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

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH.try_into().map_err(seccomp_failed)?,
    )
    .map_err(seccomp_failed)?;

    let program: BpfProgram = filter.try_into().map_err(seccomp_failed)?;
    seccompiler::apply_filter(&program).map_err(seccomp_failed)
}

#[cfg(target_os = "linux")]
fn seccomp_failed(source: impl std::fmt::Display) -> SandboxError {
    SandboxError::Seccomp {
        detail: source.to_string(),
    }
}

/// Move this process into an empty network namespace.
///
/// A fresh netns has only a (down) loopback interface and no route anywhere, so
/// there is no network to reach rather than a filtered one. That is stronger
/// than Landlock's network rules, which only cover TCP bind/connect and would
/// leave UDP and raw sockets untouched.
///
/// `CLONE_NEWUSER` is requested alongside `CLONE_NEWNET` because creating a
/// network namespace otherwise needs `CAP_SYS_ADMIN`; a user namespace grants
/// that capability *within the new namespace only*, which is what lets this work
/// unprivileged. Some distributions restrict unprivileged user namespaces (e.g.
/// AppArmor's `kernel.apparmor_restrict_unprivileged_userns`), and there the
/// call fails — which surfaces as a refusal, never as a silent fallback to an
/// unrestricted network.
#[cfg(target_os = "linux")]
fn deny_network() -> Result<(), SandboxError> {
    use nix::sched::{CloneFlags, unshare};
    use nix::unistd::{getgid, getuid};

    // Captured before the unshare: afterwards this process reads back as the
    // overflow uid, and it is the *real* identity we want to map to itself.
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();

    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET).map_err(|errno| {
        SandboxError::NetworkDenialFailed {
            detail: match errno {
                nix::errno::Errno::EPERM => {
                    "kernel refused an unprivileged user namespace; unprivileged \
                     userns may be disabled (see kernel.unprivileged_userns_clone \
                     and kernel.apparmor_restrict_unprivileged_userns)"
                }
                _ => "could not create a network namespace",
            },
        }
    })?;

    map_identity_into_userns(uid, gid);
    Ok(())
}

/// Map the real uid/gid to themselves inside the fresh user namespace.
///
/// Without this the namespace has no map, so the process reads back as the
/// overflow uid (`nobody`) even though its on-host identity is unchanged — a
/// file it writes is still owned by the real user. Tools that branch on
/// `getuid()` see a value that does not match reality; mapping the identity to
/// itself makes the namespace transparent without granting anything, since the
/// process already acts as this uid on the host.
///
/// Best-effort, deliberately. This is not a security control — running as the
/// overflow `nobody` is if anything *more* restrictive, and it is what happened
/// before this map existed. Some environments create the namespace but deny the
/// map: AppArmor's `restrict_unprivileged_userns` (default on Ubuntu 24.04+)
/// leaves an unprivileged userns without `CAP_SETUID`, so the write is refused.
/// Aborting the sandbox there would trade a truthful uid for no sandbox at all,
/// which is the wrong way round — so a failed write leaves the process as
/// `nobody` and the command still runs fully confined.
#[cfg(target_os = "linux")]
fn map_identity_into_userns(uid: u32, gid: u32) {
    // `setgroups` must be denied before an unprivileged `gid_map` write, or the
    // kernel rejects it. Denying it is correct anyway: this maps a single gid,
    // so there are no supplementary groups to set. If any write fails the rest
    // are skipped and the namespace simply stays unmapped.
    let mapped = std::fs::write("/proc/self/setgroups", "deny")
        .and_then(|()| std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1")))
        .and_then(|()| std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1")));

    if let Err(error) = mapped {
        tracing::debug!(
            target: crate::AUDIT_TARGET,
            "could not map user namespace identity, running as nobody: {error}"
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn apply(_policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    Err(SandboxError::Unsupported {
        detail: "sandboxing is only implemented for Linux",
    })
}

#[cfg(target_os = "linux")]
fn landlock_failed(source: impl std::fmt::Display) -> SandboxError {
    // Carry the kernel's own reason: "refused" without a cause is unactionable
    // for whoever has to work out which path or access right it objected to.
    SandboxError::Landlock {
        detail: source.to_string(),
    }
}
