//! Process state the sandbox depends on but Landlock and seccomp cannot express:
//! namespaces, capability sets, resource limits, and the supervisor the inner
//! stage checks for.
//!
//! All of it is inherited across `exec`, which is what lets stage 1 set it up and
//! stage 2 still be covered by it. Every change here is irreversible for the
//! process that makes it, so none of it may run inside sandbx itself — see
//! `super::exec_sandboxed`.

use crate::SandboxError;

/// Build the namespaces and drop what must be dropped before the `exec`.
///
/// Split out from [`apply`](super::apply) because these two steps are the ones that have to
/// happen in the *supervisor*, not in the stage that becomes the command:
///
/// - the namespaces, because `CLONE_NEWPID` only places this process's children,
///   so unsharing here is what makes the inner stage PID 1;
/// - the capability drops, because `PR_CAPBSET_DROP` needs `CAP_SETPCAP` in the
///   effective set, which an unprivileged process only ever holds inside a user
///   namespace it just created. All four sets and `RLIMIT_CORE` are inherited
///   across `fork` and `exec`, so dropping them here still covers the command.
pub(super) fn prepare_supervisor(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    isolate(policy)?;

    // After the unshare, not before: entering a fresh user namespace grants the
    // full capability set *within it*, so dropping earlier would be undone.
    harden_process_state()?;

    // Here as well as in the inner stage, so that *every* `exec` this design
    // performs is covered by it rather than only the last one.
    //
    // Splitting the helper in two added an `execve` — this stage into the inner
    // one — that sits after the capability sets are cleared. Without this, what
    // stops a capability being regained across it is that the binary being
    // executed is our own, unprivileged and without file capabilities, plus uid 0
    // being unmapped in the fresh user namespace. Both hold, which is why this is
    // hardening and not a fix. But it makes the guarantee rest on properties of
    // the binary and the uid map rather than on a flag that states it directly,
    // and the flag costs one syscall.
    //
    // Deliberately not removed from the inner stage. It is irreversible and
    // inherited, so the second call is a no-op — but the inner stage must not
    // depend on a caller having set it, since seccomp will not install without it.
    set_no_new_privs()
}

/// Die when the supervisor dies (#28).
///
/// This process is PID 1 of a fresh PID namespace, and the kernel SIGKILLs every
/// remaining process in a namespace whose init exits. So making this process die
/// with its supervisor is what turns the timeout's kill from advisory into
/// unconditional: whatever the command spawned, however it detached itself, it
/// goes when this process goes.
///
/// Two independent paths reach us, deliberately. The supervisor stays in the
/// process group sandbx kills, and so do we — but the command we are about to
/// become may call `setsid` and leave it, which is the whole of #28. The parent
/// death signal does not care: it fires on the supervisor's death, not on group
/// membership, and it survives `execve` of an ordinary binary. Keeping both means
/// neither one is a single point of failure — worth having, because the kernel
/// clears this signal for a secure `exec` (a setuid target or one with file
/// capabilities), where the group kill is then what still reaps us.
///
/// Set before anything else in this stage, so the window in which the supervisor
/// could die unnoticed is as short as the kernel allows. The window is not closed
/// by this alone; `confirm_supervisor` is what closes it.
pub(super) fn bind_lifetime_to_supervisor() -> Result<(), SandboxError> {
    nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL).map_err(|errno| {
        SandboxError::NamespaceSetupFailed {
            detail: match errno {
                nix::errno::Errno::EPERM => {
                    "kernel refused a parent death signal; the sandboxed command \
                     could outlive the call that started it"
                }
                _ => "could not bind the command's lifetime to its supervisor",
            },
        }
    })
}

/// Refuse to run unless the supervisor is still our parent.
///
/// This is what closes the window [`bind_lifetime_to_supervisor`] cannot: if the
/// supervisor died before the parent death signal was armed, nothing will ever kill
/// this process, and the command would run to completion as PID 1 of a namespace no
/// one is watching. Ordering is what makes the pair complete — arm first, then
/// check. A death before the check is caught by the check; a death after it is
/// caught by the signal that is already armed.
///
/// `getppid` is no use here: this process is PID 1 of a namespace whose parent lives
/// outside it, so the kernel has no number to report and returns 0. `/proc` is still
/// the host's procfs, though — it is not remounted, because that would need
/// `mount(2)`, which the filter denies — so its `ppid` field names the supervisor in
/// host numbering, which is exactly what was passed in.
///
/// Pid reuse cannot produce a false pass: the comparison is against the kernel's
/// live parent link, and an orphan is reparented to init or a subreaper, neither of
/// which can be the pid of a supervisor that just spawned us.
///
/// Runs before Landlock and seccomp, so it needs no grant for `/proc` and no
/// privilege.
pub(super) fn confirm_supervisor(expected: &str) -> Result<(), SandboxError> {
    let gone = SandboxError::NamespaceSetupFailed {
        detail: "the supervisor process is gone; refusing to run the command \
                 where nothing can reap it",
    };

    let unreadable = SandboxError::NamespaceSetupFailed {
        detail: "could not read this process's parent to confirm the supervisor \
                 is still watching it",
    };

    let stat = std::fs::read_to_string("/proc/self/stat").map_err(|_| unreadable)?;

    // Field 4 of `/proc/pid/stat`, counting from 1. Split after the *last* `)`
    // rather than on whitespace from the start: field 2 is the executable name,
    // unquoted and free to contain spaces and parentheses of its own, so counting
    // from the left is how this kind of parse goes wrong.
    let parent = stat
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(1));

    match parent {
        Some(parent) if parent == expected => Ok(()),
        _ => Err(gone),
    }
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
/// GitHub's runners) does exactly that: `isolate`'s `unshare` succeeds,
/// but `PR_CAPBSET_DROP` then returns `EPERM`. Treating that as a refusal
/// would take the sandbox away entirely on the most common Linux desktop and
/// CI hosts, in exchange for a bit that cannot be spent: once the four sets
/// below are empty and `no_new_privs` is set, the kernel caps the permitted
/// set of an `execve`d binary at the old one and refuses to raise inheritable
/// or ambient, so a leftover bounding bit can never become privilege. So it is
/// attempted and logged, not enforced — and `SECURITY.md` claims it as
/// best-effort rather than as part of the boundary. A failure is recorded as an
/// [`AuditEvent::Degraded`](crate::AuditEvent::Degraded), not at debug level: it
/// fails on whole classes of host, so the one run where it matters is not the
/// one where someone thought to raise the log level.
///
/// Order matters within this function: the bounding set is dropped *before*
/// the effective set, not after. `PR_CAPBSET_DROP` itself requires
/// `CAP_SETPCAP` in the effective set — clearing effective first would remove
/// the very right this function needs to drop the bounding set at all.
fn harden_process_state() -> Result<(), SandboxError> {
    use caps::CapSet;

    if let Err(error) = caps::clear(None, CapSet::Bounding) {
        crate::AuditEvent::degraded(
            "capability_bounding_set",
            &format!("left as inherited: {error}"),
        )
        .emit();
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

/// Set `no_new_privs`, refusing if the kernel will not.
///
/// Shared by both stages. Irreversible and inherited across `exec`, and a
/// precondition for installing a seccomp filter without `CAP_SYS_ADMIN` — so a
/// failure here is a refusal, not something to carry on from.
pub(super) fn set_no_new_privs() -> Result<(), SandboxError> {
    nix::sys::prctl::set_no_new_privs().map_err(|errno| SandboxError::Seccomp {
        detail: format!("could not set no_new_privs: {errno}"),
    })
}

fn hardening_failed(source: impl std::fmt::Display) -> SandboxError {
    SandboxError::ProcessHardening {
        detail: source.to_string(),
    }
}

/// Put this process into fresh kernel namespaces.
///
/// Denying network means an empty one: a fresh netns has only a (down) loopback
/// interface and no route anywhere, so there is no network to reach rather than a
/// filtered one. That is stronger than Landlock's network rules, which only cover
/// TCP bind/connect and would leave UDP and raw sockets untouched.
///
/// `CLONE_NEWUSER` is requested alongside because creating any other namespace
/// otherwise needs `CAP_SYS_ADMIN`; a user namespace grants that capability
/// *within the new namespaces only*, which is what lets this work unprivileged.
/// Some distributions restrict unprivileged user namespaces (e.g. AppArmor's
/// `kernel.apparmor_restrict_unprivileged_userns`), and there the call fails —
/// which surfaces as a refusal, never as a silent fallback.
///
/// One `unshare` for all of them rather than one per namespace: the kernel applies
/// the flags together, so there is no window in which the process holds some of the
/// isolation and not the rest, and no second failure path to unwind.
fn isolate(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    use nix::sched::{CloneFlags, unshare};
    use nix::unistd::{getgid, getuid};

    // The PID namespace is unconditional: a guarantee about process lifetime that
    // depended on a policy flag would not be a guarantee. It is also why the user
    // namespace is now unconditional, where it used to come along only when
    // network was denied.
    let mut flags = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWPID;
    if !policy.allows_network() {
        flags |= CloneFlags::CLONE_NEWNET;
    }

    // Captured before the unshare: afterwards this process reads back as the
    // overflow uid, and it is the *real* identity we want to map to itself.
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();

    unshare(flags).map_err(|errno| SandboxError::NamespaceSetupFailed {
        detail: match errno {
            nix::errno::Errno::EPERM => {
                "kernel refused an unprivileged user namespace; unprivileged \
                 userns may be disabled (see kernel.unprivileged_userns_clone \
                 and kernel.apparmor_restrict_unprivileged_userns)"
            }
            _ => "could not create the sandbox namespaces",
        },
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
fn map_identity_into_userns(uid: u32, gid: u32) {
    // `setgroups` must be denied before an unprivileged `gid_map` write, or the
    // kernel rejects it. Denying it is correct anyway: this maps a single gid,
    // so there are no supplementary groups to set. If any write fails the rest
    // are skipped and the namespace simply stays unmapped.
    let mapped = std::fs::write("/proc/self/setgroups", "deny")
        .and_then(|()| std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1")))
        .and_then(|()| std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1")));

    if let Err(error) = mapped {
        crate::AuditEvent::degraded(
            "userns_identity_map",
            &format!("running as nobody: {error}"),
        )
        .emit();
    }
}
