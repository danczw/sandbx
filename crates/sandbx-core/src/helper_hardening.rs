//! Process state the sandbox depends on but Landlock and seccomp cannot express:
//! namespaces, capability sets, resource limits, and the supervisor the inner stage checks
//! for.
//!
//! All of it is inherited across `exec`, so stage 1 sets it up and stage 2 is still covered.
//! Every change is irreversible for the process that makes it, so none may run inside sandbx.

use crate::SandboxError;
use crate::degradation::Degradation;
use std::{fmt, fs, io};

/// Build the namespaces and drop what must be dropped before the `exec`.
///
/// Separate from [`apply`](crate::helper::exec::apply) because both steps have to happen in the
/// *supervisor*, not in the stage that starts the command:
///
/// - the namespaces, because `CLONE_NEWPID` only places this process's children, so
///   unsharing here is what makes the inner stage PID 1;
/// - the capability drops, because `PR_CAPBSET_DROP` needs `CAP_SETPCAP` in the effective
///   set, which an unprivileged process only holds inside a user namespace it just created.
///   All four sets and `RLIMIT_CORE` are inherited across `fork` and `exec`, so dropping
///   them here still covers the command.
///
/// Names what degraded rather than recording it: this runs in the re-exec'd helper, which
/// can install no subscriber without writing sandbx's records into the command's output, so
/// [`exec_sandboxed`](super::exec_sandboxed) reports it on the channel it holds. The detail
/// is a string because it is built from an errno.
pub(super) fn prepare_supervisor(
    policy: &crate::SandboxPolicy,
) -> Result<Vec<(Degradation, String)>, SandboxError> {
    let mut degraded = Vec::new();

    // What the bound `hosts` file is built from, so they precede `bound_resolution` below; and
    // before the unshare, which for an egress-denying policy leaves no network to resolve on.
    let resolved = crate::resolver::files(policy);

    // A name that resolved to nothing bounds resolution all the same, so the run goes on, and
    // the report is the only thing telling that outcome apart from the flag working.
    if let Some(count) = resolved
        .as_ref()
        .map(|resolved| resolved.unresolved)
        .filter(|unresolved| *unresolved > 0)
    {
        degraded.push((
            Degradation::UnresolvedDnsName,
            format!("{count} allowlisted name(s) resolved to no address"),
        ));
    }

    degraded.extend(isolate(policy)?);

    // Between the unshare and the capability drops: the mounts need the namespace `isolate`
    // just made, and `CAP_SYS_ADMIN` within it, which the drops below take away.
    super::resolver::bound_resolution(resolved.map(|resolved| resolved.files))?;

    // After the unshare, not before: entering a fresh user namespace grants the full
    // capability set *within it*, so dropping earlier would be undone.
    degraded.extend(harden_process_state()?);

    // Here as well as in the inner stage, so *every* `exec` this design performs is covered.
    // Without it, a capability regained across the exec into the inner stage is stopped only
    // by the binary being our own — unprivileged, no file capabilities — plus uid 0 unmapped
    // in the fresh user namespace. Both hold, so this costs one syscall and rests on nothing
    // about the binary. Irreversible and inherited, so the inner stage's call is a no-op —
    // but that stage must not depend on a caller having set it, neither seccomp nor Landlock
    // installing without it.
    set_no_new_privs()?;

    Ok(degraded)
}

/// Die when the supervisor dies.
///
/// This process is PID 1 of a fresh PID namespace, and the kernel SIGKILLs every remaining
/// process in a namespace whose init exits — so dying with the supervisor is what turns the
/// timeout's kill from advisory into unconditional, whatever the command spawned and however
/// it detached itself.
///
/// Two independent paths reach us: the process group sandbx kills, which we never leave, and
/// this signal, which fires regardless of group. Both hold because we never `exec` and stay
/// single-threaded — the signal is per thread and an `exec` can clear it — which is why the
/// command runs as our child rather than as us.
///
/// Set before anything else in this stage, so the window in which the supervisor could die
/// unnoticed is as short as the kernel allows. [`confirm_supervisor`] is what closes it.
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
/// Closes the window [`bind_lifetime_to_supervisor`] cannot: if the supervisor died before
/// the parent death signal was armed, nothing will ever kill this process and the command
/// would run in a namespace no one is watching. Arm first, then check — a death
/// before the check is caught by the check, a death after it by the armed signal.
///
/// `getppid` is no use: this process is PID 1 of a namespace whose parent lives outside it,
/// so the kernel has no number to report and returns 0. `/proc` is still the host's procfs —
/// remounting would need `mount(2)`, which the filter denies — so its `ppid` field names the
/// supervisor in host numbering, which is what was passed in.
///
/// Pid reuse cannot produce a false pass: the comparison is against the kernel's live parent
/// link, and an orphan is reparented to init or a subreaper, neither of which can be the pid
/// of a supervisor that just spawned us.
///
/// Runs before Landlock and seccomp, so it needs no grant for `/proc` and no privilege.
pub(super) fn confirm_supervisor(expected: &str) -> Result<(), SandboxError> {
    let gone = SandboxError::NamespaceSetupFailed {
        detail: "the supervisor process is gone; refusing to run the command \
                 where nothing can reap it",
    };

    let unreadable = SandboxError::NamespaceSetupFailed {
        detail: "could not read this process's parent to confirm the supervisor \
                 is still watching it",
    };

    let stat = fs::read_to_string("/proc/self/stat").map_err(|_| unreadable)?;

    match ppid_from_stat(&stat) {
        Some(parent) if parent == expected => Ok(()),
        _ => Err(gone),
    }
}

/// The parent pid out of a `/proc/pid/stat` line, or `None` if the line has none.
///
/// Field 4, counting from 1. Split after the *last* `)` rather than on whitespace from the
/// start: field 2 is the executable name, unquoted and free to contain spaces and parentheses
/// of its own — the kernel escapes control characters there but not those. Counting from the
/// right is exact rather than merely safer, because every field after the name is numeric and
/// so holds no `)`.
///
/// A `&str` and not a parsed integer: [`confirm_supervisor`] compares against the token its
/// caller passed on the command line, and parsing both sides would have `0123` match `123`.
///
/// `None` rather than a guess for an unrecognised line, which [`confirm_supervisor`] turns
/// into a refusal to run. Split out so the parse can be checked against an adversarial name
/// with no supervisor, namespace or second process.
fn ppid_from_stat(stat: &str) -> Option<&str> {
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(1))
}

/// Drop capabilities and disable core dumps.
///
/// Landlock and seccomp bound what the sandboxed command can *do*; this bounds what a
/// descendant that somehow survives the kill can still reach. Nothing here needs privilege:
/// every call only ever removes a right this process already holds.
///
/// Does NOT set `PR_SET_DUMPABLE`: the kernel resets that flag to dumpable on every `execve`
/// of an ordinary (non-setuid, no file-capability) binary — `setup_new_exec` in `fs/exec.c` —
/// so setting it here would cover only this process's pre-exec window, not the command. The
/// namespace's init sets it on itself, never `exec`ing. `RLIMIT_CORE` does persist across exec.
///
/// The capability *bounding* set is best-effort, as `SECURITY.md` claims it. Dropping it
/// needs `CAP_SETPCAP`, which an unprivileged process holds only inside a user namespace it
/// created itself — and not even there under an LSM that strips capabilities from such a
/// namespace. AppArmor's `restrict_unprivileged_userns` (default on Ubuntu 24.04+ and on
/// GitHub's runners) does exactly that: `isolate`'s `unshare` succeeds but `PR_CAPBSET_DROP`
/// returns `EPERM`. The bit cannot be spent anyway — with the four sets below empty and
/// `no_new_privs` set, the kernel caps an `execve`d binary's permitted set at the old one and
/// refuses to raise inheritable or ambient — so refusing would take the sandbox away on whole
/// classes of host for nothing. The failure is an
/// [`AuditEvent::Degraded`](crate::AuditEvent::Degraded) at `INFO` and not debug for that
/// same reason; the parent emits it — see [`prepare_supervisor`].
///
/// Order matters: the bounding set is dropped *before* the effective set, because
/// `PR_CAPBSET_DROP` itself requires `CAP_SETPCAP` in the effective set.
fn harden_process_state() -> Result<Option<(Degradation, String)>, SandboxError> {
    use caps::CapSet;

    let degraded = drop_bounding_set(|| caps::clear(None, CapSet::Bounding));

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

    Ok(degraded)
}

/// Name the bounding set as degraded if `clear` is refused.
///
/// Split from the syscall so the decision — a refusal becomes a record rather than an error
/// — is assertable: `PR_CAPBSET_DROP` only fails on a host whose LSM strips `CAP_SETPCAP`
/// from a fresh user namespace. Generic over the error so a test can refuse without
/// constructing a `caps` error.
fn drop_bounding_set<E: fmt::Display>(
    clear: impl FnOnce() -> Result<(), E>,
) -> Option<(Degradation, String)> {
    clear().err().map(|error| {
        (
            Degradation::CapabilityBoundingSet,
            format!("left as inherited: {error}"),
        )
    })
}

/// Set `no_new_privs`, refusing if the kernel will not.
///
/// Shared by both stages. Irreversible and inherited across `exec`, and a precondition for
/// seccomp and `landlock_restrict_self` alike without `CAP_SYS_ADMIN`. Both libraries set it
/// themselves inside that install, so what this call adds is the refusal, ahead of either.
pub(super) fn set_no_new_privs() -> Result<(), SandboxError> {
    nix::sys::prctl::set_no_new_privs().map_err(|errno| SandboxError::Seccomp {
        detail: format!("could not set no_new_privs: {errno}"),
    })
}

fn hardening_failed(source: impl fmt::Display) -> SandboxError {
    SandboxError::ProcessHardening {
        detail: source.to_string(),
    }
}

/// Put this process into fresh kernel namespaces.
///
/// Denying network means an empty netns: only a (down) loopback interface and no route
/// anywhere, so there is no network to reach rather than a filtered one. A port allowlist is
/// not strictly weaker but differently shaped — it reaches the named port on every host, the
/// host's own loopback included, `allows_network` being true for it and `CLONE_NEWNET`
/// dropped. What its seccomp half has to deny is in
/// `context/decision-port-allowlist.md`.
///
/// `CLONE_NEWUSER` is requested alongside because creating any other namespace otherwise
/// needs `CAP_SYS_ADMIN`; a user namespace grants that capability *within the new namespaces
/// only*, which is what lets this work unprivileged. Where unprivileged user namespaces are
/// restricted (AppArmor's `kernel.apparmor_restrict_unprivileged_userns`) the call fails and
/// surfaces as a refusal, never as a silent fallback.
///
/// One `unshare` for all of them, so there is no window holding some of the isolation and not
/// the rest. Returns whatever [`map_identity_into_userns`] could not do, for
/// [`prepare_supervisor`] to pass on to the parent.
fn isolate(policy: &crate::SandboxPolicy) -> Result<Option<(Degradation, String)>, SandboxError> {
    use nix::sched::{CloneFlags, unshare};
    use nix::unistd::{getgid, getuid};

    // The PID namespace is unconditional, and the user namespace with it: a guarantee about
    // process lifetime that depended on a policy flag would not be a guarantee.
    let mut flags = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWPID;
    if !policy.allows_network() {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    // Only where `helper::resolver` has mounts to put in it: an empty mount namespace
    // confines nothing, and unsharing one would make every run need a kernel that allows it.
    if policy.bounds_resolution() {
        flags |= CloneFlags::CLONE_NEWNS;
    }

    // Captured before the unshare: afterwards this process reads back as the overflow
    // uid, and it is the *real* identity we want to map to itself.
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

    Ok(map_identity_into_userns(uid, gid))
}

/// Map the real uid/gid to themselves inside the fresh user namespace.
///
/// Without a map the process reads back as the overflow uid (`nobody`) even though its
/// on-host identity is unchanged — a file it writes is still owned by the real user — so
/// tools that branch on `getuid()` see a value that does not match reality. Mapping the
/// identity to itself grants nothing, the process already acting as this uid on the host.
///
/// Best-effort, and not a security control: running as the overflow `nobody` is if anything
/// *more* restrictive. Some environments create the namespace but deny the map — AppArmor's
/// `restrict_unprivileged_userns` (default on Ubuntu 24.04+) leaves an unprivileged userns
/// without `CAP_SETUID` — and aborting there would trade a truthful uid for no sandbox at
/// all, so a failed write leaves the process as `nobody` with the command still fully
/// confined.
///
/// Names the failure rather than recording it, for the reason [`prepare_supervisor`]
/// gives.
fn map_identity_into_userns(uid: u32, gid: u32) -> Option<(Degradation, String)> {
    map_identity_into_userns_with(uid, gid, |path, contents| fs::write(path, contents))
}

/// The three writes the map needs, naming the first one `write` refuses.
///
/// Split from `std::fs::write` for the reason [`drop_bounding_set`] gives: only a host that
/// creates the namespace and then denies the map enters the branch. `FnMut` so a test's
/// writer can record which paths it was handed.
fn map_identity_into_userns_with(
    uid: u32,
    gid: u32,
    mut write: impl FnMut(&str, String) -> io::Result<()>,
) -> Option<(Degradation, String)> {
    // `setgroups` must be denied before an unprivileged `gid_map` write or the kernel rejects
    // it, and a single mapped gid has no supplementary groups anyway.
    let maps = [
        ("/proc/self/setgroups", "deny".to_string()),
        ("/proc/self/gid_map", format!("{gid} {gid} 1")),
        ("/proc/self/uid_map", format!("{uid} {uid} 1")),
    ];

    // Stopping at the first refusal: the writes are ordered, so a later one the kernel would
    // reject says nothing the first does not.
    maps.into_iter()
        .find_map(|(path, contents)| write(path, contents).err())
        .map(|error| {
            (
                Degradation::UsernsIdentityMap,
                format!("running as nobody: {error}"),
            )
        })
}

#[cfg(test)]
#[path = "helper_hardening_tests.rs"]
mod tests;
