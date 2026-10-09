//! Process state the sandbox depends on but Landlock and seccomp cannot express:
//! namespaces, capability sets, resource limits, and the supervisor the inner stage checks
//! for.
//!
//! All of it is inherited across `exec`, so stage 1 sets it up and stage 2 is still covered.
//! Every change is irreversible for the process that makes it, so none may run inside sandbx.

use crate::SandboxError;
use crate::degradation::Degradation;

/// Build the namespaces and drop what must be dropped before the `exec`.
///
/// Separate from [`apply`](super::apply) because both steps have to happen in the
/// *supervisor*, not in the stage that becomes the command:
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

    // Before the unshare, which puts a policy that denies IP egress into an empty network
    // namespace — where a lookup resolves nothing at all.
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
/// Two independent paths reach us. The supervisor is in the process group sandbx kills and so
/// are we, but the command we become may `setsid` and leave it; the parent death signal fires
/// regardless of group membership and survives `execve` of an ordinary binary, and the kernel
/// clears it for a *secure* `exec` (setuid target, or file capabilities), where the group kill
/// is what still reaps us.
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
/// would run as PID 1 of a namespace no one is watching. Arm first, then check — a death
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

    let stat = std::fs::read_to_string("/proc/self/stat").map_err(|_| unreadable)?;

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
/// so setting it here would cover only this process's pre-exec window, not the command.
/// `RLIMIT_CORE` below does persist across exec.
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
fn drop_bounding_set<E: std::fmt::Display>(
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
/// seccomp and `landlock_restrict_self` alike without `CAP_SYS_ADMIN` — so a failure here is
/// a refusal. Landlock sets it itself; seccomp does not, which is why this call exists.
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
    map_identity_into_userns_with(uid, gid, |path, contents| std::fs::write(path, contents))
}

/// The three writes the map needs, naming the first one `write` refuses.
///
/// Split from `std::fs::write` for the reason [`drop_bounding_set`] gives: only a host that
/// creates the namespace and then denies the map enters the branch. `FnMut` so a test's
/// writer can record which paths it was handed.
fn map_identity_into_userns_with(
    uid: u32,
    gid: u32,
    mut write: impl FnMut(&str, String) -> std::io::Result<()>,
) -> Option<(Degradation, String)> {
    // `setgroups` must be denied before an unprivileged `gid_map` write or the kernel rejects
    // it, and a single mapped gid has no supplementary groups anyway.
    let maps = [
        ("/proc/self/setgroups", "deny".to_string()),
        ("/proc/self/gid_map", format!("{gid} {gid} 1")),
        ("/proc/self/uid_map", format!("{uid} {uid} 1")),
    ];

    for (path, contents) in maps {
        // Returning on the first refusal: the writes are ordered, so a later one the kernel
        // would reject says nothing the first does not.
        if let Err(error) = write(path, contents) {
            return Some((
                Degradation::UsernsIdentityMap,
                format!("running as nobody: {error}"),
            ));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `/proc/pid/stat` line with the executable name substituted in. Long enough to carry
    /// the fields *after* the parent, so a parse landing past field 4 returns a plausible
    /// number rather than `None`.
    fn stat_line(comm: &str) -> String {
        format!(
            "4242 ({comm}) S 1234 4242 4242 34816 4321 4194304 1537 0 0 0 \
             1 2 0 0 20 0 1 0 9876 4337664 1234 18446744073709551615"
        )
    }

    /// The control for the rest of this module; on its own it pins almost nothing, since
    /// counting four tokens from the left passes it too.
    #[test]
    fn the_parent_pid_follows_the_process_state() {
        let stat = stat_line("bash");

        assert_eq!(
            ppid_from_stat(&stat),
            Some("1234"),
            "the parent is field 4 of {stat:?}"
        );
    }

    /// Counting from the left returns the process state, which never equals a pid, so
    /// every run under a binary whose name has a space would be refused.
    #[test]
    fn a_space_in_the_executable_name_shifts_nothing() {
        let stat = stat_line("my program");

        assert_eq!(
            ppid_from_stat(&stat),
            Some("1234"),
            "a space in the executable name shifted the parse: {stat:?}"
        );
    }

    /// Why the split is on the *last* `)`: splitting on the first stops inside such a
    /// name and reads its remainder as the fields after it.
    #[test]
    fn a_paren_in_the_executable_name_truncates_nothing() {
        let stat = stat_line("weird ) name");

        assert_eq!(
            ppid_from_stat(&stat),
            Some("1234"),
            "a parenthesis in the executable name truncated the parse: {stat:?}"
        );
    }

    /// The one way [`confirm_supervisor`] could fail open: `) 1 2 3` makes the numeric fields
    /// look like they start three tokens early, so a left-counting parse returns a short,
    /// plausible integer that could *agree* with the expected pid.
    ///
    /// Robustness, not a defence against a chosen name: the line is this process's own and
    /// `confirm_supervisor` runs before the `exec`, so field 2 is sandbx's helper binary.
    #[test]
    fn an_executable_name_shaped_like_a_field_is_not_one() {
        let stat = stat_line(") 1 2 3");

        assert_eq!(
            ppid_from_stat(&stat),
            Some("1234"),
            "a name shaped like the fields after it was read as one: {stat:?}"
        );
    }

    /// Counting from the left finds a fourth token in the first case, and would hand
    /// [`confirm_supervisor`] a pid out of an unparseable line.
    #[test]
    fn a_line_with_no_executable_name_yields_nothing() {
        for stat in ["4242 bash S 1234 4242", "not a stat line", ""] {
            assert_eq!(
                ppid_from_stat(stat),
                None,
                "{stat:?} has no executable name to split on, so it names no parent"
            );
        }
    }

    /// The state letter is not a parent pid.
    #[test]
    fn a_line_that_stops_before_the_parent_yields_nothing() {
        for stat in ["4242 (bash)", "4242 (bash) S", "4242 (bash) S "] {
            assert_eq!(
                ppid_from_stat(stat),
                None,
                "{stat:?} stops before field 4, so it names no parent"
            );
        }
    }

    /// The one test that reads a line the kernel wrote, checked against the same number
    /// reported under a *name* rather than a position — so the synthetic expectations above
    /// are anchored outside this module.
    ///
    /// An anchor and not a discriminator: a neighbouring field can happen to equal the
    /// parent, and under a test harness `pgrp` usually does. The cases above pin the index.
    ///
    /// Against `status` and not `getppid`, which the kernel translates into the caller's pid
    /// namespace and reports as 0 for PID 1 of a nested one — the exact skew
    /// [`confirm_supervisor`] works around, so leaning on it would break this test inside the
    /// sandbox.
    ///
    /// The two files are read in two syscalls, so a parent exiting between them would leave
    /// `PPid:` naming init while the stat line names the old pid — unguarded, cargo being the
    /// parent under `cargo test` and outliving the harness.
    #[test]
    fn the_parse_agrees_with_procfs_under_another_name() {
        let stat = std::fs::read_to_string("/proc/self/stat").expect("procfs is mounted");
        let status = std::fs::read_to_string("/proc/self/status").expect("procfs is mounted");

        let named = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .map(str::trim)
            .expect("/proc/self/status reports a PPid");

        assert_eq!(
            ppid_from_stat(&stat),
            Some(named),
            "the stat parse and PPid: disagree about this process's parent; \
             the stat line was {stat:?}"
        );
    }

    #[test]
    fn a_refused_bounding_set_drop_reports_a_degradation() {
        let (step, detail) = drop_bounding_set(|| Err("Operation not permitted (os error 1)"))
            .expect("a refused PR_CAPBSET_DROP must name itself as degraded");

        assert_eq!(
            step,
            Degradation::CapabilityBoundingSet,
            "a refused bounding-set drop reported the wrong mechanism"
        );
        assert!(
            detail.contains("left as inherited"),
            "the detail does not say what the sandbox is left with: {detail:?}"
        );
        assert!(
            detail.contains("os error 1"),
            "the detail dropped the kernel's own reason: {detail:?}"
        );
    }

    #[test]
    fn a_bounding_set_that_drops_reports_nothing() {
        assert_eq!(
            drop_bounding_set(|| Ok::<(), String>(())),
            None,
            "a successful drop put a degradation on the trail"
        );
    }

    #[test]
    fn the_identity_map_is_written_in_kernel_order() {
        let mut written = Vec::new();

        let degraded = map_identity_into_userns_with(1000, 2000, |path, contents| {
            written.push((path.to_string(), contents));
            Ok(())
        });

        assert_eq!(degraded, None, "every write succeeded, so nothing degraded");
        assert_eq!(
            written,
            vec![
                ("/proc/self/setgroups".to_string(), "deny".to_string()),
                ("/proc/self/gid_map".to_string(), "2000 2000 1".to_string()),
                ("/proc/self/uid_map".to_string(), "1000 1000 1".to_string()),
            ],
            "setgroups must be denied before an unprivileged gid_map write, and each map \
             names one id mapped to itself"
        );
    }

    #[test]
    fn a_refused_map_reports_a_degradation_and_stops() {
        for refused in [
            "/proc/self/setgroups",
            "/proc/self/gid_map",
            "/proc/self/uid_map",
        ] {
            let mut attempted = Vec::new();

            let degraded = map_identity_into_userns_with(1000, 2000, |path, _| {
                attempted.push(path.to_string());
                if path == refused {
                    Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                } else {
                    Ok(())
                }
            });

            let (step, detail) =
                degraded.unwrap_or_else(|| panic!("{refused} was refused and nothing reported it"));

            assert_eq!(
                step,
                Degradation::UsernsIdentityMap,
                "a denied {refused} reported the wrong mechanism"
            );
            assert!(
                detail.contains("running as nobody"),
                "the detail does not say what the process is left as: {detail:?}"
            );
            assert!(
                detail.contains("permission denied"),
                "the detail dropped the kernel's own reason: {detail:?}"
            );
            assert_eq!(
                attempted.last().map(String::as_str),
                Some(refused),
                "a write after the refused one was attempted: {attempted:?}"
            );
        }
    }
}
