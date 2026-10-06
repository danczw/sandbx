//! The policy-to-Landlock mapping: which rights each grant confers, and the one rule per
//! grant that [`apply`](crate::helper::apply) installs.
//!
//! Kernel-independent — the ABI arrives as a parameter, negotiated by [`super::compat`] — and
//! so assertable without root, a network namespace or a Landlock-capable kernel.

/// The Landlock rights an axis grants on a target, narrowed to what that target can carry.
///
/// Derived from [`Axis::grants`], so a new axis needs no edit here — a literal list of
/// `(paths, rights)` pairs would still compile with an axis left out of it, that grant
/// silently absent.
///
/// Each primitive is a subtraction rather than a plain set:
///
/// - read is `from_read` minus `Execute`, because `from_read` bundles `Execute` with
///   `ReadFile`/`ReadDir` and no axis but `ReadExecute` says *run*.
/// - write is `from_all` minus the whole read set, not just `Execute`: `from_all` includes
///   `ReadFile`/`ReadDir`, so subtracting `Execute` alone confers read at the kernel while
///   `FsGuard` refuses it, and the write-only drop directory `writable_paths` promises is
///   readable.
/// - execute is the single bit, hence addable on top of read without widening anything else.
///
/// Directory-only rights (`ReadDir`, `MakeDir`, `Refer`, …) are invalid on a regular file, so
/// a policy naming one has its rights intersected with what the target can carry rather than
/// substituted — a file can never end up with more than the directory case. Dropping the
/// intersection would not degrade quietly: `PathBeneath` stats the fd, strips the dir-only
/// bits and reports `CompatResult::Partial`, which under the `HardRequirement`
/// [`apply`](crate::helper::apply) sets fails `add_rule`, so it would refuse any policy
/// naming a regular file — `--allow-read ./config.toml` does.
///
/// [`Axis::grants`]: crate::Axis::grants
pub(super) fn rights_for(
    axis: crate::Axis,
    target_is_dir: bool,
    abi: landlock::ABI,
) -> landlock::BitFlags<landlock::AccessFs> {
    use landlock::{Access, AccessFs};

    let read_rights = AccessFs::from_read(abi) & !AccessFs::Execute;
    let write_rights = AccessFs::from_all(abi) & !AccessFs::from_read(abi);

    // Destructured, not read field by field — see `Grants`.
    let crate::Grants {
        read,
        write,
        execute,
    } = axis.grants();

    let mut rights = landlock::BitFlags::EMPTY;

    if read {
        rights |= read_rights;
    }
    if write {
        rights |= write_rights;
    }
    if execute {
        rights |= AccessFs::Execute;
    }

    if target_is_dir {
        rights
    } else {
        rights & AccessFs::from_file(abi)
    }
}

/// The Landlock rules [`apply`](crate::helper::apply) will install, as `(axis, path, rights)`,
/// one per grant, ordered after [`SandboxPolicy::granted_paths`].
///
/// Adds just the one probe [`rights_for`] needs, whether the target is a directory.
/// `is_dir()` reports `false` for every error it meets, which would silently drop
/// directory-only rights — latent rather than live: a path `is_dir()` could not inspect (a
/// dangling symlink, an unsearchable parent) is also one `PathFd::new` cannot open on the next
/// line, so it becomes a refusal before the narrowed rule reaches the kernel.
///
/// A path that changes kind between the probe and the open narrows in both directions rather
/// than widening: a directory taken for a file loses directory-only rights here, a file taken
/// for a directory loses them at `add_rule`, where `PathBeneath` strips what a file cannot
/// hold and, under `HardRequirement`, reports that as an error.
///
/// The axis rides along even though `apply` has no use for it: Landlock *unions* the rules it
/// is given for a path, so a tuple of just `(path, rights)` is not the effective right set for
/// any path named on two axes — and `sandbx --allow-write` names one on two axes every time.
///
/// [`SandboxPolicy::granted_paths`]: crate::SandboxPolicy::granted_paths
pub(super) fn fs_rules(
    policy: &crate::SandboxPolicy,
    abi: landlock::ABI,
) -> Vec<(
    crate::Axis,
    &std::path::Path,
    landlock::BitFlags<landlock::AccessFs>,
)> {
    policy
        .granted_paths()
        .map(|(axis, path)| (axis, path, rights_for(axis, path.is_dir(), abi)))
        .collect()
}

/// Whether [`apply`](crate::helper::apply) hands the network axis to Landlock at all, and on
/// which ports.
///
/// The only place that chooses, because "no port rules" is not "an empty port list": handling
/// [`AccessNet`] with zero [`NetPort`] rules denies *every* TCP port, while leaving it
/// unhandled leaves TCP unrestricted. So [`Denied`] and [`AnyPort`] both map to `Unhandled` —
/// the first confined by `CLONE_NEWNET` instead, the second having asked for unrestricted
/// egress; `context/decision-port-allowlist.md` for why neither gets a port list.
///
/// [`Denied`]: crate::NetworkPolicy::Denied
/// [`AnyPort`]: crate::NetworkPolicy::AnyPort
/// [`AccessNet`]: landlock::AccessNet
/// [`NetPort`]: landlock::NetPort
pub(super) fn net_rules(
    policy: &crate::SandboxPolicy,
    abi: landlock::ABI,
) -> super::RequestedNet<'_> {
    use crate::NetworkPolicy;

    match policy.network() {
        NetworkPolicy::Denied | NetworkPolicy::AnyPort => super::RequestedNet::Unhandled,
        NetworkPolicy::Ports(ports) => super::RequestedNet::Ports {
            handled: super::compat::handled_net_access(abi),
            // Named, where `handled` is `from_all`: the two directions are not symmetric. A
            // right a future ABI adds has to be *handled*, or Landlock leaves it unrestricted
            // everywhere — but granting it on every allowlisted port is how a UDP or raw right
            // would arrive already permitted on the ports the policy named.
            granted: landlock::AccessNet::BindTcp | landlock::AccessNet::ConnectTcp,
            ports,
        },
    }
}
