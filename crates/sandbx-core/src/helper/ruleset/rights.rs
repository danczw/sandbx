//! The policy-to-Landlock mapping: which rights each grant confers, and the one
//! rule per grant that [`apply`](crate::helper::apply) installs.
//!
//! Kernel-independent — the ABI arrives as a parameter, negotiated by
//! [`super::compat`] — and so assertable without root, a network namespace or a
//! Landlock-capable kernel (#52). Nothing here restricts the calling process.

/// The Landlock rights an axis grants on a target, narrowed to what that target
/// can carry.
///
/// Pure and total: three axes times a file or a directory is six answers, every
/// one of them assertable with no privilege and no filesystem. The narrowing used
/// to sit in [`fs_rules`] next to the `is_dir()` that drives it, which fused the
/// decision to a probe and so made the file case reachable only by creating a
/// real file on disk (#52).
///
/// Derived from [`Axis::grants`], so a new axis needs no edit here. Before this
/// derived, the axes were a literal list of `(paths, rights)` pairs, and an axis
/// left out of that list did not fail to compile: its paths were never iterated,
/// no rule was installed for them, and the grant was silently absent (#51).
///
/// The three primitives, and why each is a subtraction rather than a plain set:
///
/// - **read** is `from_read` minus `Execute`. `from_read` bundles `Execute` in
///   with `ReadFile`/`ReadDir`, so granting it raw would hand out the right to
///   *run* whatever the path contains, which no axis but `ReadExecute` says (#19).
/// - **write** is `from_all` minus the whole read set, not just `Execute`.
///   `from_all` includes `ReadFile`/`ReadDir`, so taking only `Execute` away left
///   a write grant conferring read at the kernel while `FsGuard` refused it —
///   one policy, two answers, and the write-only drop directory
///   `writable_paths` promises was readable in the child (#49).
/// - **execute** is the single bit, which is why it can be added back on top of
///   read without widening anything else.
///
/// Directory-only rights (`ReadDir`, `MakeDir`, `Refer`, …) are invalid on a
/// regular file, so a policy naming one must have its rights narrowed to what the
/// target can carry. Intersecting rather than substituting keeps that a
/// restriction: a file can never end up with more than the directory case.
///
/// The kernel never sees an invalid rule: `PathBeneath` stats the fd and strips
/// the dir-only bits itself (its own comment: "Linux would return EINVAL"),
/// reporting `CompatResult::Partial`. What that costs depends on the compatibility
/// level, and [`apply`](crate::helper::apply) sets `HardRequirement`, under which a
/// `Partial` is returned as an error — so a dir-only right left on a regular file
/// makes `add_rule` fail and the whole run a refusal. Dropping this intersection
/// would therefore not degrade quietly; it would refuse to sandbox any policy that
/// names a regular file, which `--allow-read ./config.toml` does.
///
/// A refusal is still not what `rights_for_narrows_a_regular_file` asserts against.
/// It pins the file-legal set literally because the narrowing belongs *here*,
/// where it is decidable without a kernel or a real file, and because an ABI bump
/// that moves a right between the file and directory sets should fail in review
/// rather than at the first run on the new kernel.
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

/// The Landlock rules [`apply`](crate::helper::apply) will install, as `(axis, path, rights)`, one per
/// grant.
///
/// Split out so the whole filesystem mapping can be asserted without root, a
/// network namespace or a Landlock-capable kernel — `apply` itself needs all
/// three, which is why it went untested for so long (#52). The only thing this
/// touches outside the policy is whether each path is a directory, and that is
/// precisely what decides the narrowing below.
///
/// What a grant confers is [`rights_for`]'s business; all this adds is the one
/// probe that decision needs — whether the target is a directory.
///
/// `is_dir()` reports `false` for every error it meets, which would silently drop
/// directory-only rights. That is latent rather than live: a path `is_dir()` could
/// not inspect — a dangling symlink, an unsearchable parent — is also a path
/// [`apply`](crate::helper::apply)'s next line cannot open, so `PathFd::new` turns it into a refusal
/// before the narrowed rule reaches the kernel. Propagating it here would add a
/// `Result` to the seam for an error the following line already catches.
///
/// A path that changes kind between the probe and the open narrows in both
/// directions rather than widening: a directory taken for a file loses
/// directory-only rights here, and a file taken for a directory loses them at
/// `add_rule`, where `PathBeneath` strips what a file cannot hold and, under the
/// `HardRequirement` [`apply`](crate::helper::apply) sets, reports that as an error —
/// so the second case is a refusal to run, not a quiet degradation. Neither grants
/// anything the policy did not name, which is the property that matters here.
///
/// The axis rides along even though [`apply`](crate::helper::apply) has no use for it. Landlock *unions*
/// the rules it is given for a path, so a tuple of just `(path, rights)` is not
/// the effective right set for any path named on two axes — and `sandbx
/// --allow-write` names one on two axes every time. Carrying the axis keeps both
/// questions answerable: what one grant confers, and what the kernel will enforce
/// once the overlapping grants are unioned (#52).
///
/// Ordered `(axis, path, ..)` after [`SandboxPolicy::granted_paths`], the pairs
/// this is an extension of.
///
/// [`SandboxPolicy::granted_paths`]: crate::SandboxPolicy::granted_paths
pub(in crate::helper) fn fs_rules(
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
