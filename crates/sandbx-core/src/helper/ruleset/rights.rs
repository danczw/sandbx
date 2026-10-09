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
///   readable. Minus `ResolveUnix` as well, which `from_all` adds at V9 and
///   [`unix_socket_rights`] confers instead — writing a file is not dialling a socket.
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
    let write_rights = AccessFs::from_all(abi) & !AccessFs::from_read(abi) & !AccessFs::ResolveUnix;

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

/// What a rule names: a grant the harness judged, or a path this process installed itself.
///
/// The two differ in what can be confirmed about them, not in the rule they get. A grant
/// carries the object the harness vetted, so the open can be checked against it (#212). A
/// resolver file was bind-mounted by [`bound_resolution`] a moment ago, in this process and
/// after the harness judged the policy — so no harness-side pin exists, and measuring one
/// here would compare this process's answer against itself.
///
/// [`bound_resolution`]: crate::helper::resolver::bound_resolution
pub(in crate::helper) enum RuleTarget<'policy> {
    /// A path the operator granted, pinned to the object it was vetted as.
    Granted(&'policy crate::VettedPath),

    /// A resolver file sandbx bind-mounted over, which no grant names.
    Installed(&'static std::path::Path),
}

impl RuleTarget<'_> {
    /// The path to open, whichever it is.
    pub(in crate::helper) fn path(&self) -> &std::path::Path {
        match self {
            Self::Granted(granted) => granted.path(),
            Self::Installed(path) => path,
        }
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
    RuleTarget<'_>,
    landlock::BitFlags<landlock::AccessFs>,
)> {
    // Annotated, the paths being `&'static`: chaining them onto a borrow of the policy would
    // otherwise have inference demand the policy live as long.
    let resolver: Vec<(crate::Axis, &std::path::Path)> =
        resolver_paths(policy.bounds_resolution()).collect();
    let unix = unix_socket_rights(policy.allows_unix_sockets(), abi);

    policy
        .granted_paths()
        // On the grants and not on `Installed`, which is a bind mount of sandbx's own file
        // that no grant names — the flag is documented as covering the paths it granted.
        .map(|(axis, granted)| (axis, RuleTarget::Granted(granted), unix))
        .chain(
            resolver
                .into_iter()
                .map(|(axis, path)| (axis, RuleTarget::Installed(path), landlock::BitFlags::EMPTY)),
        )
        .map(|(axis, target, conferred)| {
            // After the `from_file` narrowing, which does not re-widen it: `ResolveUnix` is in
            // landlock's `ACCESS_FILE`, so a rule naming a socket inode directly keeps the bit.
            let rights = rights_for(axis, target.path().is_dir(), abi) | conferred;
            (axis, target, rights)
        })
        .collect()
}

/// `ResolveUnix` where the policy granted unix sockets, nothing otherwise.
///
/// Masked by `from_all(abi)` and never compared against `V9`:
/// `PathBeneath::check_consistency` refuses a rule whose rights exceed the handled set,
/// outside `CompatLevel` and so unconditionally — an unmasked bit would refuse every run on
/// every kernel shipping today. Conferred from the flag rather than an axis because it is one
/// boolean over the whole policy, as `--allow-dns` is.
fn unix_socket_rights(granted: bool, abi: landlock::ABI) -> landlock::BitFlags<landlock::AccessFs> {
    use landlock::Access;

    if granted {
        landlock::AccessFs::from_all(abi) & landlock::AccessFs::ResolveUnix
    } else {
        landlock::BitFlags::EMPTY
    }
}

/// Read on the three files a bounded resolver replaces, or nothing when it bounds nothing.
///
/// Not a grant the caller made, so not on the policy. Landlock binds a rule to the inode, and
/// `helper::resolver` has bind-mounted sandbx's own files over these before `apply` opens them
/// — which is why `--allow-dns` makes `--allow-read /etc` unnecessary rather than necessary.
/// Read and not read-execute: an NSS module is loaded from `/lib`, never from `/etc`.
///
/// A path [`opens_as_itself`] rejects is skipped, as an absent one is in
/// [`SandboxPolicy::allow_system_executables`].
///
/// [`SandboxPolicy::allow_system_executables`]: crate::SandboxPolicy::allow_system_executables
fn resolver_paths(bounded: bool) -> impl Iterator<Item = (crate::Axis, &'static std::path::Path)> {
    bounded
        .then_some(crate::RESOLVER_FILES)
        .into_iter()
        .flatten()
        .map(std::path::Path::new)
        .filter(|path| opens_as_itself(path))
        .map(|path| (crate::Axis::Read, path))
}

/// Whether a rule naming `path` would reach the inode `path` spells — false if it is absent,
/// and false if it is a symlink.
///
/// `mount(2)` follows a symlink, so `helper::resolver`'s bind landed on the target and
/// `open_grant`'s readback names the target: a rule spelled `/etc/resolv.conf` is
/// `GrantRedirected` wherever systemd-resolved owns that name. Naming the target instead is
/// not the fix — stage 1's `mount` and stage 2's resolution are a re-exec apart, so the
/// readback becomes a tautology and a retarget between them grants a file the bind never
/// placed.
///
/// So this flag installs no rule on a symlinked `resolv.conf`, while `install` binds over its
/// target anyway: the asymmetry is intended, and the bind is what leaves a command whose
/// *other* grants reach the resolved path reading sandbx's body rather than the host's. With
/// no such grant it reads nothing there, and the bound rests on `nsswitch.conf` for glibc and
/// the port allowlist for musl.
fn opens_as_itself(path: &std::path::Path) -> bool {
    path.symlink_metadata().is_ok_and(|at| !at.is_symlink())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The branch that decides whether a resolver path gets a rule at all. Untested until now,
    /// and `resolver_paths` reads the host's `/etc`: on a host whose `resolv.conf` is a plain
    /// file nothing here runs the symlink arm, which is how it shipped refusing every run on a
    /// systemd-resolved one.
    #[test]
    fn a_symlink_never_opens_as_itself() {
        let scratch = tempfile::tempdir().expect("a temporary directory");
        let real = scratch.path().join("real.conf");
        let link = scratch.path().join("link.conf");
        std::fs::write(&real, b"nameserver 203.0.113.1\n").expect("a file to point at");
        std::os::unix::fs::symlink(&real, &link).expect("a symlink to it");

        assert!(
            opens_as_itself(&real),
            "a plain file does not open as itself, so a bounded run installs no rule at all"
        );
        assert!(
            !opens_as_itself(&link),
            "a rule would be installed for a symlink, whose bind landed on the target — so \
             `open_grant`'s readback disagrees with the spelling and refuses the run"
        );
        assert!(
            !opens_as_itself(&scratch.path().join("absent.conf")),
            "an absent path would get a rule Landlock cannot open"
        );
    }

    /// A dangling link is still a link, which is the no-race half of the window that made
    /// resolving the target fail-open: skipped at the bind, it must be skipped here too.
    #[test]
    fn a_dangling_symlink_is_skipped_like_an_absent_path() {
        let scratch = tempfile::tempdir().expect("a temporary directory");
        let link = scratch.path().join("dangling.conf");
        std::os::unix::fs::symlink(scratch.path().join("nothing"), &link).expect("a dead link");

        assert!(
            !opens_as_itself(&link),
            "a dangling link got a rule, so a target appearing before stage 2 would be granted \
             without a bind over it"
        );
    }
}
