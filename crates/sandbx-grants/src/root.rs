//! Where a no-flag run may root its default policy, and what a path flag is vetted against;
//! nothing here reads a flag.
//!
//! [`vetted_root`] refuses in the order written, which decides the error a cwd matching two
//! arms gets. The comparisons need a [`ResolvedPath`], from [`resolved`] or a [`VettedPath`].

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::{env, io};

use sandbx_core::{SandboxError, VettedPath};

use crate::PolicyError;

/// Where home directories live, for a cwd `$HOME` does not settle.
///
/// Refused by location, whatever the environment says; only the child reading below is gated
/// on `$HOME` at all.
///
/// Rejected shapes, all likely to be re-proposed. **Depth** — refusing direct children of
/// `/` — because depth is not sensitivity: `/srv`, `/opt` and `/data` are ordinary project
/// roots, a container's `/app` *is* the working directory, and `~/.ssh` is three levels down.
/// A **denylist of dangerous children** (`/etc`, `/root`, `/proc`), whose first omission is
/// silent — rejected for variable names in `context/decision-policy.md`; this list instead
/// names the one place whose purpose is to hold other people's trees. A
/// **subdirectory-of-`$HOME` rule**: `~/code/project` is the entire use case.
///
/// Non-goal: a home root this does not list. `/srv/people`, autofs and `HOME=/tmp` with cwd
/// `/home/other` all still derive. Consulting `/etc/passwd` does not fix it — the LDAP and
/// autofs layouts that need it are the ones it cannot see — so it only moves the omission.
const HOME_PARENTS: [&str; 4] = ["/home", "/Users", "/var/home", "/root"];

/// Whether `cwd` is one of [`HOME_PARENTS`] or holds one.
///
/// Not gated on `$HOME`: a service account's `HOME=/var/lib/svc` would let `/home` through,
/// where a root there is write over every user's home whatever the variable names.
fn holds_home_directories(cwd: &Path) -> bool {
    HOME_PARENTS
        .into_iter()
        .any(|known| Path::new(known).starts_with(cwd))
}

/// The [`HOME_PARENTS`] that hold other users' homes rather than being one.
///
/// `/root` is a home as well as the place for root's, so `HOME=/root` names one where
/// `HOME=/home` names none. Widening this to all four refuses `/root/app`, the conventional
/// root container. The cwd arms still read all four — a cwd *at* `/root` is refused whatever
/// `$HOME` says — which is the asymmetry the two lists encode.
const SHARED_HOME_PARENTS: [&str; 3] = ["/home", "/Users", "/var/home"];

/// Whether `home` is one of [`SHARED_HOME_PARENTS`] or holds one, and so is nobody's home.
fn holds_other_homes(home: &Path) -> bool {
    SHARED_HOME_PARENTS
        .into_iter()
        .any(|known| Path::new(known).starts_with(home))
}

/// Whether `cwd` is a direct child of one of [`HOME_PARENTS`], and so shaped like a home.
///
/// Only with no `$HOME` to compare, which leaves `/home/other` indistinguishable from a
/// home directory; a readable `HOME` makes it a neighbour's and the operator's business.
fn looks_like_a_home(cwd: &Path) -> bool {
    HOME_PARENTS
        .into_iter()
        .any(|known| cwd.parent() == Some(Path::new(known)))
}

/// The spellings of `$HOME` a cwd is compared against, and whether it names a home at all.
///
/// Two fields because an unresolvable `$HOME` is still a path a cwd can hold, yet no usable
/// home for the stand-in to defer to. One list answering both was four reproduced holes, each
/// deriving read and write where it should refuse, so do not fold them back:
///
/// 1. Gating the home-parent arm on an empty list: `env -u HOME` from `/home` derived.
/// 2. An empty list asks only whether `HOME` was *set*: `HOME=/var/lib/svc` disabled the
///    exact arm and skipped the stand-in at once.
/// 3. Any absolute path kept for comparison silencing the stand-in: `HOME=/nonexistent`,
///    `/dev/null` or Docker's `/` with cwd `/home/other` derived (#154).
/// 4. `usable` asking only for a directory: `HOME=/home` holds homes, and `/home/other`
///    derived (#162).
///
/// An unresolvable `$HOME` is still compared: `cd /srv/people` with `HOME=/srv/people/alice`
/// unprovisioned is refused for *holding* a home.
#[derive(Debug, PartialEq, Eq)]
struct Homes {
    paths: Vec<PathBuf>,
    usable: bool,
}

/// `cwd` itself, or why no default may be rooted there.
///
/// An unusable `$HOME` leaves the exact home rule nothing to compare, so
/// [`looks_like_a_home`] stands in for it rather than being skipped, and any other cwd still
/// derives rather than being refused: `HOME` unset with cwd `/app` is the container case.
/// That is the one constraint here a plausible edit would quietly reverse.
///
/// Why each arm refuses rather than narrowing is the crate `//!`'s. What that costs: a cwd
/// shaped like a home with an unusable `$HOME` is refused, and so is `/usr/src/app`, the
/// stock `WORKDIR` in the official Node images.
///
/// **No arm compares the running `sandbx` against the cwd, and that is deliberate.**
/// `command_line` hands the kernel `/proc/self/exe`, a link to the running image's inode
/// (#149), so a replacement renamed over the binary cannot redirect the next spawn. A path
/// comparison would test a name nothing is reached by, and a carve-out — grant the tree except
/// the binary — is not expressible: a `SandboxPolicy` is grants-only, matching is prefix-only,
/// and Landlock composes rules by union with no subtraction.
///
/// So a no-flag run from `~/.cargo/bin`, `~/.local/bin` or `/opt/x/bin` derives read and
/// write over the installed binary; a `/usr`-rooted prefix is refused by the overlap arm. The
/// residue — a write grant replacing what the *next* `sandbx` invocation runs — is the
/// `.git/hooks/*` property, a non-claim in `SECURITY.md`.
fn vetted_root<'a>(
    root: &'a ResolvedPath,
    homes: &Homes,
    granted: &[VettedPath],
    owned: &[OwnedPath],
) -> Result<&'a ResolvedPath, PolicyError> {
    let cwd = root.path();

    if cwd.parent().is_none() {
        return Err(PolicyError::FilesystemRoot);
    }

    // `starts_with` is true of equal paths and whole-component.
    if let Some(home) = homes.paths.iter().find(|home| home.starts_with(cwd)) {
        return Err(PolicyError::HomeDirectory {
            cwd: cwd.to_path_buf(),
            home: home.clone(),
        });
    }

    if holds_home_directories(cwd) {
        return Err(PolicyError::HomeParent {
            cwd: cwd.to_path_buf(),
        });
    }

    if !homes.usable && looks_like_a_home(cwd) {
        return Err(PolicyError::UnnamedHome {
            cwd: cwd.to_path_buf(),
            // Named because this arm also fires on a `$HOME` that is set, which "no usable
            // HOME" would read as unset.
            home: homes.paths.first().cloned(),
        });
    }

    // Either direction, since Landlock rights cover a subtree: a cwd under a granted path,
    // `/usr/src/app` say, holds none of them. Both sides are resolved — the cwd by its type,
    // grants by `allow_system_executables` — so a merged-`/usr` host compares `/usr/bin` with
    // `/usr/bin` rather than with `/bin`.
    if let Some(path) = granted
        .iter()
        .map(VettedPath::path)
        .find(|path| path.starts_with(cwd) || cwd.starts_with(path))
    {
        return Err(PolicyError::SystemExecutables {
            cwd: cwd.to_path_buf(),
            path: path.to_path_buf(),
        });
    }

    if let Some(found) = reaches_owned(root, owned) {
        return Err(PolicyError::CwdReachesOwned {
            cwd: cwd.to_path_buf(),
            owned: found.path.clone(),
            holds: found.holds,
        });
    }

    Ok(root)
}

/// What `$HOME` names, resolved and as written.
///
/// Absolute only: an empty or relative `HOME` matches no resolved `getcwd`, so keeping it
/// would read as a home that settles the cwd while answering nothing.
fn named_homes(home: Option<&Path>) -> Homes {
    let Some(home) = home.filter(|home| home.is_absolute()) else {
        return Homes {
            paths: Vec::new(),
            usable: false,
        };
    };

    let mut paths = vec![home.to_path_buf()];
    let Ok(resolved) = home.canonicalize() else {
        return Homes {
            paths,
            usable: false,
        };
    };
    // Both forms, because Fedora Silverblue ships `/home -> /var/home`: `getcwd` says
    // `/var/home/u` where `$HOME` says `/home/u`, and comparing one bypasses the other.
    if resolved != home {
        paths.push(resolved.clone());
    }

    // Resolving is not being a home: `HOME=/dev/null` is a service-account convention,
    // Docker hands a UID with no passwd entry `HOME=/`, and `HOME=/home` is nobody's home.
    let usable = resolved.is_dir() && !holds_other_homes(&resolved);

    Homes { paths, usable }
}

/// Somewhere sandbx keeps state of its own, and what it keeps there.
///
/// `path` is absolute: both derivations drop a `$HOME` or `XDG_*` that is not, so this side
/// of a comparison never needs the working directory.
#[derive(Debug)]
pub(crate) struct OwnedPath {
    pub(crate) path: PathBuf,
    /// `&'static str`, so no shape of this can carry a key into a message.
    pub(crate) holds: &'static str,
}

/// The paths sandbx itself owns, below whichever config and state homes are in play.
///
/// A root that cannot be derived is one this host has nowhere to keep, so there is nothing
/// to reach; `agent-run --session` and `auth login` refuse it on their own account.
pub(crate) fn owned_paths(lookup: &impl Fn(&str) -> Option<OsString>) -> Vec<OwnedPath> {
    let mut owned = Vec::new();

    if let Ok(path) = sandbx_session_paths::sessions_directory(lookup) {
        owned.push(OwnedPath {
            path,
            holds: "the session transcripts a resumed run replays to the model",
        });
    }
    if let Ok(path) = sandbx_auth::config_file(lookup) {
        owned.push(OwnedPath {
            path,
            holds: "the provider key it spends",
        });
    }

    owned
}

/// `granted` made absolute, a relative flag being joined to the working directory.
///
/// Joined here because the grant crosses to the helper in this form, so what it names cannot
/// depend on where the helper stands. [`resolved`] cannot stand in — its walk bottoms out at
/// the empty path, leaving a relative grant relative. An unreadable cwd refuses rather than
/// standing in as nothing, which would match no owned path (#203).
pub(crate) fn absolute(
    granted: &Path,
    cwd: &impl Fn() -> io::Result<PathBuf>,
) -> Result<PathBuf, PolicyError> {
    if granted.is_absolute() {
        return Ok(granted.to_path_buf());
    }

    Ok(cwd()
        .map_err(|source| PolicyError::UnresolvableGrant {
            granted: granted.to_path_buf(),
            source,
        })?
        .join(granted))
}

/// A path [`resolved`] produced, or a [`VettedPath`]'s; those are the only ways to hold one.
///
/// Every comparison below needs this form: one symlinked spelling reaches what the other is
/// refused for, and a relative one reaches no owned path at all (#205). Not [`VettedPath`]
/// alone, which canonicalizes and so cannot name a path whose leaf does not exist yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedPath(PathBuf);

impl ResolvedPath {
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

/// No I/O: a vetted path is canonical already.
impl From<&VettedPath> for ResolvedPath {
    fn from(vetted: &VettedPath) -> Self {
        Self(vetted.path().to_path_buf())
    }
}

/// `path` with its deepest resolvable ancestor replaced by what that resolves to.
///
/// `canonicalize` needs the whole path to exist, and a credential nobody has stored yet
/// does not — so comparing canonical forms alone would miss `/home -> /var/home` (Fedora
/// Silverblue) and let the unresolved spelling through.
pub(crate) fn resolved(path: &Path) -> ResolvedPath {
    for (depth, ancestor) in path.ancestors().enumerate() {
        if let Ok(base) = ancestor.canonicalize() {
            return ResolvedPath(
                path.components()
                    .rev()
                    .take(depth)
                    .collect::<Vec<_>>()
                    .iter()
                    .rev()
                    .fold(base, |resolved, name| resolved.join(name)),
            );
        }
    }

    ResolvedPath(path.to_path_buf())
}

/// Whether a flag names a file a bounded resolver bind-mounts sandbx's own copy over, which
/// `SandboxPolicy::grant_bound_by_resolver` refuses the policy for.
///
/// Both spellings, overlapping on purpose: `granted` is the form the policy carries and
/// matches a flag spelled relative or through a symlink, `typed` still matches where an entry
/// cannot be canonicalized at all.
pub(crate) fn bound_by_resolver(typed: &Path, granted: &Path) -> bool {
    sandbx_core::bound_by_resolver(typed) || sandbx_core::bound_by_resolver(granted)
}

/// The path in `owned` that `granted` reaches, if it reaches one.
///
/// Either direction, since Landlock rights cover a subtree. Both callers pass what they
/// grant: vetting one spelling and granting another is the window this closes.
pub(crate) fn reaches_owned<'a>(
    granted: &ResolvedPath,
    owned: &'a [OwnedPath],
) -> Option<&'a OwnedPath> {
    let granted = granted.path();

    owned.iter().find(|owned| {
        let path = resolved(&owned.path);

        path.path().starts_with(granted) || granted.starts_with(path.path())
    })
}

/// [`vetted_root`] over this process's own state, and the working directory it judged, vetted.
pub(crate) fn current_root(
    granted: &[VettedPath],
    owned: &[OwnedPath],
) -> Result<VettedPath, PolicyError> {
    let cwd = env::current_dir().map_err(|source| PolicyError::Unavailable {
        detail: "could not read the working directory to derive a policy from",
        source,
    })?;
    // The vet proves the cwd still openable, which `PathFd::new` requires and `FsGuard` does
    // not, covering nothing under an unopenable root rather than refusing it.
    let cwd = VettedPath::vet(&cwd).map_err(|error| PolicyError::Unavailable {
        detail: "could not resolve the working directory to derive a policy from",
        source: match error {
            SandboxError::GrantUnpinnable { source, .. } => source,
            other => io::Error::other(other),
        },
    })?;

    let homes = named_homes(env::var_os("HOME").as_deref().map(Path::new));

    vetted_root(&ResolvedPath::from(&cwd), &homes, granted, owned)?;

    Ok(cwd)
}

#[cfg(test)]
#[path = "root_tests.rs"]
pub(crate) mod tests;
