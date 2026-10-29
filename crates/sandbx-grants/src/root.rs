//! Where a no-flag run may root its default policy, and what a path flag is vetted against;
//! nothing here reads a flag.
//!
//! One order is load-bearing and it is not one function's: [`vetted_root`] refuses in the
//! order written. The comparisons need a [`ResolvedPath`], from [`resolved`] or a [`VettedPath`].

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use sandbx_core::{SandboxError, VettedPath};

use crate::PolicyError;

/// Where home directories live, for a cwd `$HOME` does not settle.
///
/// Refused by location, whatever the environment says; only the child reading below is gated
/// on `$HOME` at all.
///
/// Two rejected shapes, both likely to be re-proposed. **Depth** — refusing direct children
/// of `/` — because depth is not sensitivity: `/srv`, `/opt`, `/workspace` and `/data` are
/// ordinary project roots, in a container `/app` *is* the working directory, and `~/.ssh` is
/// three levels down and far worse. And a **denylist of the dangerous children** (`/etc`,
/// `/root`, `/proc`), whose first omission is silent — the shape
/// `context/decision-policy.md` already rejected for variable names. A list of names is
/// nonetheless what this is, and the difference is that a depth rule guesses at which
/// directories are *sensitive* where this names the one place on a Unix system whose entire
/// purpose is to hold other people's trees. Nor is there a subdirectory-of-`$HOME` rule:
/// `~/code/project` is the entire use case, and the accidental no-flag run is standing in
/// `$HOME` itself.
///
/// Non-goal: a home root this does not list. `/srv/people`, autofs and `HOME=/tmp` with cwd
/// `/home/other` all still derive, a real directory somewhere unlisted being what a
/// legitimate non-standard home looks like. Consulting `/etc/passwd` was considered and does
/// not fix it — the LDAP and autofs layouts that need it are the ones `/etc/passwd` cannot
/// see either — so it moves the omission at the cost of parsing a file inside the guard. One
/// layout degrading to no protection is the accepted cost, rather than the mechanism having
/// a hole, and `--allow-read`/`--allow-write` answer for such a site either way.
const HOME_PARENTS: [&str; 4] = ["/home", "/Users", "/var/home", "/root"];

/// Whether `cwd` is one of [`HOME_PARENTS`] or holds one.
///
/// Not gated on `$HOME`: a service account's `HOME=/var/lib/svc` would let `/home` through,
/// where a root there is write over every user's home whatever the variable names. It is this
/// arm — the one depending on `$HOME` not at all — that never had any of the four holes
/// [`Homes`] records, and that is the reason to prefer it.
fn holds_home_directories(cwd: &Path) -> bool {
    HOME_PARENTS
        .into_iter()
        .any(|known| Path::new(known).starts_with(cwd))
}

/// The [`HOME_PARENTS`] that hold other users' homes rather than being one.
///
/// `/root` is a home as well as the place for root's, so `HOME=/root` names one where
/// `HOME=/home` names none. Widening this to all four refuses root's own `/root/app`, the
/// conventional root container, over a `$HOME` that is set, resolvable and names exactly the
/// home it should. The cwd arms still read all four — a cwd *at* `/root` is refused whatever
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
/// Two fields because an unresolvable `$HOME` is still a path a cwd can hold, and still no
/// usable home for the stand-in to defer to. One list answering both questions was the shape
/// of four reproduced holes, each deriving `readable=1 writable=1` where it should refuse, so
/// a fifth tightening of one list is not the fix:
///
/// 1. The whole rule gated on the list being empty: `cd /home && env -u HOME sandbx
///    sandbox-run -- true` derived read and write over every user's home.
/// 2. Empty asks whether `HOME` was *set*, not whether it named anything useful. `HOME=`,
///    `HOME=relative/path`, `HOME=/nonexistent` and — the ordinary case — a service
///    account's `HOME=/var/lib/svc` all leave a non-empty list holding a path no cwd under
///    `/home` can match, disabling the exact arm and skipping the stand-in at once.
/// 3. The same conflation one layer in, on the child reading, where `$HOME` legitimately
///    gates: any absolute path kept for *comparison* also silenced the stand-in.
///    `HOME=/nonexistent` with cwd `/home/other` derived over a neighbour's tree (#154), as
///    did `HOME=/dev/null` and the `HOME=/` Docker hands a UID with no passwd entry.
/// 4. `usable` asking only that `$HOME` resolve to a directory. `HOME=/home` does, and is a
///    place that holds homes rather than being one, so `/home/other` derived over a
///    neighbour's tree (#162) — which is why the resolved form is tested by location too,
///    subsuming `HOME=/` for free.
///
/// An unresolvable `$HOME` is still compared: `cd /srv/people` with `HOME=/srv/people/alice`
/// unprovisioned is refused for *holding* a home, which a filter that dropped the path would
/// have lost.
#[derive(Debug, PartialEq, Eq)]
struct Homes {
    paths: Vec<PathBuf>,
    usable: bool,
}

/// `cwd` itself, or why no default may be rooted there.
///
/// An unusable `$HOME` leaves the exact home rule nothing to compare — so
/// [`looks_like_a_home`] stands in for it rather than being skipped, and such a cwd still
/// derives rather than being refused: `HOME` unset with cwd `/app` is the container case.
/// That is the one constraint here a plausible edit would quietly reverse.
///
/// A derived write grant is reachable by accident in a way a typed one is not, so every arm
/// refuses outright rather than deriving a narrower root: falling back to the system paths
/// alone makes an ordinary command fail for a reason the message would not explain, and
/// granting the directory anyway is the thing being refused. So each refusal names the two
/// flags to type instead, behind one `const` so two of them cannot advise differently. What
/// that costs, visibly: a cwd shaped like a home under [`HOME_PARENTS`] with an unusable
/// `$HOME` is refused where it once derived, and so is `/usr/src/app`, the stock `WORKDIR`
/// in the official Node images. Both are real losses on deployments this feature is for, and
/// both are the trade being made — less than expected, heard about immediately, by name.
///
/// **No arm compares the running `sandbx` against the cwd, and that is deliberate.** Whether
/// a derived root may hold the enforcer is settled by not needing an answer: `command_line`
/// hands the kernel `/proc/self/exe`, a magic link to the image this process is running
/// (#149). What a path guard had to stop was live rather than theoretical — resolved by path
/// on *every* spawn, the helper could be swapped between two tool calls in one turn by
/// renaming a replacement over the binary, and the next spawn would exec it, choosing its own
/// confinement with nothing asking the operator first. (`ETXTBSY` blocks overwriting in
/// place; rename-over is what `cargo build` does.) A link to the inode cannot be redirected.
/// Any replacement for `exe.starts_with(cwd)` would be comparing a name nothing is reached
/// by, and a carve-out — grant the tree except the binary — is not expressible: a
/// `SandboxPolicy` is grants-only, matching is prefix-only, and Landlock composes rules by
/// union with no subtraction.
///
/// Dropping that arm widened something, and it is named here rather than filed under bounded
/// cost. A `/usr`-rooted prefix is still refused, by the overlap arm below and not by it, since
/// `/usr/local/bin` holds `/usr`. It was the only thing refusing a *user-level* prefix, so a
/// no-flag run from `~/.cargo/bin`, `~/.local/bin` or `/opt/x/bin` now derives read and write
/// over the directory holding the installed binary. The residue is the *next* invocation of
/// `sandbx`: a write grant over the binary replaces what runs then, by a human or a script.
/// No guard reaches that, it is the same property as `.git/hooks/*` in a granted tree, and it
/// stays a non-claim in `SECURITY.md`.
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

    // `starts_with` is true of equal paths, so one test covers "cwd is $HOME" and "cwd
    // holds it", and whole-component, so `/home/u/project-tools` is outside `/home/u/project`.
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
            // The written spelling; `named_homes` keeps it only when absolute. Named because
            // this arm fires on a `$HOME` that is *set*: "with no usable HOME" read as unset
            // and sent the operator to check whether they had exported it.
            home: homes.paths.first().cloned(),
        });
    }

    // Either direction, since Landlock rights cover a subtree. Both sides are resolved — the
    // cwd by its type, grants by `allow_system_executables` — so a merged-`/usr` host
    // compares `/usr/bin` with `/usr/bin` rather than with `/bin`. One way round was tried
    // and is not a control: a merged-`/usr` cwd of `/bin` resolves to `/usr/bin`, which
    // *holds* no granted path, handing a no-flag run write over every system binary. This
    // arm is also what keeps the derived root non-executable — the one way it could have
    // been was by sitting under a granted system path.
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

    // The default grants write over the cwd, and inside the session directory the cwd is the
    // history — #173 with no flag.
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
pub(super) struct OwnedPath {
    pub(super) path: PathBuf,
    /// `&'static str`, so no shape of this can carry a key into a message.
    pub(super) holds: &'static str,
}

/// The paths sandbx itself owns, below whichever config and state homes are in play.
///
/// A root that cannot be derived is one this host has nowhere to keep, so there is nothing
/// to reach; `agent-run --session` and `auth login` refuse it on their own account.
pub(super) fn owned_paths(lookup: &impl Fn(&str) -> Option<OsString>) -> Vec<OwnedPath> {
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
/// This process's, while it is still the one that knows it: the grant crosses the seam in this
/// form, so what it names cannot depend on where the helper happens to stand. [`resolved`]
/// cannot stand in — its walk bottoms out at the empty path, leaving a relative grant relative.
/// A cwd that cannot be read refuses rather than standing in as nothing, which would match no
/// owned path (#203).
pub(super) fn absolute(
    granted: &Path,
    cwd: &impl Fn() -> std::io::Result<PathBuf>,
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
/// refused for, and a relative one resolves against nothing and so reaches no owned path at
/// all (#205). Not [`VettedPath`] alone, which canonicalizes and so cannot name a path whose
/// leaf does not exist yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedPath(PathBuf);

impl ResolvedPath {
    pub(super) fn path(&self) -> &Path {
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
pub(super) fn resolved(path: &Path) -> ResolvedPath {
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
/// Both spellings, overlapping on purpose: `granted` is the form the policy carries and is
/// what matches a flag spelled relative or through a symlink, `typed` what still matches where
/// an entry cannot be canonicalized at all. The names come from `sandbx_core::bound_by_resolver`.
pub(super) fn bound_by_resolver(typed: &Path, granted: &Path) -> bool {
    sandbx_core::bound_by_resolver(typed) || sandbx_core::bound_by_resolver(granted)
}

/// The path in `owned` that `granted` reaches, if it reaches one.
///
/// Either direction, since Landlock rights cover a subtree: a grant above an owned path and
/// one naming something inside it both reach it. Both callers pass what they grant: vetting
/// one spelling and granting another is the window this closes.
pub(super) fn reaches_owned<'a>(
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
pub(super) fn current_root(
    granted: &[VettedPath],
    owned: &[OwnedPath],
) -> Result<VettedPath, PolicyError> {
    let cwd = std::env::current_dir().map_err(|source| PolicyError::Unavailable {
        detail: "could not read the working directory to derive a policy from",
        source,
    })?;
    // The vet proves the cwd still openable, which `PathFd::new` requires and `FsGuard` does
    // not, covering nothing under an unopenable root rather than refusing it.
    let cwd = VettedPath::vet(&cwd).map_err(|error| PolicyError::Unavailable {
        detail: "could not resolve the working directory to derive a policy from",
        source: match error {
            SandboxError::GrantUnpinnable { source, .. } => source,
            other => std::io::Error::other(other),
        },
    })?;

    let homes = named_homes(std::env::var_os("HOME").as_deref().map(Path::new));

    vetted_root(&ResolvedPath::from(&cwd), &homes, granted, owned)?;

    Ok(cwd)
}

#[cfg(test)]
#[path = "root_tests.rs"]
pub(super) mod tests;
