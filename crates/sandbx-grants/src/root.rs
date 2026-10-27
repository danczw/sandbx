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

    if let Ok(path) = sandbx_session::sessions_directory(lookup) {
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
pub(super) mod tests {
    //! The mutation check, the same one `context/decision-policy.md` does for a table change.
    //! Each mutation below was run rather than reasoned about, and the `passes` column is the
    //! load-bearing one:
    //!
    //! ```text
    //! default becomes unconditional (drop the paths_given guard)
    //!    ──► a_path_flag_replaces_the_working_directory      fails   ◄── the rule itself
    //!        each_allow_flag_widens_only_its_own_axis        fails
    //!        allow_flags_repeat_to_grant_several_paths       fails
    //!        a_path_flag_runs_from_the_home_directory        fails   ◄── on an explicit policy
    //!        the_default_matches_what_sandbox_run_derives    passes  ◄── derives its expectation
    //!
    //! default removed entirely
    //!    ──► the_working_directory_is_readable_and_writable  fails
    //!        an_env_flag_keeps_the_working_directory         fails
    //!        refuses_to_run_from_the_filesystem_root         fails
    //!        refuses_to_run_from_the_home_directory          fails
    //!
    //! home arm narrowed from starts_with to equality
    //!    ──► a_directory_holding_home_is_refused             fails
    //!        a_refusal_names_the_flags_to_type_instead       fails
    //!
    //! holds_home_directories arm deleted
    //!    ──► the_home_parents_are_refused_with_no_home_set       fails
    //!        the_home_parents_are_refused_when_home_is_elsewhere fails
    //!        a_refusal_names_the_flags_to_type_instead           fails
    //!        refuses_to_run_from_home_whatever_home_names        fails
    //!        an_unset_home_still_derives_a_root                  passes  ◄── /app is no home par.
    //!        a_named_home_leaves_a_neighbour_alone               passes
    //!
    //! that arm re-gated on homes.is_empty() (the draft-2 hole)
    //!    ──► the_home_parents_are_refused_when_home_is_elsewhere fails   ◄── $HOME=/var/lib/svc
    //!        refuses_to_run_from_home_whatever_home_names        fails
    //!        the_home_parents_are_refused_with_no_home_set       passes  ◄── the gate is satisfied
    //!
    //! the child reading deleted
    //!    ──► an_unset_home_refuses_a_child_of_one                fails
    //!        an_unresolvable_home_refuses_a_child_of_one         fails
    //!        a_home_that_is_no_directory_refuses_a_child_of_one  fails
    //!        a_refusal_names_the_flags_to_type_instead           fails
    //!        the_home_parents_are_refused_with_no_home_set       passes
    //!
    //! that gate re-read off the path list, !usable ──► paths.is_empty() (the #154 hole)
    //!    ──► an_unresolvable_home_refuses_a_child_of_one         fails
    //!        a_home_that_is_no_directory_refuses_a_child_of_one  fails
    //!        an_unset_home_refuses_a_child_of_one                passes  ◄── the gate is satisfied
    //!        refuses_to_run_from_home_whatever_home_names        passes  ◄── /home is a home par.
    //!
    //! usable stops asking for a directory (HOME=/dev/null)
    //!    ──► a_home_that_is_no_directory_refuses_a_child_of_one  fails
    //!        an_unresolvable_home_refuses_a_child_of_one         passes  ◄── it never resolved
    //!
    //! usable stops asking that $HOME holds no homes (HOME=/home, the #162 hole)
    //!    ──► a_home_that_holds_homes_refuses_a_child_of_one      fails
    //!        a_home_that_is_no_directory_refuses_a_child_of_one  fails   ◄── HOME=/ holds homes
    //!        an_unresolvable_home_refuses_a_child_of_one         passes  ◄── it never resolved
    //!
    //! that test widened from SHARED_HOME_PARENTS to all four (HOME=/root)
    //!    ──► a_root_home_still_derives_under_itself             fails   ◄── /root/app refuses
    //!        a_home_that_holds_homes_refuses_a_child_of_one      passes  ◄── /home is in both
    //!
    //! UnnamedHome stops naming the $HOME it rejected
    //!    ──► a_home_that_holds_homes_refuses_a_child_of_one      fails
    //!        an_unset_home_refuses_a_child_of_one                passes  ◄── nothing to name
    //!
    //! the written form dropped when $HOME does not resolve
    //!    ──► an_unresolvable_home_is_still_compared              fails
    //!        an_unresolvable_home_refuses_a_child_of_one         passes  ◄── the other field
    //!
    //! the Silverblue second spelling dropped
    //!    ──► a_symlinked_home_names_both_forms                   fails
    //!
    //! an unusable $HOME refused outright instead of deriving
    //!    ──► an_unresolvable_home_still_runs_from_a_project      fails
    //!        refuses_to_run_from_home_whatever_home_names        fails   ◄── the wrong refusal
    //!        an_unset_home_still_runs_from_a_project             passes  ◄── nothing to refuse on
    //!
    //! overlap arm deleted, or tested one way round
    //!    ──► a_directory_overlapping_the_system_binaries_is_refused  fails
    //!        refuses_to_run_from_the_system_binaries                 fails
    //!        a_directory_named_like_a_system_one_is_a_valid_root     passes
    //! ```
    //!
    //! Deleting the overlap arm and testing it one way round fail the same two tests, which is
    //! the signal being asked for: the loop covers each granted path *and* a directory under it,
    //! so a one-way test is detected as the absence it is. That loop reads [`granted`] rather
    //! than naming paths, because `allow_system_executables` skips a path the host lacks —
    //! `/lib64` is absent on arm64, which failed a hardcoded list on CI's aarch64 leg while
    //! passing x86_64.
    //!
    //! Two things the first mutation shows. Dropping the guard breaks tests in two suites that
    //! never mention the default — `each_allow_flag_widens_only_its_own_axis` and
    //! `allow_flags_repeat_to_grant_several_paths` both assert on the whole policy — so
    //! suppression is pinned by tests older than it. And
    //! `the_default_matches_what_sandbox_run_derives` passes, because both sides of the
    //! comparison mutate together: that is the derived-expectation trap
    //! `context/decision-policy.md` names, and it is why it is a cross-subcommand consistency
    //! test and not the one pinning what the default *is*.
    //!
    //! The gap the tests do not close, narrowed by #154 and #162: [`named_homes`] takes `$HOME`
    //! as a value and is unit-tested over every shape — unset, empty, relative, unresolvable,
    //! resolving to a non-directory, resolving to `/`, resolving to a place homes live, resolving
    //! to a real home, and symlinked, that last against a `tempfile` symlink rather than argued
    //! from a Silverblue host. All that is left reading the live process is [`current_root`]'s
    //! two lookups themselves, `getcwd` and `var_os("HOME")`; `sandbx-cli`'s `tests/cwd_policy.rs`
    //! covers what it can of them by setting `HOME` on the spawned binary.

    use sandbx_core::SandboxPolicy;

    use super::*;

    /// What every run may already execute, which `policy()` passes from the live policy.
    fn granted() -> Vec<VettedPath> {
        SandboxPolicy::default()
            .allow_system_executables()
            .executable_paths()
            .to_vec()
    }

    /// A `$HOME` that named these and resolved to a directory.
    fn homes(paths: &[&str]) -> Homes {
        Homes {
            paths: paths.iter().map(PathBuf::from).collect(),
            usable: true,
        }
    }

    /// A `$HOME` that named these and resolved to nothing a home can be.
    fn unusable(paths: &[&str]) -> Homes {
        Homes {
            usable: false,
            ..homes(paths)
        }
    }

    /// No `$HOME` at all.
    fn no_home() -> Homes {
        unusable(&[])
    }

    /// An absolute path guaranteed absent, where `/nonexistent` is only a convention.
    fn missing() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("no-such-directory")
    }

    /// A cwd as `current_root` hands it over — a fixture spelling is not canonical just by
    /// being written out (`/home` is a symlink to `/var/home` on an ostree host).
    fn at(cwd: impl AsRef<Path>) -> ResolvedPath {
        resolved(cwd.as_ref())
    }

    fn root(cwd: impl AsRef<Path>, homes: &Homes) -> Result<ResolvedPath, PolicyError> {
        vetted_root(&at(cwd), homes, &granted(), &[]).cloned()
    }

    /// An environment of the pairs given, and nothing else.
    pub(crate) fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let pairs: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), OsString::from(*value)))
            .collect();

        move |name| {
            pairs
                .iter()
                .find(|(stored, _)| stored == name)
                .map(|(_, value)| value.clone())
        }
    }

    /// The owned paths a host with this `$HOME` and nothing else set would have.
    fn owned_under(home: &str) -> Vec<OwnedPath> {
        owned_paths(&env(&[("HOME", home)]))
    }

    /// Whether `granted` reaches one of `owned`, the cwd a test runs from being readable.
    /// Through both steps [`Grants::policy`] puts a flag through, so what is asserted here
    /// is what a flag actually gets compared in.
    pub(crate) fn reaches(granted: impl AsRef<Path>, owned: &[OwnedPath]) -> bool {
        let granted = resolved(
            &absolute(granted.as_ref(), &std::env::current_dir)
                .expect("a readable working directory"),
        );

        reaches_owned(&granted, owned).is_some()
    }

    /// A working directory nothing can read, for the one spelling that needs one.
    fn no_cwd() -> impl Fn() -> std::io::Result<PathBuf> {
        || Err(std::io::Error::from(std::io::ErrorKind::NotFound))
    }

    #[test]
    fn the_working_directory_is_the_default_root() {
        assert_eq!(
            root("/srv/app", &homes(&["/home/u"])).expect("an ordinary project directory"),
            at("/srv/app"),
            "the default root is not the working directory"
        );
    }

    /// `~/code/project` is the whole use case, so only standing *at* `$HOME` may refuse.
    #[test]
    fn a_subdirectory_of_home_is_a_valid_root() {
        assert_eq!(
            root("/home/u/code/project", &homes(&["/home/u"])).expect("a project under home"),
            at("/home/u/code/project"),
            "a project inside home was refused"
        );
    }

    /// A no-flag run from `$HOME` hands over `~/.ssh` and every dotfile, which for
    /// `agent-run` is a prompt injection's blast radius.
    #[test]
    fn the_home_directory_is_refused_as_a_root() {
        let error = root("/home/u", &homes(&["/home/u"])).expect_err("home as a root");

        assert!(
            matches!(error, PolicyError::HomeDirectory { .. }),
            "{error} is not the home refusal"
        );
        assert!(
            error.to_string().contains("your home directory /home/u"),
            "{error} does not say which directory it refused"
        );
    }

    #[test]
    fn a_directory_holding_home_is_refused() {
        for parent in ["/home", "/Users", "/var/home"] {
            let home = format!("{parent}/u");
            let error = root(parent, &homes(&[&home])).expect_err("a parent of home");

            assert!(
                error
                    .to_string()
                    .contains("which holds your home directory"),
                "{error} reads as though {parent} were home itself"
            );
        }
    }

    #[test]
    fn the_filesystem_root_is_refused() {
        let error = root("/", &homes(&["/home/u"])).expect_err("the filesystem root");

        assert!(
            matches!(error, PolicyError::FilesystemRoot),
            "{error} is not the root refusal"
        );
    }

    /// Fedora Silverblue ships `/home -> /var/home`, so a guard comparing one form of
    /// `$HOME` is bypassed by standing in the other.
    #[test]
    fn a_symlinked_home_is_still_refused() {
        let both = homes(&["/var/home/u", "/home/u"]);

        for cwd in ["/var/home/u", "/home/u"] {
            let error = root(cwd, &both).expect_err("either spelling of home");
            assert!(
                matches!(error, PolicyError::HomeDirectory { .. }),
                "{error} let {cwd} through"
            );
        }
    }

    #[test]
    fn an_unset_home_still_refuses_the_root() {
        let error = root("/", &no_home()).expect_err("the filesystem root");

        assert!(
            matches!(error, PolicyError::FilesystemRoot),
            "{error} is not the root refusal"
        );
    }

    /// `HOME` is routinely unset under a systemd unit, cron, or `docker exec`.
    #[test]
    fn the_home_parents_are_refused_with_no_home_set() {
        for cwd in ["/home", "/Users", "/var/home", "/root", "/var"] {
            let error = root(cwd, &no_home()).expect_err("a well-known home location");

            assert!(
                matches!(error, PolicyError::HomeParent { .. }),
                "{error} let {cwd} through with no HOME set"
            );
        }
    }

    /// The gap the exact rule leaves: a service account's `HOME=/var/lib/svc` matches
    /// nothing under `/home`, so gating this arm on a set `HOME` lets `/home` through.
    #[test]
    fn the_home_parents_are_refused_when_home_is_elsewhere() {
        for cwd in ["/home", "/Users", "/var/home", "/root"] {
            let error =
                root(cwd, &homes(&["/var/lib/svc"])).expect_err("a well-known home location");

            assert!(
                matches!(error, PolicyError::HomeParent { .. }),
                "{error} let {cwd} through for a $HOME that names somewhere else"
            );
        }
    }

    /// With no `$HOME` naming it, a child of `/home` is indistinguishable from a home
    /// directory whatever it is called.
    #[test]
    fn an_unset_home_refuses_a_child_of_one() {
        for cwd in ["/home/other", "/Users/other", "/root/work"] {
            let error = root(cwd, &no_home()).expect_err("something shaped like a home directory");

            assert!(
                matches!(error, PolicyError::UnnamedHome { .. }),
                "{error} let {cwd} through with no HOME set"
            );
            assert!(
                error
                    .to_string()
                    .contains("with no HOME naming a home directory"),
                "{error} does not say why {cwd} could not be told apart"
            );
        }
    }

    /// A `$HOME` that resolves to nothing must not satisfy the stand-in gate (#154).
    #[test]
    fn an_unresolvable_home_refuses_a_child_of_one() {
        let homes = named_homes(Some(&missing()));

        for cwd in ["/home/other", "/Users/other", "/root/work"] {
            let error = root(cwd, &homes).expect_err("something shaped like a home directory");

            assert!(
                matches!(error, PolicyError::UnnamedHome { .. }),
                "{error} let {cwd} through for a $HOME that resolves to nothing"
            );
        }
    }

    /// Resolving is not being a home: `/dev/null` and `/` both do, and neither names one.
    #[test]
    fn a_home_that_is_no_directory_refuses_a_child_of_one() {
        for home in ["/dev/null", "/"] {
            let homes = named_homes(Some(Path::new(home)));

            let error =
                root("/home/other", &homes).expect_err("something shaped like a home directory");
            assert!(
                matches!(error, PolicyError::UnnamedHome { .. }),
                "{error} let /home/other through for $HOME={home}"
            );
        }
    }

    /// Where homes live is nobody's home, so it must not satisfy the stand-in gate (#162).
    #[test]
    fn a_home_that_holds_homes_refuses_a_child_of_one() {
        assert!(
            Path::new("/home").is_dir(),
            "no /home to resolve, so this test asserts nothing"
        );
        let homes = named_homes(Some(Path::new("/home")));

        let error =
            root("/home/other", &homes).expect_err("something shaped like a home directory");
        assert!(
            matches!(error, PolicyError::UnnamedHome { .. }),
            "{error} let /home/other through for $HOME=/home"
        );
        // The refusal fires on a `$HOME` that *is* set, where "no usable HOME" read as unset.
        assert!(
            error
                .to_string()
                .contains("HOME=/home names no home directory"),
            "{error} does not name the $HOME it rejected"
        );
    }

    /// `/root` is in [`HOME_PARENTS`] and is also root's own home, which a container sets.
    #[test]
    fn a_root_home_still_derives_under_itself() {
        assert!(
            Path::new("/root").is_dir(),
            "no /root to resolve, so this test asserts nothing"
        );
        let homes = named_homes(Some(Path::new("/root")));

        assert!(homes.usable, "$HOME=/root named no usable home");
        assert_eq!(
            root("/root/app", &homes).expect("root's own project directory"),
            at("/root/app"),
            "a root container with $HOME=/root could not derive a root under it"
        );
    }

    /// An unprovisioned home is still a path the cwd can hold, and outside
    /// [`HOME_PARENTS`] no other arm covers it.
    #[test]
    fn an_unresolvable_home_is_still_compared() {
        let homes = named_homes(Some(Path::new("/srv/people/alice")));

        let error = root("/srv/people", &homes).expect_err("a directory holding a home");
        assert!(
            matches!(error, PolicyError::HomeDirectory { .. }),
            "{error} let /srv/people through while $HOME named a home under it"
        );
    }

    #[test]
    fn an_absolute_home_that_resolves_is_usable() {
        let real = Path::new(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("the package directory this test is compiled from");

        assert_eq!(
            named_homes(Some(&real)),
            homes(&[real.to_str().expect("a UTF-8 package path")]),
            "a resolved $HOME did not name itself as a usable home"
        );
    }

    #[test]
    fn a_symlinked_home_names_both_forms() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let real = directory.path().join("var-home");
        let link = directory.path().join("home");
        std::fs::create_dir(&real).expect("a home to link to");
        std::os::unix::fs::symlink(&real, &link).expect("a symlinked home");

        let named = named_homes(Some(&link));

        assert!(named.usable, "a symlinked home resolved to no usable home");
        assert!(
            named.paths.contains(&link) && named.paths.contains(&real),
            "{named:?} does not hold both spellings of the symlinked home"
        );
    }

    #[test]
    fn an_unresolvable_home_is_not_usable() {
        let named = named_homes(Some(&missing()));

        assert!(
            !named.usable,
            "{named:?} called a home it cannot resolve usable"
        );
    }

    #[test]
    fn a_relative_or_empty_home_names_nothing() {
        for home in ["relative/path", ""] {
            assert_eq!(
                named_homes(Some(Path::new(home))),
                no_home(),
                "{home:?} named a home that settles no resolved cwd"
            );
        }
    }

    #[test]
    fn an_unset_home_names_nothing() {
        assert_eq!(
            named_homes(None),
            no_home(),
            "an unset HOME named a home anyway"
        );
    }

    /// Write plus the execute every run already has is the pair `Axis::grants` keeps apart —
    /// tested on both the path itself and a directory under it, since a merged-`/usr` host
    /// resolves `/bin` to `/usr/bin`. Driven off `granted()` rather than a name list: arm64
    /// has no `/lib64`, and `allow_system_executables` skips a path this host lacks.
    #[test]
    fn a_directory_overlapping_the_system_binaries_is_refused() {
        assert!(
            !granted().is_empty(),
            "no granted path to overlap with, so this test asserts nothing"
        );

        for granted in granted() {
            let path = granted.path();
            for cwd in [path.to_path_buf(), path.join("src/app")] {
                let error = root(&cwd, &homes(&["/home/u"])).expect_err("a system path");

                assert!(
                    matches!(error, PolicyError::SystemExecutables { .. }),
                    "{error} let {} through as a writable root",
                    cwd.display()
                );
            }
        }
    }

    /// Whole-component, so the rule claims no directory merely spelled like a system one.
    #[test]
    fn a_directory_named_like_a_system_one_is_a_valid_root() {
        for cwd in ["/usrlocal", "/libexec", "/srv/usr"] {
            assert_eq!(
                root(cwd, &homes(&["/home/u"])).expect("an ordinary project directory"),
                at(cwd),
                "prefix matching crossed a component boundary"
            );
        }
    }

    /// With a `$HOME` to compare, standing in a neighbour's directory is the operator's
    /// business and not sandbx's to guess at.
    #[test]
    fn a_named_home_leaves_a_neighbour_alone() {
        assert_eq!(
            root("/home/other", &homes(&["/home/u"])).expect("a named home identifies itself"),
            at("/home/other"),
            "the degraded rule fired where $HOME was readable"
        );
    }

    /// The container case the default exists for: `HOME` unset, cwd `/app`.
    #[test]
    fn an_unset_home_still_derives_a_root() {
        assert_eq!(
            root("/app", &no_home()).expect("a container working directory"),
            at("/app"),
            "an unset HOME refused an ordinary directory"
        );
    }

    #[test]
    fn a_refusal_names_the_flags_to_type_instead() {
        let refusals = [
            root("/", &no_home()).expect_err("the filesystem root"),
            root("/home/u", &homes(&["/home/u"])).expect_err("home as a root"),
            root("/home", &homes(&["/home/u"])).expect_err("a parent of home"),
            root("/home", &homes(&["/var/lib/svc"])).expect_err("a home parent"),
            root("/home/other", &no_home()).expect_err("something shaped like a home"),
            root("/usr", &homes(&["/home/u"])).expect_err("a system executable path"),
        ];

        for error in refusals {
            let message = error.to_string();
            assert!(
                message.contains("--allow-read") && message.contains("--allow-write"),
                "{message} does not name the flags to type instead"
            );
        }
    }

    /// Both roots, since one rule covers them and naming one would pass with the other unguarded.
    #[test]
    fn both_owned_roots_are_derived_from_home() {
        let owned: Vec<PathBuf> = owned_under("/home/u")
            .into_iter()
            .map(|owned| owned.path)
            .collect();

        assert_eq!(
            owned,
            [
                PathBuf::from("/home/u/.local/state/sandbx/sessions"),
                PathBuf::from("/home/u/.config/sandbx/credentials.toml"),
            ],
            "the owned roots are not the two sandbx writes"
        );
    }

    /// No `$HOME` leaves sandbx nowhere to keep either root, so an ordinary run still derives.
    #[test]
    fn a_host_with_no_home_owns_no_path() {
        assert!(
            owned_paths(&env(&[])).is_empty(),
            "a host with no HOME claimed an owned path anyway"
        );
    }

    /// #184 and #173: the one flag it takes, on the axis each issue was reported with.
    #[test]
    fn a_grant_above_an_owned_root_is_refused() {
        let owned = owned_under("/home/u");

        for granted in ["/home/u", "/home/u/.config", "/home/u/.local/state"] {
            assert!(
                reaches(granted, &owned),
                "{granted} reached no owned path, so the grant would be honoured"
            );
        }
    }

    /// The other direction, and the exact path: one transcript is the history, and the file is
    /// the key.
    #[test]
    fn a_grant_inside_an_owned_root_is_refused() {
        let owned = owned_under("/home/u");

        for granted in [
            "/home/u/.local/state/sandbx/sessions",
            "/home/u/.local/state/sandbx/sessions/01JA.jsonl",
            "/home/u/.config/sandbx/credentials.toml",
        ] {
            assert!(
                reaches(granted, &owned),
                "{granted} reached no owned path, so the grant would be honoured"
            );
        }
    }

    /// Whole-component, so the rule claims no path merely spelled like an owned one.
    #[test]
    fn a_path_named_like_an_owned_root_is_granted() {
        let owned = owned_under("/home/u");

        for granted in [
            "/home/u/.config/sandbx-notes",
            "/home/u/.local/state/sandbx/sessions-old",
            "/home/other/.config/sandbx",
        ] {
            assert!(
                !reaches(granted, &owned),
                "{granted} was taken for an owned path"
            );
        }
    }

    /// `--allow-read .` from the config directory is the shortest spelling of #184, and
    /// lexically it matches nothing.
    #[test]
    fn a_relative_grant_is_resolved_before_comparing() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let home = directory.path().canonicalize().expect("a resolved home");
        let config = home.join(".config").join("sandbx");
        std::fs::create_dir_all(&config).expect("a config directory to stand in");

        let owned = owned_paths(&env(&[("HOME", home.to_str().expect("a UTF-8 home"))]));
        let relative = config.join("..").join("sandbx");

        assert!(
            reaches(&relative, &owned),
            "{} reached no owned path once resolved",
            relative.display()
        );
    }

    /// The grant `--session` creates during the run it was given to: nothing on disk resolves
    /// it, so joining the cwd is the only thing that can.
    #[test]
    fn a_relative_grant_resolves_before_it_exists() {
        let cwd = std::env::current_dir().expect("a test runs from a real directory");
        let owned = vec![OwnedPath {
            path: cwd.join("nothing-stored-yet/sandbx/sessions"),
            holds: "the session transcripts a resumed run replays to the model",
        }];

        assert!(
            reaches("nothing-stored-yet", &owned),
            "a relative grant naming no existing directory reached no owned path"
        );
    }

    /// A relative grant joined to nothing reached no owned path, and so was honoured (#203).
    #[test]
    fn an_unreadable_cwd_refuses_a_relative_grant() {
        let error = absolute(Path::new("sandbx"), &no_cwd())
            .expect_err("a relative grant with no working directory to resolve it against");

        assert!(
            matches!(error, PolicyError::UnresolvableGrant { .. }),
            "{error} is not the unresolvable-grant refusal"
        );
        assert!(
            error.to_string().contains("absolute path"),
            "{error} does not say what to write instead"
        );
    }

    /// The other half of #203: needing no cwd, an absolute grant survives an unreadable one.
    #[test]
    fn an_absolute_grant_needs_no_cwd() {
        let owned = owned_under("/home/u");

        let granted = resolved(
            &absolute(Path::new("/srv/app"), &no_cwd())
                .expect("an absolute grant needs no working directory"),
        );

        assert!(
            reaches_owned(&granted, &owned).is_none(),
            "an ordinary absolute grant reached an owned path"
        );
    }

    /// Fedora Silverblue ships `/home -> /var/home`, so granting one spelling of an owned root
    /// must not bypass the other.
    #[test]
    fn a_symlinked_home_still_refuses_an_owned_root() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let real = directory.path().join("var-home");
        let link = directory.path().join("home");
        std::fs::create_dir_all(real.join(".config").join("sandbx")).expect("a real home");
        std::os::unix::fs::symlink(&real, &link).expect("a symlinked home");

        // Owned under the link, granted through the real path: two strings, one directory.
        let owned = owned_paths(&env(&[("HOME", link.to_str().expect("a UTF-8 home"))]));

        assert!(
            reaches(&real, &owned),
            "the real path reached no owned path named through the link"
        );
    }

    /// The derived default is a write grant too, so standing in the session directory is #173
    /// with no flag.
    #[test]
    fn a_root_inside_an_owned_path_is_refused() {
        let owned = owned_under("/home/u");
        let cwd = at("/home/u/.local/state/sandbx/sessions");

        let error = vetted_root(&cwd, &homes(&["/home/u"]), &granted(), &owned)
            .expect_err("the session directory as a root");

        assert!(
            matches!(error, PolicyError::CwdReachesOwned { .. }),
            "{error} is not the owned-path refusal"
        );
    }
}
