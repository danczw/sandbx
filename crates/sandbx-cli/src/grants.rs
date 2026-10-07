//! The grant flags, and the policy they describe.
//!
//! Shared by every subcommand that runs something, so the axis loop, the one widening it
//! applies, and the working-directory default exist once rather than once per subcommand.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use sandbx_core::{Axis, SandboxPolicy};

use crate::PolicyError;

/// The `--allow-…` flags every subcommand that runs something accepts.
#[derive(Debug, clap::Args)]
pub struct Grants {
    /// Grant read access to a path. Repeatable.
    ///
    /// Giving any path flag replaces the working-directory default, so this
    /// grant and its siblings become the whole of the filesystem policy.
    #[arg(long = "allow-read", value_name = "PATH")]
    allow_read: Vec<PathBuf>,

    /// Grant write access to a path. Repeatable.
    ///
    /// Grants read as well, because a tool that can rewrite a tree but not read
    /// it back is a trap rather than a safeguard. If you want a genuinely
    /// write-only drop directory, the library keeps the two apart —
    /// `SandboxPolicy::allow_write` grants write and nothing else.
    #[arg(long = "allow-write", value_name = "PATH")]
    allow_write: Vec<PathBuf>,

    /// Let a sandboxed command run programs under a path. Repeatable.
    ///
    /// Grants read as well, because that is what the kernel gives: running a
    /// program needs execute on the binary and read on the libraries its loader
    /// pulls in. The system paths every command needs to start are granted
    /// anyway; this is for anything else, such as a binary you built.
    #[arg(long = "allow-exec", value_name = "PATH")]
    allow_exec: Vec<PathBuf>,

    /// Give a sandboxed command IP egress, on one TCP port or on all of them.
    ///
    /// `--allow-network 443` allowlists a port and is repeatable; bare
    /// `--allow-network` allows every port. A port allowlist also denies UDP
    /// and raw sockets, without which it would not be an allowlist — so DNS
    /// over UDP, QUIC and `ping` stop working.
    ///
    /// Under glibc a name can still resolve over TCP: `--dns-over-tcp
    /// --allow-network 53 --allow-network 443 --allow-read /etc`. Not under
    /// musl, which has no `RES_OPTIONS` and so cannot be asked to start on TCP.
    ///
    /// `--allow-read /etc` is needed for resolution under any network policy,
    /// bare flag included; nothing else grants it. It is a path flag, so it
    /// replaces the working-directory default — name the command's own tree as
    /// well. Where `resolv.conf` is a symlink out of `/etc`, the link target
    /// needs a grant too: `--allow-read /run/systemd/resolve`.
    ///
    /// The allowlist is ports, not hosts: `--allow-network 443` reaches port
    /// 443 on every routable host. Unix-domain sockets stay denied either way.
    // `Option<Vec<u16>>` is what gives three states — absent, bare, valued.
    // `Vec<Option<u16>>` is the obvious spelling and clap_derive rejects it.
    #[arg(
        long = "allow-network",
        value_name = "PORT",
        num_args = 0..=1,
        value_parser = clap::value_parser!(u16).range(1..),
    )]
    allow_network: Option<Vec<u16>>,

    /// Let a sandboxed command open unix-domain sockets.
    ///
    /// All of them, not a chosen one — the kernel cannot scope this per path
    /// below Landlock ABI V9. That includes an ssh-agent, a docker socket or
    /// the session bus if the filesystem policy can reach them, so what it can
    /// read still bounds what it can dial.
    #[arg(long = "allow-unix-sockets")]
    allow_unix_sockets: bool,

    /// Let a sandboxed command inherit an environment variable. Repeatable.
    ///
    /// Names a variable, and takes its value from `sandbx`'s own environment —
    /// there is no way to set one from here. Everything not named is dropped
    /// before it starts, so a secret in the shell that launched `sandbx` does
    /// not reach it.
    ///
    /// The variables a command needs in order to start are granted anyway:
    /// `PATH`, `HOME`, `TERM`, `LANG`, `LC_ALL`, `LC_CTYPE` and `TZ`.
    #[arg(long = "allow-env", value_name = "NAME", value_parser = variable_name)]
    allow_env: Vec<String>,

    /// Ask glibc's stub resolver to use TCP, by setting `RES_OPTIONS=use-vc`.
    ///
    /// For resolving under a port allowlist, which denies UDP. A request to the
    /// resolver inside the command rather than something sandbx enforces: a
    /// command that ignores `RES_OPTIONS` is unaffected, and musl has no
    /// equivalent, so a statically linked musl binary keeps starting on UDP.
    ///
    /// It allowlists no port of its own — pass `--allow-network 53` as well, so
    /// the audit trail never names a port you did not. Resolution also needs
    /// `--allow-read /etc`, for `resolv.conf` and `nsswitch.conf`.
    #[arg(long = "dns-over-tcp")]
    dns_over_tcp: bool,
}

/// Accept a name `--allow-env` can actually pass, and refuse anything else.
///
/// `SandboxPolicy::allow_env` skips a name it cannot encode, so `--allow-env TOKEN=secret`
/// would exit 0 having passed nothing: the CLI refuses where the library skips.
fn variable_name(value: &str) -> Result<String, String> {
    if let Some((name, _)) = value.split_once('=') {
        return Err(format!(
            "expected a variable name, not `NAME=VALUE`: \
             --allow-env takes the value from sandbx's own environment, \
             so write `--allow-env {name}`"
        ));
    }
    if value.is_empty() {
        return Err("expected a variable name, but this one is empty".to_string());
    }
    if value.contains('\0') {
        return Err("a variable name cannot contain a NUL byte".to_string());
    }
    Ok(value.to_string())
}

/// Where home directories live, for a cwd `$HOME` does not settle.
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
/// `HOME=/home` names none. Widening this to all four refuses root's own `/root/app`.
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
/// usable home for the stand-in to defer to.
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
///
/// `cwd` comes resolved from [`current_root`], which every comparison here assumes.
fn vetted_root<'a>(
    cwd: &'a Path,
    homes: &Homes,
    granted: &[PathBuf],
    owned: &[OwnedPath],
) -> Result<&'a Path, PolicyError> {
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
            // The written spelling, which `named_homes` pushes first and keeps only when
            // absolute — so an empty or relative `HOME` names nothing here either.
            home: homes.paths.first().cloned(),
        });
    }

    // Either direction, since Landlock rights cover a subtree — and a merged-`/usr` host
    // resolves `/bin` to `/usr/bin`, which holds no granted path and so passed one way round.
    if let Some(path) = granted
        .iter()
        .find(|path| path.starts_with(cwd) || cwd.starts_with(path))
    {
        return Err(PolicyError::SystemExecutables {
            cwd: cwd.to_path_buf(),
            path: path.clone(),
        });
    }

    // The default grants write over the cwd, and inside the session directory the cwd is the
    // history — #173 with no flag.
    if let Some(found) = reaches_owned(cwd, owned) {
        return Err(PolicyError::CwdReachesOwned {
            cwd: cwd.to_path_buf(),
            owned: found.path.clone(),
            holds: found.holds,
        });
    }

    Ok(cwd)
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
struct OwnedPath {
    path: PathBuf,
    /// `&'static str`, so no shape of this can carry a key into a message.
    holds: &'static str,
}

/// The paths sandbx itself owns, below whichever config and state homes are in play.
///
/// A root that cannot be derived is one this host has nowhere to keep, so there is nothing
/// to reach; `agent-run --session` and `auth login` refuse it on their own account.
fn owned_paths(lookup: &impl Fn(&str) -> Option<OsString>) -> Vec<OwnedPath> {
    let mut owned = Vec::new();

    if let Ok(path) = sandbx_session::sessions_directory(lookup) {
        owned.push(OwnedPath {
            path,
            holds: "the session transcripts a resumed run replays to the model",
        });
    }
    if let Ok(path) = crate::auth::config_file(lookup) {
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
fn absolute(
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

/// `path` with its deepest resolvable ancestor replaced by what that resolves to.
///
/// `canonicalize` needs the whole path to exist and a credential nobody has stored yet does
/// not, so comparing canonical forms alone would miss the host where `/home` links to
/// `/var/home` — Fedora Silverblue — and let the unresolved spelling through.
fn resolved(path: &Path) -> PathBuf {
    for (depth, ancestor) in path.ancestors().enumerate() {
        if let Ok(base) = ancestor.canonicalize() {
            return path
                .components()
                .rev()
                .take(depth)
                .collect::<Vec<_>>()
                .iter()
                .rev()
                .fold(base, |resolved, name| resolved.join(name));
        }
    }

    path.to_path_buf()
}

/// The path in `owned` that `granted` reaches, if it reaches one.
///
/// Either direction, since Landlock rights cover a subtree: a grant above an owned path and
/// one naming something inside it both reach it. Both sides are [`resolved`], so one symlinked
/// spelling cannot reach what the other is refused for.
///
/// `granted` has to arrive resolved — and so absolute, or it resolves against nothing and
/// reaches no owned path. Both callers pass what they grant, which is the point: a path vetted
/// in one spelling and granted in another is the window this closes.
fn reaches_owned<'a>(granted: &Path, owned: &'a [OwnedPath]) -> Option<&'a OwnedPath> {
    debug_assert!(
        granted == resolved(granted),
        "an unresolved grant reaches the wrong owned paths here"
    );

    owned.iter().find(|owned| {
        let path = resolved(&owned.path);
        path.starts_with(granted) || granted.starts_with(&path)
    })
}

/// [`vetted_root`] over this process's own state.
fn current_root(granted: &[PathBuf], owned: &[OwnedPath]) -> Result<PathBuf, PolicyError> {
    let cwd = std::env::current_dir().map_err(|source| PolicyError::Unavailable {
        detail: "could not read the working directory to derive a policy from",
        source,
    })?;
    // `getcwd` already resolves; this is for the one thing `canonicalize` else proves — the
    // directory is still openable, which `PathFd::new` requires and `canonical_roots` would
    // answer by dropping the root rather than refusing.
    let cwd = cwd
        .canonicalize()
        .map_err(|source| PolicyError::Unavailable {
            detail: "could not resolve the working directory to derive a policy from",
            source,
        })?;

    let home = std::env::var_os("HOME").map(PathBuf::from);
    let homes = named_homes(home.as_deref());

    vetted_root(&cwd, &homes, granted, owned).map(Path::to_path_buf)
}

impl Grants {
    /// Whether any path flag was given, in which case no default is derived.
    ///
    /// Over [`Axis::ALL`] so a new path flag joins the rule rather than being left behind a
    /// default that widens it.
    fn paths_given(&self) -> bool {
        Axis::ALL
            .into_iter()
            .any(|axis| !self.paths(axis).is_empty())
    }

    /// Whether `--allow-env` named `name`, for a subcommand that refuses one.
    pub(crate) fn names_env(&self, name: &str) -> bool {
        self.allow_env.iter().any(|named| named == name)
    }

    /// The paths given for `axis`, whichever flag collects them.
    ///
    /// Exhaustive, so a new axis is a compile error rather than a flag that grants nothing.
    fn paths(&self, axis: Axis) -> &[PathBuf] {
        match axis {
            Axis::Read => &self.allow_read,
            Axis::Write => &self.allow_write,
            Axis::ReadExecute => &self.allow_exec,
        }
    }

    /// The policy these flags describe, or why none could be derived.
    ///
    /// From [`SandboxPolicy::default`], which grants nothing, plus the two grants without
    /// which nothing starts: read on the system binaries and libraries, and the startup
    /// environment — `PATH` above all, since without it a program named without a leading
    /// `/` reaches only glibc's `/bin:/usr/bin` fallback. Then read and write on the
    /// working directory, but only when no path flag was given: a path flag *replaces*
    /// that default rather than adding to it.
    pub fn policy(&self) -> Result<SandboxPolicy, PolicyError> {
        let mut policy = SandboxPolicy::default()
            .allow_system_executables()
            .allow_standard_env();

        let owned = owned_paths(&|name| std::env::var_os(name));

        if !self.paths_given() {
            // Inside the branch, not above it: an invocation that typed its own flags never
            // depends on `HOME`, and on `getcwd` only to resolve a relative one.
            let root = current_root(policy.executable_paths(), &owned)?;
            policy = policy.allow_read(&root).allow_write(&root);
        }

        for axis in Axis::ALL {
            for path in self.paths(axis) {
                // Outside the branch above: every other path refusal guards only the derived
                // default, which is why a flag bypassed all of them.
                // Granted in the form it was vetted in, not as the flag spelled it: the
                // helper opens what the policy carries, and a grant left relative or
                // unresolved is one the helper resolves itself, against its own working
                // directory and whatever the links point at by then (#205).
                let granted = resolved(&absolute(path, &std::env::current_dir)?);
                if let Some(found) = reaches_owned(&granted, &owned) {
                    return Err(PolicyError::GrantReachesOwned {
                        // As typed, which is what the operator can go and change.
                        granted: path.clone(),
                        owned: found.path.clone(),
                        holds: found.holds,
                    });
                }

                policy = policy.grant(axis, &granted);

                // The one place this CLI grants more than the flag's own axis: a tree a
                // tool can rewrite and not `cat` back is a trap. Keyed to what the axis
                // confers, not to `Write`, so a second write-conferring axis inherits it.
                if axis.grants().write {
                    policy = policy.grant(Axis::Read, &granted);
                }
            }
        }

        for name in &self.allow_env {
            policy = policy.allow_env(name);
        }

        // An empty `Vec` is the bare flag: no occurrence contributed a port. So
        // `--allow-network --allow-network 443` allowlists 443 alone — fail-closed, the
        // broader spelling yielding the narrower policy.
        match self.allow_network.as_deref() {
            None => {}
            Some([]) => policy = policy.allow_network(),
            Some(ports) => {
                for port in ports {
                    policy = policy.allow_network_port(*port);
                }
            }
        }

        if self.allow_unix_sockets {
            policy = policy.allow_unix_sockets();
        }

        if self.dns_over_tcp {
            policy = policy.hint_dns_over_tcp();
        }

        // Honouring both would drop the operator's value in silence. Over `--allow-env`'s
        // own names, not `allowed_env()`: a name nobody typed is not one they can drop.
        if let Some(name) = self.allow_env.iter().find(|name| {
            policy
                .imposed_env()
                .iter()
                .any(|(imposed, _)| name == imposed)
        }) {
            return Err(PolicyError::ImposedVariable { name: name.clone() });
        }

        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What every run may already execute, which `policy()` passes from the live policy.
    fn granted() -> Vec<PathBuf> {
        SandboxPolicy::default()
            .allow_system_executables()
            .executable_paths()
            .to_vec()
    }

    fn bare() -> Grants {
        Grants {
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            allow_exec: Vec::new(),
            allow_network: None,
            allow_unix_sockets: false,
            allow_env: Vec::new(),
            dns_over_tcp: false,
        }
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

    fn root(cwd: impl AsRef<Path>, homes: &Homes) -> Result<PathBuf, PolicyError> {
        vetted_root(cwd.as_ref(), homes, &granted(), &[]).map(Path::to_path_buf)
    }

    /// An environment of the pairs given, and nothing else.
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
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
    fn reaches(granted: impl AsRef<Path>, owned: &[OwnedPath]) -> bool {
        let granted = absolute(granted.as_ref(), &std::env::current_dir)
            .expect("a readable working directory");

        reaches_owned(&granted, owned).is_some()
    }

    #[test]
    fn the_working_directory_is_the_default_root() {
        assert_eq!(
            root("/srv/app", &homes(&["/home/u"])).expect("an ordinary project directory"),
            Path::new("/srv/app"),
            "the default root is not the working directory"
        );
    }

    /// `~/code/project` is the whole use case, so only standing *at* `$HOME` may refuse.
    #[test]
    fn a_subdirectory_of_home_is_a_valid_root() {
        assert_eq!(
            root("/home/u/code/project", &homes(&["/home/u"])).expect("a project under home"),
            Path::new("/home/u/code/project"),
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
            Path::new("/root/app"),
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

    /// Write here plus the execute every run already has is the pair `Axis::grants` keeps
    /// apart. Both the path itself and a directory under it, since a merged-`/usr` host
    /// resolves `/bin` to `/usr/bin`, which holds no granted path. Driven off `granted()`
    /// rather than a list of names: `allow_system_executables` skips a path this host
    /// lacks, and arm64 has no `/lib64`.
    #[test]
    fn a_directory_overlapping_the_system_binaries_is_refused() {
        assert!(
            !granted().is_empty(),
            "no granted path to overlap with, so this test asserts nothing"
        );

        for path in granted() {
            for cwd in [path.clone(), path.join("src/app")] {
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
                Path::new(cwd),
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
            Path::new("/home/other"),
            "the degraded rule fired where $HOME was readable"
        );
    }

    /// The container case the default exists for: `HOME` unset, cwd `/app`.
    #[test]
    fn an_unset_home_still_derives_a_root() {
        assert_eq!(
            root("/app", &no_home()).expect("a container working directory"),
            Path::new("/app"),
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

    #[test]
    fn a_path_flag_suppresses_the_default() {
        for axis in Axis::ALL {
            let mut grants = bare();
            // Matched, not pushed into one field, so a new path flag fails to compile here
            // too rather than quietly keeping the default.
            match axis {
                Axis::Read => grants.allow_read.push(PathBuf::from("/srv")),
                Axis::Write => grants.allow_write.push(PathBuf::from("/srv")),
                Axis::ReadExecute => grants.allow_exec.push(PathBuf::from("/srv")),
            }

            assert!(
                grants.paths_given(),
                "{axis:?} left the working-directory default in place"
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

    /// Driven off `Axis::ALL`, so a new path flag joins the refusal instead of being the one
    /// spelling that still reaches a key.
    #[test]
    fn every_path_axis_refuses_an_owned_root() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let home = directory.path();
        let owned = owned_paths(&env(&[(
            "HOME",
            home.to_str().expect("a UTF-8 temporary path"),
        )]));

        for axis in Axis::ALL {
            let mut grants = bare();
            match axis {
                Axis::Read => grants.allow_read.push(home.to_path_buf()),
                Axis::Write => grants.allow_write.push(home.to_path_buf()),
                Axis::ReadExecute => grants.allow_exec.push(home.to_path_buf()),
            }

            assert!(
                reaches(&grants.paths(axis)[0], &owned),
                "{axis:?} reached no owned path"
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

    /// A working directory nothing can read, for the one spelling that needs one.
    fn no_cwd() -> impl Fn() -> std::io::Result<PathBuf> {
        || Err(std::io::Error::from(std::io::ErrorKind::NotFound))
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

        let granted = absolute(Path::new("/srv/app"), &no_cwd())
            .expect("an absolute grant needs no working directory");

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
        let cwd = "/home/u/.local/state/sandbx/sessions";

        let error = vetted_root(Path::new(cwd), &homes(&["/home/u"]), &granted(), &owned)
            .expect_err("the session directory as a root");

        assert!(
            matches!(error, PolicyError::CwdReachesOwned { .. }),
            "{error} is not the owned-path refusal"
        );
    }

    /// Suppressing here would silently narrow a policy whose path axes were never touched.
    #[test]
    fn a_non_path_flag_leaves_the_default_alone() {
        let mut grants = bare();
        grants.allow_network = Some(vec![443]);
        grants.allow_unix_sockets = true;
        grants.allow_env.push("TERM".to_string());
        grants.dns_over_tcp = true;

        assert!(
            !grants.paths_given(),
            "a flag naming no path suppressed the default"
        );
    }
}
