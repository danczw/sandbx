//! The grant flags, and the policy they describe.
//!
//! Shared by every subcommand that runs something, so the axis loop, the one widening it
//! applies, and the working-directory default a no-flag run gets exist once rather than
//! once per subcommand.

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
/// `SandboxPolicy::allow_env` *skips* a name it cannot encode, which here would exit 0
/// having passed nothing, leaving whoever typed `--allow-env TOKEN=secret` believing the
/// secret crossed. So the CLI refuses loudly where the library skips quietly, and says
/// what to write instead.
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
/// Not gated on `$HOME`: a root at `/home` is write over every user's home whatever the
/// variable names, and a service account's `HOME=/var/lib/svc` would let it through.
fn holds_home_directories(cwd: &Path) -> bool {
    HOME_PARENTS
        .into_iter()
        .any(|known| Path::new(known).starts_with(cwd))
}

/// Whether `cwd` is a direct child of one of [`HOME_PARENTS`], and so shaped like a home.
///
/// Only with no `$HOME` to compare: `/home/other` is then indistinguishable from a home
/// directory, where a readable `HOME` makes it a neighbour's and the operator's business.
fn looks_like_a_home(cwd: &Path) -> bool {
    HOME_PARENTS
        .into_iter()
        .any(|known| cwd.parent() == Some(Path::new(known)))
}

/// The spellings of `$HOME` a cwd is compared against, and whether it names a home at all.
///
/// Two fields because the two questions have different answers: an unresolvable `$HOME` is
/// still a path a cwd can hold, and still no usable home for the stand-in to defer to.
#[derive(Debug, PartialEq, Eq)]
struct Homes {
    paths: Vec<PathBuf>,
    usable: bool,
}

/// `cwd` itself, or why no default may be rooted there.
///
/// An unusable `$HOME` leaves the exact home rule nothing to compare — so
/// [`looks_like_a_home`] stands in for it rather than being skipped.
fn vetted_root<'a>(
    cwd: &'a Path,
    homes: &Homes,
    granted: &[PathBuf],
) -> Result<&'a Path, PolicyError> {
    if cwd.parent().is_none() {
        return Err(PolicyError::FilesystemRoot);
    }

    // `starts_with` is true of equal paths, so one test covers both "cwd *is* $HOME" and
    // "cwd holds it", and it is whole-component, so `/home/u/project-tools` is not inside
    // `/home/u/project`.
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

    // Resolving is not being a home: `HOME=/dev/null` is a service-account convention and
    // Docker hands a UID with no passwd entry `HOME=/`. Both resolve, and match no cwd.
    let usable = resolved.parent().is_some() && resolved.is_dir();

    Homes { paths, usable }
}

/// [`vetted_root`] over this process's own state.
fn current_root(granted: &[PathBuf]) -> Result<PathBuf, PolicyError> {
    let cwd = std::env::current_dir().map_err(|source| PolicyError::Unavailable {
        detail: "could not read the working directory to derive a policy from",
        source,
    })?;
    // `getcwd` already resolves, so this is for what `canonicalize` else proves: the
    // directory is still openable, which `PathFd::new` requires and which
    // `FsGuard::canonical_roots` answers by dropping the root rather than refusing.
    let cwd = cwd
        .canonicalize()
        .map_err(|source| PolicyError::Unavailable {
            detail: "could not resolve the working directory to derive a policy from",
            source,
        })?;

    let home = std::env::var_os("HOME").map(PathBuf::from);
    let homes = named_homes(home.as_deref());

    vetted_root(&cwd, &homes, granted).map(Path::to_path_buf)
}

impl Grants {
    /// Whether any path flag was given, in which case no default is derived.
    ///
    /// Over [`Axis::ALL`] so a new path flag joins the rule rather than being left behind a
    /// default that then widens it.
    fn paths_given(&self) -> bool {
        Axis::ALL
            .into_iter()
            .any(|axis| !self.paths(axis).is_empty())
    }

    /// The paths given for `axis`, whichever flag collects them.
    ///
    /// One exhaustive match, so a new axis is a compile error here rather than a flag
    /// that parses and grants nothing.
    fn paths(&self, axis: Axis) -> &[PathBuf] {
        match axis {
            Axis::Read => &self.allow_read,
            Axis::Write => &self.allow_write,
            Axis::ReadExecute => &self.allow_exec,
        }
    }

    /// The policy these flags describe, or why none could be derived.
    ///
    /// Starts from [`SandboxPolicy::default`], which grants nothing. Two unconditional
    /// grants on top, without which nothing can be run at all: read on the system
    /// binaries and libraries, and the startup environment — `PATH` above all, since
    /// without it a program named without a leading `/` reaches only the C library's
    /// fallback (`/bin:/usr/bin` on glibc). Then read and write on the working directory,
    /// but *only* when no path flag was given — a path flag replaces that default rather
    /// than adding to it, so an explicit policy is never widened silently.
    pub fn policy(&self) -> Result<SandboxPolicy, PolicyError> {
        let mut policy = SandboxPolicy::default()
            .allow_system_executables()
            .allow_standard_env();

        if !self.paths_given() {
            // Looked up inside the branch, not above it: an invocation that typed its own
            // flags depends on neither `getcwd` nor `HOME`, so must not be refused for them.
            let root = current_root(policy.executable_paths())?;
            policy = policy.allow_read(&root).allow_write(&root);
        }

        for axis in Axis::ALL {
            for path in self.paths(axis) {
                policy = policy.grant(axis, path);

                // The one place this CLI grants more than the flag's own axis: the
                // library keeps write and read apart, but a tree a tool can rewrite and
                // not `cat` back is a trap. Keyed to what the axis *confers*, not to the
                // `Write` variant, so a second write-conferring axis inherits it.
                if axis.grants().write {
                    policy = policy.grant(Axis::Read, path);
                }
            }
        }

        for name in &self.allow_env {
            policy = policy.allow_env(name);
        }

        // An empty `Vec` is the bare flag: every occurrence was bare, so none contributed a
        // port. Which makes `--allow-network --allow-network 443` an allowlist of 443 alone
        // — fail-closed, the broader spelling yielding the narrower policy, and pinned by
        // `mixing_a_bare_flag_with_a_port_narrows_to_the_port`.
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
        vetted_root(cwd.as_ref(), homes, &granted()).map(Path::to_path_buf)
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

    /// A no-flag run from `$HOME` hands the command `~/.ssh` and every dotfile, which for
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

    /// `HOME` is routinely unset under a systemd unit, cron, or `docker exec`, and before
    /// this `/home` derived read and write over every user's home.
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
    /// nothing under `/home`, so gating this arm on a *set* `HOME` let `/home` through.
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

    /// The reading the arm above cannot give: with no `$HOME` naming it, a child of
    /// `/home` is indistinguishable from a home directory whatever it is called.
    #[test]
    fn an_unset_home_refuses_a_child_of_one() {
        for cwd in ["/home/other", "/Users/other", "/root/work"] {
            let error = root(cwd, &no_home()).expect_err("something shaped like a home directory");

            assert!(
                matches!(error, PolicyError::UnnamedHome { .. }),
                "{error} let {cwd} through with no HOME set"
            );
            assert!(
                error.to_string().contains("with no usable HOME"),
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

    /// The comparison outlives the usability verdict: an unprovisioned home is still a path
    /// the cwd can hold, and outside [`HOME_PARENTS`] no other arm covers it.
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

    /// Fedora Silverblue ships `/home -> /var/home`, and comparing one spelling of a
    /// symlinked home bypasses the other.
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
    /// resolves `/bin` to `/usr/bin` — which *holds* no granted path, and so passed when
    /// the arm was tested one way round.
    ///
    /// Driven off `granted()` rather than a list of names: `allow_system_executables`
    /// skips a path this host lacks, and arm64 has no `/lib64`.
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

    /// The degraded rule must not widen the exact one: with a `$HOME` to compare, standing
    /// in a neighbour's directory is the operator's business and not sandbx's to guess at.
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
            // Matched rather than pushed into one field, so a new path flag fails to
            // compile here too rather than quietly keeping the default.
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
