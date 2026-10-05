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
    /// over UDP, QUIC and `ping` stop working, and a name has to resolve
    /// through `/etc/hosts` or a TCP resolver.
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

/// Where home directories live, for when no `$HOME` names one.
const HOME_PARENTS: [&str; 4] = ["/home", "/Users", "/var/home", "/root"];

/// Whether `cwd` is somewhere a home directory cannot be ruled out.
///
/// Three readings, because without a `$HOME` nothing distinguishes them: `cwd` holds one of
/// the well-known locations (`/`, `/var`), is one (`/home`), or is a child of one and so
/// looks exactly like a home directory whatever it is named (`/home/other`).
fn looks_like_a_home(cwd: &Path) -> bool {
    HOME_PARENTS
        .into_iter()
        .map(Path::new)
        .any(|known| known.starts_with(cwd) || cwd.parent() == Some(known))
}

/// `cwd` itself, or why no default may be rooted there.
///
/// An empty `homes` means `HOME` was unreadable, which would leave the home rule below with
/// nothing to compare and silently stop it existing — so it degrades to [`HOME_PARENTS`]
/// rather than being skipped.
fn vetted_root<'a>(cwd: &'a Path, homes: &[PathBuf], exe: &Path) -> Result<&'a Path, PolicyError> {
    if cwd.parent().is_none() {
        return Err(PolicyError::FilesystemRoot);
    }

    // `starts_with` is true of equal paths, so one test covers both "cwd *is* $HOME" and
    // "cwd holds it", and it is whole-component, so `/home/u/project-tools` is not inside
    // `/home/u/project`.
    if let Some(home) = homes.iter().find(|home| home.starts_with(cwd)) {
        return Err(PolicyError::HomeDirectory {
            cwd: cwd.to_path_buf(),
            home: home.clone(),
        });
    }

    // Only in the degraded case: with a `$HOME` to compare, the rule above is exact, and
    // widening it would refuse `/home/other` for an operator who has no business there but
    // also no way to say so.
    if homes.is_empty() && looks_like_a_home(cwd) {
        return Err(PolicyError::UnnamedHome {
            cwd: cwd.to_path_buf(),
        });
    }

    if exe.starts_with(cwd) {
        return Err(PolicyError::EnforcerInside {
            cwd: cwd.to_path_buf(),
            exe: exe.to_path_buf(),
        });
    }

    Ok(cwd)
}

/// [`vetted_root`] over this process's own state.
fn current_root() -> Result<PathBuf, PolicyError> {
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

    // `command_line()` resolves this same path again on every spawn, which is what makes a
    // write grant over it reach the enforcer mid-turn. Falling back to the unresolved path
    // keeps a canonicalize failure from turning into a *missing* guard.
    let exe = std::env::current_exe().map_err(|source| PolicyError::EnforcerUnknown { source })?;
    let exe = exe.canonicalize().unwrap_or(exe);

    let mut homes = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        // Both forms, because Fedora Silverblue ships `/home -> /var/home`: `getcwd` says
        // `/var/home/u` where `$HOME` says `/home/u`, and comparing one bypasses the other.
        if let Ok(resolved) = home.canonicalize() {
            homes.push(resolved);
        }
        homes.push(home);
    }

    vetted_root(&cwd, &homes, &exe).map(Path::to_path_buf)
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
            let root = current_root()?;
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

        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = "/usr/local/bin/sandbx";

    fn bare() -> Grants {
        Grants {
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            allow_exec: Vec::new(),
            allow_network: false,
            allow_unix_sockets: false,
            allow_env: Vec::new(),
        }
    }

    fn homes(paths: &[&str]) -> Vec<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    fn root(cwd: &str, homes: &[PathBuf]) -> Result<PathBuf, PolicyError> {
        vetted_root(Path::new(cwd), homes, Path::new(EXE)).map(Path::to_path_buf)
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
        let error = root("/", &[]).expect_err("the filesystem root");

        assert!(
            matches!(error, PolicyError::FilesystemRoot),
            "{error} is not the root refusal"
        );
    }

    /// Without this the home rule would not degrade but *vanish*, and `/home` with `HOME`
    /// unset would derive read and write over every user's home. `HOME` is routinely unset
    /// under a systemd unit, cron, or `docker exec`.
    #[test]
    fn an_unset_home_refuses_the_well_known_homes() {
        for cwd in ["/home", "/Users", "/var/home", "/root", "/var"] {
            let error = root(cwd, &[]).expect_err("a well-known home location");

            assert!(
                matches!(error, PolicyError::UnnamedHome { .. }),
                "{error} let {cwd} through with no HOME set"
            );
            assert!(
                error.to_string().contains("with HOME unset"),
                "{error} does not say why {cwd} could not be told apart"
            );
        }
    }

    /// The reading `starts_with` alone cannot give: with no `$HOME` naming it, a child of
    /// `/home` is indistinguishable from a home directory whatever it is called.
    #[test]
    fn an_unset_home_refuses_a_child_of_one() {
        for cwd in ["/home/other", "/Users/other", "/root/work"] {
            let error = root(cwd, &[]).expect_err("something shaped like a home directory");

            assert!(
                matches!(error, PolicyError::UnnamedHome { .. }),
                "{error} let {cwd} through with no HOME set"
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
            root("/app", &[]).expect("a container working directory"),
            Path::new("/app"),
            "an unset HOME refused an ordinary directory"
        );
    }

    #[test]
    fn the_binary_inside_the_root_is_refused() {
        let error = vetted_root(
            Path::new("/home/u/sandbx"),
            &homes(&["/home/u"]),
            Path::new("/home/u/sandbx/target/debug/sandbx"),
        )
        .expect_err("the enforcer inside the root");

        assert!(
            matches!(error, PolicyError::EnforcerInside { .. }),
            "{error} is not the enforcer refusal"
        );
    }

    #[test]
    fn a_sibling_named_like_the_root_is_allowed() {
        let root = vetted_root(
            Path::new("/home/u/project"),
            &homes(&["/home/u"]),
            Path::new("/home/u/project-tools/sandbx"),
        )
        .expect("a sibling directory is not inside the root");

        assert_eq!(
            root,
            Path::new("/home/u/project"),
            "prefix matching crossed a component boundary"
        );
    }

    #[test]
    fn a_refusal_names_the_flags_to_type_instead() {
        let refusals = [
            root("/", &[]).expect_err("the filesystem root"),
            root("/home/u", &homes(&["/home/u"])).expect_err("home as a root"),
            root("/home", &homes(&["/home/u"])).expect_err("a parent of home"),
            vetted_root(
                Path::new("/home/u/sandbx"),
                &homes(&["/home/u"]),
                Path::new("/home/u/sandbx/sandbx"),
            )
            .expect_err("the enforcer inside the root"),
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
        grants.allow_network = true;
        grants.allow_unix_sockets = true;
        grants.allow_env.push("TERM".to_string());

        assert!(
            !grants.paths_given(),
            "a flag naming no path suppressed the default"
        );
    }
}
