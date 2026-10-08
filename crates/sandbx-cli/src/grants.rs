//! The grant flags, and the policy they describe.
//!
//! Shared by every subcommand that runs something, so the axis loop, the one widening it
//! applies, and the working-directory default exist once rather than once per subcommand.
//! Deriving that default, and vetting what a flag names, is [`root`].

use std::path::PathBuf;

use sandbx_core::{Axis, NAMESERVER_PORT, SandboxPolicy};

use crate::PolicyError;

mod root;

use root::{
    absolute, bound_by_resolver, current_root, owned_paths, pinned, reaches_owned, resolved,
};

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
    ///
    /// Not with `--allow-dns`, which leaves no nameserver to ask.
    #[arg(long = "dns-over-tcp")]
    dns_over_tcp: bool,

    /// Let a sandboxed command resolve a host name, and only the ones named.
    /// Repeatable.
    ///
    /// sandbx resolves each name before the command starts and gives the command
    /// a hosts file holding those addresses and no nameserver at all, in a mount
    /// namespace of its own — so a name this flag did not list does not resolve,
    /// and the host's `/etc` is untouched. Without the flag, resolution is
    /// whatever the host and the network policy allow.
    ///
    /// Needs a port allowlist, and is refused with bare `--allow-network`, with
    /// port 53 in the list, with `--dns-over-tcp` and with no egress at all:
    /// each leaves a nameserver reachable, which answers for every name. The
    /// shape that works is `--allow-dns example.com --allow-network 443`.
    ///
    /// It needs no `--allow-read /etc` — the one flag that makes a policy
    /// smaller. It bounds resolution and not connection: an IP literal needs no
    /// resolver, so the port allowlist is still what bounds where a connection
    /// can go, and a name that resolves to several addresses resolves to all of
    /// them.
    #[arg(long = "allow-dns", value_name = "NAME", value_parser = host_name)]
    allow_dns: Vec<String>,
}

/// Accept a name `--allow-dns` can actually bound, and refuse anything else.
///
/// `SandboxPolicy::allow_dns` skips an unrenderable name; the CLI refuses where the library
/// skips, since binding resolution to nothing is the one outcome success can't be told from.
fn host_name(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("expected a host name, but this one is empty".to_string());
    }
    if value.len() > sandbx_core::DNS_NAME_LIMIT {
        return Err(format!(
            "a host name is at most {} bytes, and this one is {}",
            sandbx_core::DNS_NAME_LIMIT,
            value.len()
        ));
    }
    // A libc reading the rendered hosts file splits fields on whitespace and takes `#` as a
    // comment, so either would let one flag write a second entry.
    if value.contains('#') || value.contains('\0') || value.chars().any(char::is_whitespace) {
        return Err(
            "a host name cannot contain whitespace, `#` or a NUL byte — pass one \
             --allow-dns per name"
                .to_string(),
        );
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!(
            "{value} is an address, not a name, so there is nothing to resolve: \
             --allow-dns bounds which names resolve, while --allow-network PORT is what \
             bounds where a connection can go"
        ));
    }
    Ok(value.to_string())
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
    /// From [`SandboxPolicy::default`], plus the two grants nothing starts without: read on
    /// the system binaries, and the startup environment — `PATH` above all, or a bare
    /// program name only reaches glibc's `/bin:/usr/bin` fallback. The cwd gets read and
    /// write only when no path flag was given; a path flag *replaces* that default rather
    /// than adding to it.
    pub fn policy(&self) -> Result<SandboxPolicy, PolicyError> {
        let mut policy = SandboxPolicy::default()
            .allow_system_executables()
            .allow_standard_env();

        let owned = owned_paths(&|name| std::env::var_os(name));

        if !self.paths_given() {
            // Inside the branch: a run that typed its own flags never depends on `HOME`.
            let root = current_root(policy.executable_paths(), &owned)?;
            let root = pinned(&root, &root)?;
            policy = policy.allow_read(root.clone()).allow_write(root);
        }

        // Noted in the loop and refused with the `Dns…` family below, which holds the more
        // fundamental shapes: an operator with no egress at all should hear that first.
        let mut bound_file = None;

        for axis in Axis::ALL {
            for path in self.paths(axis) {
                // Outside the branch above: every other path refusal guards only the derived
                // default, which is why a flag bypassed all of them.
                // Granted as vetted, not as spelled: left relative, the helper would resolve
                // it itself, against its own directory and whatever links point at by then (#205).
                let typed = absolute(path, &std::env::current_dir)?;
                let granted = resolved(&typed);
                if bound_file.is_none() && bound_by_resolver(&typed, &granted) {
                    bound_file = Some(path.clone());
                }
                if let Some(found) = reaches_owned(&granted, &owned) {
                    return Err(PolicyError::GrantReachesOwned {
                        granted: path.clone(), // As typed, so the operator can go change it.
                        owned: found.path.clone(),
                        holds: found.holds,
                    });
                }

                let granted = pinned(&granted, path)?;
                policy = policy.grant(axis, granted.clone());

                // Beyond the flag's own axis: an unreadable rewrite target is a trap. Keyed to
                // what the axis confers, not `Write`, so a later write-conferring axis inherits it.
                if axis.grants().write {
                    policy = policy.grant(Axis::Read, granted);
                }
            }
        }

        for name in &self.allow_env {
            policy = policy.allow_env(name);
        }

        // An empty `Vec` is the bare flag: `--allow-network --allow-network 443` allowlists
        // 443 alone — fail-closed, the broader spelling yielding the narrower policy.
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

        // Each arm is a shape in which a nameserver stays reachable, and a reachable
        // nameserver answers for every name — `context/decision-egress-proxy.md`.
        if !self.allow_dns.is_empty() {
            if self.dns_over_tcp {
                return Err(PolicyError::DnsWithResolverHint);
            }
            // A pathname socket among them: `SandboxPolicy::unbounded_resolution` has why.
            if self.allow_unix_sockets {
                return Err(PolicyError::DnsWithUnixSockets);
            }
            match self.allow_network.as_deref() {
                None => return Err(PolicyError::DnsWithoutEgress),
                Some([]) => return Err(PolicyError::DnsWithEveryPort),
                Some(ports) if ports.contains(&NAMESERVER_PORT) => {
                    return Err(PolicyError::DnsWithNameserverPort);
                }
                Some(_) => {}
            }
            // Last of the block: the grant is sound in itself, and only the pair collides.
            if let Some(granted) = bound_file {
                return Err(PolicyError::DnsGrantsBoundFile { granted });
            }
        }

        for name in &self.allow_dns {
            policy = policy.allow_dns(name);
        }

        // Honouring both drops the operator's value silently. Over `--allow-env`'s own names,
        // not `allowed_env()`: a name nobody typed is not one they can drop.
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
    use std::path::Path;

    use sandbx_core::VettedPath;

    use super::*;
    use root::tests::{env, reaches};

    fn bare() -> Grants {
        Grants {
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            allow_exec: Vec::new(),
            allow_network: None,
            allow_unix_sockets: false,
            allow_env: Vec::new(),
            dns_over_tcp: false,
            allow_dns: Vec::new(),
        }
    }

    /// The paths of a set of grants. The object beside each is derived from the path, so these
    /// tests assert over the spelling and the pin follows (#212).
    fn spellings(granted: &[VettedPath]) -> Vec<&Path> {
        granted.iter().map(VettedPath::path).collect()
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

    /// A grant is pinned to the object at its path, and a path naming nothing has none — so
    /// this refuses in the harness where Landlock used to refuse it in the helper (#212).
    #[test]
    fn a_grant_naming_nothing_cannot_be_pinned() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let mut grants = bare();
        grants.allow_read.push(directory.path().join("no-such-dir"));

        let error = grants.policy().expect_err("a grant naming nothing");

        assert!(
            matches!(error, PolicyError::UnpinnableGrant { .. }),
            "{error} is not the unpinnable-grant refusal"
        );
        assert!(
            error.to_string().contains("a path that exists"),
            "{error} does not say what to name instead"
        );
    }

    /// The helper opens what the policy carries, from a process whose working directory is
    /// not this one's — so a grant left relative would be a different directory there (#205).
    #[test]
    fn a_relative_grant_reaches_the_policy_absolute() {
        let mut grants = bare();
        grants.allow_read.push(PathBuf::from("src"));

        let policy = grants.policy().expect("the flags describe a policy");
        let expected = std::env::current_dir()
            .expect("a readable working directory")
            .join("src")
            .canonicalize()
            .expect("the crate this test is in has a src directory");

        assert_eq!(
            spellings(policy.readable_paths()),
            [expected.as_path()],
            "a relative grant crossed the seam relative"
        );
    }

    /// The other half: vetted through the link and granted through it too, the helper would
    /// open whatever it points at by then.
    #[test]
    fn a_grant_through_a_symlink_reaches_the_policy_resolved() {
        let work = tempfile::tempdir().expect("a temporary directory");
        let real = work.path().canonicalize().expect("a resolved directory");
        let link = work.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("a symlink to it");

        let mut grants = bare();
        grants.allow_write.push(link);

        let policy = grants.policy().expect("the flags describe a policy");

        assert_eq!(
            spellings(policy.writable_paths()),
            [real.as_path()],
            "a symlinked grant crossed the seam unresolved"
        );
        assert_eq!(
            spellings(policy.readable_paths()),
            [real.as_path()],
            "the read a write flag confers was granted in another form than the write"
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
