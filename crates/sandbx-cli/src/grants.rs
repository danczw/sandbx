//! The grant flags, and the policy they describe.
//!
//! Shared by every subcommand that runs something, so the axis loop and the one
//! widening it applies exist once rather than once per subcommand.

use std::path::PathBuf;

use sandbx_core::{Axis, SandboxPolicy};

/// The `--allow-…` flags every subcommand that runs something accepts.
#[derive(Debug, clap::Args)]
pub struct Grants {
    /// Grant read access to a path. Repeatable.
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
    ///
    /// `Option<Vec<u16>>` is what gives three states: absent, bare, and valued.
    /// `Vec<Option<u16>>` would be the obvious spelling and clap_derive does not
    /// support it.
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

impl Grants {
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

    /// The policy these flags describe.
    ///
    /// Starts from [`SandboxPolicy::default`], which grants nothing, so an unmentioned
    /// axis stays denied. Two unconditional grants on top, without which nothing can be
    /// run at all: read on the system binaries and libraries, and the startup
    /// environment — `PATH` above all, since without it a program named without a
    /// leading `/` reaches only the C library's fallback (`/bin:/usr/bin` on glibc).
    pub fn policy(&self) -> SandboxPolicy {
        let mut policy = SandboxPolicy::default()
            .allow_system_executables()
            .allow_standard_env();

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

        // The three states `--allow-network` can be in. An empty `Vec` is the bare flag:
        // every occurrence of the flag was bare, so none contributed a port.
        //
        // Which makes `--allow-network --allow-network 443` an allowlist of 443 alone,
        // because the bare occurrence contributes nothing to append to. Fail-closed — the
        // broader spelling yields the narrower policy, never the reverse — and pinned by
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

        policy
    }
}
