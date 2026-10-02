//! The `sandbx` command line.
//!
//! Parsing and policy derivation live here rather than in `main.rs` so they can be
//! tested without spawning anything: what a flag grants is a security question, and a
//! unit test should answer it on a machine with no sandbox-capable kernel at all.

pub mod logging;

use std::io::Write;
use std::path::PathBuf;

use sandbx_core::{Axis, SandboxError, SandboxPolicy, SandboxedCommand};

#[derive(Debug, clap::Parser)]
#[command(
    name = "sandbx",
    version,
    about = "A security-first AI coding agent harness"
)]
/// A parsed `sandbx` invocation.
///
/// Public so a test can inspect what an argv grants without spawning anything.
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// What `sandbx` can be asked to do.
#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Run a command under the sandbox and report what it did.
    ///
    /// Everything is denied unless a flag grants it, except what a command needs
    /// in order to start: read access to the system binaries and libraries, and
    /// a handful of environment variables. The rest of the environment is
    /// cleared, so a secret in the shell that launched `sandbx` does not reach
    /// the command. The command runs under Landlock, an empty network namespace
    /// and a seccomp filter; on a kernel that cannot enforce those, it is
    /// refused rather than run unrestricted.
    ///
    /// Put the command after `--`:
    ///
    /// ```text
    /// sandbx sandbox-run --allow-read /srv -- cat /srv/notes.txt
    /// ```
    SandboxRun(SandboxRun),
}

/// `sandbx sandbox-run [--allow-…] -- <command> [args…]`
#[derive(Debug, clap::Args)]
pub struct SandboxRun {
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

    /// Let the command run programs under a path. Repeatable.
    ///
    /// Grants read as well, because that is what the kernel gives: running a
    /// program needs execute on the binary and read on the libraries its loader
    /// pulls in. The system paths every command needs to start are granted
    /// anyway; this is for anything else, such as a binary you built.
    #[arg(long = "allow-exec", value_name = "PATH")]
    allow_exec: Vec<PathBuf>,

    /// Give the command a network namespace with an interface.
    ///
    /// IP egress only; unix-domain sockets stay denied.
    #[arg(long = "allow-network")]
    allow_network: bool,

    /// Let the command open unix-domain sockets.
    ///
    /// All of them, not a chosen one — the kernel cannot scope this per path
    /// below Landlock ABI V9. That includes an ssh-agent, a docker socket or
    /// the session bus if the filesystem policy can reach them, so what the
    /// command can read still bounds what it can dial.
    #[arg(long = "allow-unix-sockets")]
    allow_unix_sockets: bool,

    /// Let the command inherit an environment variable. Repeatable.
    ///
    /// Names a variable, and takes its value from `sandbx`'s own environment —
    /// there is no way to set one from here. Everything not named is dropped
    /// before the command starts, so a secret in the shell that launched
    /// `sandbx` does not reach it.
    ///
    /// The variables a command needs in order to start are granted anyway:
    /// `PATH`, `HOME`, `TERM`, `LANG`, `LC_ALL`, `LC_CTYPE` and `TZ`.
    #[arg(long = "allow-env", value_name = "NAME", value_parser = variable_name)]
    allow_env: Vec<String>,

    /// Kill the command if it runs longer than this many seconds.
    ///
    /// Unset means no limit, matching a plain shell. The agent sets one of its
    /// own; at a terminal you already have Ctrl-C.
    #[arg(long = "timeout", value_name = "SECONDS")]
    timeout: Option<u64>,

    /// The command to run, and its arguments.
    // `last` is what keeps the separator meaningful: everything past `--` is the
    // command's, including flags sandbx itself defines. Not a doc comment, which
    // would reach `--help`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

/// Accept a name `--allow-env` can actually pass, and refuse anything else.
///
/// `SandboxPolicy::allow_env` *skips* a name it cannot encode, which is right for a
/// caller composing a policy in code and wrong here: `--allow-env TOKEN=secret` would
/// exit 0 having passed nothing, leaving the person who typed it believing the secret
/// crossed. So the CLI refuses loudly where the library skips quietly, and says what
/// to write instead. `=` gets a tailored message, being the mistake an `export` habit
/// produces rather than a typo.
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

impl SandboxRun {
    /// The paths given for `axis`, whichever flag collects them.
    ///
    /// One exhaustive match, so a new axis is a compile error here rather than a flag
    /// that parses and grants nothing. The flags stay separate fields because each
    /// carries its own `--help` text.
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
    /// axis stays denied.
    ///
    /// Two unconditional grants on top, because without them this subcommand can run
    /// nothing at all and the resulting error names neither cause nor fix: read access
    /// to the system binaries and libraries, and the startup environment — `PATH`
    /// above all, since without it a program named without a leading `/` reaches only
    /// the C library's fallback (`/bin:/usr/bin` on glibc). The user's own files,
    /// writes, network and every other variable stay denied.
    pub fn policy(&self) -> SandboxPolicy {
        let mut policy = SandboxPolicy::default()
            .allow_system_executables()
            .allow_standard_env();

        for axis in Axis::ALL {
            for path in self.paths(axis) {
                policy = policy.grant(axis, path);

                // The one place this CLI grants more than the flag's own axis. The
                // library keeps the axes separate so a caller can build a write-only
                // drop directory; at the command line that is a trap, since
                // `--allow-write ~/project` would let a tool rewrite the tree and then
                // fail to `cat` it back. Keyed to what the axis *confers*, not to the
                // `Write` variant, so a second write-conferring axis inherits it.
                if axis.grants().write {
                    policy = policy.grant(Axis::Read, path);
                }
            }
        }

        for name in &self.allow_env {
            policy = policy.allow_env(name);
        }

        if self.allow_network {
            policy = policy.allow_network();
        }
        if self.allow_unix_sockets {
            policy = policy.allow_unix_sockets();
        }

        policy
    }

    /// The program to run, split off from the arguments that follow it.
    ///
    /// Cannot panic: `required = true` on a `last` argument means clap rejects
    /// an empty command before this can be reached.
    pub fn program(&self) -> &str {
        &self.command[0]
    }

    /// The program's arguments, empty when it was given none.
    pub fn arguments(&self) -> &[String] {
        &self.command[1..]
    }

    /// The `--timeout` seconds as a [`Duration`], or `None` for no limit.
    ///
    /// [`Duration`]: std::time::Duration
    pub fn timeout(&self) -> Option<std::time::Duration> {
        self.timeout.map(std::time::Duration::from_secs)
    }

    /// Run it, forward its output, and report the code to exit with.
    pub fn execute(&self) -> Result<i32, SandboxError> {
        let mut command =
            SandboxedCommand::new(self.program(), self.policy()).args(self.arguments());
        if let Some(limit) = self.timeout() {
            command = command.timeout(limit);
        }
        let output = command.output()?;

        // Interleaving is lost: the command runs to completion rather than streaming,
        // which no caller needs yet.
        let _ = std::io::stdout().write_all(&output.stdout);
        let _ = std::io::stderr().write_all(&output.stderr);

        Ok(sandbx_core::exit_code(&output.status))
    }
}
