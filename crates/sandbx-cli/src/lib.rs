//! The `sandbx` command line.
//!
//! Parsing and policy derivation live here rather than in `main.rs` so they can
//! be tested without spawning anything: what a flag grants is a security
//! question, and it should be answerable by a unit test on a machine with no
//! sandbox-capable kernel at all.

use std::io::Write;
use std::path::PathBuf;

use sandbx_core::{SandboxError, SandboxPolicy, SandboxedCommand};

/// The `sandbx` binary.
#[derive(Debug, clap::Parser)]
#[command(
    name = "sandbx",
    version,
    about = "A security-first AI coding agent harness"
)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands of `sandbx`.
///
/// Only the sandbox is implemented; the agent that will use it is not built
/// yet. Shipping this one alone makes the enforcement inspectable by hand
/// instead of only through the test suite.
#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Run a command under the sandbox and report what it did.
    ///
    /// Everything is denied unless a flag grants it, except read access to the
    /// system binaries and libraries a command needs in order to start. The
    /// command runs under Landlock, an empty network namespace and a seccomp
    /// filter; on a kernel that cannot enforce those, it is refused rather than
    /// run unrestricted.
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
    #[arg(long = "allow-write", value_name = "PATH")]
    allow_write: Vec<PathBuf>,

    /// Give the command a network namespace with an interface.
    #[arg(long = "allow-network")]
    allow_network: bool,

    /// The command to run, and its arguments.
    // `last` is what keeps the separator meaningful: everything past `--` is
    // the command's, including flags sandbx itself defines. A doc comment here
    // would reach `--help`, so this stays an ordinary comment.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

impl SandboxRun {
    /// The policy these flags describe.
    ///
    /// Starts from [`SandboxPolicy::default`], which grants nothing, so an
    /// unmentioned axis stays denied.
    ///
    /// The one unconditional grant is read access to the system binaries and
    /// libraries a command needs to start — without it this subcommand can run
    /// nothing at all, and the resulting `exec` permission error names neither
    /// the cause nor the fix. It does not weaken what the flags are about: the
    /// user's own files, writes and network all stay denied.
    pub fn policy(&self) -> SandboxPolicy {
        let mut policy = SandboxPolicy::default().allow_system_executables();

        for path in &self.allow_read {
            policy = policy.allow_read(path);
        }
        for path in &self.allow_write {
            policy = policy.allow_write(path);
        }
        if self.allow_network {
            policy = policy.allow_network();
        }

        policy
    }

    /// The program to run.
    pub fn program(&self) -> &str {
        // `required = true` on a `last` argument means clap rejects an empty
        // command before this can be reached.
        &self.command[0]
    }

    /// The arguments passed to that program.
    pub fn arguments(&self) -> &[String] {
        &self.command[1..]
    }

    /// Run it, forward its output, and report the code to exit with.
    pub fn execute(&self) -> Result<i32, SandboxError> {
        let output = SandboxedCommand::new(self.program(), self.policy())
            .args(self.arguments().to_vec())
            .output()?;

        // Forwarded verbatim. Interleaving is lost because the command is run to
        // completion rather than streamed — acceptable for a debugging tool, and
        // the alternative is a streaming API no caller needs yet.
        let _ = std::io::stdout().write_all(&output.stdout);
        let _ = std::io::stderr().write_all(&output.stderr);

        Ok(exit_code(&output.status))
    }
}

/// Translate a child's fate into an exit code, the way a shell does.
///
/// A command killed by the sandbox dies by signal and has no exit code of its
/// own; reporting 0 there would say "succeeded" about a process seccomp shot.
fn exit_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;

    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}
