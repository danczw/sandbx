//! The `sandbx` command line.
//!
//! Parsing and policy derivation live here, not in `main.rs`, so a unit test can answer
//! what a flag grants on a machine with no sandbox-capable kernel.

mod agent;
mod error;
mod grants;
pub mod logging;
mod sandbox;

pub use agent::AgentRun;
pub use error::{AgentError, PolicyError, SandboxRunError};
pub use grants::Grants;
pub use sandbox::SandboxRun;

#[derive(Debug, clap::Parser)]
#[command(
    name = "sandbx",
    version,
    about = "A security-first AI coding agent harness",
    // Without this, clap derives the long help from the doc comment below and
    // prints its second paragraph — a note about test visibility — to anyone
    // running `sandbx --help`. `None` falls back to `about` for both forms.
    long_about = None
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

    /// Ask an agent one question, and let it use tools to answer.
    ///
    /// The prompt goes out, the answer streams back on stdout, and every tool
    /// the model calls runs under the same boundary `sandbox-run` uses: denied
    /// unless a flag grants it, refused rather than run unrestricted on a kernel
    /// that cannot enforce it. Needs `ANTHROPIC_API_KEY` in the environment; no
    /// tool sees it unless you pass that name to `--allow-env`, which hands over
    /// the value in full.
    ///
    /// Single-shot: one question, one answer, then the process ends. Nothing
    /// asks you before a tool call runs.
    ///
    /// Put the prompt after `--`:
    ///
    /// ```text
    /// sandbx agent-run --allow-read /srv -- "what is in /srv?"
    /// ```
    AgentRun(AgentRun),
}
