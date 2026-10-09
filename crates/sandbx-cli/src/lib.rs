//! The `sandbx` command line.
//!
//! Parsing and policy derivation live here, not in `main.rs`, so a unit test can answer
//! what a flag grants on a machine with no sandbox-capable kernel.

mod agent;
mod auth;
mod error;
mod grants;
mod hash;
pub mod logging;
mod sandbox;
mod session;

pub use agent::{AgentRun, Tui};
pub use auth::Auth;
pub use error::{AgentError, AuthError, HashError, PolicyError, SandboxRunError};
pub use grants::Grants;
pub use hash::Hash;
pub use sandbox::SandboxRun;
pub use session::SessionChoice;

#[derive(Debug, clap::Parser)]
#[command(
    name = "sandbx",
    version,
    about = "A security-first AI coding agent harness",
    // Or clap derives the long help from the doc comment below and prints its note
    // about test visibility; `None` falls back to `about` for both forms.
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
    /// With no path flag, the working directory is readable and writable, so
    /// working on the project you are standing in needs no flags. A `--allow-…`
    /// path flag replaces that default rather than adding to it. Standing at the
    /// filesystem root, in your home directory, or in a directory holding it is
    /// refused rather than granted — pass the flags for the tree you mean.
    ///
    /// Everything else is denied unless a flag grants it, except what a command
    /// needs in order to start: read access to the system binaries and
    /// libraries, and a handful of environment variables. The rest of the
    /// environment is cleared, so a secret in the shell that launched `sandbx`
    /// does not reach the command. The command runs under Landlock, a seccomp
    /// filter, and — unless a flag grants network — an empty network namespace;
    /// where a port is allowlisted the filter bounds the port instead, and the
    /// host is not bounded at all. On a kernel that cannot enforce those, it is
    /// refused rather than run unrestricted.
    ///
    /// Put the command after `--`:
    ///
    /// ```text
    /// sandbx sandbox-run -- grep -rn TODO .
    /// sandbx sandbox-run --allow-read /srv -- cat /srv/notes.txt
    /// ```
    SandboxRun(SandboxRun),

    /// Ask an agent one question, and let it use tools to answer.
    ///
    /// The prompt goes out, the answer streams back on stdout, and every tool
    /// the model calls is bounded by the same flags: denied unless a flag grants
    /// it, refused rather than run unrestricted on a kernel that cannot enforce
    /// it. Only `bash` reaches the kernel boundary `sandbox-run` uses; the other
    /// six are confined in-process against the same policy, so a bug there is
    /// not caught by Landlock. Needs a key, from `ANTHROPIC_API_KEY` or from
    /// `sandbx auth login`. The key is sandbx's own: `--allow-env
    /// ANTHROPIC_API_KEY` is refused here, since sandbx makes the provider call
    /// itself and no tool call needs that value. A stored key is not in the
    /// environment, and a path flag reaching it is refused — what remains is
    /// anything reading the file as you, outside sandbx.
    ///
    /// That includes the working-directory default, which here is what a prompt
    /// injection reaches: with no path flag the model may rewrite anything under
    /// the directory you ran this from. Pass the flags for a narrower tree when
    /// that is more than the question needs.
    ///
    /// Single-shot: one question, one answer, then the process ends. Nothing
    /// asks you before a tool call runs, so which tools may run is settled
    /// before the question goes out — see `--allow-tool`, which denies a
    /// `write`, an `edit` and a `bash` until you name one.
    ///
    /// Put the prompt after `--`:
    ///
    /// ```text
    /// sandbx agent-run --allow-read /srv -- "what is in /srv?"
    /// ```
    AgentRun(AgentRun),

    /// Ask the same question on a screen you can watch, and stop.
    ///
    /// Takes every flag `agent-run` takes and bounds a tool call the same way.
    /// What differs is the reporting: the answer, the model's reasoning and the
    /// verdict on each tool call are drawn in one pane as they arrive, and
    /// ctrl-c or escape ends the turn where it stands.
    ///
    /// Interrupting costs two things, which the screen says again at the time:
    /// nothing of that turn is stored, even under `--session`, and a tool
    /// already running finishes — sandbx cannot cancel one mid-call, and the
    /// process waits for it before it exits.
    ///
    /// Two flags read differently here. `--show-thinking` draws the reasoning in
    /// the pane rather than on stderr, and `--no-wrap-up` changes nothing: no
    /// wrap-up round is sent under `tui` at all, so a turn out of rounds ends on
    /// tool work either way.
    ///
    /// Needs a terminal on stdout, and refuses `--approve call`: that prompt
    /// wants the terminal this screen has taken. Use `agent-run` for either.
    ///
    /// Put the prompt after `--`:
    ///
    /// ```text
    /// sandbx tui --allow-tool bash -- "what is in this directory?"
    /// ```
    Tui(Tui),

    /// Print a file's SHA-256, in the form `--pin-sha256` takes.
    ///
    /// The only subcommand that runs nothing and confines nothing: it reads the
    /// file in the harness, the way `sha256sum` does, because the digest has to
    /// exist before there is a policy to pin anything under. The hex and a
    /// newline, and nothing else, so it composes:
    ///
    /// ```text
    /// sandbx sandbox-run --allow-exec "$PWD/target/debug/mytool" \
    ///   --pin-sha256 "$(sandbx hash target/debug/mytool)" \
    ///   -- "$PWD/target/debug/mytool"
    /// ```
    Hash(Hash),

    /// Store, remove or check the API key `agent-run` authenticates with.
    ///
    /// Two sources, in this order: `ANTHROPIC_API_KEY` from the environment, then a
    /// credential file at `$XDG_CONFIG_HOME/sandbx/credentials.toml` — or
    /// `~/.config/sandbx/credentials.toml` — which `auth login` writes with mode 0600 in a
    /// directory at 0700, and which sandbx refuses to read if anyone but you can reach
    /// either. So exporting the variable needs no `auth login`, and `auth login` means you
    /// do not have to export anything.
    ///
    /// `auth login` takes the key on stdin and will not prompt for it, so it is never
    /// echoed to your terminal and never lands in your shell's history:
    ///
    /// ```text
    /// read -rs KEY && printf %s "$KEY" | sandbx auth login
    /// sandbx auth status
    /// ```
    ///
    /// The stored key is in cleartext. The file's mode keeps it from other users on the
    /// host; it does not keep it from anything running as you, and the sandbox does not
    /// confine sandbx itself — see SECURITY.md.
    #[command(subcommand_required = true, arg_required_else_help = true)]
    Auth(Auth),
}
