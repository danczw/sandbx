//! What can stop a subcommand before it has an answer.

mod auth;

use std::path::PathBuf;

use sandbx_agent::TurnError;
use sandbx_core::SandboxError;
use sandbx_providers::ProviderError;

pub use auth::AuthError;

/// What to type instead, appended to every [`PolicyError`] about the working directory so
/// two refusals cannot advise differently.
const ADVICE: &str = "pass --allow-read PATH and --allow-write PATH \
                      for the tree the command needs";

/// Why `sandbx hash` printed no digest.
///
/// One field and no variants: a path that cannot be opened and one that cannot be read
/// through are the same answer to the operator, and the errno distinguishes them.
#[derive(Debug)]
pub struct HashError {
    /// The file as it was named.
    pub(crate) path: PathBuf,
    /// The underlying OS failure.
    pub(crate) source: std::io::Error,
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "could not hash {}: {}", self.path.display(), self.source)
    }
}

impl std::error::Error for HashError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Why the flags described no policy.
///
/// Every variant refuses rather than falling back to a narrower policy, which would make
/// an ordinary command fail for a reason the message could not explain; see
/// `context/decision-default-policy.md`.
#[derive(Debug)]
pub enum PolicyError {
    /// The process state the default is derived from could not be read.
    Unavailable {
        /// What could not be read, for the operator to act on.
        detail: &'static str,
        /// The underlying OS failure.
        source: std::io::Error,
    },

    /// The working directory is the home directory, or holds it.
    HomeDirectory {
        /// The directory a default would have been rooted at.
        cwd: PathBuf,
        /// The home directory that is it, or is inside it.
        home: PathBuf,
    },

    /// The working directory is where home directories live, or holds it.
    HomeParent {
        /// The directory a default would have been rooted at.
        cwd: PathBuf,
    },

    /// With no `HOME` naming a home directory, the cwd could not be ruled out as one.
    UnnamedHome {
        /// The directory a default would have been rooted at.
        cwd: PathBuf,
        /// The absolute `$HOME` rejected as no home, or `None` when there was none to name.
        home: Option<PathBuf>,
    },

    /// The working directory holds a path every command is already granted execute on.
    SystemExecutables {
        /// The directory a default would have been rooted at.
        cwd: PathBuf,
        /// The granted path found inside it.
        path: PathBuf,
    },

    /// The working directory is the filesystem root.
    FilesystemRoot,

    /// `--allow-env` named a variable the policy sets itself.
    ImposedVariable {
        /// The variable both flags claim.
        name: String,
    },

    /// `--pin-sha256` was given more than once.
    RepeatedPin,

    /// `--pin-sha256` was given for a program that is not an absolute path.
    PinNeedsAbsoluteProgram {
        /// The program as it was typed.
        program: String,
    },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable { detail, source } => write!(f, "{detail}: {source} — {ADVICE}"),
            Self::HomeParent { cwd } => write!(
                f,
                "refusing to derive a policy from {}, which is where home directories live \
                 — {ADVICE}",
                cwd.display()
            ),
            // Naming the value matters where it is set and still rejected — `HOME=/home` is
            // where homes live, not one of them, and "no usable HOME" reads as unset.
            Self::UnnamedHome {
                cwd,
                home: Some(home),
            } => write!(
                f,
                "refusing to derive a policy from {}: HOME={} names no home directory, \
                 so sandbx cannot tell it from one — {ADVICE}",
                cwd.display(),
                home.display()
            ),
            Self::UnnamedHome { cwd, home: None } => write!(
                f,
                "refusing to derive a policy from {}: with no HOME naming a home directory, \
                 sandbx cannot tell it from one — {ADVICE}",
                cwd.display()
            ),
            Self::SystemExecutables { cwd, path } => write!(
                f,
                "refusing to derive a policy from {}: it holds {}, which every command may \
                 already execute, so a write grant there rewrites what runs next — {ADVICE}",
                cwd.display(),
                path.display()
            ),
            Self::HomeDirectory { cwd, home } if cwd == home => write!(
                f,
                "refusing to derive a policy from your home directory {} — {ADVICE}",
                home.display()
            ),
            Self::HomeDirectory { cwd, home } => write!(
                f,
                "refusing to derive a policy from {}, which holds your home directory {} — {ADVICE}",
                cwd.display(),
                home.display()
            ),
            Self::FilesystemRoot => {
                write!(
                    f,
                    "refusing to derive a policy from the filesystem root — {ADVICE}"
                )
            }
            // No `ADVICE`: this refusal is about neither a path nor the working directory.
            Self::ImposedVariable { name } => write!(
                f,
                "--dns-over-tcp sets {name} itself, so --allow-env {name} would be dropped \
                 rather than honoured — pass one of the two, not both"
            ),
            // No `ADVICE` either, for the same reason, and both say what to write instead.
            Self::RepeatedPin => write!(
                f,
                "one run execs one program, so there is one digest to pin — \
                 pass --pin-sha256 once"
            ),
            Self::PinNeedsAbsoluteProgram { program } => write!(
                f,
                "--pin-sha256 needs an absolute program, and {program} is not one: sandbx \
                 opens the file to hash it, while a bare name is resolved against the PATH \
                 the policy gives the command — write `$PWD/{program}` or \
                 `$(command -v {program})`"
            ),
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HomeDirectory { .. }
            | Self::HomeParent { .. }
            | Self::UnnamedHome { .. }
            | Self::SystemExecutables { .. }
            | Self::FilesystemRoot
            | Self::ImposedVariable { .. }
            | Self::RepeatedPin
            | Self::PinNeedsAbsoluteProgram { .. } => None,
            Self::Unavailable { source, .. } => Some(source),
        }
    }
}

/// Why `sandbox-run` did not run the command.
///
/// Separate from [`SandboxError`], which `sandbx-core` owns: deriving a policy is the
/// CLI's own step, and core must not grow a variant it never produces.
#[derive(Debug)]
pub enum SandboxRunError {
    /// The flags described no policy.
    Policy(PolicyError),

    /// The sandbox itself refused, or the command could not be run under it.
    Sandbox(SandboxError),
}

impl From<PolicyError> for SandboxRunError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<SandboxError> for SandboxRunError {
    fn from(error: SandboxError) -> Self {
        Self::Sandbox(error)
    }
}

impl std::fmt::Display for SandboxRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(error) => write!(f, "{error}"),
            Self::Sandbox(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SandboxRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(error) => Some(error),
            Self::Sandbox(error) => Some(error),
        }
    }
}

/// Why a turn did not finish.
///
/// A failing *tool* is not in here: it comes back to the model as an error result for it
/// to try something else, which is the loop's own contract.
#[derive(Debug)]
pub enum AgentError {
    /// The prompt was blank, which the API rejects as an empty text block.
    EmptyPrompt,

    /// The flags described no policy, so no tool could be bounded.
    Policy(PolicyError),

    /// The runtime the turn needs could not be built.
    Runtime(std::io::Error),

    /// The answer could not be written out — a closed pipe, most often.
    Output(std::io::Error),

    /// No API key could be resolved from the environment or the credential file.
    Credential(AuthError),

    /// The provider client could not be constructed — a rejected base URL, most often.
    Provider(ProviderError),

    /// The turn itself ended without an answer.
    Turn(TurnError),
}

impl From<PolicyError> for AgentError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<AuthError> for AgentError {
    fn from(error: AuthError) -> Self {
        Self::Credential(error)
    }
}

impl From<ProviderError> for AgentError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

impl From<TurnError> for AgentError {
    fn from(error: TurnError) -> Self {
        Self::Turn(error)
    }
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPrompt => write!(f, "the prompt is empty"),
            Self::Policy(error) => write!(f, "{error}"),
            Self::Runtime(error) => write!(f, "building the async runtime: {error}"),
            Self::Output(error) => write!(f, "writing the answer: {error}"),
            Self::Credential(error) => write!(f, "{error}"),
            Self::Provider(error) => write!(f, "{error}"),
            Self::Turn(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::EmptyPrompt => None,
            Self::Policy(error) => Some(error),
            Self::Runtime(error) | Self::Output(error) => Some(error),
            Self::Credential(error) => Some(error),
            Self::Provider(error) => Some(error),
            Self::Turn(error) => Some(error),
        }
    }
}
