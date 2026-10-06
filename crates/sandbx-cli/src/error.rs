//! What can stop a subcommand before it has an answer.

use std::path::PathBuf;

use sandbx_agent::TurnError;
use sandbx_core::SandboxError;
use sandbx_providers::ProviderError;

/// What to type instead, appended to every [`PolicyError`] about the working directory so
/// two refusals cannot advise differently.
const ADVICE: &str = "pass --allow-read PATH and --allow-write PATH \
                      for the tree the command needs";

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

    /// With no usable `HOME`, the working directory could not be ruled out as a home.
    UnnamedHome {
        /// The directory a default would have been rooted at.
        cwd: PathBuf,
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
            Self::UnnamedHome { cwd } => write!(
                f,
                "refusing to derive a policy from {}: with no usable HOME, \
                 sandbx cannot tell it from a home directory — {ADVICE}",
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
            | Self::ImposedVariable { .. } => None,
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

    /// The provider client could not be constructed — no API key, most often.
    Provider(ProviderError),

    /// The turn itself ended without an answer.
    Turn(TurnError),
}

impl From<PolicyError> for AgentError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
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
            Self::Provider(error) => Some(error),
            Self::Turn(error) => Some(error),
        }
    }
}
