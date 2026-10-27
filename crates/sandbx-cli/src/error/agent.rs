//! What stops a turn, under `agent-run` or `tui`.

use sandbx_auth::AuthError;
use sandbx_providers::ProviderError;
use sandbx_session_error::SessionError;
use sandbx_turn::TurnError;

use sandbx_grants::PolicyError;

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

    /// The session could not be opened, or the finished turn could not be saved.
    ///
    /// A failed save is an error, not a warning: exiting 0 would leave the next
    /// `--session` resuming a conversation missing its last turn.
    Session(SessionError),

    /// `tui` was asked for where stdout is not a terminal.
    NotATerminal,

    /// `--approve call` was asked for under `tui`, which has no prompt to ask with.
    ApproveUnderTui,

    /// The screen could not be taken, or stopped accepting what was drawn on it.
    Screen(std::io::Error),

    /// `--approve call` was asked for and there is no terminal to ask on.
    NoTerminal {
        /// Opening `/dev/tty`, which is `ENXIO` with no controlling terminal.
        source: std::io::Error,
    },

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

impl From<SessionError> for AgentError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
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
            // Forwarded rather than prefixed: the session's own prose already names the
            // path and carries the advice.
            Self::Session(error) => write!(f, "{error}"),
            // The flag is named because dropping it is the whole remedy, and the run
            // refuses rather than serving the weaker regime it asks to replace.
            Self::NotATerminal => write!(
                f,
                "`tui` draws a full screen and stdout is not a terminal; \
                 use `agent-run` for a run whose output is read by something else"
            ),
            // The follow-up is named: a flag refused with no issue beside it reads as unconsidered.
            Self::ApproveUnderTui => write!(
                f,
                "`{}` is not available under `tui`: its question wants the terminal the \
                 screen has taken, and a modal to ask it with is #225. Use `agent-run` to \
                 be asked per call",
                crate::agent::APPROVE_CALL
            ),
            Self::Screen(error) => write!(f, "drawing the screen: {error}"),
            Self::NoTerminal { source } => write!(
                f,
                "`{}` needs a terminal to ask on and there is none: {source}. \
                 Drop the flag to take the answer from `--allow-tool` instead",
                crate::agent::APPROVE_CALL
            ),
            Self::Turn(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::EmptyPrompt | Self::NotATerminal | Self::ApproveUnderTui => None,
            Self::Policy(error) => Some(error),
            Self::Runtime(error) | Self::Output(error) | Self::Screen(error) => Some(error),
            Self::Credential(error) => Some(error),
            Self::Provider(error) => Some(error),
            Self::Session(error) => Some(error),
            Self::NoTerminal { source } => Some(source),
            Self::Turn(error) => Some(error),
        }
    }
}
