//! What can stop `agent-run` before it has an answer.

use sandbx_agent::TurnError;
use sandbx_providers::ProviderError;

/// Why a turn did not finish.
///
/// A failing *tool* is not in here: it comes back to the model as an error result for it
/// to try something else, which is the loop's own contract.
#[derive(Debug)]
pub enum AgentError {
    /// The prompt was blank, which the API rejects as an empty text block.
    EmptyPrompt,

    /// The runtime the turn needs could not be built.
    Runtime(std::io::Error),

    /// The answer could not be written out — a closed pipe, most often.
    Output(std::io::Error),

    /// The provider client could not be constructed — no API key, most often.
    Provider(ProviderError),

    /// The turn itself ended without an answer.
    Turn(TurnError),
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
            Self::Runtime(error) | Self::Output(error) => Some(error),
            Self::Provider(error) => Some(error),
            Self::Turn(error) => Some(error),
        }
    }
}
