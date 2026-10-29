//! What stops `sandbox-run`.

use sandbx_core::SandboxError;

use sandbx_grants::PolicyError;

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
