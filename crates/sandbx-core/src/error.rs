use std::path::PathBuf;

/// Why a sandbox operation was refused.
///
/// Every variant is a refusal. There is deliberately no "allowed with warning"
/// case: a caller that believes it is sandboxed and is not is worse off than
/// one that gets an error.
#[derive(Debug)]
pub enum SandboxError {
    /// The path is not inside any root the policy allows.
    PathNotAllowed {
        /// The path as the caller supplied it.
        requested: PathBuf,
    },

    /// The path could not be resolved to a real location, so it cannot be
    /// proven to be inside an allowed root.
    ///
    /// Treated as a refusal rather than a pass: an unresolvable path is exactly
    /// what a traversal attempt looks like.
    Unresolvable {
        /// The path as the caller supplied it.
        requested: PathBuf,
        /// The underlying resolution failure.
        source: std::io::Error,
    },

    /// The helper process was given argv it could not parse.
    ///
    /// A refusal rather than a best-effort parse: running with a policy that
    /// differs from the one sandbx intended is the exact failure the sandbox
    /// exists to prevent.
    BadHelperArgs {
        /// What was wrong, for the operator to act on.
        detail: &'static str,
    },

    /// The kernel refused to apply the Landlock ruleset.
    Landlock {
        /// The failing step and the kernel's reason.
        detail: String,
    },

    /// The syscall filter could not be installed.
    ///
    /// A refusal: without it, a sandboxed tool could reach syscalls Landlock
    /// cannot express.
    Seccomp {
        /// What failed, for the operator to act on.
        detail: String,
    },

    /// The network could not be taken away from the sandboxed process.
    ///
    /// A refusal: running with network access the policy denied is worse than
    /// not running at all.
    NetworkDenialFailed {
        /// What failed, for the operator to act on.
        detail: &'static str,
    },

    /// A sandboxed process could not be started.
    SpawnFailed {
        /// What failed, for the operator to act on.
        detail: &'static str,
        /// The underlying OS failure.
        source: std::io::Error,
    },

    /// This kernel or platform cannot enforce a sandbox.
    ///
    /// Returned instead of running unsandboxed, so an unsupported environment
    /// stops sandbx rather than silently removing every restriction.
    Unsupported {
        /// What is missing, for the operator to act on.
        detail: &'static str,
    },
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathNotAllowed { requested } => {
                write!(
                    f,
                    "path is outside every allowed root: {}",
                    requested.display()
                )
            }
            Self::Unresolvable { requested, source } => {
                write!(
                    f,
                    "could not resolve path {}: {source}",
                    requested.display()
                )
            }
            Self::Unsupported { detail } => {
                write!(f, "sandboxing is not available here: {detail}")
            }
            Self::BadHelperArgs { detail } => {
                write!(f, "malformed sandbox helper arguments: {detail}")
            }
            Self::SpawnFailed { detail, source } => {
                write!(f, "{detail}: {source}")
            }
            Self::Landlock { detail } => {
                write!(f, "kernel refused the Landlock ruleset: {detail}")
            }
            Self::NetworkDenialFailed { detail } => {
                write!(f, "could not deny network access: {detail}")
            }
            Self::Seccomp { detail } => {
                write!(f, "could not install the syscall filter: {detail}")
            }
        }
    }
}

impl std::error::Error for SandboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PathNotAllowed { .. }
            | Self::Unsupported { .. }
            | Self::BadHelperArgs { .. }
            | Self::Landlock { .. }
            | Self::NetworkDenialFailed { .. }
            | Self::Seccomp { .. } => None,
            Self::Unresolvable { source, .. } | Self::SpawnFailed { source, .. } => Some(source),
        }
    }
}
