use std::path::PathBuf;

/// Why a sandbox operation was refused.
///
/// Every variant is a refusal; there is no "allowed with warning" case, because a caller
/// that believes it is sandboxed and is not is worse off than one that gets an error.
#[derive(Debug)]
pub enum SandboxError {
    /// The path is not inside any root the policy allows.
    PathNotAllowed {
        /// The path as the caller supplied it.
        requested: PathBuf,
    },

    /// The path could not be resolved, so it cannot be proven to be inside an allowed
    /// root. A refusal rather than a pass: this is what a traversal attempt looks like.
    Unresolvable {
        /// The path as the caller supplied it.
        requested: PathBuf,
        /// The underlying resolution failure.
        source: std::io::Error,
    },

    /// The helper process was given argv it could not parse. A refusal rather than a
    /// best-effort parse: running with a policy that differs from the one sandbx intended
    /// is the failure the sandbox exists to prevent.
    BadHelperArgs {
        /// What was wrong, for the operator to act on.
        detail: &'static str,
    },

    /// The kernel refused to apply the Landlock ruleset.
    Landlock {
        /// The failing step and the kernel's reason.
        detail: String,
    },

    /// The syscall filter could not be installed. A refusal: without it, a sandboxed tool
    /// could reach syscalls Landlock cannot express.
    Seccomp {
        /// What failed, for the operator to act on.
        detail: String,
    },

    /// The kernel namespaces the sandbox runs the command in could not be created.
    ///
    /// One variant for all of them — user, PID, and, when the policy denies network, the
    /// network namespace — because there is one `unshare` call and the kernel answers it
    /// with one errno; splitting it would mean reporting a guess as a fact. A refusal:
    /// running with network access the policy denied, or with descendants that outlive the
    /// call, is worse than not running at all.
    NamespaceSetupFailed {
        /// What failed, for the operator to act on.
        detail: &'static str,
    },

    /// This process is not in the state a sandboxed command may be born into:
    /// capabilities not dropped, core dumps not disabled, or an environment an earlier
    /// stage should have narrowed and did not.
    ///
    /// All three are inherited across `exec`, which is why they are one fact about this
    /// process rather than three failures, and a refusal: any of them still available
    /// would widen what a descendant could reach.
    ProcessHardening {
        /// What failed, for the operator to act on.
        detail: String,
    },

    /// A sandboxed process could not be started.
    SpawnFailed {
        /// What failed, for the operator to act on.
        detail: &'static str,
        /// The underlying OS failure.
        source: std::io::Error,
    },

    /// A sandboxed process outran its time limit and was killed.
    ///
    /// Distinct from [`SpawnFailed`](Self::SpawnFailed): collapsing "never finished" into
    /// "never started" would make a wedged command look like a broken helper.
    TimedOut {
        /// The limit it exceeded.
        after: std::time::Duration,
    },

    /// This kernel cannot enforce a sandbox.
    ///
    /// Returned instead of running unsandboxed. A kernel, not a platform: a non-Linux
    /// target never reaches this, the crate refusing to build for one. What it covers is a
    /// kernel too old for the Landlock baseline, one with Landlock disabled at boot, or one
    /// that accepted a ruleset and enforced none of it.
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
            Self::TimedOut { after } => {
                write!(f, "command exceeded its {after:?} limit and was killed")
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
            Self::NamespaceSetupFailed { detail } => {
                write!(f, "could not create the sandbox namespaces: {detail}")
            }
            Self::ProcessHardening { detail } => {
                write!(f, "could not harden process state: {detail}")
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
            | Self::NamespaceSetupFailed { .. }
            | Self::ProcessHardening { .. }
            | Self::TimedOut { .. }
            | Self::Seccomp { .. } => None,
            Self::Unresolvable { source, .. } | Self::SpawnFailed { source, .. } => Some(source),
        }
    }
}
