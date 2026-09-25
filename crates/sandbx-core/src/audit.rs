use crate::SandboxPolicy;

/// `tracing` target carrying the audit trail.
///
/// A dedicated target lets one subscriber route these to durable storage while
/// ordinary diagnostics go elsewhere, without either emitter knowing about
/// files. Filter on this to separate the two streams.
pub const AUDIT_TARGET: &str = "echo::audit";

/// Something the sandbox did, recorded so it can be reviewed afterwards.
///
/// This is a product feature rather than debug output: it answers "what did the
/// agent do to my machine". Emitted at `INFO` so it survives the default filter
/// — at `DEBUG` it would be absent for everyone who did not opt in, which is
/// exactly when a record matters.
///
/// Deliberately records *metadata only*, never a command's output. That a tool
/// read a file is a different proposition from storing what the file contained;
/// output is where secrets live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent<'a> {
    /// An operation the policy permitted.
    Allowed {
        /// Tool that asked.
        tool: &'a str,
        /// What it acted on — a path, or the program being run.
        subject: &'a str,
    },

    /// An operation the policy refused.
    Denied {
        /// Tool that asked.
        tool: &'a str,
        /// What it tried to act on.
        subject: &'a str,
        /// Why it was refused. "Denied" alone is not actionable.
        reason: &'a str,
    },

    /// A sandboxed process was started, and under what shape of policy.
    Spawned {
        /// Program being run.
        program: &'a str,
        /// How many paths were readable.
        readable: usize,
        /// How many paths were writable.
        writable: usize,
        /// Whether network access was granted.
        network: bool,
    },
}

impl<'a> AuditEvent<'a> {
    /// Record a permitted operation.
    pub fn allowed(tool: &'a str, subject: &'a str) -> Self {
        Self::Allowed { tool, subject }
    }

    /// Record a refusal and its reason.
    pub fn denied(tool: &'a str, subject: &'a str, reason: &'a str) -> Self {
        Self::Denied {
            tool,
            subject,
            reason,
        }
    }

    /// Record a spawn, summarising the policy rather than reproducing it.
    pub fn spawned(program: &'a str, policy: &SandboxPolicy) -> Self {
        Self::Spawned {
            program,
            readable: policy.readable_paths().len(),
            writable: policy.writable_paths().len(),
            network: policy.allows_network(),
        }
    }

    /// Emit this event on the audit target.
    pub fn emit(&self) {
        match self {
            Self::Allowed { tool, subject } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "allowed",
                tool,
                subject,
            ),
            Self::Denied {
                tool,
                subject,
                reason,
            } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "denied",
                tool,
                subject,
                reason,
            ),
            Self::Spawned {
                program,
                readable,
                writable,
                network,
            } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "spawned",
                program,
                readable,
                writable,
                network,
            ),
        }
    }
}
