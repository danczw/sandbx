use crate::{Axis, SandboxPolicy};

/// `tracing` target carrying the audit trail.
///
/// A dedicated target lets one subscriber route these to durable storage while
/// ordinary diagnostics go elsewhere, without either emitter knowing about
/// files. Filter on this to separate the two streams.
pub const AUDIT_TARGET: &str = "sandbx::audit";

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
        /// Who asked: a tool's registry name, or a guard operation such as
        /// `open_read`. A label to group records by, not a key to look up.
        tool: &'a str,
        /// What it acted on — a path, or the program being run.
        subject: &'a str,
    },

    /// An operation the policy refused.
    Denied {
        /// Who asked, in the same form as in [`Allowed`](Self::Allowed).
        tool: &'a str,
        /// What it would have acted on, had the policy allowed it.
        subject: &'a str,
        /// Why it was refused. "Denied" alone is not actionable.
        reason: &'a str,
    },

    /// A sandboxed process was started, and under what shape of policy.
    Spawned {
        /// The program the sandbox is about to become.
        program: &'a str,
        /// How many paths were readable, not which ones: the record summarises
        /// the policy's shape, and inlining a long path list would bury the
        /// spawn it accompanies.
        readable: usize,
        /// How many paths were writable, on the same basis as `readable`.
        writable: usize,
        /// Counted separately from `readable`: execute is a distinct capability,
        /// and folding it in would understate what the spawn was granted.
        executable: usize,
        /// Whether IP egress was granted. Says nothing about unix sockets, which
        /// `unix_sockets` records on its own.
        network: bool,
        /// Recorded separately from `network`: it is a distinct capability, and
        /// folding it in would understate the reach of the spawn.
        unix_sockets: bool,
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
    ///
    /// The counts are destructured out of one pass over [`Axis::ALL`] rather than
    /// read axis by axis, which is this site's compile-time backstop: a fourth
    /// axis makes the array lengths disagree and the build fails here. It cannot
    /// derive its *fields* the way the enforcement layers derive their rules —
    /// `tracing` needs static field names — so being forced to notice is the most
    /// this site can offer, and it is what the other four axes' worth of silent
    /// drift (#51) cost.
    pub fn spawned(program: &'a str, policy: &SandboxPolicy) -> Self {
        // Positional destructuring depends on `Axis::ALL`'s *order* as well as
        // its length, and only the length is checked by the pattern. Reordering
        // the table would otherwise keep compiling and keep passing, while every
        // record from then on filed the write count under `readable` — an audit
        // trail that misstates the policy, which is worse than one that fails.
        const _: () = assert!(matches!(
            Axis::ALL,
            [Axis::Read, Axis::Write, Axis::ReadExecute]
        ));

        let [readable, writable, executable] = Axis::ALL.map(|axis| policy.paths(axis).len());

        Self::Spawned {
            program,
            readable,
            writable,
            executable,
            network: policy.allows_network(),
            unix_sockets: policy.allows_unix_sockets(),
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
                executable,
                network,
                unix_sockets,
            } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "spawned",
                program,
                readable,
                writable,
                executable,
                network,
                unix_sockets,
            ),
        }
    }
}
