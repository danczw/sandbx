use crate::{Axis, SandboxPolicy};

/// `tracing` target carrying the audit trail.
///
/// A dedicated target lets one subscriber route these to durable storage while
/// ordinary diagnostics go elsewhere, without either emitter knowing about
/// files. Filter on this to separate the two streams.
///
/// The `sandbx` binary installs one that admits this target at `INFO` and drops
/// everything else, writing to stderr; see the `logging` module in `sandbx-cli`.
/// Named in prose rather than linked because the dependency runs the other way.
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

    /// A best-effort hardening step did not take effect, and the sandbox
    /// carried on without it.
    ///
    /// Distinct from [`Denied`](Self::Denied): nothing the agent asked for was
    /// refused.
    ///
    /// What the failure costs depends on the step, so `mechanism` carries that
    /// rather than this variant implying one answer: a bounding set left as
    /// inherited is a weaker sandbox, while an unmapped identity costs only uid
    /// fidelity and is, if anything, more restrictive.
    ///
    /// Recorded at `INFO` either way. These steps fail on whole classes of host
    /// (AppArmor's `restrict_unprivileged_userns`) rather than intermittently,
    /// so the run where it matters is not the run where someone thought to raise
    /// the log level.
    Degraded {
        /// Which step did not take effect, as a stable label rather than prose,
        /// so a trail can be filtered by it.
        mechanism: &'a str,
        /// Why it did not, and what holds instead.
        detail: &'a str,
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
        /// How long the environment allowlist is, not what is in it: the same
        /// basis as the path counts. A name is not a secret, but a value
        /// routinely is, and a record that listed names would invite the next
        /// change to list values beside them.
        ///
        /// The allowlist's length, deliberately, and not the number of variables
        /// that end up crossing — a name the harness does not hold is passed as
        /// nothing at all, so the two differ (a default `sandbx sandbox-run`
        /// records `env=7` on a host where `TZ` and the `LC_*` pair are unset,
        /// and the command sees four). Like `readable`, this records what the
        /// policy granted rather than what the command went on to use: the record
        /// is written before the spawn, and what it is for is the decision.
        env: usize,
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

    /// Record a hardening step that did not take effect.
    pub fn degraded(mechanism: &'a str, detail: &'a str) -> Self {
        Self::Degraded { mechanism, detail }
    }

    /// Record a spawn, summarising the policy rather than reproducing it.
    ///
    /// This record cannot derive its *fields* the way the enforcement layers
    /// derive their rules — `tracing` needs static field names — so what it does
    /// instead is refuse to compile when an axis is added, which is the one thing
    /// it can offer and what its silent drift (#51) cost. The mechanism is the
    /// exhaustive match, the same one the other non-derivable site uses
    /// (`SandboxRun::paths`): each field names the axis it counts, so nothing here
    /// depends on the table's order.
    pub fn spawned(program: &'a str, policy: &SandboxPolicy) -> Self {
        let (mut readable, mut writable, mut executable) = (0, 0, 0);

        for axis in Axis::ALL {
            let count = policy.paths(axis).len();
            match axis {
                Axis::Read => readable = count,
                Axis::Write => writable = count,
                Axis::ReadExecute => executable = count,
            }
        }

        Self::Spawned {
            program,
            readable,
            writable,
            executable,
            network: policy.allows_network(),
            unix_sockets: policy.allows_unix_sockets(),
            env: policy.allowed_env().len(),
        }
    }

    /// Emit this event on the audit target.
    ///
    /// Records nothing unless a subscriber is listening on [`AUDIT_TARGET`]:
    /// `tracing` drops an event with no subscriber installed, silently and at
    /// every level. A library cannot install one without deciding for whoever
    /// embeds it, so the binary does — and for a while nothing did, which is what
    /// #89 cost. Anything embedding this crate owes itself the same subscriber.
    ///
    /// Which is why the re-exec'd helper does not call this at all. That process
    /// installs no subscriber and must not — its stderr is the sandboxed command's
    /// own — so the hardening steps that run there name what degraded and let the
    /// parent emit it, over the channel `degradation.rs` describes (#95). A call
    /// to this from inside helper mode records nothing.
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
            Self::Degraded { mechanism, detail } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "degraded",
                mechanism,
                detail,
            ),
            Self::Spawned {
                program,
                readable,
                writable,
                executable,
                network,
                unix_sockets,
                env,
            } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "spawned",
                program,
                readable,
                writable,
                executable,
                network,
                unix_sockets,
                env,
            ),
        }
    }
}
