use crate::{Axis, NetworkPolicy, SandboxPolicy};

/// `tracing` target carrying the audit trail.
///
/// A dedicated target lets one subscriber route these to durable storage while ordinary
/// diagnostics go elsewhere; `sandbx-cli`'s `logging` module installs one that admits this
/// target at `INFO` and drops everything else.
pub const AUDIT_TARGET: &str = "sandbx::audit";

/// Something the sandbox did, recorded so it can be reviewed afterwards.
///
/// Emitted at `INFO`, so it survives the default filter. *Metadata only*, never a command's
/// output: that a tool read a file is a different proposition from what the file contained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent<'a> {
    /// An operation the policy permitted.
    Allowed {
        /// Who asked: a tool's registry name, or a guard operation such as `open_read`.
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
        /// Why it was refused; "denied" alone is not actionable.
        reason: &'a str,
    },

    /// A best-effort hardening step did not take effect, and the sandbox carried on.
    ///
    /// Not a [`Denied`](Self::Denied): nothing the agent asked for was refused. What the
    /// failure costs depends on the step, so `mechanism` carries that — a bounding set left
    /// as inherited is a weaker sandbox, an unmapped identity costs only uid fidelity. At
    /// `INFO` either way, these steps failing on whole classes of host (AppArmor's
    /// `restrict_unprivileged_userns`) rather than intermittently.
    Degraded {
        /// Which step did not take effect, as a stable label a trail can be filtered by.
        mechanism: &'a str,
        /// Why it did not, and what holds instead.
        detail: &'a str,
    },

    /// A sandboxed process was started, and under what shape of policy.
    Spawned {
        /// The program the sandbox is about to become.
        program: &'a str,
        /// How many paths were readable, not which ones.
        readable: usize,
        /// How many paths were writable.
        writable: usize,
        /// How many paths were read-executable, counted apart from `readable`.
        executable: usize,
        /// What shape of IP egress was granted — `denied`, `any` or `ports`; says nothing
        /// about unix sockets.
        ///
        /// A closed set of labels rather than a stringified [`NetworkPolicy`], so `emit` stays
        /// a field assignment with no allocation on the audit path.
        network: &'static str,
        /// How many ports the allowlist named, not which ones — matching `env`'s shape. Zero
        /// unless `network` is `ports`; the numbers are already in `/proc/self/cmdline`.
        network_ports: usize,
        /// Whether unix-domain sockets were granted.
        unix_sockets: bool,
        /// How long the environment allowlist is, never the names in it — a record listing
        /// names would invite the next change to list values beside them. Its length, not
        /// the number that cross: a name the harness does not hold is passed as nothing.
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
    /// `tracing` needs static field names, so these cannot be derived from [`Axis::ALL`] the
    /// way the enforcement layers derive their rules; the exhaustive match is what makes an
    /// added axis a compile error.
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

        let (network, network_ports) = match policy.network() {
            NetworkPolicy::Denied => ("denied", 0),
            NetworkPolicy::AnyPort => ("any", 0),
            NetworkPolicy::Ports(ports) => ("ports", ports.len()),
        };

        Self::Spawned {
            program,
            readable,
            writable,
            executable,
            network,
            network_ports,
            unix_sockets: policy.allows_unix_sockets(),
            env: policy.allowed_env().len(),
        }
    }

    /// Emit this event on the audit target.
    ///
    /// Records nothing unless a subscriber is listening on [`AUDIT_TARGET`]: `tracing` drops
    /// an event with no subscriber, silently and at every level, and a library cannot
    /// install one without deciding for whoever embeds it. Which is why the re-exec'd helper
    /// never calls this — its stderr is the sandboxed command's own — and names what
    /// degraded over the channel `degradation.rs` describes instead.
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
                network_ports,
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
                network_ports,
                unix_sockets,
                env,
            ),
        }
    }
}
