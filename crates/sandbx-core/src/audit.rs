use crate::{Axis, NetworkPolicy, SandboxPolicy};

/// `tracing` target carrying the audit trail, kept apart from ordinary diagnostics so a
/// subscriber can route it on its own; see `context/guide-logging.md`.
pub const AUDIT_TARGET: &str = "sandbx::audit";

/// Something the sandbox did, recorded so it can be reviewed afterwards.
///
/// Emitted at `INFO`, so it survives the default filter. Metadata only, never a command's
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

    /// An operation the policy permitted, against a name that denotes nothing.
    ///
    /// No `reason`: nothing refused it. Emitted only inside a granted root — outside one, a
    /// path's absence is what the refusal conceals.
    Absent {
        /// Who asked, as in [`Allowed`](Self::Allowed).
        tool: &'a str,
        /// The name that denotes nothing.
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
    /// Not a [`Denied`](Self::Denied): nothing the agent asked for was refused. At `INFO`
    /// because these steps fail on whole classes of host (AppArmor's
    /// `restrict_unprivileged_userns`) rather than intermittently.
    Degraded {
        /// Which step did not take effect, as a stable label a trail can be filtered by.
        mechanism: &'a str,
        /// Why it did not, and what holds instead.
        detail: &'a str,
    },

    /// A sandboxed process was started, and under what shape of policy.
    ///
    /// Written before the exec, so [`Exited`](Self::Exited) or [`Failed`](Self::Failed) is
    /// what says it ran.
    Spawned {
        /// The program the sandbox is about to become.
        program: &'a str,
        /// How many paths were readable, not which ones.
        readable: usize,
        /// How many paths were writable.
        writable: usize,
        /// How many paths were read-executable, counted apart from `readable`.
        executable: usize,
        /// What shape of IP egress was granted: `denied`, `any` or `ports`, a closed set
        /// rather than a stringified [`NetworkPolicy`], so `emit` allocates nothing.
        network: &'static str,
        /// How many ports the allowlist named, never which. Zero unless `network` is `ports`.
        network_ports: usize,
        /// Whether unix-domain sockets were granted.
        unix_sockets: bool,
        /// How long the environment allowlist is, never the names in it. Its length, not the
        /// number that cross: a name the harness does not hold is passed as nothing.
        env: usize,
        /// Whether the resolver hint was set; the variable it imposes is not counted in `env`.
        dns_over_tcp: bool,
        /// Whether a digest had to match before the exec. Not the digest, already in
        /// `/proc/self/cmdline`; what an auditor cannot recover is that it was checked.
        pinned: bool,
    },

    /// A sandboxed process ended, and with what status.
    Exited {
        /// The program the spawn record named.
        program: &'a str,
        /// What it ended with, encoded the way a shell does — 128 + n for a signal.
        code: i32,
    },

    /// A sandboxed process ended without a status of its own.
    ///
    /// Separate from [`Exited`](Self::Exited) rather than an absent `code`: `tracing` omits
    /// a `None` field, so one event would vary its own field set.
    Failed {
        /// The program the spawn record named.
        program: &'a str,
        /// Why it has none, as a stable label a trail can be filtered by.
        reason: &'static str,
    },
}

impl<'a> AuditEvent<'a> {
    /// Record a permitted operation.
    pub fn allowed(tool: &'a str, subject: &'a str) -> Self {
        Self::Allowed { tool, subject }
    }

    /// Record an attempt on a name that denotes nothing.
    pub fn absent(tool: &'a str, subject: &'a str) -> Self {
        Self::Absent { tool, subject }
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
    /// way the enforcement layers are; the exhaustive match is what makes an added axis a
    /// compile error instead. `pinned` is a parameter because a digest is not policy.
    pub fn spawned(program: &'a str, policy: &SandboxPolicy, pinned: bool) -> Self {
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
            dns_over_tcp: policy.hints_dns_over_tcp(),
            pinned,
        }
    }

    /// Record how a spawned command ended.
    ///
    /// The code is derived from the status through [`exit_code`](crate::exit_code) rather
    /// than passed in, so the number on the trail is the one `sandbx` exits with.
    pub fn exited(program: &'a str, status: &std::process::ExitStatus) -> Self {
        Self::Exited {
            program,
            code: crate::exit_code(status),
        }
    }

    /// Record a run that ended without a status, naming what stopped it.
    ///
    /// Takes the label and not the error, so this module stays ignorant of `SandboxError`;
    /// the call site passes [`SandboxError::label`](crate::SandboxError::label).
    pub fn failed(program: &'a str, reason: &'static str) -> Self {
        Self::Failed { program, reason }
    }

    /// Emit this event on the audit target.
    ///
    /// Records nothing unless a subscriber is listening on [`AUDIT_TARGET`]: `tracing` drops
    /// an event with no subscriber, silently and at every level. Hence the re-exec'd helper,
    /// which installs none, reports over `degradation.rs`'s channel instead.
    pub fn emit(&self) {
        match self {
            Self::Allowed { tool, subject } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "allowed",
                tool,
                subject,
            ),
            Self::Absent { tool, subject } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "absent",
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
                dns_over_tcp,
                pinned,
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
                dns_over_tcp,
                pinned,
            ),
            Self::Exited { program, code } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "exited",
                program,
                code,
            ),
            Self::Failed { program, reason } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "failed",
                program,
                reason,
            ),
        }
    }
}
