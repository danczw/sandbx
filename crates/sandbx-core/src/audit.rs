//! The audit trail: what the sandbox did, as `tracing` events on [`AUDIT_TARGET`].
//!
//! All seven variants emit at `INFO`, the one property to defend: at `DEBUG` a trail would
//! reach only those who opted in, and a record matters most where nobody did. Field table,
//! and why a record names the access and not the verdict: `context/guide-logging.md`.

use crate::{Axis, NetworkPolicy, SandboxPolicy, SpawnId};
use std::process::ExitStatus;

/// `tracing` target carrying the audit trail, kept apart from ordinary diagnostics so a
/// subscriber can route it on its own; see `context/guide-logging.md`.
pub const AUDIT_TARGET: &str = "sandbx::audit";

/// How much of a command's argument list a record carries, in characters of the **rendered**
/// list — after the escaping, not before.
///
/// The number is `gate::printable`'s and the reason is the same, but the measurement is not:
/// that one caps the raw text and strips afterwards, so 512 there is 512 characters the
/// model wrote. Here an escape costs what it renders as — six for an ESC, two for a
/// newline or a quote — so an escape-heavy command is cut well short of 512 of its own
/// characters. Capping the raw text instead would mean rendering after cutting, and a cut
/// that landed inside a multi-byte character would then be escaped into visible garbage.
///
/// Not `gate::printable` itself: it reaches `sandbx_text::invisible`, an edge
/// `crates/sandbx-text/src/lib.rs` refuses this crate. Nor is the coverage identical, and
/// the gap is four codepoints: `escape_debug` escapes everything `is_control` plus the
/// `Cf` and `Mn` classes — so every bidi override, every zero-width character and the C1
/// range — but leaves the Hangul fillers U+115F, U+1160, U+3164 and U+FFA0, which are `Lo`
/// letters. They render as blank width and cannot end the field or start a line, which is
/// why that is a difference and not a hole.
const ARGS_CAP: usize = 512;

/// What a record carries where there is no session. Outside a `SessionId`'s `0-9a-z`, so a
/// reader cannot mistake it for one.
const SESSION_ABSENT: &str = "-";

/// What a record carries where there is no run — only [`AuditEvent::Degraded`] has one,
/// `rooted_access` being emitted before anything is spawned. Outside a
/// [`SpawnId`]'s hex-and-dot spelling for the same reason as [`SESSION_ABSENT`].
const SPAWN_ABSENT: &str = "-";

/// A command's arguments as one field value, cut to [`ARGS_CAP`] with the cut marked.
///
/// The list's own `Debug`, so each argument is quoted and `escape_debug`'d — an argument
/// holding a space stays one argument, and nothing a model wrote can carry a raw newline or
/// escape sequence onto the trail. Rendered before it is cut, so a cut can only bisect an
/// escape sequence and never expose the byte it was hiding. Emitted with `%` in
/// [`AuditEvent::emit`], which is what keeps the layer from escaping it a second time.
pub(crate) fn args_field(args: &[String]) -> String {
    let rendered = format!("{args:?}");
    let mut out: String = rendered.chars().take(ARGS_CAP).collect();

    // Marked, not silent: a reader who cannot see the whole command still knows so.
    if rendered.chars().nth(ARGS_CAP).is_some() {
        out.push('…');
    }

    out
}

/// Something the sandbox did, recorded so it can be reviewed afterwards. Emitted at
/// `INFO`, so it survives the default filter. Metadata only, never a command's output:
/// that a tool read a file is a different proposition from what the file contained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent<'a> {
    /// An operation the policy permitted.
    Allowed {
        /// Who asked: a tool's registry name, or a guard's access — `read` or `write`.
        tool: &'a str,
        /// What it acted on — a path, or the program being run.
        subject: &'a str,
    },

    /// An operation the policy permitted, against a name that denotes nothing. No `reason`:
    /// nothing refused it. Emitted only inside a granted root — outside one, a path's
    /// absence is what the refusal conceals.
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

    /// A best-effort hardening step did not take effect, and the sandbox carried on. Not a
    /// [`Denied`](Self::Denied): nothing the agent asked for was refused. At `INFO` because
    /// these steps fail on whole classes of host (AppArmor's `restrict_unprivileged_userns`)
    /// rather than intermittently.
    Degraded {
        /// Which step did not take effect, as a stable label a trail can be filtered by.
        mechanism: &'a str,
        /// The run this weakened, or `SPAWN_ABSENT` for a step that belongs to no run —
        /// `rooted_access` is emitted while the in-process gate is built, before any spawn.
        /// A degradation falls *between* a spawn and its outcome, so without this the
        /// middle of a run would still be attributed by position (#249).
        spawn: &'a str,
        /// The session this ran under, as in [`Spawned`](Self::Spawned). `rooted_access`
        /// does carry one despite having no run: what it weakens is every access for the
        /// session, so this is the field that record is about — which is why
        /// [`FsGuard::for_session`](crate::FsGuard::for_session) exists, the record being
        /// written while the guard is built and so unreachable by a setter.
        session: &'a str,
        /// Why it did not, and what holds instead.
        detail: &'a str,
    },

    /// A sandboxed process was started, and under what shape of policy. Written before the
    /// exec, so [`Exited`](Self::Exited) or [`Failed`](Self::Failed) is what says it ran.
    Spawned {
        /// The run this record opens, and that exactly one outcome closes. Unique across
        /// processes, so two sandbx runs sharing a sink stay separable (#249).
        spawn: &'a str,
        /// The session this ran under, or `SESSION_ABSENT` where there is none —
        /// `sandbox-run` has no session. A sentinel and not an `Option` for the reason
        /// [`Failed`](Self::Failed) is a variant of its own.
        session: &'a str,
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
        /// How long the name allowlist is, never the names in it, and not how many resolved:
        /// a name that resolves to nothing is still one the policy permitted.
        dns_names: usize,
        /// Whether a digest had to match before the exec. Not the digest, already in
        /// `/proc/self/cmdline`; what an auditor cannot recover is that it was checked.
        pinned: bool,
        /// What the program was asked to do, cut to `ARGS_CAP`. Here because `program` is
        /// `/bin/sh` for every `bash` call, so the `-c` string — the command itself — was
        /// on no record at all (#249).
        ///
        /// **Last on the record, and that placement is load-bearing.** It is the one field
        /// a model writes and the one `emit` renders unquoted, so a command spelling
        /// `readable=99 pinned=true` would shadow the real field of that name for anything
        /// parsing first-match, and an odd number of quotes in it would desync a
        /// quote-pairing reader for the rest of the line. Every field it could shadow now
        /// precedes it.
        args: &'a str,
    },

    /// A sandboxed process ended, and with what status.
    Exited {
        /// The run this closes, as its [`Spawned`](Self::Spawned) named it.
        spawn: &'a str,
        /// The session this ran under, as in [`Spawned`](Self::Spawned).
        session: &'a str,
        /// The program the spawn record named.
        program: &'a str,
        /// What it ended with, encoded the way a shell does — 128 + n for a signal.
        code: i32,
    },

    /// A sandboxed process ended without a status of its own. Separate from
    /// [`Exited`](Self::Exited) rather than an absent `code`: `tracing` omits a `None`
    /// field, so one event would vary its own field set.
    Failed {
        /// The run this closes, as its [`Spawned`](Self::Spawned) named it.
        spawn: &'a str,
        /// The session this ran under, as in [`Spawned`](Self::Spawned).
        session: &'a str,
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
    ///
    /// `spawn` is an `Option` because one mechanism has no run to name: building an
    /// [`FsGuard`](crate::FsGuard) reports a granted root that lost the directory it was
    /// vetted on, which weakens every access for the session rather than one spawn.
    pub fn degraded(
        mechanism: &'a str,
        spawn: Option<&'a SpawnId>,
        session: Option<&'a str>,
        detail: &'a str,
    ) -> Self {
        Self::Degraded {
            mechanism,
            spawn: spawn.map_or(SPAWN_ABSENT, SpawnId::as_str),
            session: session.unwrap_or(SESSION_ABSENT),
            detail,
        }
    }

    /// Record a spawn, summarising the policy rather than reproducing it. `tracing` needs
    /// static field names, so these cannot be derived from [`Axis::ALL`] the way the
    /// enforcement layers are; the exhaustive match is what makes an added axis a compile
    /// error instead. `pinned` is a parameter because a digest is not policy.
    ///
    /// `session` is an `Option` here and a sentinel on the record: the rule a `None` field
    /// breaks is about the field set `tracing` emits, not about this signature pretending
    /// every run has a session. `args` comes pre-rendered from `args_field`, the cap
    /// belonging to the trail rather than to each caller.
    pub fn spawned(
        program: &'a str,
        args: &'a str,
        spawn: &'a SpawnId,
        session: Option<&'a str>,
        policy: &SandboxPolicy,
        pinned: bool,
    ) -> Self {
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
            spawn: spawn.as_str(),
            session: session.unwrap_or(SESSION_ABSENT),
            program,
            readable,
            writable,
            executable,
            network,
            network_ports,
            unix_sockets: policy.allows_unix_sockets(),
            env: policy.allowed_env().len(),
            dns_over_tcp: policy.hints_dns_over_tcp(),
            dns_names: policy.allowed_dns_names().len(),
            pinned,
            args,
        }
    }

    /// Record how a spawned command ended. The code is derived from the status through
    /// [`exit_code`](crate::exit_code) rather than passed in, so the number on the trail is
    /// the one `sandbx` exits with.
    pub fn exited(
        program: &'a str,
        spawn: &'a SpawnId,
        session: Option<&'a str>,
        status: &ExitStatus,
    ) -> Self {
        Self::Exited {
            spawn: spawn.as_str(),
            session: session.unwrap_or(SESSION_ABSENT),
            program,
            code: crate::exit_code(status),
        }
    }

    /// Record a run that ended without a status, naming what stopped it. Takes the label
    /// and not the error, so this module stays ignorant of `SandboxError`; the call site
    /// passes [`SandboxError::label`](crate::SandboxError::label).
    pub fn failed(
        program: &'a str,
        spawn: &'a SpawnId,
        session: Option<&'a str>,
        reason: &'static str,
    ) -> Self {
        Self::Failed {
            spawn: spawn.as_str(),
            session: session.unwrap_or(SESSION_ABSENT),
            program,
            reason,
        }
    }

    /// Emit this event on the audit target. Records nothing unless a subscriber is
    /// listening on [`AUDIT_TARGET`]: `tracing` drops an event with no subscriber, silently
    /// and at every level. Hence the re-exec'd helper, which installs none, reports over
    /// `degradation.rs`'s channel instead.
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
            Self::Degraded {
                mechanism,
                spawn,
                session,
                detail,
            } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "degraded",
                spawn,
                session,
                mechanism,
                detail,
            ),
            Self::Spawned {
                spawn,
                session,
                program,
                readable,
                writable,
                executable,
                network,
                network_ports,
                unix_sockets,
                env,
                dns_over_tcp,
                dns_names,
                pinned,
                args,
            } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "spawned",
                spawn,
                session,
                program,
                readable,
                writable,
                executable,
                network,
                network_ports,
                unix_sockets,
                env,
                dns_over_tcp,
                dns_names,
                pinned,
                // Last, and `%` rather than quoted: the variant's own doc has both whys.
                args = %args,
            ),
            Self::Exited {
                spawn,
                session,
                program,
                code,
            } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "exited",
                spawn,
                session,
                program,
                code,
            ),
            Self::Failed {
                spawn,
                session,
                program,
                reason,
            } => tracing::info!(
                target: AUDIT_TARGET,
                decision = "failed",
                spawn,
                session,
                program,
                reason,
            ),
        }
    }
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
