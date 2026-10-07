//! The closed set of refusals a helper stage reports on the audit channel.
//!
//! A subset of what [`SandboxError::label`](crate::SandboxError::label) can return, and the
//! five it leaves out are the point: a channel record outranks the exit status, so a label
//! naming a decision the parent or [`FsGuard`](crate::FsGuard) makes for itself would let a
//! forged line claim an outcome that never happened. The criterion is whether the label names
//! one decider, not what failed. `context/decision-helper-audit-channel.md`.

use crate::SandboxError;

/// How much of the helper's stderr a relayed refusal carries.
///
/// It reaches an operator on one line and a model inside a `tool_result`, and nothing
/// downstream bounds it — `ToolLimits::max_bytes` caps a command's output, not an error's
/// detail. Four `Display` lines' worth, which is more than any refusal the helper writes.
const STDERR_LIMIT: usize = 4096;

/// A refusal a helper stage reported for itself, rather than running the command.
///
/// A type and not a string: the parent turns one of these back into an audit record and an
/// error for its caller, so a label it accepted on trust would let whatever wrote the channel
/// name the reason a run did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperRefusal {
    /// The stage could not parse its argv — [`SandboxError::BadHelperArgs`].
    BadHelperArgs,

    /// The kernel refused the ruleset — [`SandboxError::Landlock`].
    Landlock,

    /// The syscall filter would not install — [`SandboxError::Seccomp`].
    Seccomp,

    /// The namespaces could not be created — [`SandboxError::NamespaceSetupFailed`].
    NamespaceSetupFailed,

    /// This process is not a state a command may be born into —
    /// [`SandboxError::ProcessHardening`].
    ProcessHardening,

    /// The supervisor could not start the stage below it —
    /// [`SandboxError::InnerStageFailed`].
    InnerStageFailed,

    /// The innermost stage could not become the command — [`SandboxError::ExecFailed`].
    ExecFailed,

    /// The program is not the bytes it was pinned to — [`SandboxError::PinMismatch`].
    PinMismatch,

    /// A pinned program could not be read — [`SandboxError::PinUnreadable`].
    PinUnreadable,

    /// A pinned program is a `#!` script — [`SandboxError::PinnedScript`].
    PinnedScript,

    /// This kernel cannot enforce a sandbox — [`SandboxError::Unsupported`].
    Unsupported,
}

impl HelperRefusal {
    /// Every refusal that can cross the channel; drives `from_label`.
    pub const ALL: [Self; 11] = [
        Self::BadHelperArgs,
        Self::Landlock,
        Self::Seccomp,
        Self::NamespaceSetupFailed,
        Self::ProcessHardening,
        Self::InnerStageFailed,
        Self::ExecFailed,
        Self::PinMismatch,
        Self::PinUnreadable,
        Self::PinnedScript,
        Self::Unsupported,
    ];

    /// The name this refusal carries on the wire and in the audit trail.
    ///
    /// The same word the variant it relays answers
    /// [`label`](crate::SandboxError::label) with, so a trail filtered by `reason=` cannot
    /// tell which side of the channel decided it — and a trail is filtered by these strings,
    /// so they are a compatibility surface.
    pub const fn label(self) -> &'static str {
        match self {
            Self::BadHelperArgs => "bad_helper_args",
            Self::Landlock => "landlock",
            Self::Seccomp => "seccomp",
            Self::NamespaceSetupFailed => "namespace_setup_failed",
            Self::ProcessHardening => "process_hardening",
            Self::InnerStageFailed => "inner_stage_failed",
            Self::ExecFailed => "exec_failed",
            Self::PinMismatch => "pin_mismatch",
            Self::PinUnreadable => "pin_unreadable",
            Self::PinnedScript => "pinned_script",
            Self::Unsupported => "unsupported",
        }
    }

    /// The refusal `label` names, if it names one at all.
    ///
    /// A lookup over [`ALL`](Self::ALL) rather than a second `match`, so a label
    /// [`label`](Self::label) can emit is one this accepts by construction.
    pub(crate) fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|known| known.label() == label)
    }

    /// This refusal as the error the caller gets, carrying what the helper said about it.
    ///
    /// From the stderr and not the channel: a refusal record carries no detail, so the
    /// helper's own `Display` — which the parent relays verbatim — is the only prose about it
    /// that exists. Truncated on a character boundary, and lossily decoded because these
    /// bytes are a pipe rather than a bounded record.
    pub(crate) fn relayed(self, stderr: &[u8]) -> SandboxError {
        SandboxError::HelperRefused {
            refusal: self,
            detail: String::from_utf8_lossy(stderr)
                .trim()
                .chars()
                .take(STDERR_LIMIT)
                .collect(),
        }
    }
}

impl SandboxError {
    /// This error as the refusal a helper stage may report, if it is one.
    ///
    /// The one place the two sets are mapped, and exhaustive — so a new variant has to decide
    /// whether a stage of the helper is the only thing that can decide it.
    pub(crate) fn refusal(&self) -> Option<HelperRefusal> {
        match self {
            Self::BadHelperArgs { .. } => Some(HelperRefusal::BadHelperArgs),
            Self::Landlock { .. } => Some(HelperRefusal::Landlock),
            Self::Seccomp { .. } => Some(HelperRefusal::Seccomp),
            Self::NamespaceSetupFailed { .. } => Some(HelperRefusal::NamespaceSetupFailed),
            Self::ProcessHardening { .. } => Some(HelperRefusal::ProcessHardening),
            Self::InnerStageFailed { .. } => Some(HelperRefusal::InnerStageFailed),
            Self::ExecFailed { .. } => Some(HelperRefusal::ExecFailed),
            Self::PinMismatch { .. } => Some(HelperRefusal::PinMismatch),
            Self::PinUnreadable { .. } => Some(HelperRefusal::PinUnreadable),
            Self::PinnedScript { .. } => Some(HelperRefusal::PinnedScript),
            Self::Unsupported { .. } => Some(HelperRefusal::Unsupported),
            // Decided here or by `FsGuard`, so a record claiming one would outrank an
            // outcome the parent watched happen. `HelperRefused` is this relay's own output
            // and exists only parent-side, so reporting it would be a second crossing.
            Self::PathNotAllowed { .. }
            | Self::Unresolvable { .. }
            | Self::NotFound { .. }
            | Self::SpawnFailed { .. }
            | Self::HelperRefused { .. }
            | Self::TimedOut { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_refusal_round_trips_through_its_own_label() {
        for refusal in HelperRefusal::ALL {
            assert_eq!(
                HelperRefusal::from_label(refusal.label()),
                Some(refusal),
                "{refusal:?} does not round-trip through its own label"
            );
        }
    }

    #[test]
    fn no_two_refusals_share_a_label() {
        let mut labels: Vec<_> = HelperRefusal::ALL.iter().map(|r| r.label()).collect();
        labels.sort_unstable();
        let total = labels.len();
        labels.dedup();

        assert_eq!(labels.len(), total, "two refusals share a label");
    }

    /// A forged one would outrank the exit status and claim a kill that never happened.
    #[test]
    fn the_reasons_the_helper_does_not_decide_cannot_cross_the_channel() {
        for label in [
            "timeout",
            "spawn_failed",
            "path_not_allowed",
            "unresolvable",
            "not_found",
        ] {
            assert_eq!(
                HelperRefusal::from_label(label),
                None,
                "{label} is not a helper stage's to report, but the channel accepted it"
            );
        }
    }

    #[test]
    fn a_label_we_did_not_define_is_refused() {
        for label in ["", "not_a_refusal", "seccomp ", "SECCOMP"] {
            assert_eq!(
                HelperRefusal::from_label(label),
                None,
                "{label:?} was accepted as one of our labels"
            );
        }
    }
}
