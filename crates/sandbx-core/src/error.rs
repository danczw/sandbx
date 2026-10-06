use std::path::PathBuf;

/// Which grant a path was checked against.
///
/// Carried by a refusal so it can name the grant that was missing. The guard keeps its
/// root sets apart, so "outside every allowed root" would be false of a path that is
/// inside one and was checked against the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Checked against the readable roots.
    Read,
    /// Checked against the writable roots.
    Write,
}

impl Access {
    /// How the audit trail names the operation.
    pub fn operation(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    /// What a path this access refused is outside of.
    ///
    /// The one wording, read by both the audit record's reason and [`SandboxError`]'s
    /// `Display`, so a record and the message a caller saw cannot disagree.
    pub fn outside(self) -> &'static str {
        match self {
            Self::Read => "outside every readable root",
            Self::Write => "outside every writable root",
        }
    }
}

/// Why a sandbox operation was refused.
///
/// Every variant is a refusal; there is no "allowed with warning" case, because a caller
/// that believes it is sandboxed and is not is worse off than one that gets an error.
#[derive(Debug)]
pub enum SandboxError {
    /// The path is not inside any root the policy allows for this access.
    PathNotAllowed {
        /// The path as the caller supplied it.
        requested: PathBuf,
        /// The grant it was checked against, and so the one it lacked.
        access: Access,
    },

    /// The path could not be resolved, so cannot be proven to be inside an allowed root —
    /// which is also what a traversal attempt looks like.
    Unresolvable {
        /// The path as the caller supplied it.
        requested: PathBuf,
        /// The underlying resolution failure.
        source: std::io::Error,
    },

    /// The helper process was given argv it could not parse. Not parsed best-effort: a
    /// policy other than the one sandbx intended is the failure the sandbox prevents.
    BadHelperArgs {
        /// What was wrong, for the operator to act on.
        detail: &'static str,
    },

    /// The kernel refused to apply the Landlock ruleset.
    Landlock {
        /// The failing step and the kernel's reason.
        detail: String,
    },

    /// The syscall filter could not be installed; without it a sandboxed tool could reach
    /// syscalls Landlock cannot express.
    Seccomp {
        /// What failed, for the operator to act on.
        detail: String,
    },

    /// The kernel namespaces the sandbox runs the command in could not be created.
    ///
    /// One variant for all of them — user, PID, and, when the policy denies network, the
    /// network namespace — because there is one `unshare` call and the kernel answers it
    /// with one errno; splitting it would mean reporting a guess as a fact.
    NamespaceSetupFailed {
        /// What failed, for the operator to act on.
        detail: &'static str,
    },

    /// This process is not in the state a sandboxed command may be born into:
    /// capabilities not dropped, core dumps not disabled, or an environment an earlier
    /// stage should have narrowed and did not.
    ///
    /// All three are inherited across `exec`, hence one fact about this process rather than
    /// three failures.
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

    /// The innermost stage could not become the command, so it never ran.
    ///
    /// Distinct from [`SpawnFailed`](Self::SpawnFailed), which is a *helper* that did not
    /// start.
    ExecFailed {
        /// The underlying OS failure.
        source: std::io::Error,
    },

    /// A sandboxed process outran its time limit and was killed.
    ///
    /// Distinct from [`SpawnFailed`](Self::SpawnFailed), which would make a wedged command
    /// look like a broken helper.
    TimedOut {
        /// The limit it exceeded.
        after: std::time::Duration,
    },

    /// This kernel cannot enforce a sandbox.
    ///
    /// Returned instead of running unsandboxed. A kernel, not a platform — a non-Linux
    /// target never reaches this, the crate refusing to build for one — so: too old for the
    /// Landlock baseline, Landlock disabled at boot, or a ruleset accepted and not enforced.
    Unsupported {
        /// What is missing, for the operator to act on.
        detail: &'static str,
    },
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathNotAllowed { requested, access } => {
                write!(f, "path is {}: {}", access.outside(), requested.display())
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
            Self::ExecFailed { source } => {
                write!(f, "could not execute the sandboxed command: {source}")
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
            Self::Unresolvable { source, .. }
            | Self::SpawnFailed { source, .. }
            | Self::ExecFailed { source } => Some(source),
        }
    }
}

impl SandboxError {
    /// The refusals a helper stage can report on its audit channel, and so the closed set
    /// the parent validates a label off that channel against.
    ///
    /// A strict subset of what [`label`](Self::label) can return, not all of it. The four
    /// it leaves out are decisions the parent and [`FsGuard`](crate::FsGuard) make for
    /// themselves — `timeout`, `spawn_failed`, `path_not_allowed`, `unresolvable` — and a
    /// record off the channel outranks the exit status, so admitting one would let a
    /// forged line claim a kill that never happened and displace the real outcome.
    ///
    /// Hand-maintained against `label`, which the compiler cannot help with. A helper
    /// refusal missing from here is dropped rather than mistrusted: the trail falls back
    /// to the relayed exit status, which is what it said before #157.
    pub(crate) const REPORTED_BY_HELPER: [&str; 7] = [
        "bad_helper_args",
        "landlock",
        "seccomp",
        "namespace_setup_failed",
        "process_hardening",
        "exec_failed",
        "unsupported",
    ];

    /// A stable name for this refusal, which the audit trail is filtered by.
    ///
    /// Exhaustive, so a new variant has to decide what a trail calls it; `Display` carries
    /// the prose and this carries the label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::PathNotAllowed { .. } => "path_not_allowed",
            Self::Unresolvable { .. } => "unresolvable",
            Self::BadHelperArgs { .. } => "bad_helper_args",
            Self::Landlock { .. } => "landlock",
            Self::Seccomp { .. } => "seccomp",
            Self::NamespaceSetupFailed { .. } => "namespace_setup_failed",
            Self::ProcessHardening { .. } => "process_hardening",
            Self::SpawnFailed { .. } => "spawn_failed",
            Self::ExecFailed { .. } => "exec_failed",
            // The word the operator typed and the docs use, so it is the word a trail
            // reader greps for.
            Self::TimedOut { .. } => "timeout",
            Self::Unsupported { .. } => "unsupported",
        }
    }

    /// The helper-reportable refusal `label` names, as our own `'static` copy of it.
    ///
    /// A lookup over [`REPORTED_BY_HELPER`](Self::REPORTED_BY_HELPER) rather than a second
    /// `match`, which could not rebuild the variant anyway: a label carries no detail. The
    /// `'static` return is the point — it is what lets a label read off the channel reach
    /// `AuditEvent::failed` without the trail borrowing from the bytes.
    pub(crate) fn reportable_label(label: &str) -> Option<&'static str> {
        Self::REPORTED_BY_HELPER
            .into_iter()
            .find(|known| *known == label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One of every variant, so the labels can be checked against the channel's closed
    /// set. The `match` below is exhaustive, so a new variant fails to compile here until
    /// it is acknowledged — and whether it also belongs in `REPORTED_BY_HELPER` is the
    /// question this list exists to put in front of whoever adds one.
    fn every_variant() -> Vec<SandboxError> {
        let io = || std::io::Error::other("sample");

        let all = vec![
            SandboxError::PathNotAllowed {
                requested: PathBuf::from("/sample"),
                access: Access::Read,
            },
            SandboxError::Unresolvable {
                requested: PathBuf::from("/sample"),
                source: io(),
            },
            SandboxError::BadHelperArgs { detail: "sample" },
            SandboxError::Landlock {
                detail: "sample".to_string(),
            },
            SandboxError::Seccomp {
                detail: "sample".to_string(),
            },
            SandboxError::NamespaceSetupFailed { detail: "sample" },
            SandboxError::ProcessHardening {
                detail: "sample".to_string(),
            },
            SandboxError::SpawnFailed {
                detail: "sample",
                source: io(),
            },
            SandboxError::ExecFailed { source: io() },
            SandboxError::TimedOut {
                after: std::time::Duration::from_secs(1),
            },
            SandboxError::Unsupported { detail: "sample" },
        ];

        for error in &all {
            match error {
                SandboxError::PathNotAllowed { .. }
                | SandboxError::Unresolvable { .. }
                | SandboxError::BadHelperArgs { .. }
                | SandboxError::Landlock { .. }
                | SandboxError::Seccomp { .. }
                | SandboxError::NamespaceSetupFailed { .. }
                | SandboxError::ProcessHardening { .. }
                | SandboxError::SpawnFailed { .. }
                | SandboxError::ExecFailed { .. }
                | SandboxError::TimedOut { .. }
                | SandboxError::Unsupported { .. } => {}
            }
        }

        all
    }

    #[test]
    fn no_two_variants_share_a_label() {
        let mut labels: Vec<_> = every_variant().iter().map(SandboxError::label).collect();
        labels.sort_unstable();
        let total = labels.len();
        labels.dedup();

        assert_eq!(labels.len(), total, "two variants share a label");
    }

    #[test]
    fn every_helper_reportable_label_is_one_a_variant_returns() {
        let labels: Vec<_> = every_variant().iter().map(SandboxError::label).collect();

        for reportable in SandboxError::REPORTED_BY_HELPER {
            assert!(
                labels.contains(&reportable),
                "{reportable} is on the channel's closed set but names no variant"
            );
        }
    }

    /// The channel's record outranks the relayed exit status, so a reason the parent or
    /// `FsGuard` decides for itself must not be nameable on it: a forged `timeout` would
    /// claim a kill that never happened and suppress the real outcome.
    #[test]
    fn the_reasons_the_helper_does_not_decide_cannot_cross_the_channel() {
        for label in [
            "timeout",
            "spawn_failed",
            "path_not_allowed",
            "unresolvable",
        ] {
            assert_eq!(
                SandboxError::reportable_label(label),
                None,
                "{label} is not a helper stage's to report, but the channel accepted it"
            );
        }
    }

    #[test]
    fn a_label_we_did_not_define_is_refused() {
        for label in ["", "not_a_refusal", "seccomp ", "SECCOMP"] {
            assert_eq!(
                SandboxError::reportable_label(label),
                None,
                "{label:?} was accepted as one of our labels"
            );
        }
    }
}
