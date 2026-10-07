use std::path::PathBuf;

/// Which grant a path was checked against.
///
/// Carried by a refusal so it names the grant that was missing: the guard keeps its root
/// sets apart, so a path can be inside one and outside the other.
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
    /// The one wording, shared by the audit record's reason and [`SandboxError`]'s
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
/// Every variant is a refusal; there is no "allowed with warning" case, a caller that
/// believes it is sandboxed and is not being worse off than one that gets an error.
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

    /// A path inside a granted root names no file, so no policy objected to it.
    ///
    /// Returned only where the roots already cover the area: elsewhere absence is concealed
    /// as [`PathNotAllowed`](Self::PathNotAllowed), ENOENT against EACCES over arbitrary
    /// paths reading back as a map of the host.
    NotFound {
        /// The component that names nothing — the parent, for a write to a missing directory.
        requested: PathBuf,
        /// The underlying failure: ENOENT, ENOTDIR or ENAMETOOLONG.
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
    /// One variant for user, PID and — when the policy denies network — the network
    /// namespace: one `unshare` creates them all and the kernel answers it with one errno.
    NamespaceSetupFailed {
        /// What failed, for the operator to act on.
        detail: &'static str,
    },

    /// This process is not in the state a sandboxed command may be born into:
    /// capabilities not dropped, core dumps not disabled, or an environment an earlier
    /// stage should have narrowed and did not.
    ///
    /// All three are inherited across `exec`, so this is one fact about this process rather
    /// than three failures.
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

    /// The supervisor stage could not start the stage below it.
    ///
    /// Separate from [`SpawnFailed`](Self::SpawnFailed) because one site returns it, and a
    /// single decider is what `REPORTED_BY_HELPER` admits a label on.
    InnerStageFailed {
        /// What failed, for the operator to act on.
        detail: &'static str,
        /// The underlying OS failure.
        source: std::io::Error,
    },

    /// The innermost stage could not become the command, so it never ran.
    ExecFailed {
        /// The underlying OS failure.
        source: std::io::Error,
    },

    /// The bytes at the program's path are not the ones the caller pinned, so it never ran.
    PinMismatch {
        /// The program as the caller named it.
        program: String,
        /// What the caller said the bytes would hash to.
        expected: crate::Sha256Digest,
        /// What they actually hashed to.
        actual: crate::Sha256Digest,
    },

    /// A pinned program could not be read, so its bytes were never established.
    ///
    /// Distinct from [`ExecFailed`](Self::ExecFailed) because the two diverge: a mode-111
    /// binary is executable and unreadable, so it runs unpinned and cannot be pinned.
    PinUnreadable {
        /// The program as the caller named it.
        program: String,
        /// The underlying OS failure, from the open or from a read.
        source: std::io::Error,
    },

    /// A pinned program is a `#!` script, which the pin cannot cover.
    ///
    /// The kernel hands the interpreter the path sandbx exec'd — the hashed descriptor —
    /// and the interpreter opens it again, by then closed.
    /// See `context/decision-pinned-entry-point.md`.
    PinnedScript {
        /// The program as the caller named it.
        program: String,
    },

    /// A sandboxed process outran its time limit and was killed.
    TimedOut {
        /// The limit it exceeded.
        after: std::time::Duration,
    },

    /// This kernel cannot enforce a sandbox.
    ///
    /// Returned instead of running unsandboxed. A kernel and not a platform, the crate
    /// refusing to build for a non-Linux target at all, so: too old for the Landlock
    /// baseline, Landlock disabled at boot, or a ruleset accepted and not enforced.
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
            Self::NotFound { requested, source } => {
                write!(f, "could not find {}: {source}", requested.display())
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
            Self::SpawnFailed { detail, source } | Self::InnerStageFailed { detail, source } => {
                write!(f, "{detail}: {source}")
            }
            Self::ExecFailed { source } => {
                write!(f, "could not execute the sandboxed command: {source}")
            }
            Self::PinMismatch {
                program,
                expected,
                actual,
            } => {
                // Both digests, because only the pair tells the operator whether they
                // pinned the wrong bytes or the bytes changed under them.
                write!(
                    f,
                    "{program} is not the binary it was pinned to: expected {expected}, \
                     found {actual}"
                )
            }
            Self::PinUnreadable { program, source } => {
                write!(
                    f,
                    "could not read {program} to check its pin: {source} — a pin needs read \
                     access, which execute alone does not give"
                )
            }
            Self::PinnedScript { program } => {
                write!(
                    f,
                    "{program} is a #! script, which --pin-sha256 cannot cover: pin an ELF \
                     binary, or run the interpreter as the program instead"
                )
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
            | Self::PinMismatch { .. }
            | Self::PinnedScript { .. }
            | Self::Seccomp { .. } => None,
            Self::Unresolvable { source, .. }
            | Self::NotFound { source, .. }
            | Self::SpawnFailed { source, .. }
            | Self::InnerStageFailed { source, .. }
            | Self::PinUnreadable { source, .. }
            | Self::ExecFailed { source } => Some(source),
        }
    }
}

impl SandboxError {
    /// The closed set a label off the helper's audit channel is validated against.
    ///
    /// A strict subset of [`label`](Self::label), because a channel record outranks the exit
    /// status: admitting one of the parent's or [`FsGuard`](crate::FsGuard)'s own decisions
    /// would let a forged line claim a kill that never happened. The criterion is a single
    /// decider and not what failed, so `inner_stage_failed` is in and `spawn_failed` out
    /// though both name a process that would not start. Hand-maintained against `label`; an
    /// omission falls back to the relayed exit status.
    pub(crate) const REPORTED_BY_HELPER: [&str; 11] = [
        "bad_helper_args",
        "landlock",
        "seccomp",
        "namespace_setup_failed",
        "process_hardening",
        "inner_stage_failed",
        "exec_failed",
        "pin_mismatch",
        "pin_unreadable",
        "pinned_script",
        "unsupported",
    ];

    /// A stable name for this refusal, which the audit trail is filtered by.
    ///
    /// Exhaustive, so a new variant has to decide what a trail calls it.
    pub fn label(&self) -> &'static str {
        match self {
            Self::PathNotAllowed { .. } => "path_not_allowed",
            Self::Unresolvable { .. } => "unresolvable",
            Self::NotFound { .. } => "not_found",
            Self::BadHelperArgs { .. } => "bad_helper_args",
            Self::Landlock { .. } => "landlock",
            Self::Seccomp { .. } => "seccomp",
            Self::NamespaceSetupFailed { .. } => "namespace_setup_failed",
            Self::ProcessHardening { .. } => "process_hardening",
            Self::SpawnFailed { .. } => "spawn_failed",
            Self::InnerStageFailed { .. } => "inner_stage_failed",
            Self::ExecFailed { .. } => "exec_failed",
            Self::PinMismatch { .. } => "pin_mismatch",
            Self::PinUnreadable { .. } => "pin_unreadable",
            Self::PinnedScript { .. } => "pinned_script",
            // The word the operator typed and the docs use, so it is the word a trail
            // reader greps for.
            Self::TimedOut { .. } => "timeout",
            Self::Unsupported { .. } => "unsupported",
        }
    }

    /// The helper-reportable refusal `label` names, as a `'static` copy — so a label read off
    /// the channel reaches `AuditEvent::failed` without the trail borrowing from the bytes.
    pub(crate) fn reportable_label(label: &str) -> Option<&'static str> {
        Self::REPORTED_BY_HELPER
            .into_iter()
            .find(|known| *known == label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two digests that differ, so a mismatch sample really mismatches. Parsed and not
    /// hashed, so which label a variant carries does not depend on file I/O.
    fn digests() -> (crate::Sha256Digest, crate::Sha256Digest) {
        let parse = |hex: &str| crate::Sha256Digest::parse(hex).expect("64 lowercase hex");

        (
            parse("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            parse("0000000000000000000000000000000000000000000000000000000000000001"),
        )
    }

    /// One of every variant. The `match` below is exhaustive, so a new variant fails to
    /// compile until someone decides whether it belongs in `REPORTED_BY_HELPER` too.
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
            // Not `io()`: the variant is only built behind `fs_guard::names_nothing`.
            SandboxError::NotFound {
                requested: PathBuf::from("/sample"),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
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
            SandboxError::InnerStageFailed {
                detail: "sample",
                source: io(),
            },
            SandboxError::ExecFailed { source: io() },
            SandboxError::PinMismatch {
                program: "/sample".to_string(),
                expected: digests().0,
                actual: digests().1,
            },
            SandboxError::PinUnreadable {
                program: "/sample".to_string(),
                source: io(),
            },
            SandboxError::PinnedScript {
                program: "/sample".to_string(),
            },
            SandboxError::TimedOut {
                after: std::time::Duration::from_secs(1),
            },
            SandboxError::Unsupported { detail: "sample" },
        ];

        for error in &all {
            match error {
                SandboxError::PathNotAllowed { .. }
                | SandboxError::Unresolvable { .. }
                | SandboxError::NotFound { .. }
                | SandboxError::BadHelperArgs { .. }
                | SandboxError::Landlock { .. }
                | SandboxError::Seccomp { .. }
                | SandboxError::NamespaceSetupFailed { .. }
                | SandboxError::ProcessHardening { .. }
                | SandboxError::SpawnFailed { .. }
                | SandboxError::InnerStageFailed { .. }
                | SandboxError::ExecFailed { .. }
                | SandboxError::PinMismatch { .. }
                | SandboxError::PinUnreadable { .. }
                | SandboxError::PinnedScript { .. }
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
