//! What the sandbox refuses, and the access each refusal names.
//!
//! Over the 400-line budget on purpose: it is one `Display` arm per variant, and the
//! list of everything that can refuse a run is only readable in one place.

use std::path::PathBuf;

use crate::ObjectId;

mod refusal;

pub use refusal::HelperRefusal;

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

    /// A granted path opened as a different one, so the sandbox would not have been the one
    /// the harness judged.
    ///
    /// The policy is built in one process and the rules are opened in another, and the open
    /// follows every symlink; a link redirected in between would otherwise be checked against
    /// one directory and granted on another (#205).
    GrantRedirected {
        /// The path the policy grants, as the harness resolved it.
        granted: PathBuf,
        /// What opening it actually landed on.
        opened: PathBuf,
    },

    /// A granted path opened as the same name and a different object, so the sandbox would
    /// have been granted on a directory the harness never judged.
    ///
    /// What [`GrantRedirected`](Self::GrantRedirected) cannot see: a `rename(2)` putting one
    /// real directory where another was vetted leaves the spelling identical, so only the
    /// object tells them apart (#212).
    GrantReplaced {
        /// The path the policy grants, as the harness resolved it.
        granted: PathBuf,
        /// The object the harness measured when it vetted that path.
        vetted: ObjectId,
        /// The object opening it actually landed on.
        opened: ObjectId,
    },

    /// A granted root no longer holds the object the policy vetted, so an in-process tool
    /// would have reached a directory the harness never judged.
    ///
    /// The in-process twin of [`GrantReplaced`](Self::GrantReplaced), decided by
    /// [`FsGuard`](crate::FsGuard) per access: there is no descriptor to carry, and no helper
    /// stage to relay it (#212).
    RootReplaced {
        /// The root the policy grants, as the harness resolved it.
        granted: PathBuf,
        /// The object the harness measured when it vetted that root.
        vetted: ObjectId,
        /// The object the root holds now.
        opened: ObjectId,
    },

    /// A granted path could not be pinned to an object, so the harness has nothing for the
    /// helper to confirm its descriptor against.
    ///
    /// Harness-side and never reported by a helper stage: a path that names nothing is also
    /// one Landlock refuses a rule for, so this is that refusal, moved to where it can say
    /// which grant it was.
    GrantUnpinnable {
        /// The path as the caller supplied it, which is what they can go and change.
        granted: PathBuf,
        /// Why it could not be resolved and measured.
        source: std::io::Error,
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

    /// The harness could not hide its own process state, so a granted `/proc` would still
    /// reach the provider key in its environment.
    ///
    /// Separate from [`ProcessHardening`](Self::ProcessHardening), which is about the state a
    /// sandboxed command is born into.
    ProcessConcealment {
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
    /// single decider is what [`HelperRefusal`] admits a label on.
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

    /// A helper stage refused the run and named itself on the audit channel, so the command
    /// never ran — see [`HelperRefusal`].
    ///
    /// The status it exited with says only that it was non-zero, which is indistinguishable
    /// from the command doing so. This is that status replaced by what the channel said.
    HelperRefused {
        /// Which stage refused, and why.
        refusal: HelperRefusal,
        /// The helper's own stderr, which is where the reason travels.
        detail: String,
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

    /// The policy bounds which names resolve and leaves a nameserver reachable, so it would
    /// bound nothing while reporting as applied.
    ///
    /// [`SandboxPolicy::unbounded_resolution`] names the shape and decides this.
    ///
    /// [`SandboxPolicy::unbounded_resolution`]: crate::SandboxPolicy::unbounded_resolution
    UnboundedResolution {
        /// Which route to a nameserver is still open, for the operator to close.
        detail: &'static str,
    },

    /// The policy grants a file its own bounded resolver will bind sandbx's copy over, so the
    /// object the harness vetted is not the one the command would read.
    ///
    /// [`SandboxPolicy::grant_bound_by_resolver`] names the grant and decides this.
    ///
    /// [`SandboxPolicy::grant_bound_by_resolver`]: crate::SandboxPolicy::grant_bound_by_resolver
    GrantBoundByResolver {
        /// The granted path the bind lands on, for the operator to drop.
        granted: PathBuf,
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
            Self::UnboundedResolution { detail } => {
                write!(f, "a name allowlist would bound nothing here: {detail}")
            }
            Self::GrantBoundByResolver { granted } => {
                write!(
                    f,
                    "a name allowlist replaces {} with sandbx's own copy, so a grant naming it \
                     pins the rule to the host's file while the command reads another object \
                     at that same path — drop the grant, and grant the directory holding it if \
                     the command needs the rest of it",
                    granted.display()
                )
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
            // Both paths: whoever redirected the link knows where it points, the grant is in
            // an argv the command can read anyway, and without the target the operator cannot
            // tell a moved directory from a planted link.
            Self::GrantRedirected { granted, opened } => {
                write!(
                    f,
                    "granted path {} opened as {}, so it was not the path the policy was \
                     checked against",
                    granted.display(),
                    opened.display()
                )
            }
            Self::GrantReplaced {
                granted,
                vetted,
                opened,
            } => {
                write!(
                    f,
                    "granted path {} opened as object {opened} and not the {vetted} it was \
                     checked against, so it is no longer the directory the policy judged",
                    granted.display()
                )
            }
            Self::RootReplaced {
                granted,
                vetted,
                opened,
            } => {
                write!(
                    f,
                    "granted root {} holds object {opened} and not the {vetted} it was \
                     checked against, so it is no longer the directory the policy judged",
                    granted.display()
                )
            }
            Self::GrantUnpinnable { granted, source } => {
                write!(
                    f,
                    "could not pin granted path {} to the object it names: {source}",
                    granted.display()
                )
            }
            Self::NamespaceSetupFailed { detail } => {
                write!(f, "could not create the sandbox namespaces: {detail}")
            }
            Self::ProcessHardening { detail } => {
                write!(f, "could not harden process state: {detail}")
            }
            Self::ProcessConcealment { detail } => {
                write!(
                    f,
                    "refusing to run without concealing sandbx's own process state, which is \
                     what keeps an exported key out of a tool granted /proc: {detail}"
                )
            }
            Self::Seccomp { detail } => {
                write!(f, "could not install the syscall filter: {detail}")
            }
            // The detail is the helper's own `Display` as it printed it, already a whole
            // sentence; wrapping it would say twice what the label says once.
            Self::HelperRefused { refusal, detail } => match detail.is_empty() {
                true => write!(
                    f,
                    "the sandbox refused to run the command: {}",
                    refusal.label()
                ),
                false => write!(f, "{detail}"),
            },
        }
    }
}

impl std::error::Error for SandboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PathNotAllowed { .. }
            | Self::Unsupported { .. }
            | Self::UnboundedResolution { .. }
            | Self::GrantBoundByResolver { .. }
            | Self::BadHelperArgs { .. }
            | Self::Landlock { .. }
            | Self::GrantRedirected { .. }
            | Self::GrantReplaced { .. }
            | Self::RootReplaced { .. }
            | Self::NamespaceSetupFailed { .. }
            | Self::ProcessHardening { .. }
            | Self::ProcessConcealment { .. }
            | Self::TimedOut { .. }
            | Self::PinMismatch { .. }
            | Self::PinnedScript { .. }
            | Self::HelperRefused { .. }
            | Self::Seccomp { .. } => None,
            Self::Unresolvable { source, .. }
            | Self::NotFound { source, .. }
            | Self::GrantUnpinnable { source, .. }
            | Self::SpawnFailed { source, .. }
            | Self::InnerStageFailed { source, .. }
            | Self::PinUnreadable { source, .. }
            | Self::ExecFailed { source } => Some(source),
        }
    }
}

impl SandboxError {
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
            Self::GrantRedirected { .. } => "grant_redirected",
            Self::GrantReplaced { .. } => "grant_replaced",
            Self::RootReplaced { .. } => "root_replaced",
            Self::GrantUnpinnable { .. } => "grant_unpinnable",
            Self::Seccomp { .. } => "seccomp",
            Self::NamespaceSetupFailed { .. } => "namespace_setup_failed",
            Self::ProcessHardening { .. } => "process_hardening",
            Self::ProcessConcealment { .. } => "process_concealment",
            Self::SpawnFailed { .. } => "spawn_failed",
            Self::InnerStageFailed { .. } => "inner_stage_failed",
            Self::ExecFailed { .. } => "exec_failed",
            Self::PinMismatch { .. } => "pin_mismatch",
            Self::PinUnreadable { .. } => "pin_unreadable",
            Self::PinnedScript { .. } => "pinned_script",
            // Borrowed, so a trail filtered by `reason=` cannot tell which side of the
            // channel decided it — the same refusal either way.
            Self::HelperRefused { refusal, .. } => refusal.label(),
            // The word the operator typed and the docs use, so it is the word a trail
            // reader greps for.
            Self::TimedOut { .. } => "timeout",
            Self::Unsupported { .. } => "unsupported",
            Self::UnboundedResolution { .. } => "unbounded_resolution",
            Self::GrantBoundByResolver { .. } => "grant_bound_by_resolver",
        }
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

    /// A pin in its wire form, the only spelling of one a test can write — the fields are
    /// private so that the two measuring constructors stay the only producers.
    fn object(token: &str) -> ObjectId {
        ObjectId::parse(token).expect("a device and an inode parted by `:`")
    }

    /// One of every variant. The `match` below is exhaustive, so a new variant fails to
    /// compile until someone decides whether it is a [`HelperRefusal`] too — but the arm is
    /// all it forces: a variant left out of the array below compiles, and every test deriving
    /// from this skips it in silence.
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
            SandboxError::GrantRedirected {
                granted: PathBuf::from("/sample"),
                opened: PathBuf::from("/elsewhere"),
            },
            SandboxError::GrantReplaced {
                granted: PathBuf::from("/sample"),
                vetted: object("259:17"),
                opened: object("259:18"),
            },
            SandboxError::RootReplaced {
                granted: PathBuf::from("/sample"),
                vetted: object("259:17"),
                opened: object("259:18"),
            },
            SandboxError::GrantUnpinnable {
                granted: PathBuf::from("/sample"),
                source: io(),
            },
            SandboxError::Seccomp {
                detail: "sample".to_string(),
            },
            SandboxError::NamespaceSetupFailed { detail: "sample" },
            SandboxError::ProcessHardening {
                detail: "sample".to_string(),
            },
            SandboxError::ProcessConcealment {
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
            SandboxError::UnboundedResolution { detail: "sample" },
            SandboxError::GrantBoundByResolver {
                granted: PathBuf::from("/etc/hosts"),
            },
            // `Landlock` because it is the refusal whose label collides, so an edit giving
            // the relay a label of its own fails `no_two_variants_share_a_label` instead of
            // passing it.
            SandboxError::HelperRefused {
                refusal: HelperRefusal::Landlock,
                detail: "sample".to_string(),
            },
        ];

        for error in &all {
            match error {
                SandboxError::PathNotAllowed { .. }
                | SandboxError::Unresolvable { .. }
                | SandboxError::NotFound { .. }
                | SandboxError::BadHelperArgs { .. }
                | SandboxError::Landlock { .. }
                | SandboxError::GrantRedirected { .. }
                | SandboxError::GrantReplaced { .. }
                | SandboxError::RootReplaced { .. }
                | SandboxError::GrantUnpinnable { .. }
                | SandboxError::Seccomp { .. }
                | SandboxError::NamespaceSetupFailed { .. }
                | SandboxError::ProcessHardening { .. }
                | SandboxError::ProcessConcealment { .. }
                | SandboxError::SpawnFailed { .. }
                | SandboxError::InnerStageFailed { .. }
                | SandboxError::ExecFailed { .. }
                | SandboxError::PinMismatch { .. }
                | SandboxError::PinUnreadable { .. }
                | SandboxError::PinnedScript { .. }
                | SandboxError::TimedOut { .. }
                | SandboxError::HelperRefused { .. }
                | SandboxError::UnboundedResolution { .. }
                | SandboxError::GrantBoundByResolver { .. }
                | SandboxError::Unsupported { .. } => {}
            }
        }

        all
    }

    /// Every label but the relay's, which borrows the label of the variant it relays — so a
    /// set including it cannot check that the borrowed one is unique.
    fn labels_decided_here() -> Vec<&'static str> {
        every_variant()
            .iter()
            .filter(|error| !matches!(error, SandboxError::HelperRefused { .. }))
            .map(SandboxError::label)
            .collect()
    }

    #[test]
    fn no_two_variants_share_a_label() {
        let mut labels = labels_decided_here();
        labels.sort_unstable();
        let total = labels.len();
        labels.dedup();

        assert_eq!(labels.len(), total, "two variants share a label");
    }

    /// The trail must call a refusal the same thing whichever side of the channel decided it,
    /// a `reason=` filter being written once.
    #[test]
    fn a_refusal_is_called_what_the_variant_it_relays_is_called() {
        for error in every_variant() {
            if let Some(refusal) = error.refusal() {
                assert_eq!(
                    refusal.label(),
                    error.label(),
                    "{} and the refusal it reports as disagree",
                    error.label()
                );
            }
        }

        let labels = labels_decided_here();
        for refusal in HelperRefusal::ALL {
            let relayed = SandboxError::HelperRefused {
                refusal,
                detail: String::new(),
            };

            assert_eq!(
                relayed.label(),
                refusal.label(),
                "a relayed refusal was renamed on the way to the caller"
            );
            assert!(
                labels.contains(&refusal.label()),
                "{} crosses the channel but names no variant",
                refusal.label()
            );
        }
    }

    /// The direction the exhaustive `refusal` match cannot cover alone: a refusal given arms
    /// in `label` and `refusal` but left out of `ALL` compiles, and then `from_label` rejects
    /// the label its own writer emits and the record is dropped on arrival (#185).
    #[test]
    fn every_refusal_a_variant_reports_is_one_the_channel_admits() {
        for error in every_variant() {
            if let Some(refusal) = error.refusal() {
                assert!(
                    HelperRefusal::ALL.contains(&refusal),
                    "{} reports {refusal:?}, which is missing from HelperRefusal::ALL",
                    error.label()
                );
            }
        }
    }

    /// Each is a decision the parent or [`FsGuard`](crate::FsGuard) watched itself, so a
    /// channel record claiming one would outrank the outcome it saw.
    #[test]
    fn the_reasons_the_helper_does_not_decide_are_not_refusals() {
        for error in every_variant() {
            let decided_here = matches!(
                error,
                SandboxError::PathNotAllowed { .. }
                    | SandboxError::Unresolvable { .. }
                    | SandboxError::NotFound { .. }
                    | SandboxError::RootReplaced { .. }
                    | SandboxError::GrantUnpinnable { .. }
                    | SandboxError::SpawnFailed { .. }
                    | SandboxError::HelperRefused { .. }
                    | SandboxError::ProcessConcealment { .. }
                    | SandboxError::UnboundedResolution { .. }
                    | SandboxError::GrantBoundByResolver { .. }
                    | SandboxError::TimedOut { .. }
            );

            assert_eq!(
                error.refusal().is_none(),
                decided_here,
                "{} is on the wrong side of the channel",
                error.label()
            );
        }
    }

    /// A forged record would outrank the exit status the parent watched. Derived, not listed:
    /// a list goes one label behind each time a reason is added.
    #[test]
    fn the_reasons_the_helper_does_not_decide_cannot_cross_the_channel() {
        for error in every_variant() {
            // `HelperRefused` is the relay and carries the label of the refusal it relays, so
            // it parses back by construction; nothing sandbx decided is behind it.
            if error.refusal().is_some() || matches!(error, SandboxError::HelperRefused { .. }) {
                continue;
            }

            assert_eq!(
                HelperRefusal::from_label(error.label()),
                None,
                "{} is not a helper stage's to report, but the channel accepted it",
                error.label()
            );
        }
    }
}
