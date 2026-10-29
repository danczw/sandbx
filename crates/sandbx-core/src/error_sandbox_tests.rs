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

/// One of every variant. The exhaustive `match` below forces a new variant to decide
/// whether it is a [`HelperRefusal`] — but not to appear in the array itself, which a
/// variant left out of still compiles, and every test deriving from this skips in silence.
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
        // `Landlock`: the refusal whose label collides, so giving the relay its own
        // label fails `no_two_variants_share_a_label` instead of passing it.
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

/// Hard-coded, so a rename fails rather than agreeing with itself.
#[test]
fn each_variant_keeps_the_label_a_trail_filters_by() {
    for error in every_variant() {
        let expected = match error {
            SandboxError::PathNotAllowed { .. } => "path_not_allowed",
            SandboxError::Unresolvable { .. } => "unresolvable",
            SandboxError::NotFound { .. } => "not_found",
            SandboxError::BadHelperArgs { .. } => "bad_helper_args",
            SandboxError::Landlock { .. } => "landlock",
            SandboxError::GrantRedirected { .. } => "grant_redirected",
            SandboxError::GrantReplaced { .. } => "grant_replaced",
            SandboxError::RootReplaced { .. } => "root_replaced",
            SandboxError::GrantUnpinnable { .. } => "grant_unpinnable",
            SandboxError::Seccomp { .. } => "seccomp",
            SandboxError::NamespaceSetupFailed { .. } => "namespace_setup_failed",
            SandboxError::ProcessHardening { .. } => "process_hardening",
            SandboxError::ProcessConcealment { .. } => "process_concealment",
            SandboxError::SpawnFailed { .. } => "spawn_failed",
            SandboxError::InnerStageFailed { .. } => "inner_stage_failed",
            SandboxError::ExecFailed { .. } => "exec_failed",
            SandboxError::PinMismatch { .. } => "pin_mismatch",
            SandboxError::PinUnreadable { .. } => "pin_unreadable",
            SandboxError::PinnedScript { .. } => "pinned_script",
            SandboxError::TimedOut { .. } => "timeout",
            SandboxError::Unsupported { .. } => "unsupported",
            SandboxError::UnboundedResolution { .. } => "unbounded_resolution",
            SandboxError::GrantBoundByResolver { .. } => "grant_bound_by_resolver",
            // Borrowed: pinned by `a_refusal_is_called_what_the_variant_it_relays_is_called`.
            SandboxError::HelperRefused { .. } => continue,
        };

        assert_eq!(
            error.label(),
            expected,
            "a label a trail filters by was renamed"
        );
    }
}

#[test]
fn no_two_variants_share_a_label() {
    let mut labels = labels_decided_here();
    labels.sort_unstable();
    let total = labels.len();
    labels.dedup();

    assert_eq!(labels.len(), total, "two variants share a label");
}

/// The trail must call a refusal the same thing whichever side of the channel decided
/// it, so a `reason=` filter is written once.
#[test]
fn a_refusal_is_called_what_the_variant_it_relays_is_called() {
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

/// A `Helper` arm whose refusal is missing from `ALL` compiles; its record is dropped (#185).
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
