//! Public contract of [`KernelSupport`]: capability reporting and fail-closed
//! refusal.
//!
//! Most of these construct a capability report directly rather than probing the
//! running kernel, so the fail-closed decision is verified deterministically on
//! any machine — including one where Landlock works fine.
//!
//! Network enforcement is not covered here: it comes from an empty network
//! namespace rather than Landlock, and is verified in the child at spawn time.

use sandbx_core::KernelSupport;

#[test]
fn kernel_without_landlock_enforces_nothing() {
    assert!(!KernelSupport::new(false).enforces_filesystem());
}

#[test]
fn kernel_with_landlock_enforces_filesystem() {
    assert!(KernelSupport::new(true).enforces_filesystem());
}

/// The fail-closed rule: without enforcement there is no sandbox, so this must
/// fail rather than return something that silently permits everything.
#[test]
fn unsupported_kernel_is_refused_not_degraded() {
    assert!(
        KernelSupport::new(false).require_enforceable().is_err(),
        "a kernel that cannot enforce must be refused, never degraded to no-op"
    );
}

#[test]
fn capable_kernel_is_accepted() {
    assert!(KernelSupport::new(true).require_enforceable().is_ok());
}

/// Probing must not itself restrict the calling process.
///
/// `detect` builds a Landlock ruleset to see whether the kernel accepts one.
/// Creating a ruleset allocates a kernel object but enforces nothing — only
/// `restrict_self` applies it — so sandbx must still be able to read files it
/// could read before probing.
#[test]
fn detect_does_not_restrict_the_current_process() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), b"before").unwrap();

    let _ = KernelSupport::detect();

    assert!(
        std::fs::read(file.path()).is_ok(),
        "probing must not restrict the probing process"
    );
}

/// On a machine that reports support, that report must be actionable.
#[test]
fn detected_support_agrees_with_its_own_verdict() {
    let support = KernelSupport::detect();

    assert_eq!(
        support.enforces_filesystem(),
        support.require_enforceable().is_ok(),
        "require_enforceable must agree with enforces_filesystem"
    );
}
