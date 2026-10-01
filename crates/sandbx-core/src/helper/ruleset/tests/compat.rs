//! The ABI ladder and the enforcement verdict — the two answers that depend on
//! the kernel, asked without one.

use super::{NEGOTIABLE_ABI, enforcement_verdict};

/// The negotiable ladder spans exactly the two documented constants.
///
/// Its ends are [`LATEST_ABI`] and [`BASELINE_ABI`] by construction. What
/// construction cannot pin is the order and the rungs between them: `ABI` is
/// a closed enum with no iterator and no arithmetic, so the interior is
/// hand-written, and `negotiated_abi` takes the first rung that works and
/// calls it the highest the kernel has. Out of order, that is simply wrong —
/// it would settle for a lower ABI than available and leave the rights above
/// it unrequested, which is the silent hole `BASELINE_ABI`'s doc describes.
/// A gap would skip an ABI the kernel could have enforced in full.
///
/// [`LATEST_ABI`]: super::super::compat::LATEST_ABI
/// [`BASELINE_ABI`]: super::super::compat::BASELINE_ABI
#[test]
fn the_abi_ladder_descends_without_gaps() {
    for pair in NEGOTIABLE_ABI.windows(2) {
        assert_eq!(
            pair[0] as i32 - 1,
            pair[1] as i32,
            "{:?} and {:?} are out of order or have a gap between them",
            pair[0],
            pair[1]
        );
    }
}

/// Only a fully enforced ruleset is accepted.
///
/// `SECURITY.md` claims "a ruleset the kernel only partly applies is treated
/// as failure", and until now that was false: the check was
/// `== NotEnforced`, so `PartiallyEnforced` passed. That was not a corner
/// case — `apply` asked for `LATEST_ABI` best-effort, so on every kernel
/// below the newest ABI this crate knows, *every* run was partly enforced and
/// accepted. Partial enforcement means Landlock left some requested access
/// type unhandled, and an unhandled access type is unrestricted everywhere —
/// the same silent hole `BASELINE_ABI`'s doc describes for a pinned-low ABI.
///
/// Total over the enum rather than a comparison, so a status added by a future
/// landlock release fails to compile here instead of falling through to the
/// accepting arm.
#[test]
fn only_full_enforcement_is_accepted() {
    use landlock::RulesetStatus;

    assert!(enforcement_verdict(RulesetStatus::FullyEnforced).is_ok());

    for status in [RulesetStatus::PartiallyEnforced, RulesetStatus::NotEnforced] {
        let named = format!("{status:?}");
        assert!(
            enforcement_verdict(status).is_err(),
            "{named} was accepted, so the sandbox runs with a hole in it"
        );
    }
}
