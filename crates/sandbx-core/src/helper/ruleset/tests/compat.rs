//! The ABI ladder and the enforcement verdict — the two answers that depend on
//! the kernel, asked without one.

use super::{NEGOTIABLE_ABI, SandboxError, enforcement_verdict, negotiated_abi_from};

/// The error a kernel returns for an ABI it has only *part* of.
///
/// The one error [`negotiated_abi_from`] treats as a verdict on which ABI this
/// kernel has, and so the only one it steps down a rung on. Under
/// `CompatLevel::HardRequirement`, `handle_access` refuses a partly-supported set
/// and names the rights that are missing — landlock's `access.rs` reaches this
/// through `CompatResult::Partial`, and the message reads "partially incompatible
/// access-rights: .. ResolveUnix".
///
/// Built by hand rather than provoked from a kernel, which is the whole point of
/// the seam: the discrimination below used to be reachable only on a
/// Landlock-capable host, so nothing asserted it (#87). `AccessError` is an
/// exhaustive enum and the wrappers are `#[non_exhaustive]` only at the enum
/// level, which forbids exhaustive *matching*, not naming a variant — landlock's
/// own `ruleset_error_breaking_change` test builds this same chain.
fn an_abi_verdict(abi: landlock::ABI) -> landlock::RulesetError {
    use landlock::{
        Access, AccessError, AccessFs, CompatError, HandleAccessError, HandleAccessesError,
        RulesetError,
    };

    RulesetError::HandleAccesses(HandleAccessesError::Fs(HandleAccessError::Compat(
        CompatError::Access(AccessError::PartiallyCompatible {
            access: AccessFs::from_all(abi),
            incompatible: AccessFs::ResolveUnix.into(),
        }),
    )))
}

/// The same refusal when the kernel has *none* of the set — Landlock absent, or
/// not enabled at boot.
///
/// Still an ABI verdict, so still steppable: landlock reports `Incompatible`
/// rather than `PartiallyCompatible` when the supported set is empty. That makes
/// it the realistic error for a host that has no Landlock at all, which is the
/// host [`a_kernel_below_the_baseline_is_refused_as_unsupported`] models.
fn no_abi_at_all(abi: landlock::ABI) -> landlock::RulesetError {
    use landlock::{
        Access, AccessError, AccessFs, CompatError, HandleAccessError, HandleAccessesError,
        RulesetError,
    };

    RulesetError::HandleAccesses(HandleAccessesError::Fs(HandleAccessError::Compat(
        CompatError::Access(AccessError::Incompatible {
            access: AccessFs::from_all(abi),
        }),
    )))
}

/// An error that says nothing about which ABI the kernel has.
///
/// `MissingHandledAccess` stands in for the error a real failure of this kind
/// would carry — `CreateRulesetError::CreateRulesetCall { source }`, the
/// `landlock_create_ruleset(2)` syscall failing with, say, `EPERM` or `ENOSYS`.
/// That variant is `#[non_exhaustive]` *per variant*, so it cannot be constructed
/// outside landlock. The substitution is sound because the decision under test
/// reads only the outermost variant: anything that is not
/// `RulesetError::HandleAccesses` is a non-verdict error.
fn not_an_abi_verdict() -> landlock::RulesetError {
    landlock::RulesetError::CreateRuleset(landlock::CreateRulesetError::MissingHandledAccess)
}

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

/// An ABI verdict steps down one rung and settles there.
///
/// The ordinary case, and the one every real host below the ceiling takes. Two
/// things are asserted because the ladder has two properties: that the rung
/// settled on is the next one down, and that the walk *stopped* there rather than
/// continuing past a rung it could have had. The constant's order is pinned
/// separately by [`the_abi_ladder_descends_without_gaps`]; what is new here is
/// that `negotiated_abi_from` honours it.
///
/// Rungs are named by position in [`NEGOTIABLE_ABI`] rather than as `V9`/`V8`, so
/// an ABI bump does not have to edit a test about the walk. The rungs themselves
/// are what the ladder test and `each_axis_confers_exactly_the_documented_set`
/// hold to their spelled-out values.
#[test]
fn an_abi_verdict_steps_down_exactly_one_rung() {
    let (top, next) = (NEGOTIABLE_ABI[0], NEGOTIABLE_ABI[1]);

    let mut asked = Vec::new();
    let settled = negotiated_abi_from(|abi| {
        asked.push(abi);
        if abi == top {
            Err(an_abi_verdict(abi))
        } else {
            Ok(())
        }
    });

    assert!(
        matches!(settled, Ok(abi) if abi == next),
        "a kernel that hard-requires {next:?} was not given it: got {settled:?}"
    );
    assert_eq!(
        asked,
        [top, next],
        "the walk did not stop at the first rung the kernel accepted"
    );
}

/// A non-verdict error refuses, rather than stepping down to a rung the kernel
/// would have accepted.
///
/// The decision this whole seam exists for. Stepping down on an error that is not
/// an ABI verdict hands back a lower ABI than the kernel actually supports; every
/// right above it then goes unhandled, and Landlock leaves an unhandled access
/// type unrestricted *everywhere*. It is the silent hole `BASELINE_ABI` guards
/// against, reached from above instead of below. Replacing the refusing arm with
/// `continue` left `cargo test --workspace` at zero failures, the gated
/// real-kernel suite at zero failures, and both CI jobs green (#87).
///
/// **The probe accepting every rung below the failing one is load-bearing, not
/// incidental.** A probe that failed at every rung would make this test pass
/// under the very mutation it exists to catch: the correct code refuses with
/// `Landlock`, and the mutant walks off the end of the ladder and refuses with
/// `Unsupported` — both errors, so `is_err()` cannot tell them apart. That is the
/// shape the first attempt at `compiled_filter`'s polarity assertion had, where
/// `EPERM` appeared in the program either way (#91). With an accepting rung below,
/// the mutant returns `Ok`.
///
/// **The variant is asserted, not `is_err()`,** because `continue` is not the only
/// way to lose this. `break` leaves the loop and falls through to the baseline
/// refusal, reporting "ABI 5, Linux 6.10" for a cause that has nothing to do with
/// the floor — an error message that sends the reader to the wrong kernel.
/// `SandboxError` carries no `PartialEq`, so `matches!` is the tool.
///
/// **The recorded walk is a second, independent witness.** If the error check is
/// ever weakened, the sequence still catches a rung being tried after the refusal.
#[test]
fn a_non_verdict_error_refuses_rather_than_stepping_down() {
    let top = NEGOTIABLE_ABI[0];

    let mut asked = Vec::new();
    let outcome = negotiated_abi_from(|abi| {
        asked.push(abi);
        if abi == top {
            Err(not_an_abi_verdict())
        } else {
            // Every lower rung is accepted, so stepping down would succeed. That
            // is what makes the two outcomes differ here.
            Ok(())
        }
    });

    assert!(
        matches!(outcome, Err(SandboxError::Landlock { .. })),
        "a non-verdict error did not refuse; the kernel's own reason was lost \
         and a lower ABI may have been accepted: got {outcome:?}"
    );
    assert_eq!(
        asked,
        [top],
        "the walk continued past a non-verdict error, so it may settle on a \
         lower ABI than the kernel supports and leave every right above it \
         unhandled"
    );
}

/// A kernel with no Landlock at all is refused as unsupported, not as a Landlock
/// failure.
///
/// The floor `BASELINE_ABI` documents: every rung is an ABI verdict, the walk
/// exhausts the ladder, and what comes back names the baseline this build
/// requires. The pair with
/// [`a_non_verdict_error_refuses_rather_than_stepping_down`] is the point — two
/// refusals that must stay distinguishable, because they send whoever reads them
/// to different problems. One says "this kernel is too old"; the other says "the
/// kernel objected, here is why".
#[test]
fn a_kernel_below_the_baseline_is_refused_as_unsupported() {
    let mut asked = Vec::new();
    let outcome = negotiated_abi_from(|abi| {
        asked.push(abi);
        Err(no_abi_at_all(abi))
    });

    assert!(
        matches!(outcome, Err(SandboxError::Unsupported { .. })),
        "a kernel below the baseline was not refused as unsupported: got {outcome:?}"
    );
    assert_eq!(
        asked, NEGOTIABLE_ABI,
        "the walk did not try every rung before refusing, so a kernel that has \
         the baseline could be turned away"
    );
}
