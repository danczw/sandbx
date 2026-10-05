//! The ABI ladder and the enforcement verdict — the two answers that depend on the
//! kernel, asked without one.

use super::{BASELINE_ABI, NEGOTIABLE_ABI, SandboxError, enforcement_verdict, negotiated_abi_from};

/// The kernel release [`BASELINE_ABI`] shipped in, which `landlock` does not carry. Lives
/// here rather than beside the constant because production states it in prose only — in
/// the refusal message and the docs — so this is the expectation those are checked against.
const BASELINE_KERNEL: &str = "6.10";

/// The error a kernel returns for an ABI it has only *part* of, and so the only one
/// [`negotiated_abi_from`] steps down a rung on: under `CompatLevel::HardRequirement`,
/// `handle_access` refuses a partly-supported set, which landlock reaches through
/// `CompatResult::Partial`.
///
/// Built by hand rather than provoked from a kernel. `AccessError` is an exhaustive enum
/// and the wrappers are `#[non_exhaustive]` only at the enum level, which forbids
/// exhaustive *matching*, not naming a variant — landlock's own
/// `ruleset_error_breaking_change` test builds this same chain.
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

/// The same refusal when the kernel has *none* of the set — Landlock absent, or not
/// enabled at boot.
///
/// Still an ABI verdict, so still steppable: landlock reports `Incompatible` rather than
/// `PartiallyCompatible` when the supported set is empty, which makes this the realistic
/// error for the host [`a_kernel_below_the_baseline_is_unsupported`] models.
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
/// `MissingHandledAccess` stands in for what a real failure of this kind would carry —
/// `CreateRulesetError::CreateRulesetCall { source }`, the `landlock_create_ruleset(2)`
/// syscall failing with `EPERM` or `ENOSYS` — which is `#[non_exhaustive]` *per variant*
/// and so cannot be constructed outside landlock. Sound because the decision under test
/// reads only the outermost variant: anything that is not `RulesetError::HandleAccesses`
/// is a non-verdict error.
fn not_an_abi_verdict() -> landlock::RulesetError {
    landlock::RulesetError::CreateRuleset(landlock::CreateRulesetError::MissingHandledAccess)
}

/// The ladder's ends are [`LATEST_ABI`] and [`BASELINE_ABI`] by construction; the order
/// and the rungs between them are not, because `ABI` is a closed enum with no iterator
/// and no arithmetic. `negotiated_abi` takes the first rung that works, so out of order it
/// would settle for a lower ABI than available and leave the rights above it unrequested —
/// the silent hole `BASELINE_ABI`'s doc describes. A gap would skip an ABI the kernel could
/// have enforced in full.
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

/// `SECURITY.md` claims "a ruleset the kernel only partly applies is treated as failure".
/// Total over the enum rather than a comparison, so a status added by a future landlock
/// release fails to compile here instead of falling through to the accepting arm.
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

/// The ordinary case, and the one every real host below the ceiling takes. Two assertions
/// because the ladder has two properties: the rung settled on is the next one down, and
/// the walk *stopped* there rather than continuing past a rung it could have had.
///
/// Rungs are named by position in [`NEGOTIABLE_ABI`] rather than as `V9`/`V8`, so an ABI
/// bump need not edit a test about the walk; their spelled-out values are held by
/// [`the_abi_ladder_descends_without_gaps`] and
/// `each_axis_confers_exactly_the_documented_set`.
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

/// The decision this whole seam exists for. Stepping down on an error that is not an ABI
/// verdict hands back a lower ABI than the kernel supports; every right above it then
/// goes unhandled, and Landlock leaves an unhandled access type unrestricted
/// *everywhere*. Replacing the refusing arm with `continue` left both suites and both CI
/// jobs green.
///
/// The probe accepting every rung below the failing one is load-bearing: a probe that
/// failed everywhere would pass under the very mutation this catches, since the correct
/// code refuses with `Landlock` and the mutant walks off the ladder and refuses with
/// `Unsupported` — both errors, indistinguishable to `is_err()`. With an accepting rung
/// below, the mutant returns `Ok`.
///
/// The variant is asserted, not `is_err()`, because `continue` is not the only way to
/// lose this: `break` falls through to the baseline refusal, reporting "ABI 5, Linux
/// 6.10" for a cause unrelated to the floor. `SandboxError` carries no `PartialEq`, so
/// `matches!` is the tool. The recorded walk is a second, independent witness.
#[test]
fn a_non_verdict_error_refuses_without_stepping_down() {
    let top = NEGOTIABLE_ABI[0];

    let mut asked = Vec::new();
    let outcome = negotiated_abi_from(|abi| {
        asked.push(abi);
        if abi == top {
            Err(not_an_abi_verdict())
        } else {
            // Every lower rung is accepted, so stepping down would succeed. That is
            // what makes the two outcomes differ here.
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

/// The floor `BASELINE_ABI` documents: every rung is an ABI verdict, the walk exhausts
/// the ladder, and what comes back names the baseline this build requires.
///
/// This refusal and [`a_non_verdict_error_refuses_without_stepping_down`]'s must stay
/// distinguishable: "this kernel is too old" versus "the kernel objected, here is why".
#[test]
fn a_kernel_below_the_baseline_is_unsupported() {
    let mut asked = Vec::new();
    let outcome = negotiated_abi_from(|abi| {
        asked.push(abi);
        Err(no_abi_at_all(abi))
    });

    let Err(SandboxError::Unsupported { detail }) = &outcome else {
        panic!("a kernel below the baseline was not refused as unsupported: got {outcome:?}");
    };

    let abi = format!("ABI {}", BASELINE_ABI as i32);
    for want in [abi.as_str(), BASELINE_KERNEL] {
        assert!(
            detail.contains(want),
            "the refusal does not name the floor it is refusing for ({want}): {detail}"
        );
    }

    assert_eq!(
        asked, NEGOTIABLE_ABI,
        "the walk did not try every rung before refusing, so a kernel that has \
         the baseline could be turned away"
    );
}

/// A floor bump that misses a prose copy leaves `SECURITY.md` claiming enforcement the
/// code does not provide — a defect in the claim rather than in the code.
///
/// Containment, not equality: this catches a file that never names the current floor, not
/// one that also still names an older one.
#[test]
fn every_prose_copy_of_the_floor_is_current() {
    let abi = format!("ABI {}", BASELINE_ABI as i32);
    let both: &[&str] = &[abi.as_str(), BASELINE_KERNEL];
    let kernel_only: &[&str] = &[BASELINE_KERNEL];

    for (name, text, wanted) in [
        (
            "SECURITY.md",
            include_str!("../../../../../../SECURITY.md"),
            both,
        ),
        (
            "README.md",
            include_str!("../../../../../../README.md"),
            kernel_only,
        ),
        (
            ".github/workflows/ci.yml",
            include_str!("../../../../../../.github/workflows/ci.yml"),
            both,
        ),
        (
            "sandbx-core/Cargo.toml",
            include_str!("../../../../Cargo.toml"),
            both,
        ),
        (
            "tests/enforcement.rs",
            include_str!("../../../../tests/enforcement.rs"),
            both,
        ),
    ] {
        for want in wanted {
            assert!(
                text.contains(want),
                "{name} does not state the current floor ({want}); a bump to \
                 BASELINE_ABI or BASELINE_KERNEL has left it behind"
            );
        }
    }
}
