//! Which Landlock ABI this kernel gets, and whether what it enforced counts.
//!
//! The floor and the ceiling live here with the ladder between them, because the
//! three move together — and so does [`enforcement_verdict`], which is only
//! refusable *because* [`negotiated_abi`] asks for nothing the kernel cannot
//! hard-require. What a grant confers at the chosen ABI is
//! [`super::rights`]'s business.

use crate::SandboxError;

/// The Landlock ABI floor [`apply`](crate::helper::apply) refuses to run below, and the ceiling it
/// negotiates up to.
///
/// `SECURITY.md` claims "Landlock, ABI 5 minimum" and refusal to run on a kernel
/// older than 6.10; this pair is the only place that floor is *enforced*. The
/// same number is also stated in prose in `README.md`, in this crate's
/// `Cargo.toml` and in `ci.yml`, and nothing checks those against this value —
/// so they move in the same change.
///
/// ABI 5 is a floor rather than a preference. Landlock leaves any access type
/// *not* in the handled set unrestricted everywhere, so pinning a lower ABI does
/// not enforce less — it leaves whole categories unguarded. That is how
/// `truncate(2)` was once permitted on any file regardless of policy. So
/// [`BASELINE_ABI`] is attached under `CompatLevel::HardRequirement`, making an
/// older kernel a refusal instead of a silent hole.
///
/// [`LATEST_ABI`] is the ceiling of the same argument, not an exception to it.
/// It was once handled best-effort — rights the kernel happened to have enforced,
/// the rest dropped — and that is exactly what made `SECURITY.md`'s "a ruleset
/// the kernel only partly applies is treated as failure" untrue: asking for
/// rights the kernel lacks makes the ruleset `PartiallyEnforced`, so on every
/// kernel below `LATEST_ABI` *every* run was partly enforced, and refusing that
/// would have refused nearly every host. [`negotiated_abi`] instead settles on
/// the newest ABI the kernel will hard-require in full, so nothing is ever
/// dropped and [`enforcement_verdict`] can refuse a partial result.
///
/// Changing either value changes what sandbx promises, so `SECURITY.md` and the
/// kernel floor quoted in `README.md` move in the same change.
pub(super) const BASELINE_ABI: landlock::ABI = landlock::ABI::V5; // Linux 6.10: Truncate, Refer, IoctlDev

/// Newest ABI [`apply`](crate::helper::apply) negotiates for. See [`BASELINE_ABI`].
pub(super) const LATEST_ABI: landlock::ABI = landlock::ABI::V9; // Linux 6.15: ResolveUnix

/// Every ABI [`negotiated_abi`] will settle for, newest first.
///
/// Spans [`LATEST_ABI`] down to [`BASELINE_ABI`] and stops there: below the
/// baseline is a refusal, not a lower rung. Written out rather than derived
/// because `ABI` is a closed enum with no iterator and no arithmetic — and a
/// literal ladder is the thing an ABI bump must be forced to edit, next to the
/// two constants that bound it.
pub(super) const NEGOTIABLE_ABI: [landlock::ABI; 5] = [
    LATEST_ABI,
    landlock::ABI::V8,
    landlock::ABI::V7,
    landlock::ABI::V6,
    BASELINE_ABI,
];

/// The newest ABI this kernel will hard-require, at or above [`BASELINE_ABI`].
///
/// Replaces the old best-effort arm, and the reason is [`enforcement_verdict`].
/// Asking for `LATEST_ABI` best-effort meant the kernel silently dropped whatever
/// it did not have, which made the ruleset `PartiallyEnforced` on every kernel
/// older than the newest ABI this crate knows — a verdict that cannot be refused
/// without refusing nearly every host. Asking only for what the kernel confirms
/// it handles makes full enforcement the normal outcome, so partial enforcement
/// becomes the anomaly it is documented to be.
///
/// Probing with `create()` is deliberate: it builds a ruleset without applying it,
/// so this walks the ladder in one process and nothing is restricted until
/// [`apply`](crate::helper::apply) calls `restrict_self`. The kernel's own version syscall would be
/// cheaper, but it is `unsafe` and `landlock` keeps its wrapper private — and a
/// probe that asks the same question the real call will ask cannot disagree with
/// it, which the duplicated ABI floor behind `d4676cc` is the argument for.
///
/// A kernel below [`BASELINE_ABI`] falls off the end and is refused, which is the
/// floor that constant documents.
pub(in crate::helper) fn negotiated_abi() -> Result<landlock::ABI, SandboxError> {
    use landlock::{Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetError};

    for abi in NEGOTIABLE_ABI {
        let built = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .and_then(|ruleset| ruleset.create());

        match built {
            Ok(_) => return Ok(abi),
            // The one error that is an ABI verdict: under `HardRequirement`,
            // `handle_access` refuses and names the rights this kernel does not
            // have (`partially incompatible access-rights: .. ResolveUnix`). Only
            // this steps down a rung.
            Err(RulesetError::HandleAccesses(_)) => continue,
            // Anything else says nothing about which ABI the kernel has. Stepping
            // down on it would hand back a lower ABI than the kernel supports, and
            // every right above it would then go unhandled — which Landlock leaves
            // unrestricted everywhere. That is the silent hole `BASELINE_ABI`
            // exists to prevent, so a non-verdict error is a refusal.
            Err(error) => return Err(landlock_failed(error)),
        }
    }

    Err(SandboxError::Unsupported {
        detail: "kernel does not support the Landlock baseline this build \
                 requires (ABI 5, Linux 6.10); refusing to run unconfined",
    })
}

/// Accept only a ruleset the kernel enforces in full.
///
/// `SECURITY.md` promises that a partly applied ruleset is treated as failure,
/// and a partly applied ruleset is one where Landlock left some requested access
/// type unhandled — which leaves that type unrestricted everywhere, the same
/// silent hole [`BASELINE_ABI`] describes. So there is nothing to accept here but
/// full enforcement.
///
/// Total over `RulesetStatus` rather than a comparison against one variant: that
/// is what the old `== NotEnforced` check was, and it let `PartiallyEnforced`
/// through for as long as it existed. A variant added by a future landlock
/// release now fails to compile instead of landing in an accepting arm.
pub(in crate::helper) fn enforcement_verdict(
    status: landlock::RulesetStatus,
) -> Result<(), SandboxError> {
    use landlock::RulesetStatus;

    match status {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced => Err(SandboxError::Unsupported {
            detail: "kernel enforced only part of the ruleset; some access type \
                     is unrestricted, so the sandbox would not hold",
        }),
        RulesetStatus::NotEnforced => Err(SandboxError::Unsupported {
            detail: "kernel accepted the ruleset but enforced none of it",
        }),
    }
}

pub(in crate::helper) fn landlock_failed(source: impl std::fmt::Display) -> SandboxError {
    // Carry the kernel's own reason: "refused" without a cause is unactionable
    // for whoever has to work out which path or access right it objected to.
    SandboxError::Landlock {
        detail: source.to_string(),
    }
}
