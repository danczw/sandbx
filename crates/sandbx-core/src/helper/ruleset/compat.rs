//! Which Landlock ABI this kernel gets, and whether what it enforced counts.
//!
//! The floor, the ceiling and the ladder between them move together, and so does
//! [`enforcement_verdict`], which is only refusable *because* [`negotiated_abi`] asks
//! for nothing the kernel cannot hard-require. What a grant confers at the chosen ABI
//! is [`super::rights`]'s business.

use crate::SandboxError;

/// The Landlock ABI floor [`apply`](crate::helper::apply) refuses to run below, and
/// the ceiling it negotiates up to.
///
/// This pair is the only place the floor `SECURITY.md` claims — ABI 5, no kernel older
/// than 6.10 — is enforced. The same number is stated in prose in `README.md`, in this
/// crate's `Cargo.toml` and in `ci.yml`, and nothing checks those against this value,
/// so they move in the same change as this one.
///
/// A floor rather than a preference: Landlock leaves any access type *not* in the
/// handled set unrestricted everywhere, so pinning a lower ABI does not enforce less —
/// it leaves whole categories unguarded, which is how `truncate(2)` was once permitted
/// on any file regardless of policy. Hence `CompatLevel::HardRequirement`, making an
/// older kernel a refusal instead of a silent hole.
///
/// [`LATEST_ABI`] is the ceiling of the same argument, not an exception to it. Handling
/// it best-effort — keeping whatever rights the kernel enforced, dropping the rest —
/// makes the ruleset `PartiallyEnforced` on every kernel below it, so refusing a
/// partial result would refuse nearly every host. [`negotiated_abi`] instead settles on
/// the newest ABI the kernel will hard-require in full, so nothing is ever dropped and
/// [`enforcement_verdict`] can refuse a partial result.
pub(super) const BASELINE_ABI: landlock::ABI = landlock::ABI::V5; // Linux 6.10: Truncate, Refer, IoctlDev

/// Newest ABI [`apply`](crate::helper::apply) negotiates for. See [`BASELINE_ABI`].
pub(super) const LATEST_ABI: landlock::ABI = landlock::ABI::V9; // Linux 7.1: ResolveUnix

/// Every ABI [`negotiated_abi`] will settle for, newest first.
///
/// Spans [`LATEST_ABI`] down to [`BASELINE_ABI`] and stops there: below the baseline is
/// a refusal, not a lower rung. Written out rather than derived because `ABI` is a
/// closed enum with no iterator and no arithmetic — and a literal ladder is the thing
/// an ABI bump must be forced to edit, next to the two constants that bound it.
pub(super) const NEGOTIABLE_ABI: [landlock::ABI; 5] = [
    LATEST_ABI,
    landlock::ABI::V8,
    landlock::ABI::V7,
    landlock::ABI::V6,
    BASELINE_ABI,
];

/// Every right the kernel is asked to *handle* at `abi`, in one spelling.
///
/// Both halves of the negotiation need this set and they must be the same set:
/// [`kernel_probe`] asks the kernel whether it will hard-require it, and
/// [`requested_at`](super::requested_at) hands it to [`apply`](crate::helper::apply) to
/// install. Written twice they could drift, and the probe would then settle on an ABI
/// by answering a question `apply` does not go on to ask — leaving a right `apply`
/// requested outside what the kernel ever confirmed.
///
/// `from_all` and not an enumeration: a right a future ABI adds lands in the handled set
/// automatically and is therefore *denied* unless some axis confers it, rather than
/// being left unhandled — and Landlock leaves an unhandled access type unrestricted
/// everywhere.
pub(super) fn handled_access(abi: landlock::ABI) -> landlock::BitFlags<landlock::AccessFs> {
    use landlock::Access;

    landlock::AccessFs::from_all(abi)
}

/// Ask the kernel whether it will hard-require the whole of `abi`.
///
/// The real rung test behind [`negotiated_abi`], and the only part of the negotiation
/// that needs a kernel.
///
/// Probing with `create()` builds a ruleset without applying it, so the ladder walks in
/// one process and nothing is restricted until [`apply`](crate::helper::apply) calls
/// `restrict_self`. The kernel's version syscall would be cheaper, but it is `unsafe`
/// and `landlock` keeps its wrapper private — and a probe that asks the same question
/// the real call will ask cannot disagree with it. [`handled_access`] is what keeps
/// that "same question" true by construction.
///
/// The built ruleset is discarded: what is wanted is the verdict, and the one `apply`
/// installs is built from the negotiated ABI afterwards. The error is returned
/// unwrapped — classifying it is [`negotiated_abi_from`]'s decision.
fn kernel_probe(abi: landlock::ABI) -> Result<(), landlock::RulesetError> {
    use landlock::{CompatLevel, Compatible, Ruleset, RulesetAttr};

    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled_access(abi))
        .and_then(|ruleset| ruleset.create())
        .map(|_| ())
}

/// The newest ABI this kernel will hard-require, at or above [`BASELINE_ABI`].
///
/// Asking only for what the kernel confirms it handles makes full enforcement the
/// normal outcome, so partial enforcement becomes the anomaly [`enforcement_verdict`]
/// can refuse. Asking for `LATEST_ABI` best-effort instead would have the kernel
/// silently drop what it lacks, leaving every older kernel `PartiallyEnforced`.
pub(super) fn negotiated_abi() -> Result<landlock::ABI, SandboxError> {
    negotiated_abi_from(kernel_probe)
}

/// Walk [`NEGOTIABLE_ABI`] with `probe` and settle on the first rung it accepts.
///
/// Split from the kernel it used to probe directly, because the decision below is not
/// the walk — it is which errors are an *ABI verdict* and which are not, and that was
/// unreachable without a Landlock-capable host. The mutation this guards against is one
/// arm of the match: a non-verdict error stepping down instead of refusing left both
/// test suites at zero failures.
///
/// What makes that a security bug rather than a style question: stepping down hands
/// back a lower ABI than the kernel supports, every right above it then goes unhandled,
/// and Landlock leaves an unhandled access type unrestricted *everywhere*. It is the
/// silent hole [`BASELINE_ABI`] exists to prevent, arrived at from above.
///
/// `FnMut` rather than `Fn` for the tests' sake alone — it lets a probe record which
/// rungs it was asked about by pushing into a local `Vec`, with no interior mutability.
/// [`kernel_probe`] is a `fn` item, so production is unaffected.
///
/// A kernel below [`BASELINE_ABI`] falls off the end and is refused. That refusal is
/// deliberately a *different* error from the one above: `Unsupported` names the floor,
/// `Landlock` carries the kernel's own reason. Collapsing them would report "ABI 5,
/// Linux 6.10" for a cause that has nothing to do with the baseline.
pub(super) fn negotiated_abi_from(
    mut probe: impl FnMut(landlock::ABI) -> Result<(), landlock::RulesetError>,
) -> Result<landlock::ABI, SandboxError> {
    use landlock::RulesetError;

    for abi in NEGOTIABLE_ABI {
        match probe(abi) {
            Ok(()) => return Ok(abi),
            // The one error that is an ABI verdict: under `HardRequirement`,
            // `handle_access` refuses and names the rights this kernel does not have
            // (`partially incompatible access-rights: .. ResolveUnix`). Only this steps
            // down a rung.
            Err(RulesetError::HandleAccesses(_)) => continue,
            // Anything else says nothing about which ABI the kernel has. Stepping down
            // on it would hand back a lower ABI than the kernel supports, leaving every
            // right above it unhandled — which Landlock leaves unrestricted everywhere.
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
/// `SECURITY.md` promises that a partly applied ruleset is treated as failure, and a
/// partly applied ruleset is one where Landlock left some requested access type
/// unhandled — which leaves that type unrestricted everywhere, the same silent hole
/// [`BASELINE_ABI`] describes.
///
/// Total over `RulesetStatus` rather than a comparison against one variant: that is
/// what the old `== NotEnforced` check was, and it let `PartiallyEnforced` through for
/// as long as it existed. A variant added by a future landlock release now fails to
/// compile instead of landing in an accepting arm.
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
    // Carry the kernel's own reason: "refused" without a cause is unactionable for
    // whoever has to work out which path or access right it objected to.
    SandboxError::Landlock {
        detail: source.to_string(),
    }
}
