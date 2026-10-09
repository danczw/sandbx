//! Which Landlock ABI this kernel gets, and whether what it enforced counts.
//!
//! The floor, the ceiling and the ladder between them move together, and so does
//! [`enforcement_verdict`], which is only refusable *because* [`negotiated_abi`] asks for
//! nothing the kernel cannot hard-require. What a grant confers at the chosen ABI is
//! [`super::rights`]'s business.

use crate::SandboxError;

/// The Landlock ABI floor [`apply`](crate::helper::apply) refuses to run below, and the
/// ceiling it negotiates up to.
///
/// This pair is the only place the floor `SECURITY.md` claims — ABI 5, Linux 6.10 — is
/// enforced; seven files restate it in prose, that one included, and a bump leaving any of
/// them behind fails `every_prose_copy_of_the_floor_is_current`, which lists them.
///
/// A floor rather than a preference: Landlock leaves any access type *not* in the handled set
/// unrestricted everywhere, so pinning a lower ABI leaves whole categories unguarded. Hence
/// `CompatLevel::HardRequirement`, making an older kernel a refusal instead of a silent hole.
pub(super) const BASELINE_ABI: landlock::ABI = landlock::ABI::V5; // Linux 6.10: IoctlDev

/// Newest ABI [`apply`](crate::helper::apply) negotiates for. See [`BASELINE_ABI`].
pub(super) const LATEST_ABI: landlock::ABI = landlock::ABI::V9; // Linux 7.1: ResolveUnix

/// Every ABI [`negotiated_abi`] will settle for, newest first.
///
/// Spans [`LATEST_ABI`] down to [`BASELINE_ABI`] and stops there: below the baseline is a
/// refusal, not a lower rung. Written out because `ABI` is a closed enum with no iterator and
/// no arithmetic — and a literal ladder is what an ABI bump is forced to edit, next to the two
/// constants that bound it.
pub(super) const NEGOTIABLE_ABI: [landlock::ABI; 5] = [
    LATEST_ABI,
    landlock::ABI::V8,
    landlock::ABI::V7,
    landlock::ABI::V6,
    BASELINE_ABI,
];

/// Every right the kernel is asked to *handle* at `abi`, in one spelling.
///
/// [`kernel_probe`] asks whether the kernel will hard-require this set and
/// [`requested_at`](super::requested_at) hands it to [`apply`](crate::helper::apply) to
/// install, so two spellings could drift and have the probe settle on an ABI by answering a
/// question `apply` never asks.
///
/// `from_all` and not an enumeration, so a right a future ABI adds lands in the handled set
/// and is therefore *denied* unless some axis confers it — Landlock leaves an unhandled
/// access type unrestricted everywhere.
pub(super) fn handled_access(abi: landlock::ABI) -> landlock::BitFlags<landlock::AccessFs> {
    use landlock::Access;

    landlock::AccessFs::from_all(abi)
}

/// Every network right the kernel is asked to handle at `abi`, in one spelling.
///
/// [`handled_access`]'s counterpart, same argument. Both of `BindTcp | ConnectTcp` arrived in
/// ABI V4, below [`BASELINE_ABI`], so the set is never empty here. Whether the axis is handled
/// *at all* is [`net_rules`](super::rights::net_rules)'s decision.
pub(super) fn handled_net_access(abi: landlock::ABI) -> landlock::BitFlags<landlock::AccessNet> {
    use landlock::Access;

    landlock::AccessNet::from_all(abi)
}

/// Ask the kernel whether it will hard-require the whole of `abi`.
///
/// The rung test behind [`negotiated_abi`]. `create()` builds a ruleset without applying it,
/// so the ladder walks in one process and nothing is restricted until
/// [`apply`](crate::helper::apply) calls `restrict_self`. The kernel's version syscall would
/// be cheaper but is `unsafe` with a private `landlock` wrapper, and a probe asking the
/// question the real call will ask cannot disagree with it — which [`handled_access`] keeps
/// true by construction.
///
/// Both axes, and policy-independent in both, so the negotiated ABI stays a property of the
/// kernel rather than of the run: a probe skipping the network axis could pick a rung whose
/// network rights `apply` then hard-requires and is refused for, with no step-down left.
///
/// The error is returned unwrapped — classifying it is [`negotiated_abi_from`]'s. Unsupported
/// network rights arrive as the same `HandleAccesses`, so it needs no new arm.
fn kernel_probe(abi: landlock::ABI) -> Result<(), landlock::RulesetError> {
    use landlock::{CompatLevel, Compatible, Ruleset, RulesetAttr};

    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled_access(abi))
        .and_then(|ruleset| ruleset.handle_access(handled_net_access(abi)))
        .and_then(|ruleset| ruleset.create())
        .map(|_| ())
}

/// The newest ABI this kernel will hard-require, at or above [`BASELINE_ABI`].
///
/// Asking only for what the kernel confirms it handles makes full enforcement the normal
/// outcome, so partial enforcement is the anomaly [`enforcement_verdict`] can refuse.
/// Asking for `LATEST_ABI` best-effort would have the kernel silently drop what it lacks,
/// leaving every older kernel `PartiallyEnforced`.
pub(super) fn negotiated_abi() -> Result<landlock::ABI, SandboxError> {
    negotiated_abi_from(kernel_probe)
}

/// Walk [`NEGOTIABLE_ABI`] with `probe` and settle on the first rung it accepts.
///
/// Split from the kernel it probes because the decision below is not the walk but which
/// errors are an *ABI verdict* — untestable without a Landlock-capable host, and a non-verdict
/// error stepping down instead of refusing is a silent hole both test suites pass.
///
/// `FnMut` rather than `Fn` for the tests' sake alone: it lets a probe record which rungs it
/// was asked about by pushing into a local `Vec`, with no interior mutability.
///
/// A kernel below [`BASELINE_ABI`] falls off the end and is refused with a *different* error
/// from the one above: `Unsupported` names the floor, `Landlock` carries the kernel's own
/// reason. Collapsing them would report "ABI 5, Linux 6.10" for a cause that has nothing to
/// do with the baseline.
pub(super) fn negotiated_abi_from(
    mut probe: impl FnMut(landlock::ABI) -> Result<(), landlock::RulesetError>,
) -> Result<landlock::ABI, SandboxError> {
    use landlock::RulesetError;

    for abi in NEGOTIABLE_ABI {
        match probe(abi) {
            Ok(()) => return Ok(abi),
            // The one error that is an ABI verdict: under `HardRequirement`, `handle_access`
            // refuses and names the rights this kernel lacks (`partially incompatible
            // access-rights: .. ResolveUnix`).
            Err(RulesetError::HandleAccesses(_)) => continue,
            // Anything else says nothing about which ABI the kernel has, and stepping down on
            // it would leave every right above the chosen rung unhandled — which Landlock
            // leaves unrestricted everywhere.
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
/// `SECURITY.md` promises that a partly applied ruleset is treated as failure: it is one where
/// Landlock left a requested access type unhandled, and so unrestricted everywhere.
///
/// Total over `RulesetStatus` rather than a comparison against one variant — `== NotEnforced`
/// lets `PartiallyEnforced` through — so a variant a future landlock release adds fails to
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
    // Carry the kernel's own reason: "refused" alone leaves no clue which path or access
    // right it objected to.
    SandboxError::Landlock {
        detail: source.to_string(),
    }
}
