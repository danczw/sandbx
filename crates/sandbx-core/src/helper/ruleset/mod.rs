//! Building and applying the Landlock filesystem ruleset.
//!
//! Split along the question each half answers: [`compat`] is what *this kernel* will
//! enforce — the ABI floor, the ceiling, the ladder between them, the verdict on what
//! came back — and [`rights`] is what the *policy* maps to, kernel-independent but for
//! the ABI it is handed. They meet in [`requested`], because the rights a grant
//! confers depend on which ABI was negotiated. Nothing here restricts this process.

use crate::SandboxError;

mod compat;
mod rights;
#[cfg(test)]
mod tests;

pub(super) use compat::{enforcement_verdict, landlock_failed};

/// Everything [`apply`](super::apply) asks the kernel for, derived from one ABI.
///
/// The two fields have to agree about which ABI they were built at; computing them
/// together is what makes a disagreement unexpressible rather than merely discouraged.
/// The two directions are not symmetric:
///
/// - rules *above* the handled set — `PathBeneath` narrows the rule, the ruleset comes
///   back `PartiallyEnforced`, and [`enforcement_verdict`] refuses it. Loud.
/// - rules *below* it — every right the newer ABI added is silently not granted, so a
///   policy promises more than the kernel is told to allow. Nothing refuses it, and no
///   kernel-free test can see it either: `AccessFs::from_all` is constant across
///   V5..V8, so V8→V9 (`ResolveUnix`) is the only rung boundary that moves a bit. That
///   asymmetry is why this is a type and not a test.
///
/// Destructured by every consumer rather than read field by field — the [`Grants`]
/// precedent — so a field added here fails to compile at `apply` instead of being
/// silently ignored.
///
/// [`Grants`]: crate::Grants
pub(super) struct Requested<'policy> {
    /// Every right the kernel is told to police. See [`compat::handled_access`].
    pub(super) handled: landlock::BitFlags<landlock::AccessFs>,
    /// One rule per grant, as `(axis, path, rights)`. See [`rights::fs_rules`].
    pub(super) rules: Vec<(
        crate::Axis,
        &'policy std::path::Path,
        landlock::BitFlags<landlock::AccessFs>,
    )>,
}

/// What `policy` asks for at `abi`, with no kernel involved.
///
/// The pure half of [`requested`], split off so the agreement between the two fields
/// is assertable at both ends of the negotiable range without a Landlock-capable host.
///
/// Private, and `apply` gets [`requested`] instead: a caller that can name an ABI here
/// is a caller that could pass a second one, which is what [`Requested`] exists to
/// prevent.
fn requested_at(policy: &crate::SandboxPolicy, abi: landlock::ABI) -> Requested<'_> {
    Requested {
        handled: compat::handled_access(abi),
        rules: rights::fs_rules(policy, abi),
    }
}

/// Negotiate an ABI with this kernel and build everything `policy` asks for at it.
///
/// Does the negotiation itself rather than taking an ABI, so [`apply`](super::apply)
/// never holds one: with no ABI in scope there is no second ABI to pass, and `apply`
/// loses `Access`/`AccessFs` from its imports — so reintroducing the divergence means
/// reintroducing two imports, which a reviewer sees in the diff. Nothing tests what
/// `apply` hands to `handle_access`, and nothing can without a kernel.
///
/// Fails closed: a kernel below the baseline is refused here, before a ruleset is
/// built and long before anything is restricted.
pub(super) fn requested(policy: &crate::SandboxPolicy) -> Result<Requested<'_>, SandboxError> {
    Ok(requested_at(policy, compat::negotiated_abi()?))
}
