//! Building and applying the Landlock filesystem ruleset.
//!
//! [`compat`] is what *this kernel* will enforce: the ABI floor, the ceiling, the ladder
//! between them, the verdict on what came back. [`rights`] is what the *policy* maps to
//! at a given ABI. They meet in [`requested`], because the rights a grant confers depend
//! on which ABI was negotiated. Nothing here restricts this process.

use crate::SandboxError;

mod compat;
mod rights;
#[cfg(test)]
mod tests;

pub(super) use compat::{enforcement_verdict, landlock_failed};

/// Everything [`apply`](super::apply) asks the kernel for, derived from one ABI.
///
/// Both fields must have been built at the same ABI; computing them together makes a
/// disagreement unexpressible. The two directions are not symmetric:
///
/// - rules *above* the handled set: `PathBeneath` narrows the rule, the ruleset comes
///   back `PartiallyEnforced`, and [`enforcement_verdict`] refuses it.
/// - rules *below* it: every right the newer ABI added is silently not granted, so the
///   policy promises more than the kernel is told to allow. Nothing refuses it, and no
///   kernel-free test can see it — `AccessFs::from_all` is constant across V5..V8, so
///   V8→V9 (`ResolveUnix`) is the only rung boundary that moves a bit.
///
/// Destructured by every consumer — the [`Grants`] precedent — so a field added here
/// fails to compile at `apply` instead of being silently ignored.
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
/// The pure half of [`requested`], so the agreement between the two fields is assertable
/// at both ends of the negotiable range without a Landlock-capable host. Private because a
/// caller that can name an ABI here could pass a second one, which [`Requested`] prevents.
fn requested_at(policy: &crate::SandboxPolicy, abi: landlock::ABI) -> Requested<'_> {
    Requested {
        handled: compat::handled_access(abi),
        rules: rights::fs_rules(policy, abi),
    }
}

/// Negotiate an ABI with this kernel and build everything `policy` asks for at it.
///
/// Negotiates rather than taking an ABI, so [`apply`](super::apply) never holds one and
/// loses `Access`/`AccessFs` from its imports — reintroducing the divergence shows up in
/// the diff, which nothing can test without a kernel.
///
/// Fails closed: a kernel below the baseline is refused here, before a ruleset is built.
pub(super) fn requested(policy: &crate::SandboxPolicy) -> Result<Requested<'_>, SandboxError> {
    Ok(requested_at(policy, compat::negotiated_abi()?))
}
