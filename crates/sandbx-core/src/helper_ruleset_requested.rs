//! What one ABI's negotiation asks the kernel for: the filesystem rules, and the
//! network axis beside them.
//!
//! [`requested`] negotiates and builds together, so the fields cannot come from
//! different ABIs. [`super::compat`] is what this kernel will enforce, [`super::rights`]
//! what the policy maps to at a given ABI.

use crate::SandboxError;

use super::{compat, rights};

/// Everything [`apply`](crate::helper::exec::apply) asks the kernel for, derived from one ABI.
///
/// Every field must have been built at the same ABI; computing them together makes a
/// disagreement unexpressible. The two directions are not symmetric:
///
/// - rules *above* the handled set: `PathBeneath` narrows the rule, the ruleset comes back
///   `PartiallyEnforced`, and [`enforcement_verdict`](compat::enforcement_verdict) refuses it.
/// - rules *below* it: every right the newer ABI added is silently not granted, so the policy
///   promises more than the kernel is told to allow. Nothing refuses it, and no kernel-free
///   test can see it — `AccessFs::from_all` is constant across V5..V8, so V8→V9
///   (`ResolveUnix`) is the only rung boundary that moves a bit.
///
/// Destructured by every consumer — the [`Grants`] precedent — so a field added here fails to
/// compile at `apply` instead of being silently ignored.
///
/// [`Grants`]: crate::Grants
pub(in crate::helper) struct Requested<'policy> {
    /// Every right the kernel is told to police. See [`compat::handled_access`].
    pub(in crate::helper) handled: landlock::BitFlags<landlock::AccessFs>,
    /// One rule per grant, as `(axis, path, rights)`. See [`rights::fs_rules`].
    pub(in crate::helper) rules: Vec<(
        crate::Axis,
        rights::RuleTarget<'policy>,
        landlock::BitFlags<landlock::AccessFs>,
    )>,
    /// What to ask for on the network axis. See [`rights::net_rules`].
    pub(in crate::helper) net: RequestedNet<'policy>,
}

/// What [`apply`](crate::helper::exec::apply) asks Landlock for on the network axis.
///
/// A sibling of `handled` and not a widening of it: `BitFlags<AccessFs>` and
/// `BitFlags<AccessNet>` are distinct types, and an *empty* `BitFlags<AccessNet>` would be the
/// fail-open spelling of [`Unhandled`](Self::Unhandled) — which it is not, since handling the
/// axis with no port rule denies every TCP port. The enum makes rights and ports inseparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::helper) enum RequestedNet<'policy> {
    /// Do not hand Landlock the network axis; TCP is bounded by whatever is below it.
    Unhandled,
    /// Hand it over, permitting `ports` and refusing every other.
    Ports {
        /// Every network right the kernel is told to police. See
        /// [`compat::handled_net_access`].
        handled: landlock::BitFlags<landlock::AccessNet>,
        /// What each port rule permits — a fixed subset of `handled`, so a right a future ABI
        /// adds is policed everywhere and granted nowhere. See [`rights::net_rules`].
        granted: landlock::BitFlags<landlock::AccessNet>,
        /// The allowlist, already free of port 0 — `SandboxPolicy::allow_network_port`
        /// skips it and `HelperArgs::decode` refuses it.
        ports: &'policy [u16],
    },
}

/// What `policy` asks for at `abi`, with no kernel involved.
///
/// The pure half of [`requested`], so the agreement between the fields is assertable at both
/// ends of the negotiable range without a Landlock-capable host. `pub(super)`, and deliberately
/// not `pub(in crate::helper)` like its three neighbours here: a caller that can name an ABI
/// could pass a second one, which [`Requested`] prevents. Widening it would hand `apply` that
/// caller's job.
pub(super) fn requested_at(policy: &crate::SandboxPolicy, abi: landlock::ABI) -> Requested<'_> {
    Requested {
        handled: compat::handled_access(abi),
        rules: rights::fs_rules(policy, abi),
        net: rights::net_rules(policy, abi),
    }
}

/// Negotiate an ABI with this kernel and build everything `policy` asks for at it.
///
/// Negotiates rather than taking an ABI, so [`apply`](crate::helper::exec::apply) never holds one
/// and loses `Access`/`AccessFs` from its imports — reintroducing the divergence shows up in
/// the diff, which nothing can test without a kernel. Fails closed: a kernel below the
/// baseline is refused here, before a ruleset is built.
pub(in crate::helper) fn requested(
    policy: &crate::SandboxPolicy,
) -> Result<Requested<'_>, SandboxError> {
    Ok(requested_at(policy, compat::negotiated_abi()?))
}
