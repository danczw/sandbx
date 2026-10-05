//! Which of the three network states hands Landlock the network axis, and what the port
//! rules carry when it does.
//!
//! Asked through [`requested_at`] rather than `net_rules`, for the reason
//! [`rules`](super::rules) gives: that is what `apply` installs.

use super::{BASELINE_ABI, LATEST_ABI, RequestedNet, SandboxPolicy, requested_at};

/// What `policy` asks for on the network axis, at both ends of the negotiable range.
///
/// Both rungs, because an ABI-dependent `Unhandled` would be a port allowlist that silently
/// stopped being enforced on one kernel and not another.
fn net_at_both_abis(policy: &SandboxPolicy) -> [RequestedNet<'_>; 2] {
    [
        requested_at(policy, BASELINE_ABI).net,
        requested_at(policy, LATEST_ABI).net,
    ]
}

/// The default policy is confined by an empty network namespace, which is strictly stronger
/// than any port list. Handling the axis here would also cost it `bind` on loopback.
#[test]
fn a_denied_policy_does_not_handle_the_network_axis() {
    for net in net_at_both_abis(&SandboxPolicy::default()) {
        assert_eq!(net, RequestedNet::Unhandled);
    }
}

/// The direction that would fail *closed*: handling the axis for a policy that named no
/// ports denies every TCP port, which is narrower than `--allow-network` says.
#[test]
fn an_unrestricted_grant_does_not_handle_the_network_axis() {
    for net in net_at_both_abis(&SandboxPolicy::default().allow_network()) {
        assert_eq!(
            net,
            RequestedNet::Unhandled,
            "an unrestricted grant handed Landlock the network axis, which denies \
             every port it was not given a rule for"
        );
    }
}

/// The direction that would fail *open*: taking `Unhandled` for a port list leaves TCP
/// unrestricted while the CLI reports an allowlist. `tests/enforcement_network.rs` is where
/// a real kernel says so.
#[test]
fn a_port_list_handles_the_axis_and_carries_every_port() {
    let policy = SandboxPolicy::default()
        .allow_network_port(443)
        .allow_network_port(80);

    for net in net_at_both_abis(&policy) {
        let RequestedNet::Ports { granted, ports, .. } = net else {
            panic!("a port allowlist left the network axis unhandled, so TCP is unrestricted");
        };

        assert_eq!(
            ports,
            [443, 80],
            "a port the policy named was not installed"
        );
        assert!(
            !granted.is_empty(),
            "the port rules carry no rights, so Landlock has nothing to permit \
             and the allowlist denies the ports it names"
        );
    }
}

/// The three states must not collapse into two. Compared pairwise rather than against a
/// table of expectations, so this stays an observation about the mapping rather than a
/// restatement of it.
#[test]
fn the_three_network_cases_map_to_distinct_requests() {
    let denied = SandboxPolicy::default();
    let any = SandboxPolicy::default().allow_network();
    let ports = SandboxPolicy::default().allow_network_port(443);

    let requests = [
        requested_at(&denied, LATEST_ABI).net,
        requested_at(&any, LATEST_ABI).net,
        requested_at(&ports, LATEST_ABI).net,
    ];

    // `Denied` and `AnyPort` deliberately agree — see `net_rules` — so only the port list is
    // required to differ. It has to differ from *both*, which is the whole claim.
    assert_ne!(requests[2], requests[0]);
    assert_ne!(requests[2], requests[1]);
}

/// Spelled out rather than read from `handled_net_access`: a test deriving its expectation
/// from the same call the code makes asserts only that the code is self-consistent.
///
/// Neither right is enough alone — without `ConnectTcp` an allowlisted port is unreachable,
/// without `BindTcp` a command may listen on any port. Asked at the floor, the weakest
/// kernel this build accepts, where both are still present because both arrived in ABI V4.
#[test]
fn a_port_rule_grants_both_tcp_rights_and_nothing_else() {
    let policy = SandboxPolicy::default().allow_network_port(443);

    let RequestedNet::Ports { granted, .. } = requested_at(&policy, BASELINE_ABI).net else {
        panic!("a port allowlist left the network axis unhandled");
    };

    assert_eq!(
        granted,
        landlock::AccessNet::BindTcp | landlock::AccessNet::ConnectTcp,
        "the rights a port rule grants are not exactly the two an allowlist promises"
    );
}

/// The asymmetry `net_rules` exists to keep: the handled set is `from_all`, so a network
/// right a future ABI adds is policed, while the port rules grant a fixed pair, so that
/// right arrives permitted on no port. Taking `handled` for both would hand a UDP or raw
/// right to every port the operator allowlisted, which is the direction that fails open.
///
/// Asserted as a subset relation rather than against two literals, because the claim is
/// about which way they may differ, not about today's values — and Landlock refuses a rule
/// carrying a right the ruleset does not handle, so the inclusion is also a precondition.
#[test]
fn a_port_rule_grants_no_more_than_the_kernel_is_told_to_police() {
    let policy = SandboxPolicy::default().allow_network_port(443);

    for abi in [BASELINE_ABI, LATEST_ABI] {
        let RequestedNet::Ports {
            handled, granted, ..
        } = requested_at(&policy, abi).net
        else {
            panic!("a port allowlist left the network axis unhandled");
        };

        assert!(
            handled.contains(granted),
            "a port rule grants {granted:?}, which is not inside the handled set \
             {handled:?}, so Landlock refuses the rule"
        );
    }
}
