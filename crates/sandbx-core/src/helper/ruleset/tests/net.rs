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

/// The direction that would fail *open*, and the one assertion in this file that a kernel-free
/// test can make about it: taking `Unhandled` for a port list leaves TCP unrestricted while
/// the CLI reports an allowlist. `tests/enforcement_network.rs` is where the kernel says so.
#[test]
fn a_port_list_handles_the_axis_and_carries_every_port() {
    let policy = SandboxPolicy::default()
        .allow_network_port(443)
        .allow_network_port(80);

    for net in net_at_both_abis(&policy) {
        let RequestedNet::Ports { rights, ports } = net else {
            panic!("a port allowlist left the network axis unhandled, so TCP is unrestricted");
        };

        assert_eq!(
            ports,
            [443, 80],
            "a port the policy named was not installed"
        );
        assert!(
            !rights.is_empty(),
            "the port rules carry no rights, so Landlock has nothing to permit \
             and the allowlist denies the ports it names"
        );
    }
}

/// The three states must not collapse into two: a mapping that answered the same thing for
/// a port list as for one of the others would pass every test above that it was not the
/// subject of.
///
/// Compared pairwise rather than against a table of expectations, so this stays an
/// observation about the mapping rather than a restatement of it.
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
/// Both rights are needed and neither is enough. Without `ConnectTcp` an allowlisted port is
/// unreachable; without `BindTcp` a command may listen on any port, which an allowlist of
/// outbound ports would not have mentioned.
///
/// Asked at the floor, because that is the weakest kernel this build accepts — and both
/// rights arrived in ABI V4, below it, so the set is never empty.
#[test]
fn the_baseline_abi_handles_both_tcp_rights() {
    let policy = SandboxPolicy::default().allow_network_port(443);

    let RequestedNet::Ports { rights, .. } = requested_at(&policy, BASELINE_ABI).net else {
        panic!("a port allowlist left the network axis unhandled");
    };

    for right in [
        landlock::AccessNet::BindTcp,
        landlock::AccessNet::ConnectTcp,
    ] {
        assert!(
            rights.contains(right),
            "{right:?} is not handled at the ABI floor"
        );
    }
}
