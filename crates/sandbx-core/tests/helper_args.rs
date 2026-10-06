//! The policy has to survive the trip to the helper process as argv.
//!
//! Round-tripping is a security property: a path dropped in encoding becomes a
//! permission the helper never grants, and one wrongly added becomes one it grants
//! by mistake.

use sandbx_core::{HelperArgs, SandboxPolicy};

#[test]
fn round_trips_an_empty_policy() {
    let args = HelperArgs::encode(&SandboxPolicy::default(), "/bin/true", &[], None);
    let decoded = HelperArgs::decode(&args).unwrap();

    assert_eq!(decoded.policy, SandboxPolicy::default());
    assert_eq!(decoded.program, "/bin/true");
    assert!(decoded.args.is_empty());
}

#[test]
fn round_trips_paths_and_network() {
    let policy = SandboxPolicy::default()
        .allow_read("/usr/lib")
        .allow_read("/etc/ssl")
        .allow_write("/tmp/work")
        .allow_read_execute("/bin")
        .allow_network()
        .allow_unix_sockets();

    let args = HelperArgs::encode(&policy, "/bin/sh", &["-c".into(), "echo hi".into()], None);
    let decoded = HelperArgs::decode(&args).unwrap();

    assert_eq!(decoded.policy, policy);
    assert_eq!(decoded.program, "/bin/sh");
    assert_eq!(decoded.args, vec!["-c".to_string(), "echo hi".to_string()]);
}

/// Everything after `--` is the sandboxed command, so a tool argument that looks
/// like a helper flag must not be read as one.
#[test]
fn command_arguments_are_not_parsed_as_helper_flags() {
    let policy = SandboxPolicy::default().allow_read("/usr");

    let args = HelperArgs::encode(
        &policy,
        "/bin/echo",
        &["--allow-network".into(), "--ro".into(), "/etc".into()],
        None,
    );
    let decoded = HelperArgs::decode(&args).unwrap();

    assert_eq!(
        decoded.policy, policy,
        "arguments after `--` must not widen the policy"
    );
    assert_eq!(
        decoded.args,
        vec![
            "--allow-network".to_string(),
            "--ro".to_string(),
            "/etc".to_string()
        ]
    );
}

/// Order and count both: Landlock installs one rule per port, so a port dropped in
/// encoding is a port the command cannot reach while the CLI says it can.
#[test]
fn a_port_list_round_trips() {
    use sandbx_core::NetworkPolicy;

    let policy = SandboxPolicy::default()
        .allow_network_port(443)
        .allow_network_port(80)
        .allow_read("/usr/lib");

    let args = HelperArgs::encode(&policy, "/bin/true", &[], None);
    let decoded = HelperArgs::decode(&args).unwrap();

    assert_eq!(decoded.policy, policy);
    assert_eq!(
        *decoded.policy.network(),
        NetworkPolicy::Ports(vec![443, 80]),
        "the port list came back as a different network state"
    );
}

/// The wire for an unrestricted grant is unchanged, which is what keeps
/// [`round_trips_paths_and_network`] asserting something: a bare flag must not start
/// decoding as a port list of none, which is a narrower policy than it names.
#[test]
fn an_unrestricted_grant_round_trips_as_the_bare_flag() {
    use sandbx_core::NetworkPolicy;

    let args = HelperArgs::encode(
        &SandboxPolicy::default().allow_network(),
        "/bin/true",
        &[],
        None,
    );

    assert!(
        args.iter().any(|arg| arg == "--allow-network"),
        "an unrestricted grant no longer crosses as the bare flag: {args:?}"
    );
    assert_eq!(
        *HelperArgs::decode(&args).unwrap().policy.network(),
        NetworkPolicy::AnyPort
    );
}

/// The refusal reason is matched and not only the failure, because the token after the flag
/// is consumed either way: without the check `--allow-network-port 65536` would be refused
/// anyway, for the missing `--` that `65536` swallowed.
///
/// `65536` is the one that distinguishes `parse::<u16>` from a hand-rolled check with an
/// `as` cast in it, which would truncate it to port 0.
#[test]
fn a_malformed_port_on_the_wire_is_refused() {
    for port in ["", "https", "-1", "65536", "443.0", " 443", "0x1bb"] {
        let args = vec![
            "--allow-network-port".to_string(),
            port.to_string(),
            "--".to_string(),
            "/bin/true".to_string(),
        ];

        let Err(refusal) = HelperArgs::decode(&args) else {
            panic!("{port:?} was accepted as a port");
        };

        assert!(
            matches!(
                refusal,
                sandbx_core::SandboxError::BadHelperArgs { detail }
                    if detail.contains("network port that is not a number")
            ),
            "{port:?} was refused for the wrong reason: {refusal:?}"
        );
    }
}

/// `allow_network_port` skips port 0; this seam refuses it, because `encode` never emits
/// one — so a 0 here means the argv was built by something speaking another protocol.
#[test]
fn port_zero_on_the_wire_is_refused() {
    let args = vec![
        "--allow-network-port".to_string(),
        "0".to_string(),
        "--".to_string(),
        "/bin/true".to_string(),
    ];

    let refusal = HelperArgs::decode(&args).expect_err("port 0 was accepted");

    assert!(
        matches!(
            refusal,
            sandbx_core::SandboxError::BadHelperArgs { detail }
                if detail.contains("network port 0")
        ),
        "refused for the wrong reason: {refusal:?}"
    );
}

/// Carrying on would mean running under a policy other than the intended one.
#[test]
fn a_port_flag_without_a_port_is_refused() {
    let emitted = HelperArgs::encode(
        &SandboxPolicy::default().allow_network_port(443),
        "/bin/true",
        &[],
        None,
    );
    let flag = emitted[0].clone();

    let refusal = HelperArgs::decode(std::slice::from_ref(&flag))
        .expect_err("the port flag was accepted with no port after it");

    assert!(
        matches!(
            refusal,
            sandbx_core::SandboxError::BadHelperArgs { detail }
                if detail.contains("network port flag with no port")
        ),
        "{flag} was refused for the wrong reason: {refusal:?}"
    );
}

#[test]
fn missing_separator_is_rejected() {
    assert!(HelperArgs::decode(&["--ro".into(), "/usr".into()]).is_err());
}

#[test]
fn unknown_flag_is_rejected() {
    let args = vec![
        "--wat".to_string(),
        "--".to_string(),
        "/bin/true".to_string(),
    ];
    assert!(
        HelperArgs::decode(&args).is_err(),
        "an unrecognised flag must fail rather than be ignored"
    );
}

#[test]
fn empty_command_is_rejected() {
    assert!(HelperArgs::decode(&["--".into()]).is_err());
}

/// Walks [`Axis::ALL`] rather than naming flags by hand, so an axis `encode`
/// emits and `decode` refuses fails here without anyone extending the test.
#[test]
fn round_trips_a_grant_on_every_axis() {
    use sandbx_core::Axis;

    for axis in Axis::ALL {
        let policy = SandboxPolicy::default().grant(axis, "/srv/data");

        let args = HelperArgs::encode(&policy, "/bin/true", &[], None);
        let decoded = HelperArgs::decode(&args)
            .unwrap_or_else(|error| panic!("{axis:?} did not survive encoding: {error}"));

        assert_eq!(
            decoded.policy, policy,
            "a grant on {axis:?} came back as a different policy"
        );
    }
}

/// Derived from the table too, so the flag spellings are not restated: a flag
/// `encode` emits is a flag `decode` must police.
#[test]
fn every_axis_rejects_a_path_flag_without_its_path() {
    use sandbx_core::Axis;

    for axis in Axis::ALL {
        let emitted = HelperArgs::encode(
            &SandboxPolicy::default().grant(axis, "/srv"),
            "/bin/true",
            &[],
            None,
        );
        let flag = emitted[0].clone();

        // Matched on the reason: this argv also lacks the `--` separator, so
        // `is_err()` alone would pass with the pathless-flag check removed.
        let refusal = HelperArgs::decode(std::slice::from_ref(&flag))
            .expect_err("{flag} was accepted with no path after it");

        assert!(
            matches!(
                refusal,
                sandbx_core::SandboxError::BadHelperArgs { detail }
                    if detail.contains("path flag with no path")
            ),
            "{flag} was refused for the wrong reason: {refusal:?}"
        );
    }
}

#[test]
fn round_trips_an_env_allowlist() {
    let policy = SandboxPolicy::default()
        .allow_standard_env()
        .allow_env("GIT_AUTHOR_NAME");

    let args = HelperArgs::encode(&policy, "/bin/true", &[], None);
    let decoded = HelperArgs::decode(&args).unwrap();

    assert_eq!(decoded.policy, policy);
}

/// argv is readable by the sandboxed command through its own
/// `/proc/self/cmdline`, so a value here reaches the process the allowlist exists
/// to keep it from.
#[test]
fn the_wire_carries_the_name_and_not_the_value() {
    let args = HelperArgs::encode(
        // Cargo sets `CARGO_MANIFEST_DIR` in this process, so the encoder had a
        // value available to leak.
        &SandboxPolicy::default().allow_env("CARGO_MANIFEST_DIR"),
        "/bin/true",
        &[],
        None,
    );

    assert!(
        args.iter().any(|arg| arg == "CARGO_MANIFEST_DIR"),
        "{args:?}"
    );
    let value = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    assert!(
        !args.iter().any(|arg| arg.contains(&value)),
        "the variable's value reached argv: {args:?}"
    );
}

/// Carrying on would mean running under a policy other than the intended one.
#[test]
fn an_env_flag_without_a_name_is_rejected() {
    let emitted = HelperArgs::encode(
        &SandboxPolicy::default().allow_env("HOME"),
        "/bin/true",
        &[],
        None,
    );
    let flag = emitted[0].clone();

    // Matched on the reason: this argv also lacks the `--` separator, so
    // `is_err()` alone would pass with the check removed.
    let refusal = HelperArgs::decode(std::slice::from_ref(&flag))
        .expect_err("the env flag was accepted with no name after it");

    assert!(
        matches!(
            refusal,
            sandbx_core::SandboxError::BadHelperArgs { detail }
                if detail.contains("env flag with no variable name")
        ),
        "{flag} was refused for the wrong reason: {refusal:?}"
    );
}

/// `allow_env` skips such a name; this seam refuses it, because a name `encode`
/// cannot emit means the argv was built by something speaking another protocol.
#[test]
fn an_env_name_with_an_equals_sign_is_rejected() {
    let args = vec![
        "--env".to_string(),
        "FOO=bar".to_string(),
        "--".to_string(),
        "/bin/true".to_string(),
    ];

    let refusal = HelperArgs::decode(&args).expect_err("`FOO=bar` was accepted as a name");

    assert!(
        matches!(
            refusal,
            sandbx_core::SandboxError::BadHelperArgs { detail }
                if detail.contains("env variable name containing")
        ),
        "refused for the wrong reason: {refusal:?}"
    );
}

/// Load-bearing, not bookkeeping: stage 1 sets `RES_OPTIONS`, so a stage 2 decoding a
/// policy without the hint would refuse the run.
#[test]
fn round_trips_the_resolver_hint() {
    let policy = SandboxPolicy::default()
        .allow_standard_env()
        .hint_dns_over_tcp();

    let args = HelperArgs::encode(&policy, "/bin/true", &[], None);
    let decoded = HelperArgs::decode(&args).unwrap();

    assert!(decoded.policy.hints_dns_over_tcp());
    assert_eq!(decoded.policy, policy);
}

#[test]
fn an_unhinted_policy_emits_no_hint_flag() {
    let args = HelperArgs::encode(&SandboxPolicy::default(), "/bin/true", &[], None);

    assert!(!args.iter().any(|arg| arg == "--dns-over-tcp"), "{args:?}");
}

/// The pair is a constant the policy owns, so the encoder has nothing to read out of the
/// harness and put in argv.
#[test]
fn the_wire_names_no_resolver_value() {
    let args = HelperArgs::encode(
        &SandboxPolicy::default().hint_dns_over_tcp(),
        "/bin/true",
        &[],
        None,
    );

    assert!(!args.iter().any(|arg| arg.contains("use-vc")), "{args:?}");
}

/// The digest an operator writes, in the one form [`sandbx_core::Sha256Digest`] accepts.
const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// It crosses beside the policy and not inside it, so this is the check that it crosses at
/// all — and that the policy came back unchanged next to it.
#[test]
fn round_trips_a_pinned_program() {
    let digest = sandbx_core::Sha256Digest::parse(DIGEST).expect("64 lowercase hex characters");
    let policy = SandboxPolicy::default().allow_read_execute("/bin");

    let args = HelperArgs::encode(&policy, "/bin/true", &[], Some(digest));
    let decoded = HelperArgs::decode(&args).unwrap();

    assert_eq!(decoded.pin, Some(digest));
    assert_eq!(
        decoded.policy, policy,
        "a pin came back as a different policy"
    );
}

#[test]
fn an_unpinned_run_emits_no_pin_flag() {
    let args = HelperArgs::encode(&SandboxPolicy::default(), "/bin/true", &[], None);

    assert!(!args.iter().any(|arg| arg == "--pin-sha256"), "{args:?}");
    assert_eq!(HelperArgs::decode(&args).unwrap().pin, None);
}

/// Carrying on would mean running an image nothing checked.
#[test]
fn a_pin_flag_without_a_digest_is_refused() {
    let refusal = HelperArgs::decode(&["--pin-sha256".into()])
        .expect_err("the pin flag was accepted with no digest after it");

    assert!(
        matches!(
            refusal,
            sandbx_core::SandboxError::BadHelperArgs { detail }
                if detail.contains("pin flag with no digest")
        ),
        "refused for the wrong reason: {refusal:?}"
    );
}

/// Uppercase among them, and that is the one that matters: `encode` emits lowercase, so a
/// wire accepting both spellings would admit a digest sandbx could not have produced.
#[test]
fn a_pin_digest_encode_could_not_emit_is_refused() {
    for hex in [
        &DIGEST[..63],
        &format!("{DIGEST}0")[..],
        &DIGEST.to_uppercase(),
        "not hex at all, though still sixty-four characters long for the parser",
    ] {
        let args = vec![
            "--pin-sha256".to_string(),
            hex.to_string(),
            "--".to_string(),
            "/bin/true".to_string(),
        ];

        let refusal = HelperArgs::decode(&args).expect_err("accepted as a pinned digest");

        assert!(
            matches!(
                refusal,
                sandbx_core::SandboxError::BadHelperArgs { detail }
                    if detail.contains("pin digest that is not")
            ),
            "{hex} was refused for the wrong reason: {refusal:?}"
        );
    }
}

/// Last-wins would quietly choose one of two images named for one program.
#[test]
fn a_second_pin_flag_is_refused() {
    let args = vec![
        "--pin-sha256".to_string(),
        DIGEST.to_string(),
        "--pin-sha256".to_string(),
        DIGEST.to_string(),
        "--".to_string(),
        "/bin/true".to_string(),
    ];

    let refusal = HelperArgs::decode(&args).expect_err("two pin flags were accepted");

    assert!(
        matches!(
            refusal,
            sandbx_core::SandboxError::BadHelperArgs { detail }
                if detail.contains("more than one pin flag")
        ),
        "refused for the wrong reason: {refusal:?}"
    );
}
