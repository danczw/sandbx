//! The policy has to survive the trip to the helper process as argv.
//!
//! Round-tripping is a security property: a path dropped in encoding becomes a
//! permission the helper never grants, and one wrongly added becomes one it grants
//! by mistake.

use sandbx_core::{HelperArgs, SandboxPolicy};

#[test]
fn round_trips_an_empty_policy() {
    let args = HelperArgs::encode(&SandboxPolicy::default(), "/bin/true", &[]);
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

    let args = HelperArgs::encode(&policy, "/bin/sh", &["-c".into(), "echo hi".into()]);
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

        let args = HelperArgs::encode(&policy, "/bin/true", &[]);
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

    let args = HelperArgs::encode(&policy, "/bin/true", &[]);
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
