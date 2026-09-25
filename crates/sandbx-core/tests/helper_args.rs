//! The policy has to survive the trip to the helper process as argv.
//!
//! Round-tripping is a security property, not a convenience: a path silently
//! dropped in encoding becomes a permission the helper never grants, and a path
//! wrongly *added* becomes one it grants by mistake.

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
        .allow_network();

    let args = HelperArgs::encode(&policy, "/bin/sh", &["-c".into(), "echo hi".into()]);
    let decoded = HelperArgs::decode(&args).unwrap();

    assert_eq!(decoded.policy, policy);
    assert_eq!(decoded.program, "/bin/sh");
    assert_eq!(decoded.args, vec!["-c".to_string(), "echo hi".to_string()]);
}

/// The separator matters: everything after `--` is the sandboxed command, so a
/// tool argument that looks like a helper flag must not be read as one.
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
fn flag_without_its_value_is_rejected() {
    assert!(HelperArgs::decode(&["--ro".into()]).is_err());
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
