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
        .allow_read_execute("/bin")
        .allow_network()
        .allow_unix_sockets();

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

/// Every axis must survive the trip, including one added later.
///
/// The three-axis case above names its flags by hand; this one walks
/// [`Axis::ALL`], so an axis that `encode` emits and `decode` refuses — or
/// quietly files under the wrong axis — fails here without anyone remembering to
/// extend the test.
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

/// A path flag with nothing after it is a refusal on every axis, not just `--ro`.
///
/// Derived from the table the same way, so the flag spellings are not restated
/// here either — a flag `encode` emits is a flag `decode` must police.
#[test]
fn a_path_flag_without_its_path_is_rejected_on_every_axis() {
    use sandbx_core::Axis;

    for axis in Axis::ALL {
        let emitted = HelperArgs::encode(
            &SandboxPolicy::default().grant(axis, "/srv"),
            "/bin/true",
            &[],
        );
        let flag = emitted[0].clone();

        assert!(
            HelperArgs::decode(std::slice::from_ref(&flag)).is_err(),
            "{flag} was accepted with no path and no separator after it"
        );
    }
}
