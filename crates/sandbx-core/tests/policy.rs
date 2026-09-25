//! Public contract of [`SandboxPolicy`].

use sandbx_core::SandboxPolicy;

/// The foundational guarantee: a policy nobody configured grants nothing.
///
/// Every other sandbox behaviour builds on this. If the default ever grants an
/// access, a caller that forgets to configure the policy silently gets an
/// unsandboxed agent.
#[test]
fn default_policy_denies_everything() {
    let policy = SandboxPolicy::default();

    assert!(
        policy.readable_paths().is_empty(),
        "default policy must not grant read access to any path"
    );
    assert!(
        policy.writable_paths().is_empty(),
        "default policy must not grant write access to any path"
    );
    assert!(
        policy.executable_paths().is_empty(),
        "default policy must not grant execute access to any path"
    );
    assert!(
        !policy.allows_network(),
        "default policy must not grant network access"
    );
}

/// A command cannot start without its interpreter, loader and shared
/// libraries, so every caller that spawns anything needs these paths. They were
/// being re-listed per caller; one definition means one place to be wrong.
#[test]
fn system_executables_grants_the_paths_a_command_needs_to_start() {
    let policy = SandboxPolicy::default().allow_system_executables();

    for expected in ["/usr", "/bin", "/lib"] {
        let path = std::path::Path::new(expected);
        if !path.exists() {
            continue;
        }
        assert!(
            policy.executable_paths().contains(&path.to_path_buf()),
            "{expected} exists but was not granted"
        );
    }
}

/// Being able to run `ls` must not imply being able to overwrite it, or reach
/// the network. This grant is deliberately one axis wide.
#[test]
fn system_executables_grants_no_write_or_network() {
    let policy = SandboxPolicy::default().allow_system_executables();

    assert!(
        !policy.executable_paths().is_empty(),
        "granted nothing at all"
    );
    assert!(policy.writable_paths().is_empty(), "granted write access");
    assert!(!policy.allows_network(), "granted network access");
}

/// The point of #19: `allow_read` means read, and nothing else. `from_read`
/// bundles `Execute` at the Landlock layer, so the separation has to be made
/// here — a read grant must never reach the executable axis.
#[test]
fn read_and_write_grants_do_not_confer_execute() {
    let policy = SandboxPolicy::default()
        .allow_read("/srv/data")
        .allow_write("/srv/data");

    assert!(
        policy.executable_paths().is_empty(),
        "a read or write grant leaked into the execute axis"
    );
}

/// The one grant that does confer it, and only for the path named.
#[test]
fn read_execute_grants_both_axes_deliberately() {
    let policy = SandboxPolicy::default().allow_read_execute("/opt/tool");

    assert_eq!(
        policy.executable_paths(),
        [std::path::PathBuf::from("/opt/tool")]
    );
    assert!(
        policy.readable_paths().is_empty(),
        "read+execute is one axis; it must not also populate the read-only list"
    );
}

/// Landlock rejects a rule for a path that does not exist, which would turn a
/// portability difference between distributions into a failure to sandbox.
#[test]
fn system_executables_skips_paths_this_system_lacks() {
    let policy = SandboxPolicy::default().allow_system_executables();

    for path in policy.executable_paths() {
        assert!(path.exists(), "{} does not exist here", path.display());
    }
}

/// It widens an existing policy rather than replacing it.
#[test]
fn system_executables_keeps_what_was_already_granted() {
    let policy = SandboxPolicy::default()
        .allow_write("/srv/out")
        .allow_system_executables();

    assert_eq!(
        policy.writable_paths(),
        [std::path::PathBuf::from("/srv/out")]
    );
}
