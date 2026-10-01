//! Public contract of [`SandboxPolicy`].

use sandbx_core::SandboxPolicy;

/// Every other sandbox behaviour builds on this: if the default ever grants an
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
    assert!(
        !policy.allows_unix_sockets(),
        "default policy must not grant unix-domain sockets"
    );
}

/// A command cannot start without its interpreter, loader and shared
/// libraries, so every caller that spawns anything needs these paths.
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

/// The separation #8 is about: reaching a host daemon over a socket in the
/// filesystem is not IP egress, so one grant must not imply the other.
#[test]
fn granting_network_does_not_grant_unix_sockets() {
    let policy = SandboxPolicy::default().allow_network();

    assert!(policy.allows_network());
    assert!(
        !policy.allows_unix_sockets(),
        "network granted unix sockets along with it"
    );
}

#[test]
fn granting_unix_sockets_does_not_grant_network() {
    let policy = SandboxPolicy::default().allow_unix_sockets();

    assert!(policy.allows_unix_sockets());
    assert!(!policy.allows_network(), "unix sockets granted network too");
}

/// The three-way claim `SECURITY.md` makes, asserted rather than restated.
///
/// Read grants read and nothing else; write grants write and nothing else; the
/// one named exception, read+execute, grants both of those and still no write.
/// Every consumer derives its own vocabulary from this table, so this is the
/// assertion that pins what all of them mean.
#[test]
fn axis_grants_are_the_documented_three_way_claim() {
    use sandbx_core::Axis;

    let read = Axis::Read.grants();
    assert!(read.read);
    assert!(!read.write, "a read grant conferred write");
    assert!(!read.execute, "a read grant conferred execute (#19)");

    let write = Axis::Write.grants();
    assert!(write.write);
    assert!(!write.read, "a write grant conferred read (#49)");
    assert!(!write.execute, "a write grant conferred execute");

    let read_execute = Axis::ReadExecute.grants();
    assert!(read_execute.execute);
    assert!(
        read_execute.read,
        "read+execute must confer read: a program needs its loader's libraries"
    );
    assert!(!read_execute.write, "an execute grant conferred write");
}

/// Execute is the one right no other axis hands out.
#[test]
fn only_one_axis_confers_execute() {
    use sandbx_core::Axis;

    let conferring: Vec<_> = Axis::ALL
        .into_iter()
        .filter(|axis| axis.grants().execute)
        .collect();

    assert_eq!(
        conferring,
        [Axis::ReadExecute],
        "execute must come from exactly one axis, named for it"
    );
}

/// A grant must land on the axis it was made on and on no other — otherwise one
/// flag silently widens another, which is the whole of #19 and #49.
#[test]
fn a_grant_lands_only_on_its_own_axis() {
    use sandbx_core::Axis;

    let granted = std::path::PathBuf::from("/srv/data");

    for axis in Axis::ALL {
        let policy = SandboxPolicy::default().grant(axis, &granted);

        for other in Axis::ALL {
            let expected: &[std::path::PathBuf] = if other == axis {
                std::slice::from_ref(&granted)
            } else {
                &[]
            };
            assert_eq!(
                policy.paths(other),
                expected,
                "a grant on {axis:?} showed up under {other:?}"
            );
        }
    }
}

/// `granted_paths` is what every consumer iterates, so it must yield each grant exactly
/// once: a pair dropped here is a permission silently withheld, and a pair
/// invented is one silently added.
#[test]
fn granted_paths_yields_every_grant_once_in_axis_order() {
    use sandbx_core::Axis;

    let policy = SandboxPolicy::default()
        .allow_read("/a")
        .allow_write("/b")
        .allow_read_execute("/c")
        .allow_read("/d");

    let visited: Vec<_> = policy
        .granted_paths()
        .map(|(axis, path)| (axis, path.display().to_string()))
        .collect();

    assert_eq!(
        visited,
        [
            (Axis::Read, "/a".to_string()),
            (Axis::Read, "/d".to_string()),
            (Axis::Write, "/b".to_string()),
            (Axis::ReadExecute, "/c".to_string()),
        ]
    );
}

/// Default-deny, stated over the table rather than axis by axis: a new axis is
/// covered by this the day it is added.
#[test]
fn the_default_policy_grants_no_path_on_any_axis() {
    use sandbx_core::Axis;

    let policy = SandboxPolicy::default();

    for axis in Axis::ALL {
        assert!(
            policy.paths(axis).is_empty(),
            "the default policy granted a path on {axis:?}"
        );
    }
    assert_eq!(policy.granted_paths().count(), 0);
}
