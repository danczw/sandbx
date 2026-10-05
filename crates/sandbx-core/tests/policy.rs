//! Public contract of [`SandboxPolicy`].

use sandbx_core::{NetworkPolicy, SandboxPolicy};

/// If the default ever grants an access, a caller that forgets to configure the
/// policy silently gets an unsandboxed agent.
#[test]
fn default_policy_denies_everything() {
    use sandbx_core::Axis;

    let policy = SandboxPolicy::default();

    // Over the table, so an axis added later is covered the day it is added.
    for axis in Axis::ALL {
        assert!(
            policy.paths(axis).is_empty(),
            "the default policy granted a path on {axis:?}"
        );
    }
    assert_eq!(
        policy.granted_paths().count(),
        0,
        "the default policy yielded a grant"
    );
    assert!(
        !policy.allows_network(),
        "default policy must not grant network access"
    );
    assert_eq!(
        *policy.network(),
        NetworkPolicy::Denied,
        "the default network state is not `Denied`, so a policy nobody configured \
         reaches somewhere"
    );
    assert!(
        !policy.allows_unix_sockets(),
        "default policy must not grant unix-domain sockets"
    );
    assert!(
        policy.allowed_env().is_empty(),
        "default policy must not pass any environment variable through"
    );
}

/// A command cannot start without its interpreter, loader and shared libraries.
#[test]
fn system_executables_grants_what_a_command_needs() {
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

/// `AccessFs::from_read` bundles `Execute` at the Landlock layer, so the
/// separation has to be made here.
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
/// difference between distributions into a failure to sandbox.
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

/// Reaching a host daemon over a socket in the filesystem is not IP egress.
#[test]
fn granting_network_does_not_grant_unix_sockets() {
    let policy = SandboxPolicy::default().allow_network();

    assert!(policy.allows_network());
    assert!(
        !policy.allows_unix_sockets(),
        "network granted unix sockets along with it"
    );
}

/// A port allowlist is a narrowing of egress, not an absence of it.
///
/// `hardening::isolate` reads `allows_network` to decide whether to unshare the network
/// namespace. If a port grant answered no, the command would get an empty netns and the
/// allowlist would permit nothing.
#[test]
fn a_port_grant_allows_network() {
    let policy = SandboxPolicy::default().allow_network_port(443);

    assert!(
        policy.allows_network(),
        "a port grant reads as no network, so the command gets an empty netns and \
         the allowlist reaches nothing"
    );
    assert_eq!(*policy.network(), NetworkPolicy::Ports(vec![443]));
}

/// Order is the caller's and duplicates are the caller's mistake, not a refusal: a script
/// composing flags should get the policy it meant.
#[test]
fn ports_accumulate_and_deduplicate() {
    let policy = SandboxPolicy::default()
        .allow_network_port(443)
        .allow_network_port(80)
        .allow_network_port(443);

    assert_eq!(*policy.network(), NetworkPolicy::Ports(vec![443, 80]));
}

/// Port 0 is skipped, not refused — `allow_env`'s precedent. `bind(0)` asks the kernel to
/// choose a port, which an allowlist cannot express, and `NetPort::new(0, …)` matches
/// nothing, so a rule for it would be a grant that grants nothing.
#[test]
fn port_zero_is_skipped() {
    let only_zero = SandboxPolicy::default().allow_network_port(0);
    assert_eq!(
        *only_zero.network(),
        NetworkPolicy::Denied,
        "port 0 became a grant, so a policy that allowlists nothing reachable \
         still leaves the netns unshared"
    );

    let alongside = SandboxPolicy::default()
        .allow_network_port(443)
        .allow_network_port(0);
    assert_eq!(*alongside.network(), NetworkPolicy::Ports(vec![443]));
}

/// The builder only ever adds reach, so the broader grant wins whichever order they arrive
/// in — a later call cannot narrow what an earlier one opened.
#[test]
fn an_unrestricted_grant_absorbs_a_port_grant() {
    let port_then_any = SandboxPolicy::default()
        .allow_network_port(443)
        .allow_network();
    assert_eq!(*port_then_any.network(), NetworkPolicy::AnyPort);

    let any_then_port = SandboxPolicy::default()
        .allow_network()
        .allow_network_port(443);
    assert_eq!(
        *any_then_port.network(),
        NetworkPolicy::AnyPort,
        "a port grant narrowed an unrestricted one, so a policy reads tighter \
         than the caller asked for"
    );
}

#[test]
fn granting_unix_sockets_does_not_grant_network() {
    let policy = SandboxPolicy::default().allow_unix_sockets();

    assert!(policy.allows_unix_sockets());
    assert!(!policy.allows_network(), "unix sockets granted network too");
}

#[test]
fn granting_a_variable_widens_nothing_else() {
    use sandbx_core::Axis;

    let policy = SandboxPolicy::default().allow_env("CI");

    assert_eq!(policy.allowed_env(), ["CI"]);
    for axis in Axis::ALL {
        assert!(
            policy.paths(axis).is_empty(),
            "an env grant granted a path on {axis:?}"
        );
    }
    assert!(!policy.allows_network(), "an env grant granted network");
    assert!(
        !policy.allows_unix_sockets(),
        "an env grant granted unix sockets"
    );
}

#[test]
fn granting_a_path_passes_no_variable() {
    let policy = SandboxPolicy::default()
        .allow_read("/srv")
        .allow_system_executables();

    assert!(
        policy.allowed_env().is_empty(),
        "a path grant passed a variable through"
    );
}

#[test]
fn allow_env_adds_only_that_name() {
    let policy = SandboxPolicy::default()
        .allow_env("FOO")
        .allow_env("BAR".to_string());

    assert_eq!(policy.allowed_env(), ["FOO", "BAR"]);
}

/// Compared whole and in order: the CLI's `--help` names these seven, so a name
/// added to the constant has to be added here and there too.
#[test]
fn standard_env_is_the_documented_startup_set() {
    let policy = SandboxPolicy::default().allow_standard_env();

    assert_eq!(
        policy.allowed_env(),
        ["PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ"]
    );
}

/// Pinned separately from the whole-set comparison above: without `PATH` a bare
/// program name falls back to the C library's own search path (`/bin:/usr/bin` on
/// glibc), so `cat` still starts and anything installed elsewhere does not.
#[test]
fn standard_env_carries_path() {
    assert!(
        SandboxPolicy::default()
            .allow_standard_env()
            .allowed_env()
            .iter()
            .any(|name| name == "PATH")
    );
}

/// `=` would make the wire format ambiguous, `NUL` cannot cross `exec`, and the
/// empty string can never match (`std::env::var_os("")` is always `None`).
/// Dropping at the gate is what keeps `HelperArgs` round-tripping: nothing
/// `encode` emits is something `decode` refuses. The CLI's `--allow-env` refuses
/// these loudly instead.
#[test]
fn allow_env_skips_a_name_it_could_not_encode() {
    for bad in ["FOO=bar", "FOO\0BAR", "=", "\0", ""] {
        let policy = SandboxPolicy::default().allow_env(bad);

        assert!(
            policy.allowed_env().is_empty(),
            "{bad:?} was accepted as a variable name"
        );
    }
}

#[test]
fn skipping_an_unencodable_name_keeps_the_rest() {
    let policy = SandboxPolicy::default()
        .allow_env("BEFORE")
        .allow_env("BAD=value")
        .allow_env("AFTER");

    assert_eq!(policy.allowed_env(), ["BEFORE", "AFTER"]);
}

/// The three-way claim `SECURITY.md` makes. Compared whole, so a right quietly
/// added to a row fails here and not only where a consumer reads that field.
#[test]
fn axis_grants_are_the_documented_three_way_claim() {
    use sandbx_core::{Axis, Grants};

    for (axis, expected) in [
        (
            Axis::Read,
            Grants {
                read: true,
                write: false,
                execute: false,
            },
        ),
        // Write and nothing else: a drop directory stays unreadable.
        (
            Axis::Write,
            Grants {
                read: false,
                write: true,
                execute: false,
            },
        ),
        // The only axis conferring execute; read comes with it because a program
        // needs its loader's libraries.
        (
            Axis::ReadExecute,
            Grants {
                read: true,
                write: false,
                execute: true,
            },
        ),
    ] {
        assert_eq!(axis.grants(), expected, "{axis:?} grants the wrong rights");
    }
}

/// A grant landing on a second axis is one flag silently widening another.
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

/// Every consumer iterates `granted_paths`: a pair dropped here is a permission
/// silently withheld, and a pair invented is one silently added.
#[test]
fn granted_paths_yields_each_grant_in_axis_order() {
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
