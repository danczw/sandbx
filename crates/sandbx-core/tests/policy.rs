//! Public contract of [`SandboxPolicy`].

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use sandbx_core::{NetworkPolicy, SandboxPolicy, VettedPath};

/// `path`, pinned to the object it names. A grant carries the object the harness measured
/// (#212), so a policy test grants somewhere that exists rather than a spelling no process
/// has to be able to open.
fn vetted(path: impl AsRef<Path>) -> VettedPath {
    VettedPath::vet(path).expect("an existing path to pin the grant to")
}

/// A directory to grant, resolved — `vet` resolves, so a host reaching its temporary
/// directory through a symlink would otherwise pin a path these tests never spelled.
fn scratch() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let root = dir.path().canonicalize().expect("its resolved path");

    (dir, root)
}

/// What a policy granted on `axis`, as paths — the grants also carry an object, which only
/// the tests about the pin itself have anything to say about.
fn granted_on(policy: &SandboxPolicy, axis: sandbx_core::Axis) -> Vec<&Path> {
    policy.paths(axis).iter().map(VettedPath::path).collect()
}

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

/// A command cannot start without its interpreter, loader and shared libraries. Each as it
/// resolves, a merged-`/usr` host spelling `/bin` as a symlink: the grant has to name the
/// directory the helper opens, which is what it would refuse otherwise.
#[test]
fn system_executables_grants_what_a_command_needs() {
    let policy = SandboxPolicy::default().allow_system_executables();

    for expected in ["/usr", "/bin", "/lib"] {
        let Ok(path) = std::path::Path::new(expected).canonicalize() else {
            continue;
        };
        assert!(
            policy
                .executable_paths()
                .iter()
                .any(|granted| granted.path() == path),
            "{expected} exists but was not granted as {}",
            path.display()
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
    let (_dir, root) = scratch();
    let policy = SandboxPolicy::default()
        .allow_read(vetted(&root))
        .allow_write(vetted(&root));

    assert!(
        policy.executable_paths().is_empty(),
        "a read or write grant leaked into the execute axis"
    );
}

#[test]
fn read_execute_grants_both_axes_deliberately() {
    let (_dir, root) = scratch();
    let policy = SandboxPolicy::default().allow_read_execute(vetted(&root));

    assert_eq!(
        granted_on(&policy, sandbx_core::Axis::ReadExecute),
        [root.as_path()]
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

    for granted in policy.executable_paths() {
        assert!(
            granted.path().exists(),
            "{} does not exist here",
            granted.path().display()
        );
    }
}

#[test]
fn system_executables_keeps_what_was_already_granted() {
    let (_dir, root) = scratch();
    let policy = SandboxPolicy::default()
        .allow_write(vetted(&root))
        .allow_system_executables();

    assert_eq!(
        granted_on(&policy, sandbx_core::Axis::Write),
        [root.as_path()]
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

/// `hardening::isolate` reads `allows_network` to decide whether to unshare the network
/// namespace, so a port grant answering no would leave the command in an empty netns with
/// the allowlist permitting nothing.
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

/// `bind(0)` asks the kernel to choose a port, which an allowlist cannot express, and
/// `NetPort::new(0, …)` matches nothing — so a rule for it would grant nothing. Skipped
/// rather than refused, following `allow_env`.
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
    let (_dir, root) = scratch();
    let policy = SandboxPolicy::default()
        .allow_read(vetted(&root))
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

/// `=` would make the wire format ambiguous, `NUL` cannot cross `exec`, and the empty
/// string can never match (`std::env::var_os("")` is always `None`). Dropped at the gate
/// rather than refused, so nothing `encode` emits is something `decode` refuses.
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

    let (_dir, granted) = scratch();

    for axis in Axis::ALL {
        let policy = SandboxPolicy::default().grant(axis, vetted(&granted));

        for other in Axis::ALL {
            let expected: &[&Path] = if other == axis {
                &[granted.as_path()]
            } else {
                &[]
            };
            assert_eq!(
                granted_on(&policy, other),
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

    let (_dir, root) = scratch();
    let at = |name: &str| {
        let path = root.join(name);
        std::fs::create_dir(&path).expect("a directory to grant");
        path
    };
    let (a, b, c, d) = (at("a"), at("b"), at("c"), at("d"));

    let policy = SandboxPolicy::default()
        .allow_read(vetted(&a))
        .allow_write(vetted(&b))
        .allow_read_execute(vetted(&c))
        .allow_read(vetted(&d));

    let visited: Vec<_> = policy
        .granted_paths()
        .map(|(axis, granted)| (axis, granted.path().to_path_buf()))
        .collect();

    assert_eq!(
        visited,
        [
            (Axis::Read, a),
            (Axis::Read, d),
            (Axis::Write, b),
            (Axis::ReadExecute, c),
        ]
    );
}

#[test]
fn dns_over_tcp_imposes_the_resolver_variable() {
    let policy = SandboxPolicy::default().hint_dns_over_tcp();

    assert!(policy.hints_dns_over_tcp());
    assert_eq!(policy.imposed_env(), [("RES_OPTIONS", "use-vc")]);
}

#[test]
fn a_bare_policy_imposes_no_variable() {
    let policy = SandboxPolicy::default();

    assert!(!policy.hints_dns_over_tcp());
    assert!(policy.imposed_env().is_empty());
}

/// Keeps `allowed_env` meaning "names whose values come from the harness", and with it the
/// audit record's `env` count.
#[test]
fn an_imposed_variable_is_not_in_the_allowlist() {
    let policy = SandboxPolicy::default()
        .allow_standard_env()
        .hint_dns_over_tcp();

    assert_eq!(policy.allowed_env().len(), 7);
    assert!(
        !policy
            .allowed_env()
            .iter()
            .any(|name| name == "RES_OPTIONS"),
        "the hint reached the allowlist"
    );
}

/// A hint is not a grant: TCP 53 still has to be named, or the trail would report a port
/// nobody asked for.
#[test]
fn the_resolver_hint_widens_nothing_else() {
    let policy = SandboxPolicy::default().hint_dns_over_tcp();

    assert_eq!(policy.network(), &NetworkPolicy::Denied);
    assert!(!policy.allows_network());
    assert!(!policy.allows_unix_sockets());
    assert_eq!(policy.granted_paths().count(), 0);
}

#[test]
fn permits_env_covers_the_allowlist_and_the_hint() {
    let policy = SandboxPolicy::default()
        .allow_env("FOO")
        .hint_dns_over_tcp();

    for permitted in ["FOO", "RES_OPTIONS"] {
        assert!(
            policy.permits_env(OsStr::new(permitted)),
            "{permitted} was not permitted"
        );
    }
    assert!(
        !policy.permits_env(OsStr::new("BAR")),
        "a name neither allowlisted nor imposed was permitted"
    );
}

/// Otherwise the helper's inherited-environment check would pass a variable no policy
/// asked for.
#[test]
fn an_unhinted_policy_permits_no_resolver_variable() {
    let policy = SandboxPolicy::default().allow_env("FOO");

    assert!(!policy.permits_env(OsStr::new("RES_OPTIONS")));
}

/// Two directories that exist, since a start directory is one a `chdir` would reach.
fn two_roots() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let (dir, root) = scratch();
    let first = root.join("first");
    let second = root.join("second");
    std::fs::create_dir(&first).expect("the first root");
    std::fs::create_dir(&second).expect("the second root");

    (dir, first, second)
}

/// Somewhere the command may act, which is why write comes first: a run granted write on a
/// tree and read elsewhere would otherwise start read-only.
#[test]
fn a_command_starts_in_the_first_writable_root() {
    let (dir, first, second) = two_roots();
    let policy = SandboxPolicy::default()
        .allow_read(vetted(dir.path()))
        .allow_write(vetted(&first))
        .allow_write(vetted(&second));

    assert_eq!(policy.working_root(), Some(first.as_path()));
}

#[test]
fn a_read_only_policy_starts_in_its_first_readable_root() {
    let (_dir, first, second) = two_roots();
    let policy = SandboxPolicy::default()
        .allow_read(vetted(&first))
        .allow_read(vetted(second));

    assert_eq!(policy.working_root(), Some(first.as_path()));
}

/// `--allow-write /dev/null` is an ordinary grant, and a `chdir` to a file fails the spawn.
#[test]
fn a_grant_naming_a_file_is_not_somewhere_to_start() {
    let (_dir, first, second) = two_roots();
    let file = first.join("drop.txt");
    std::fs::write(&file, b"x").expect("a file to grant");

    let policy = SandboxPolicy::default()
        .allow_write(vetted(&file))
        .allow_write(vetted(&second));

    assert_eq!(policy.working_root(), Some(second.as_path()));
}

/// Never the system binaries: they are granted on the execute axis alone, and a command born
/// in `/usr/bin` starts somewhere the operator offered as nobody's workspace.
#[test]
fn an_execute_only_policy_names_nowhere_to_start() {
    let (_dir, first, _) = two_roots();
    let policy = SandboxPolicy::default()
        .allow_read_execute(vetted(first))
        .allow_system_executables();

    assert_eq!(policy.working_root(), None);
}

#[test]
fn a_policy_granting_nothing_names_nowhere_to_start() {
    assert_eq!(SandboxPolicy::default().working_root(), None);
}

/// All four shapes, and decided here rather than in the CLI alone — an embedder writing one
/// meets the refusal too.
#[test]
fn a_name_allowlist_beside_a_reachable_nameserver_is_unenforceable() {
    let bounded = || SandboxPolicy::default().allow_dns("example.com");

    for (policy, expected) in [
        (bounded().hint_dns_over_tcp(), "--dns-over-tcp"),
        (bounded().allow_unix_sockets(), "pathname socket"),
        (bounded().allow_network(), "every port"),
        (
            bounded().allow_network_port(sandbx_core::NAMESERVER_PORT),
            "port 53",
        ),
    ] {
        let reason = policy
            .unbounded_resolution()
            .unwrap_or_else(|| panic!("a nameserver stays reachable and nothing said so"));

        assert!(
            reason.contains(expected),
            "the refusal does not name the route that is still open: {reason}"
        );
    }
}

/// The negative half, so the check above cannot be a method that refuses every bounded policy.
#[test]
fn a_bounded_policy_with_no_route_to_a_nameserver_is_enforceable() {
    for policy in [
        SandboxPolicy::default()
            .allow_dns("example.com")
            .allow_network_port(443),
        SandboxPolicy::default().allow_dns("example.com"),
        SandboxPolicy::default()
            .allow_unix_sockets()
            .allow_network(),
        SandboxPolicy::default(),
    ] {
        assert_eq!(
            policy.unbounded_resolution(),
            None,
            "a policy that bounds what it says was refused"
        );
    }
}

/// Every file the resolver binds over, not `resolv.conf` alone: the collision is a property of
/// being bound over, so a refusal naming one path would leave the other two pinning rules to
/// objects sandbx itself replaces.
#[test]
fn a_grant_naming_a_file_the_resolver_binds_over_is_refused() {
    for bound in sandbx_core::RESOLVER_FILES {
        // A host that does not have the entry has nothing to vet — musl leaves no
        // `nsswitch.conf` — and a grant naming nothing refuses as unpinnable first.
        let Ok(pinned) = VettedPath::vet(bound) else {
            continue;
        };
        let policy = SandboxPolicy::default()
            .allow_dns("example.com")
            .allow_network_port(443)
            .allow_read(vetted(bound));

        // The vetted spelling and not `bound` itself: a grant carries what it canonicalized
        // to, which on a systemd host is the stub `/etc/resolv.conf` points at.
        assert_eq!(
            policy.grant_bound_by_resolver(),
            Some(pinned.path()),
            "a grant on {bound} was not reported, so the pin is measured against sandbx's \
             own copy and the run refuses as a substituted object"
        );
    }
}

/// Over the host's own entries, so where the three files are regular this is the matcher's
/// first arm twice; `resolver`'s `a_symlinked_entry_is_bound_under_the_name_the_bind_lands_on`
/// is where the resolving arm is claimed.
#[test]
fn every_entry_this_host_has_is_bound_under_the_name_it_resolves_to() {
    for bound in sandbx_core::RESOLVER_FILES {
        let Ok(real) = Path::new(bound).canonicalize() else {
            continue;
        };

        assert!(
            sandbx_core::bound_by_resolver(&real),
            "{bound} resolves to {}, which the bind replaces and nothing reported",
            real.display()
        );
    }
}

/// The negative half, and the one shape the refusal must not grow to cover: binding a file
/// inside `/etc` leaves `/etc`'s own inode alone, so the directory grant's pin still holds.
#[test]
fn a_grant_above_the_bind_and_a_bind_with_no_allowlist_are_both_kept() {
    let dns = || SandboxPolicy::default().allow_dns("example.com");

    for policy in [
        dns().allow_read(vetted("/etc")),
        dns().allow_read(vetted("/")),
        // No allowlist, so nothing is bound and the host's own files are what is granted.
        SandboxPolicy::default().allow_read(vetted("/etc/hosts")),
    ] {
        assert_eq!(
            policy.grant_bound_by_resolver(),
            None,
            "a grant the resolver does not bind over was refused"
        );
    }
}
