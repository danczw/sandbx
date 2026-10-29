//! The mutation check, the same one `context/decision-policy.md` does for a table change.
//! Each mutation below was run rather than reasoned about, and the `passes` column is the
//! load-bearing one:
//!
//! ```text
//! default becomes unconditional (drop the paths_given guard)
//!    ──► a_path_flag_replaces_the_working_directory      fails   ◄── the rule itself
//!        each_allow_flag_widens_only_its_own_axis        fails
//!        allow_flags_repeat_to_grant_several_paths       fails
//!        a_path_flag_runs_from_the_home_directory        fails   ◄── on an explicit policy
//!        the_default_matches_what_sandbox_run_derives    passes  ◄── derives its expectation
//!
//! default removed entirely
//!    ──► the_working_directory_is_readable_and_writable  fails
//!        an_env_flag_keeps_the_working_directory         fails
//!        refuses_to_run_from_the_filesystem_root         fails
//!        refuses_to_run_from_the_home_directory          fails
//!
//! home arm narrowed from starts_with to equality
//!    ──► a_directory_holding_home_is_refused             fails
//!        a_refusal_names_the_flags_to_type_instead       fails
//!
//! holds_home_directories arm deleted
//!    ──► the_home_parents_are_refused_with_no_home_set       fails
//!        the_home_parents_are_refused_when_home_is_elsewhere fails
//!        a_refusal_names_the_flags_to_type_instead           fails
//!        refuses_to_run_from_home_whatever_home_names        fails
//!        an_unset_home_still_derives_a_root                  passes  ◄── /app is no home par.
//!        a_named_home_leaves_a_neighbour_alone               passes
//!
//! that arm re-gated on homes.is_empty() (the draft-2 hole)
//!    ──► the_home_parents_are_refused_when_home_is_elsewhere fails   ◄── $HOME=/var/lib/svc
//!        refuses_to_run_from_home_whatever_home_names        fails
//!        the_home_parents_are_refused_with_no_home_set       passes  ◄── the gate is satisfied
//!
//! the child reading deleted
//!    ──► an_unset_home_refuses_a_child_of_one                fails
//!        an_unresolvable_home_refuses_a_child_of_one         fails
//!        a_home_that_is_no_directory_refuses_a_child_of_one  fails
//!        a_refusal_names_the_flags_to_type_instead           fails
//!        the_home_parents_are_refused_with_no_home_set       passes
//!
//! that gate re-read off the path list, !usable ──► paths.is_empty() (the #154 hole)
//!    ──► an_unresolvable_home_refuses_a_child_of_one         fails
//!        a_home_that_is_no_directory_refuses_a_child_of_one  fails
//!        an_unset_home_refuses_a_child_of_one                passes  ◄── the gate is satisfied
//!        refuses_to_run_from_home_whatever_home_names        passes  ◄── /home is a home par.
//!
//! usable stops asking for a directory (HOME=/dev/null)
//!    ──► a_home_that_is_no_directory_refuses_a_child_of_one  fails
//!        an_unresolvable_home_refuses_a_child_of_one         passes  ◄── it never resolved
//!
//! usable stops asking that $HOME holds no homes (HOME=/home, the #162 hole)
//!    ──► a_home_that_holds_homes_refuses_a_child_of_one      fails
//!        a_home_that_is_no_directory_refuses_a_child_of_one  fails   ◄── HOME=/ holds homes
//!        an_unresolvable_home_refuses_a_child_of_one         passes  ◄── it never resolved
//!
//! that test widened from SHARED_HOME_PARENTS to all four (HOME=/root)
//!    ──► a_root_home_still_derives_under_itself             fails   ◄── /root/app refuses
//!        a_home_that_holds_homes_refuses_a_child_of_one      passes  ◄── /home is in both
//!
//! UnnamedHome stops naming the $HOME it rejected
//!    ──► a_home_that_holds_homes_refuses_a_child_of_one      fails
//!        an_unset_home_refuses_a_child_of_one                passes  ◄── nothing to name
//!
//! the written form dropped when $HOME does not resolve
//!    ──► an_unresolvable_home_is_still_compared              fails
//!        an_unresolvable_home_refuses_a_child_of_one         passes  ◄── the other field
//!
//! the Silverblue second spelling dropped
//!    ──► a_symlinked_home_names_both_forms                   fails
//!
//! an unusable $HOME refused outright instead of deriving
//!    ──► an_unresolvable_home_still_runs_from_a_project      fails
//!        refuses_to_run_from_home_whatever_home_names        fails   ◄── the wrong refusal
//!        an_unset_home_still_runs_from_a_project             passes  ◄── nothing to refuse on
//!
//! overlap arm deleted, or tested one way round
//!    ──► a_directory_overlapping_the_system_binaries_is_refused  fails
//!        refuses_to_run_from_the_system_binaries                 fails
//!        a_directory_named_like_a_system_one_is_a_valid_root     passes
//! ```
//!
//! Deleting the overlap arm and testing it one way round fail the same two tests, which is
//! the signal being asked for: the loop covers each granted path *and* a directory under it,
//! so a one-way test is detected as the absence it is. That loop reads [`granted`] rather
//! than naming paths, because `allow_system_executables` skips a path the host lacks —
//! `/lib64` is absent on arm64, which failed a hardcoded list on CI's aarch64 leg while
//! passing x86_64.
//!
//! Two things the first mutation shows. Dropping the guard breaks tests in two suites that
//! never mention the default — `each_allow_flag_widens_only_its_own_axis` and
//! `allow_flags_repeat_to_grant_several_paths` both assert on the whole policy — so
//! suppression is pinned by tests older than it. And
//! `the_default_matches_what_sandbox_run_derives` passes, because both sides of the
//! comparison mutate together: that is the derived-expectation trap
//! `context/decision-policy.md` names, and it is why it is a cross-subcommand consistency
//! test and not the one pinning what the default *is*.
//!
//! The gap the tests do not close, narrowed by #154 and #162: [`named_homes`] takes `$HOME`
//! as a value and is unit-tested over every shape — unset, empty, relative, unresolvable,
//! resolving to a non-directory, resolving to `/`, resolving to a place homes live, resolving
//! to a real home, and symlinked, that last against a `tempfile` symlink rather than argued
//! from a Silverblue host. All that is left reading the live process is [`current_root`]'s
//! two lookups themselves, `getcwd` and `var_os("HOME")`; `sandbx-cli`'s `tests/cwd_policy.rs`
//! covers what it can of them by setting `HOME` on the spawned binary.

use std::ffi::OsString;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};
use std::{env, fs, io};

use sandbx_core::{SandboxPolicy, VettedPath};

use super::{
    Homes, OwnedPath, ResolvedPath, absolute, named_homes, owned_paths, reaches_owned, resolved,
    vetted_root,
};
use crate::PolicyError;

/// What every run may already execute, which `policy()` passes from the live policy.
fn granted() -> Vec<VettedPath> {
    SandboxPolicy::default()
        .allow_system_executables()
        .executable_paths()
        .to_vec()
}

/// A `$HOME` that named these and resolved to a directory.
fn homes(paths: &[&str]) -> Homes {
    Homes {
        paths: paths.iter().map(PathBuf::from).collect(),
        usable: true,
    }
}

/// A `$HOME` that named these and resolved to nothing a home can be.
fn unusable(paths: &[&str]) -> Homes {
    Homes {
        usable: false,
        ..homes(paths)
    }
}

/// No `$HOME` at all.
fn no_home() -> Homes {
    unusable(&[])
}

/// An absolute path guaranteed absent, where `/nonexistent` is only a convention.
fn missing() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("no-such-directory")
}

/// A cwd as `current_root` hands it over — a fixture spelling is not canonical just by
/// being written out (`/home` is a symlink to `/var/home` on an ostree host).
fn at(cwd: impl AsRef<Path>) -> ResolvedPath {
    resolved(cwd.as_ref())
}

fn root(cwd: impl AsRef<Path>, homes: &Homes) -> Result<ResolvedPath, PolicyError> {
    vetted_root(&at(cwd), homes, &granted(), &[]).cloned()
}

/// An environment of the pairs given, and nothing else.
pub(crate) fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
    let pairs: Vec<(String, OsString)> = pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), OsString::from(*value)))
        .collect();

    move |name| {
        pairs
            .iter()
            .find(|(stored, _)| stored == name)
            .map(|(_, value)| value.clone())
    }
}

/// The owned paths a host with this `$HOME` and nothing else set would have.
fn owned_under(home: &str) -> Vec<OwnedPath> {
    owned_paths(&env(&[("HOME", home)]))
}

/// Whether `granted` reaches one of `owned`, the cwd a test runs from being readable.
/// Through both steps [`Grants::policy`] puts a flag through, so what is asserted here
/// is what a flag actually gets compared in.
pub(crate) fn reaches(granted: impl AsRef<Path>, owned: &[OwnedPath]) -> bool {
    let granted = resolved(
        &absolute(granted.as_ref(), &std::env::current_dir).expect("a readable working directory"),
    );

    reaches_owned(&granted, owned).is_some()
}

/// A working directory nothing can read, for the one spelling that needs one.
fn no_cwd() -> impl Fn() -> io::Result<PathBuf> {
    || Err(io::Error::from(io::ErrorKind::NotFound))
}

#[test]
fn the_working_directory_is_the_default_root() {
    assert_eq!(
        root("/srv/app", &homes(&["/home/u"])).expect("an ordinary project directory"),
        at("/srv/app"),
        "the default root is not the working directory"
    );
}

/// `~/code/project` is the whole use case, so only standing *at* `$HOME` may refuse.
#[test]
fn a_subdirectory_of_home_is_a_valid_root() {
    assert_eq!(
        root("/home/u/code/project", &homes(&["/home/u"])).expect("a project under home"),
        at("/home/u/code/project"),
        "a project inside home was refused"
    );
}

/// A no-flag run from `$HOME` hands over `~/.ssh` and every dotfile, which for
/// `agent-run` is a prompt injection's blast radius.
#[test]
fn the_home_directory_is_refused_as_a_root() {
    let error = root("/home/u", &homes(&["/home/u"])).expect_err("home as a root");

    assert!(
        matches!(error, PolicyError::HomeDirectory { .. }),
        "{error} is not the home refusal"
    );
    assert!(
        error.to_string().contains("your home directory /home/u"),
        "{error} does not say which directory it refused"
    );
}

#[test]
fn a_directory_holding_home_is_refused() {
    for parent in ["/home", "/Users", "/var/home"] {
        let home = format!("{parent}/u");
        let error = root(parent, &homes(&[&home])).expect_err("a parent of home");

        assert!(
            error
                .to_string()
                .contains("which holds your home directory"),
            "{error} reads as though {parent} were home itself"
        );
    }
}

#[test]
fn the_filesystem_root_is_refused() {
    let error = root("/", &homes(&["/home/u"])).expect_err("the filesystem root");

    assert!(
        matches!(error, PolicyError::FilesystemRoot),
        "{error} is not the root refusal"
    );
}

/// Fedora Silverblue ships `/home -> /var/home`, so a guard comparing one form of
/// `$HOME` is bypassed by standing in the other.
#[test]
fn a_symlinked_home_is_still_refused() {
    let both = homes(&["/var/home/u", "/home/u"]);

    for cwd in ["/var/home/u", "/home/u"] {
        let error = root(cwd, &both).expect_err("either spelling of home");
        assert!(
            matches!(error, PolicyError::HomeDirectory { .. }),
            "{error} let {cwd} through"
        );
    }
}

#[test]
fn an_unset_home_still_refuses_the_root() {
    let error = root("/", &no_home()).expect_err("the filesystem root");

    assert!(
        matches!(error, PolicyError::FilesystemRoot),
        "{error} is not the root refusal"
    );
}

/// `HOME` is routinely unset under a systemd unit, cron, or `docker exec`.
#[test]
fn the_home_parents_are_refused_with_no_home_set() {
    for cwd in ["/home", "/Users", "/var/home", "/root", "/var"] {
        let error = root(cwd, &no_home()).expect_err("a well-known home location");

        assert!(
            matches!(error, PolicyError::HomeParent { .. }),
            "{error} let {cwd} through with no HOME set"
        );
    }
}

/// The gap the exact rule leaves: a service account's `HOME=/var/lib/svc` matches
/// nothing under `/home`, so gating this arm on a set `HOME` lets `/home` through.
#[test]
fn the_home_parents_are_refused_when_home_is_elsewhere() {
    for cwd in ["/home", "/Users", "/var/home", "/root"] {
        let error = root(cwd, &homes(&["/var/lib/svc"])).expect_err("a well-known home location");

        assert!(
            matches!(error, PolicyError::HomeParent { .. }),
            "{error} let {cwd} through for a $HOME that names somewhere else"
        );
    }
}

/// With no `$HOME` naming it, a child of `/home` is indistinguishable from a home
/// directory whatever it is called.
#[test]
fn an_unset_home_refuses_a_child_of_one() {
    for cwd in ["/home/other", "/Users/other", "/root/work"] {
        let error = root(cwd, &no_home()).expect_err("something shaped like a home directory");

        assert!(
            matches!(error, PolicyError::UnnamedHome { .. }),
            "{error} let {cwd} through with no HOME set"
        );
        assert!(
            error
                .to_string()
                .contains("with no HOME naming a home directory"),
            "{error} does not say why {cwd} could not be told apart"
        );
    }
}

/// A `$HOME` that resolves to nothing must not satisfy the stand-in gate (#154).
#[test]
fn an_unresolvable_home_refuses_a_child_of_one() {
    let homes = named_homes(Some(&missing()));

    for cwd in ["/home/other", "/Users/other", "/root/work"] {
        let error = root(cwd, &homes).expect_err("something shaped like a home directory");

        assert!(
            matches!(error, PolicyError::UnnamedHome { .. }),
            "{error} let {cwd} through for a $HOME that resolves to nothing"
        );
    }
}

/// Resolving is not being a home: `/dev/null` and `/` both do, and neither names one.
#[test]
fn a_home_that_is_no_directory_refuses_a_child_of_one() {
    for home in ["/dev/null", "/"] {
        let homes = named_homes(Some(Path::new(home)));

        let error =
            root("/home/other", &homes).expect_err("something shaped like a home directory");
        assert!(
            matches!(error, PolicyError::UnnamedHome { .. }),
            "{error} let /home/other through for $HOME={home}"
        );
    }
}

/// Where homes live is nobody's home, so it must not satisfy the stand-in gate (#162).
#[test]
fn a_home_that_holds_homes_refuses_a_child_of_one() {
    assert!(
        Path::new("/home").is_dir(),
        "no /home to resolve, so this test asserts nothing"
    );
    let homes = named_homes(Some(Path::new("/home")));

    let error = root("/home/other", &homes).expect_err("something shaped like a home directory");
    assert!(
        matches!(error, PolicyError::UnnamedHome { .. }),
        "{error} let /home/other through for $HOME=/home"
    );
    // The refusal fires on a `$HOME` that *is* set, where "no usable HOME" read as unset.
    assert!(
        error
            .to_string()
            .contains("HOME=/home names no home directory"),
        "{error} does not name the $HOME it rejected"
    );
}

/// `/root` is in [`HOME_PARENTS`] and is also root's own home, which a container sets.
#[test]
fn a_root_home_still_derives_under_itself() {
    assert!(
        Path::new("/root").is_dir(),
        "no /root to resolve, so this test asserts nothing"
    );
    let homes = named_homes(Some(Path::new("/root")));

    assert!(homes.usable, "$HOME=/root named no usable home");
    assert_eq!(
        root("/root/app", &homes).expect("root's own project directory"),
        at("/root/app"),
        "a root container with $HOME=/root could not derive a root under it"
    );
}

/// An unprovisioned home is still a path the cwd can hold, and outside
/// [`HOME_PARENTS`] no other arm covers it.
#[test]
fn an_unresolvable_home_is_still_compared() {
    let homes = named_homes(Some(Path::new("/srv/people/alice")));

    let error = root("/srv/people", &homes).expect_err("a directory holding a home");
    assert!(
        matches!(error, PolicyError::HomeDirectory { .. }),
        "{error} let /srv/people through while $HOME named a home under it"
    );
}

#[test]
fn an_absolute_home_that_resolves_is_usable() {
    let real = Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .expect("the package directory this test is compiled from");

    assert_eq!(
        named_homes(Some(&real)),
        homes(&[real.to_str().expect("a UTF-8 package path")]),
        "a resolved $HOME did not name itself as a usable home"
    );
}

#[test]
fn a_symlinked_home_names_both_forms() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let real = directory.path().join("var-home");
    let link = directory.path().join("home");
    fs::create_dir(&real).expect("a home to link to");
    unix_fs::symlink(&real, &link).expect("a symlinked home");

    let named = named_homes(Some(&link));

    assert!(named.usable, "a symlinked home resolved to no usable home");
    assert!(
        named.paths.contains(&link) && named.paths.contains(&real),
        "{named:?} does not hold both spellings of the symlinked home"
    );
}

#[test]
fn an_unresolvable_home_is_not_usable() {
    let named = named_homes(Some(&missing()));

    assert!(
        !named.usable,
        "{named:?} called a home it cannot resolve usable"
    );
}

#[test]
fn a_relative_or_empty_home_names_nothing() {
    for home in ["relative/path", ""] {
        assert_eq!(
            named_homes(Some(Path::new(home))),
            no_home(),
            "{home:?} named a home that settles no resolved cwd"
        );
    }
}

#[test]
fn an_unset_home_names_nothing() {
    assert_eq!(
        named_homes(None),
        no_home(),
        "an unset HOME named a home anyway"
    );
}

/// Write plus the execute every run already has is the pair `Axis::grants` keeps apart —
/// tested on both the path itself and a directory under it, since a merged-`/usr` host
/// resolves `/bin` to `/usr/bin`. Driven off `granted()` rather than a name list: arm64
/// has no `/lib64`, and `allow_system_executables` skips a path this host lacks.
#[test]
fn a_directory_overlapping_the_system_binaries_is_refused() {
    assert!(
        !granted().is_empty(),
        "no granted path to overlap with, so this test asserts nothing"
    );

    for granted in granted() {
        let path = granted.path();
        for cwd in [path.to_path_buf(), path.join("src/app")] {
            let error = root(&cwd, &homes(&["/home/u"])).expect_err("a system path");

            assert!(
                matches!(error, PolicyError::SystemExecutables { .. }),
                "{error} let {} through as a writable root",
                cwd.display()
            );
        }
    }
}

/// Whole-component, so the rule claims no directory merely spelled like a system one.
#[test]
fn a_directory_named_like_a_system_one_is_a_valid_root() {
    for cwd in ["/usrlocal", "/libexec", "/srv/usr"] {
        assert_eq!(
            root(cwd, &homes(&["/home/u"])).expect("an ordinary project directory"),
            at(cwd),
            "prefix matching crossed a component boundary"
        );
    }
}

/// With a `$HOME` to compare, standing in a neighbour's directory is the operator's
/// business and not sandbx's to guess at.
#[test]
fn a_named_home_leaves_a_neighbour_alone() {
    assert_eq!(
        root("/home/other", &homes(&["/home/u"])).expect("a named home identifies itself"),
        at("/home/other"),
        "the degraded rule fired where $HOME was readable"
    );
}

/// The container case the default exists for: `HOME` unset, cwd `/app`.
#[test]
fn an_unset_home_still_derives_a_root() {
    assert_eq!(
        root("/app", &no_home()).expect("a container working directory"),
        at("/app"),
        "an unset HOME refused an ordinary directory"
    );
}

#[test]
fn a_refusal_names_the_flags_to_type_instead() {
    let refusals = [
        root("/", &no_home()).expect_err("the filesystem root"),
        root("/home/u", &homes(&["/home/u"])).expect_err("home as a root"),
        root("/home", &homes(&["/home/u"])).expect_err("a parent of home"),
        root("/home", &homes(&["/var/lib/svc"])).expect_err("a home parent"),
        root("/home/other", &no_home()).expect_err("something shaped like a home"),
        root("/usr", &homes(&["/home/u"])).expect_err("a system executable path"),
    ];

    for error in refusals {
        let message = error.to_string();
        assert!(
            message.contains("--allow-read") && message.contains("--allow-write"),
            "{message} does not name the flags to type instead"
        );
    }
}

/// Both roots, since one rule covers them and naming one would pass with the other unguarded.
#[test]
fn both_owned_roots_are_derived_from_home() {
    let owned: Vec<PathBuf> = owned_under("/home/u")
        .into_iter()
        .map(|owned| owned.path)
        .collect();

    assert_eq!(
        owned,
        [
            PathBuf::from("/home/u/.local/state/sandbx/sessions"),
            PathBuf::from("/home/u/.config/sandbx/credentials.toml"),
        ],
        "the owned roots are not the two sandbx writes"
    );
}

/// No `$HOME` leaves sandbx nowhere to keep either root, so an ordinary run still derives.
#[test]
fn a_host_with_no_home_owns_no_path() {
    assert!(
        owned_paths(&env(&[])).is_empty(),
        "a host with no HOME claimed an owned path anyway"
    );
}

/// #184 and #173: the one flag it takes, on the axis each issue was reported with.
#[test]
fn a_grant_above_an_owned_root_is_refused() {
    let owned = owned_under("/home/u");

    for granted in ["/home/u", "/home/u/.config", "/home/u/.local/state"] {
        assert!(
            reaches(granted, &owned),
            "{granted} reached no owned path, so the grant would be honoured"
        );
    }
}

/// The other direction, and the exact path: one transcript is the history, and the file is
/// the key.
#[test]
fn a_grant_inside_an_owned_root_is_refused() {
    let owned = owned_under("/home/u");

    for granted in [
        "/home/u/.local/state/sandbx/sessions",
        "/home/u/.local/state/sandbx/sessions/01JA.jsonl",
        "/home/u/.config/sandbx/credentials.toml",
    ] {
        assert!(
            reaches(granted, &owned),
            "{granted} reached no owned path, so the grant would be honoured"
        );
    }
}

/// Whole-component, so the rule claims no path merely spelled like an owned one.
#[test]
fn a_path_named_like_an_owned_root_is_granted() {
    let owned = owned_under("/home/u");

    for granted in [
        "/home/u/.config/sandbx-notes",
        "/home/u/.local/state/sandbx/sessions-old",
        "/home/other/.config/sandbx",
    ] {
        assert!(
            !reaches(granted, &owned),
            "{granted} was taken for an owned path"
        );
    }
}

/// `--allow-read .` from the config directory is the shortest spelling of #184, and
/// lexically it matches nothing.
#[test]
fn a_relative_grant_is_resolved_before_comparing() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let home = directory.path().canonicalize().expect("a resolved home");
    let config = home.join(".config").join("sandbx");
    fs::create_dir_all(&config).expect("a config directory to stand in");

    let owned = owned_paths(&env(&[("HOME", home.to_str().expect("a UTF-8 home"))]));
    let relative = config.join("..").join("sandbx");

    assert!(
        reaches(&relative, &owned),
        "{} reached no owned path once resolved",
        relative.display()
    );
}

/// The grant `--session` creates during the run it was given to: nothing on disk resolves
/// it, so joining the cwd is the only thing that can.
#[test]
fn a_relative_grant_resolves_before_it_exists() {
    let cwd = std::env::current_dir().expect("a test runs from a real directory");
    let owned = vec![OwnedPath {
        path: cwd.join("nothing-stored-yet/sandbx/sessions"),
        holds: "the session transcripts a resumed run replays to the model",
    }];

    assert!(
        reaches("nothing-stored-yet", &owned),
        "a relative grant naming no existing directory reached no owned path"
    );
}

/// A relative grant joined to nothing reached no owned path, and so was honoured (#203).
#[test]
fn an_unreadable_cwd_refuses_a_relative_grant() {
    let error = absolute(Path::new("sandbx"), &no_cwd())
        .expect_err("a relative grant with no working directory to resolve it against");

    assert!(
        matches!(error, PolicyError::UnresolvableGrant { .. }),
        "{error} is not the unresolvable-grant refusal"
    );
    assert!(
        error.to_string().contains("absolute path"),
        "{error} does not say what to write instead"
    );
}

/// The other half of #203: needing no cwd, an absolute grant survives an unreadable one.
#[test]
fn an_absolute_grant_needs_no_cwd() {
    let owned = owned_under("/home/u");

    let granted = resolved(
        &absolute(Path::new("/srv/app"), &no_cwd())
            .expect("an absolute grant needs no working directory"),
    );

    assert!(
        reaches_owned(&granted, &owned).is_none(),
        "an ordinary absolute grant reached an owned path"
    );
}

/// Fedora Silverblue ships `/home -> /var/home`, so granting one spelling of an owned root
/// must not bypass the other.
#[test]
fn a_symlinked_home_still_refuses_an_owned_root() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let real = directory.path().join("var-home");
    let link = directory.path().join("home");
    fs::create_dir_all(real.join(".config").join("sandbx")).expect("a real home");
    unix_fs::symlink(&real, &link).expect("a symlinked home");

    // Owned under the link, granted through the real path: two strings, one directory.
    let owned = owned_paths(&env(&[("HOME", link.to_str().expect("a UTF-8 home"))]));

    assert!(
        reaches(&real, &owned),
        "the real path reached no owned path named through the link"
    );
}

/// The derived default is a write grant too, so standing in the session directory is #173
/// with no flag.
#[test]
fn a_root_inside_an_owned_path_is_refused() {
    let owned = owned_under("/home/u");
    let cwd = at("/home/u/.local/state/sandbx/sessions");

    let error = vetted_root(&cwd, &homes(&["/home/u"]), &granted(), &owned)
        .expect_err("the session directory as a root");

    assert!(
        matches!(error, PolicyError::CwdReachesOwned { .. }),
        "{error} is not the owned-path refusal"
    );
}
