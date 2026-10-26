//! Public contract of [`SandboxedCommand`].

use sandbx_core::{HELPER_FLAG, SandboxPolicy, SandboxedCommand};

/// `path`, pinned to the object it names — the shape every grant takes (#212).
fn vetted(path: impl AsRef<std::path::Path>) -> sandbx_core::VettedPath {
    sandbx_core::VettedPath::vet(path).expect("an existing path to pin the grant to")
}

/// A scratch directory whose own path is already resolved, so granting it grants a path that
/// opens as itself — which the helper requires. `$TMPDIR` is a symlink on some hosts.
fn scratch() -> tempfile::TempDir {
    let root = std::env::temp_dir()
        .canonicalize()
        .expect("the temporary directory exists");
    tempfile::Builder::new()
        .tempdir_in(root)
        .expect("a temporary directory")
}

/// What lets a shipped sandbx need no second binary installed.
#[test]
fn defaults_to_re_executing_this_image_by_inode() {
    let (helper, argv) = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
        .command_line()
        .unwrap();

    assert_eq!(helper, std::path::Path::new("/proc/self/exe"));
    assert_eq!(argv.first().map(String::as_str), Some(HELPER_FLAG));

    let image = std::fs::metadata(&helper).expect("/proc must be mounted for the re-exec");

    assert!(
        image.is_file(),
        "the default helper path does not resolve to the running image"
    );
}

/// Positional and ahead of the policy: `HelperArgs::decode` refuses a flag it does not
/// recognise, so `exec_sandboxed` splits this one off before decoding.
#[test]
fn asks_the_helper_to_report_on_the_channel() {
    let (_, argv) = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
        .helper("/nonexistent/helper")
        .command_line()
        .unwrap();

    assert_eq!(
        argv.get(1).map(String::as_str),
        Some("--sandbx-audit-stdin"),
        "the audit flag must directly follow the dispatch flag: {argv:?}"
    );
}

/// A grant lost here is a permission the tool silently does not get; one invented is one
/// it should not have had.
#[test]
fn carries_the_policy_into_the_command_line() {
    let (_, argv) = SandboxedCommand::new(
        "/bin/sh",
        SandboxPolicy::default().allow_read(vetted("/usr")),
    )
    .arg("-c")
    .arg("true")
    .helper("/nonexistent/helper")
    .command_line()
    .unwrap();

    assert!(argv.windows(2).any(|w| w == ["--ro", "/usr"]));
    assert_eq!(&argv[argv.len() - 3..], &["/bin/sh", "-c", "true"]);
}

/// The clearing happens in a process the helper spawns, which knows only what argv
/// told it.
#[test]
fn carries_the_env_allowlist_into_the_command_line() {
    let (_, argv) = SandboxedCommand::new(
        "/bin/true",
        SandboxPolicy::default().allow_env("GIT_AUTHOR_NAME"),
    )
    .helper("/nonexistent/helper")
    .command_line()
    .unwrap();

    assert!(argv.windows(2).any(|w| w == ["--env", "GIT_AUTHOR_NAME"]));
}

/// One calling convention for every helper: two would let a binary implement the
/// wrong one and fail only at runtime.
#[test]
fn explicit_helper_still_takes_the_dispatch_flag() {
    let (helper, argv) = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
        .helper("/some/helper")
        .command_line()
        .unwrap();

    assert_eq!(helper, std::path::Path::new("/some/helper"));
    assert_eq!(argv.first().map(String::as_str), Some(HELPER_FLAG));
}

/// The obligation `command_line` documents: the start directory is not in the argv, so a
/// caller that spawns this itself gets its own working directory and not the policy's.
#[test]
fn the_start_directory_is_not_in_the_command_line() {
    let dir = scratch();
    let root = dir.path().to_str().unwrap().to_string();

    let policy = SandboxPolicy::default().allow_write(vetted(dir.path()));
    let (_, argv) = SandboxedCommand::new("/bin/true", policy.clone())
        .helper("/nonexistent/helper")
        .command_line()
        .unwrap();

    assert_eq!(
        policy.working_root(),
        Some(dir.path()),
        "the policy this asserts about does not name a start directory"
    );
    assert_eq!(
        argv.iter().filter(|arg| **arg == root).count(),
        1,
        "the start directory crossed in the argv as well: {argv:?}"
    );
}

/// Helper mode runs in-process only where it refuses before restricting anything: a real
/// `HELPER_FLAG` run would restrict this test process and `exec`.
#[test]
fn an_ordinary_invocation_is_not_helper_mode() {
    let argv = ["sandbx", "sandbox-run", "--", "/bin/true"].map(std::ffi::OsString::from);
    let mut ran = false;

    let code = sandbx_core::with_helper_dispatch(argv, || {
        ran = true;
        std::process::ExitCode::SUCCESS
    });

    assert!(ran);
    assert_eq!(code, std::process::ExitCode::SUCCESS);
}

#[test]
fn an_argv_with_no_arguments_is_not_helper_mode() {
    for argv in [vec![], vec![std::ffi::OsString::from("sandbx")]] {
        let mut ran = false;

        let code = sandbx_core::with_helper_dispatch(argv, || {
            ran = true;
            std::process::ExitCode::SUCCESS
        });

        assert!(ran, "a too-short argv must be reported as an ordinary run");
        assert_eq!(code, std::process::ExitCode::SUCCESS);
    }
}

/// An inner stage given no supervisor pid refuses before restricting anything.
#[test]
fn a_failed_helper_run_never_runs_the_ordinary_main() {
    let argv = ["sandbx", sandbx_core::HELPER_INNER_FLAG].map(std::ffi::OsString::from);
    let mut ran = false;

    let code = sandbx_core::with_helper_dispatch(argv, || {
        ran = true;
        std::process::ExitCode::SUCCESS
    });

    assert!(
        !ran,
        "a failed helper run fell through to the ordinary path"
    );
    assert_eq!(code, std::process::ExitCode::FAILURE);
}

/// `command_line` and not `output`: this argv is the one an embedder may spawn itself.
#[test]
fn a_policy_that_bounds_no_name_cannot_be_turned_into_an_argv() {
    let policy = SandboxPolicy::default()
        .allow_dns("example.com")
        .allow_unix_sockets();

    let refusal = SandboxedCommand::new("/bin/true", policy)
        .command_line()
        .expect_err("an argv was built for a policy whose allowlist bounds nothing");

    assert_eq!(refusal.label(), "unbounded_resolution", "got {refusal:?}");
}

/// At this level and not the CLI's: an embedder spawning the argv itself would otherwise reach
/// the helper, where the pin is measured against the copy sandbx bound and the run refuses as
/// a substituted object — a false `GrantReplaced` on a legitimate pair.
#[test]
fn a_policy_granting_a_file_its_own_resolver_replaces_cannot_be_turned_into_an_argv() {
    let policy = SandboxPolicy::default()
        .allow_dns("example.com")
        .allow_network_port(443)
        .allow_read(vetted("/etc/hosts"));

    let refusal = SandboxedCommand::new("/bin/true", policy)
        .command_line()
        .expect_err("an argv was built for a grant the run's own resolver binds over");

    assert_eq!(
        refusal.label(),
        "grant_bound_by_resolver",
        "got {refusal:?}"
    );

    // The remedy and not only the refusal: a grant on the directory is legal beside the flag,
    // and a library caller has nowhere but the source to learn that.
    let message = refusal.to_string();
    assert!(
        message.contains("/etc/hosts") && message.contains("directory"),
        "the refusal names no path to go and look at, or no way forward: {message}"
    );
}
