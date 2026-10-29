use super::*;
use std::{fs, io};

/// A `/proc/pid/stat` line with the executable name substituted in. Long enough to carry
/// the fields *after* the parent, so a parse landing past field 4 returns a plausible
/// number rather than `None`.
fn stat_line(comm: &str) -> String {
    format!(
        "4242 ({comm}) S 1234 4242 4242 34816 4321 4194304 1537 0 0 0 \
         1 2 0 0 20 0 1 0 9876 4337664 1234 18446744073709551615"
    )
}

/// The control for the rest of this module; on its own it pins almost nothing, since
/// counting four tokens from the left passes it too.
#[test]
fn the_parent_pid_follows_the_process_state() {
    let stat = stat_line("bash");

    assert_eq!(
        ppid_from_stat(&stat),
        Some("1234"),
        "the parent is field 4 of {stat:?}"
    );
}

/// Counting from the left returns the process state, which never equals a pid, so
/// every run under a binary whose name has a space would be refused.
#[test]
fn a_space_in_the_executable_name_shifts_nothing() {
    let stat = stat_line("my program");

    assert_eq!(
        ppid_from_stat(&stat),
        Some("1234"),
        "a space in the executable name shifted the parse: {stat:?}"
    );
}

/// Why the split is on the *last* `)`: splitting on the first stops inside such a
/// name and reads its remainder as the fields after it.
#[test]
fn a_paren_in_the_executable_name_truncates_nothing() {
    let stat = stat_line("weird ) name");

    assert_eq!(
        ppid_from_stat(&stat),
        Some("1234"),
        "a parenthesis in the executable name truncated the parse: {stat:?}"
    );
}

/// The one way [`confirm_supervisor`] could fail open: `) 1 2 3` makes the numeric fields
/// look like they start three tokens early, so a left-counting parse returns a short,
/// plausible integer that could *agree* with the expected pid.
///
/// Robustness, not a defence against a chosen name: the line is this process's own and
/// `confirm_supervisor` runs before the `exec`, so field 2 is sandbx's helper binary.
#[test]
fn an_executable_name_shaped_like_a_field_is_not_one() {
    let stat = stat_line(") 1 2 3");

    assert_eq!(
        ppid_from_stat(&stat),
        Some("1234"),
        "a name shaped like the fields after it was read as one: {stat:?}"
    );
}

/// Counting from the left finds a fourth token in the first case, and would hand
/// [`confirm_supervisor`] a pid out of an unparseable line.
#[test]
fn a_line_with_no_executable_name_yields_nothing() {
    for stat in ["4242 bash S 1234 4242", "not a stat line", ""] {
        assert_eq!(
            ppid_from_stat(stat),
            None,
            "{stat:?} has no executable name to split on, so it names no parent"
        );
    }
}

/// The state letter is not a parent pid.
#[test]
fn a_line_that_stops_before_the_parent_yields_nothing() {
    for stat in ["4242 (bash)", "4242 (bash) S", "4242 (bash) S "] {
        assert_eq!(
            ppid_from_stat(stat),
            None,
            "{stat:?} stops before field 4, so it names no parent"
        );
    }
}

/// The one test that reads a line the kernel wrote, checked against the same number
/// reported under a *name* rather than a position — so the synthetic expectations above
/// are anchored outside this module.
///
/// An anchor and not a discriminator: a neighbouring field can happen to equal the
/// parent, and under a test harness `pgrp` usually does. The cases above pin the index.
///
/// Against `status` and not `getppid`, which the kernel translates into the caller's pid
/// namespace and reports as 0 for PID 1 of a nested one — the exact skew
/// [`confirm_supervisor`] works around, so leaning on it would break this test inside the
/// sandbox.
///
/// The two files are read in two syscalls, so a parent exiting between them would leave
/// `PPid:` naming init while the stat line names the old pid — unguarded, cargo being the
/// parent under `cargo test` and outliving the harness.
#[test]
fn the_parse_agrees_with_procfs_under_another_name() {
    let stat = fs::read_to_string("/proc/self/stat").expect("procfs is mounted");
    let status = fs::read_to_string("/proc/self/status").expect("procfs is mounted");

    let named = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .map(str::trim)
        .expect("/proc/self/status reports a PPid");

    assert_eq!(
        ppid_from_stat(&stat),
        Some(named),
        "the stat parse and PPid: disagree about this process's parent; \
         the stat line was {stat:?}"
    );
}

#[test]
fn a_refused_bounding_set_drop_reports_a_degradation() {
    let (step, detail) = drop_bounding_set(|| Err("Operation not permitted (os error 1)"))
        .expect("a refused PR_CAPBSET_DROP must name itself as degraded");

    assert_eq!(
        step,
        Degradation::CapabilityBoundingSet,
        "a refused bounding-set drop reported the wrong mechanism"
    );
    assert!(
        detail.contains("left as inherited"),
        "the detail does not say what the sandbox is left with: {detail:?}"
    );
    assert!(
        detail.contains("os error 1"),
        "the detail dropped the kernel's own reason: {detail:?}"
    );
}

#[test]
fn a_bounding_set_that_drops_reports_nothing() {
    assert_eq!(
        drop_bounding_set(|| Ok::<(), String>(())),
        None,
        "a successful drop put a degradation on the trail"
    );
}

#[test]
fn the_identity_map_is_written_in_kernel_order() {
    let mut written = Vec::new();

    let degraded = map_identity_into_userns_with(1000, 2000, |path, contents| {
        written.push((path.to_string(), contents));
        Ok(())
    });

    assert_eq!(degraded, None, "every write succeeded, so nothing degraded");
    assert_eq!(
        written,
        vec![
            ("/proc/self/setgroups".to_string(), "deny".to_string()),
            ("/proc/self/gid_map".to_string(), "2000 2000 1".to_string()),
            ("/proc/self/uid_map".to_string(), "1000 1000 1".to_string()),
        ],
        "setgroups must be denied before an unprivileged gid_map write, and each map \
         names one id mapped to itself"
    );
}

#[test]
fn a_refused_map_reports_a_degradation_and_stops() {
    for refused in [
        "/proc/self/setgroups",
        "/proc/self/gid_map",
        "/proc/self/uid_map",
    ] {
        let mut attempted = Vec::new();

        let degraded = map_identity_into_userns_with(1000, 2000, |path, _| {
            attempted.push(path.to_string());
            if path == refused {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        });

        let (step, detail) =
            degraded.unwrap_or_else(|| panic!("{refused} was refused and nothing reported it"));

        assert_eq!(
            step,
            Degradation::UsernsIdentityMap,
            "a denied {refused} reported the wrong mechanism"
        );
        assert!(
            detail.contains("running as nobody"),
            "the detail does not say what the process is left as: {detail:?}"
        );
        assert!(
            detail.contains("permission denied"),
            "the detail dropped the kernel's own reason: {detail:?}"
        );
        assert_eq!(
            attempted.last().map(String::as_str),
            Some(refused),
            "a write after the refused one was attempted: {attempted:?}"
        );
    }
}
