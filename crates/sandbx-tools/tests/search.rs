//! Public contract of the `grep` and `find` tools.
//!
//! Both walk a directory tree via `FsGuard::walk_readable`, which owns the
//! confinement rule: a symlink inside a readable directory can point anywhere,
//! so symlinked entries are re-checked rather than trusted. These assert the
//! tools inherit that, not that they re-implement it.
// `mkfifo` is spawned to build a test fixture — a named pipe cannot be
// created through std. This is not code executing around the sandbox,
// which is what the workspace ban on `Command::new` exists to stop.
#![allow(clippy::disallowed_methods)]

use sandbx_core::SandboxPolicy;
use sandbx_tools::{BuiltinTool, ExecutionContext, ToolError};
use serde_json::json;

fn context(policy: SandboxPolicy) -> ExecutionContext {
    ExecutionContext::new(policy).unwrap()
}

#[test]
fn grep_finds_matching_lines_with_locations() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.rs"), "fn alpha() {}\nfn beta() {}\n").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "beta" }),
            &ctx,
        )
        .unwrap();

    assert!(
        out.content.contains("a.rs:2"),
        "no location: {}",
        out.content
    );
    assert!(
        out.content.contains("fn beta()"),
        "no line: {}",
        out.content
    );
}

#[test]
fn grep_searches_subdirectories() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    std::fs::write(root.path().join("sub/deep.txt"), "needle here\n").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "needle" }),
            &ctx,
        )
        .unwrap();

    assert!(out.content.contains("deep.txt"), "got: {}", out.content);
}

#[test]
fn grep_reports_no_matches_rather_than_failing() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.txt"), "nothing\n").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "absent" }),
            &ctx,
        )
        .unwrap();

    assert_eq!(out.content, "no matches");
}

/// A symlink in a searched directory must not leak the contents of its target.
#[cfg(unix)]
#[test]
fn grep_does_not_follow_a_symlink_out_of_the_root() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::write(elsewhere.path().join("secret.txt"), "SECRET-NEEDLE\n").unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), root.path().join("escape")).unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "SECRET-NEEDLE" }),
            &ctx,
        )
        .unwrap();

    assert!(
        !out.content.contains("SECRET-NEEDLE"),
        "grep followed a symlink outside the allowed root: {}",
        out.content
    );
}

#[test]
fn grep_refuses_a_root_outside_the_policy() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(allowed.path()));
    let err = BuiltinTool::Grep
        .execute(
            json!({ "path": elsewhere.path().to_str().unwrap(), "pattern": "x" }),
            &ctx,
        )
        .unwrap_err();

    assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
}

#[test]
fn find_matches_file_names() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    std::fs::write(root.path().join("sub/target.rs"), "").unwrap();
    std::fs::write(root.path().join("other.txt"), "").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Find
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "name": "target" }),
            &ctx,
        )
        .unwrap();

    assert!(out.content.contains("target.rs"), "got: {}", out.content);
    assert!(!out.content.contains("other.txt"), "got: {}", out.content);
}

/// The same symlink guarantee for `find`: names outside the root stay hidden.
#[cfg(unix)]
#[test]
fn find_does_not_follow_a_symlink_out_of_the_root() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::write(elsewhere.path().join("secret-name.txt"), "").unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), root.path().join("escape")).unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Find
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "name": "secret-name" }),
            &ctx,
        )
        .unwrap();

    assert!(
        !out.content.contains("secret-name"),
        "find followed a symlink outside the allowed root: {}",
        out.content
    );
}

/// Hits must be ordered by line number, not by its rendered text.
///
/// Sorting formatted `path:N: text` strings orders numbers lexicographically,
/// putting line 10 before line 2 — visible in any file with ten or more hits.
#[test]
fn grep_orders_hits_by_line_number() {
    let root = tempfile::tempdir().unwrap();
    let body: String = (1..=12).map(|_| "needle\n").collect();
    std::fs::write(root.path().join("many.txt"), body).unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "needle" }),
            &ctx,
        )
        .unwrap();

    let lines: Vec<usize> = out
        .content
        .lines()
        .filter_map(|l| {
            l.rsplit_once(':')
                .and_then(|(head, _)| head.rsplit(':').next()?.parse().ok())
        })
        .collect();

    assert_eq!(lines, (1..=12).collect::<Vec<_>>(), "got:\n{}", out.content);
}

/// A FIFO in the tree must not wedge the call: reading one with no writer
/// blocks forever.
#[cfg(unix)]
#[test]
fn grep_does_not_block_on_a_fifo() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("real.txt"), "needle\n").unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(root.path().join("pipe"))
        .status()
        .expect("mkfifo should run");
    assert!(status.success());

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "needle" }),
            &ctx,
        )
        .unwrap();

    assert!(out.content.contains("real.txt"), "got: {}", out.content);
}

/// A symlink to a *file* outside the root is the case that actually exercises
/// the walk's confinement; a symlink to a directory is skipped for unrelated
/// reasons and would pass even with the check removed.
#[cfg(unix)]
#[test]
fn grep_does_not_follow_a_symlink_to_a_file_outside_the_root() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::write(elsewhere.path().join("secret.txt"), "SECRET-NEEDLE\n").unwrap();
    std::os::unix::fs::symlink(
        elsewhere.path().join("secret.txt"),
        root.path().join("innocent.txt"),
    )
    .unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "SECRET-NEEDLE" }),
            &ctx,
        )
        .unwrap();

    assert!(
        !out.content.contains("SECRET-NEEDLE"),
        "grep followed a symlink to a file outside the root: {}",
        out.content
    );
}
