//! The work a tool does must stay bounded, not just what it returns.
//!
//! `limits.rs` covers the output caps, which trim an answer already paid for. These
//! cover the input budget: `grep` and `find` walk a tree and `grep` reads every file
//! in it, so on a large root the cost is paid before any output cap applies. The
//! in-process tools have no timeout — `ExecutionContext`'s bounds the spawned
//! command alone — so this budget is all that bounds one broad search.

use sandbx_core::{SandboxPolicy, VettedPath};
use sandbx_tools::{BuiltinTool, ExecutionContext, ToolLimits};
use serde_json::json;

/// `path`, pinned to the object it names — the shape every grant takes (#212).
fn vetted(path: impl AsRef<std::path::Path>) -> VettedPath {
    VettedPath::vet(path).expect("an existing path to pin the grant to")
}

fn context(policy: SandboxPolicy, limits: ToolLimits) -> ExecutionContext {
    ExecutionContext::new(policy).with_limits(limits)
}

/// A tree of `count` files, each holding `body` and one match.
fn tree(count: usize, body: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for i in 0..count {
        std::fs::write(
            root.path().join(format!("f{i}.txt")),
            format!("needle\n{body}"),
        )
        .unwrap();
    }
    root
}

#[test]
fn grep_stops_at_the_file_scan_cap() {
    let root = tree(50, "");
    let ctx = context(
        SandboxPolicy::default().allow_read(vetted(root.path())),
        ToolLimits::default().with_max_files_scanned(5),
    );

    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "needle" }),
            &ctx,
        )
        .unwrap();

    let hits = out
        .content()
        .lines()
        .filter(|l| l.contains("needle"))
        .count();
    assert_eq!(hits, 5, "scan cap not applied:\n{}", out.content());
}

/// A model that cannot tell a complete search from an abandoned one concludes the
/// symbol does not exist.
#[test]
fn grep_reports_that_it_stopped_early() {
    let root = tree(50, "");
    let ctx = context(
        SandboxPolicy::default().allow_read(vetted(root.path())),
        ToolLimits::default().with_max_files_scanned(5),
    );

    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "needle" }),
            &ctx,
        )
        .unwrap();

    assert!(
        out.content().contains("stopped early"),
        "no incomplete-search marker:\n{}",
        out.content()
    );
}

/// Bytes, not just file count: a few large files cost as much as many small ones.
#[test]
fn grep_stops_at_the_byte_scan_budget() {
    let root = tree(50, &"filler\n".repeat(500));
    let ctx = context(
        SandboxPolicy::default().allow_read(vetted(root.path())),
        ToolLimits::default().with_max_bytes_scanned(4 * 1024),
    );

    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "needle" }),
            &ctx,
        )
        .unwrap();

    let hits = out
        .content()
        .lines()
        .filter(|l| l.contains("needle"))
        .count();
    assert!(hits < 50, "byte budget not applied: {hits} files scanned");
    assert!(
        out.content().contains("stopped early"),
        "no incomplete-search marker:\n{}",
        out.content()
    );
}

/// One byte past `MAX_FILE_BYTES`, which is 2 MiB in `grep` and not a knob.
const OVER_THE_CAP: usize = 2 * 1024 * 1024 + 1;

/// The budget is not the only thing that leaves a file unsearched, and an unmarked skip
/// says the pattern is not there.
#[test]
fn an_oversized_file_is_not_a_file_without_the_match() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("big.txt"),
        format!("needle\n{}", "x".repeat(OVER_THE_CAP)),
    )
    .unwrap();
    std::fs::write(root.path().join("small.txt"), b"needle\n").unwrap();
    let ctx = context(
        SandboxPolicy::default().allow_read(vetted(root.path())),
        ToolLimits::default(),
    );

    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "needle" }),
            &ctx,
        )
        .unwrap();

    assert!(
        out.content().contains("stopped early"),
        "an unread file passed for one with no match:\n{}",
        out.content()
    );
    // Without this the test would also pass on a walk that searched nothing, which is
    // the opposite defect.
    assert!(
        out.content().contains("small.txt"),
        "the walk read nothing at all:\n{}",
        out.content()
    );
}

/// A refusal mid-walk is the same gap as the cap: a tree that reads as holding no match.
#[test]
fn a_file_the_host_refuses_marks_the_search_partial() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let locked = root.path().join("locked.txt");
    std::fs::write(&locked, b"needle\n").unwrap();
    std::fs::write(root.path().join("open.txt"), b"needle\n").unwrap();
    let ctx = context(
        SandboxPolicy::default().allow_read(vetted(root.path())),
        ToolLimits::default(),
    );

    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Probed through `read`, which has no skip arm to hide it: as root the open succeeds
    // and the fixture proves nothing, so that has to fail loudly rather than pass.
    let refused = BuiltinTool::Read.execute(json!({ "path": locked.to_str().unwrap() }), &ctx);
    let searched = BuiltinTool::Grep.execute(
        json!({ "path": root.path().to_str().unwrap(), "pattern": "needle" }),
        &ctx,
    );
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();

    assert!(
        refused.is_err(),
        "the host opened a 0o000 file; run as root?"
    );
    let out = searched.unwrap();
    assert!(
        out.content().contains("stopped early"),
        "a refused file passed for one with no match:\n{}",
        out.content()
    );
    assert!(
        out.content().contains("open.txt"),
        "the walk read nothing at all:\n{}",
        out.content()
    );
}

/// `find` never reads a file, so only the walk's cap applies.
#[test]
fn find_reports_a_truncated_walk() {
    let root = tree(50, "");
    let ctx = context(
        SandboxPolicy::default().allow_read(vetted(root.path())),
        ToolLimits::default().with_max_files_scanned(5),
    );

    let out = BuiltinTool::Find
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "name": "f" }),
            &ctx,
        )
        .unwrap();

    assert!(
        out.content().contains("stopped early"),
        "no incomplete-search marker:\n{}",
        out.content()
    );
}

/// A marker on complete results teaches the model to ignore it.
#[test]
fn a_search_within_the_budget_is_not_marked() {
    let root = tree(3, "");
    let ctx = context(
        SandboxPolicy::default().allow_read(vetted(root.path())),
        ToolLimits::default(),
    );

    // Each takes a differently named argument, so the input is per tool.
    let path = root.path().to_str().unwrap();
    let inputs = [
        (
            BuiltinTool::Grep,
            json!({ "path": path, "pattern": "needle" }),
        ),
        (BuiltinTool::Find, json!({ "path": path, "name": "f" })),
    ];

    for (tool, input) in inputs {
        let out = tool.execute(input, &ctx).unwrap();

        assert!(
            !out.content().contains("stopped early"),
            "{} marked a complete search:\n{}",
            tool.name(),
            out.content()
        );
    }
}
