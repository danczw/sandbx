//! The work a tool does must stay bounded, not just what it returns.
//!
//! `limits.rs` covers the output caps, which trim an answer already paid for. These
//! cover the input budget: `grep` and `find` walk a tree and `grep` reads every file
//! in it, so on a large root the cost is paid before any output cap applies. The
//! in-process tools have no timeout — `ExecutionContext`'s bounds the spawned
//! command alone — so this budget is all that bounds one broad search.

use sandbx_core::SandboxPolicy;
use sandbx_tools::{BuiltinTool, ExecutionContext, ToolLimits};
use serde_json::json;

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
        SandboxPolicy::default().allow_read(root.path()),
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

/// The marker matters as much as the cap: a model that cannot tell a complete search
/// from an abandoned one concludes the symbol does not exist.
#[test]
fn grep_reports_that_it_stopped_early() {
    let root = tree(50, "");
    let ctx = context(
        SandboxPolicy::default().allow_read(root.path()),
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

/// Bytes, not just file count: a few large files cost as much to scan as many small
/// ones, and only the byte budget sees it.
#[test]
fn grep_stops_at_the_byte_scan_budget() {
    let root = tree(50, &"filler\n".repeat(500));
    let ctx = context(
        SandboxPolicy::default().allow_read(root.path()),
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

/// `find` never reads a file, so only the walk's cap applies — but it must report
/// the cut-off for the same reason `grep` does.
#[test]
fn find_reports_a_truncated_walk() {
    let root = tree(50, "");
    let ctx = context(
        SandboxPolicy::default().allow_read(root.path()),
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

/// A marker on complete results is worse than none: it teaches the model to ignore
/// it.
#[test]
fn a_search_within_the_budget_is_not_marked() {
    let root = tree(3, "");
    let ctx = context(
        SandboxPolicy::default().allow_read(root.path()),
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
