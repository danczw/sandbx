//! Tool output must stay bounded.
//!
//! Unbounded output is not a security problem — it stays inside the allowed
//! roots — but one broad `grep` can consume the whole context window, evicting
//! the conversation that explains what the agent was doing. The marker matters
//! as much as the cap: a silently truncated list looks complete, and the model
//! draws conclusions from it.

use sandbx_core::SandboxPolicy;
use sandbx_tools::{BuiltinTool, ExecutionContext, OutputLimits};
use serde_json::json;

fn context(policy: SandboxPolicy, limits: OutputLimits) -> ExecutionContext {
    ExecutionContext::new(policy).unwrap().with_limits(limits)
}

/// A tree with `count` files, each containing one match.
fn tree_with_matches(count: usize) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for i in 0..count {
        std::fs::write(root.path().join(format!("f{i}.txt")), "needle\n").unwrap();
    }
    root
}

#[test]
fn grep_caps_the_number_of_hits() {
    let root = tree_with_matches(50);
    let ctx = context(
        SandboxPolicy::default().allow_read(root.path()),
        OutputLimits::default().with_max_entries(10),
    );

    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "needle" }),
            &ctx,
        )
        .unwrap();

    let hits = out.content.lines().filter(|l| l.contains("needle")).count();
    assert_eq!(hits, 10, "cap not applied:\n{}", out.content);
}

/// Truncation must be visible, or the model treats a partial list as complete.
#[test]
fn grep_says_when_it_truncated() {
    let root = tree_with_matches(50);
    let ctx = context(
        SandboxPolicy::default().allow_read(root.path()),
        OutputLimits::default().with_max_entries(10),
    );

    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "needle" }),
            &ctx,
        )
        .unwrap();

    assert!(
        out.content.contains("truncated"),
        "no truncation marker:\n{}",
        out.content
    );
}

/// A result that fits must not be marked, or the marker means nothing.
#[test]
fn grep_does_not_mark_a_complete_result() {
    let root = tree_with_matches(3);
    let ctx = context(
        SandboxPolicy::default().allow_read(root.path()),
        OutputLimits::default().with_max_entries(10),
    );

    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "needle" }),
            &ctx,
        )
        .unwrap();

    assert!(
        !out.content.contains("truncated"),
        "marked a complete result:\n{}",
        out.content
    );
}

#[test]
fn find_caps_and_marks() {
    let root = tree_with_matches(50);
    let ctx = context(
        SandboxPolicy::default().allow_read(root.path()),
        OutputLimits::default().with_max_entries(5),
    );

    let out = BuiltinTool::Find
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "name": "f" }),
            &ctx,
        )
        .unwrap();

    assert_eq!(
        out.content.lines().filter(|l| l.contains(".txt")).count(),
        5
    );
    assert!(out.content.contains("truncated"), "got:\n{}", out.content);
}

#[test]
fn ls_caps_and_marks() {
    let root = tree_with_matches(50);
    let ctx = context(
        SandboxPolicy::default().allow_read(root.path()),
        OutputLimits::default().with_max_entries(7),
    );

    let out = BuiltinTool::Ls
        .execute(json!({ "path": root.path().to_str().unwrap() }), &ctx)
        .unwrap();

    assert_eq!(
        out.content.lines().filter(|l| l.contains(".txt")).count(),
        7
    );
    assert!(out.content.contains("truncated"), "got:\n{}", out.content);
}

/// `read` is capped by bytes rather than entries — one file, arbitrarily long.
#[test]
fn read_caps_by_bytes_and_marks() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("big.txt");
    std::fs::write(&file, "x".repeat(10_000)).unwrap();

    let ctx = context(
        SandboxPolicy::default().allow_read(root.path()),
        OutputLimits::default().with_max_bytes(100),
    );

    let out = BuiltinTool::Read
        .execute(json!({ "path": file.to_str().unwrap() }), &ctx)
        .unwrap();

    assert!(out.content.contains("truncated"), "got:\n{}", out.content);
    assert!(
        out.content.len() < 500,
        "content not truncated: {} bytes",
        out.content.len()
    );
}

#[test]
fn read_does_not_mark_a_file_that_fits() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("small.txt");
    std::fs::write(&file, "short").unwrap();

    let ctx = context(
        SandboxPolicy::default().allow_read(root.path()),
        OutputLimits::default().with_max_bytes(100),
    );

    let out = BuiltinTool::Read
        .execute(json!({ "path": file.to_str().unwrap() }), &ctx)
        .unwrap();

    assert_eq!(out.content, "short");
}

/// Truncating mid-character must not produce invalid UTF-8 or panic.
#[test]
fn read_truncates_on_a_character_boundary() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("wide.txt");
    // Three-byte characters, so most byte offsets fall mid-character.
    std::fs::write(&file, "日".repeat(1000)).unwrap();

    let ctx = context(
        SandboxPolicy::default().allow_read(root.path()),
        OutputLimits::default().with_max_bytes(100),
    );

    let out = BuiltinTool::Read
        .execute(json!({ "path": file.to_str().unwrap() }), &ctx)
        .unwrap();

    assert!(out.content.contains('日'));
    assert!(out.content.contains("truncated"));
}

/// A context built without limits still bounds output, or the default is a trap.
#[test]
fn limits_apply_by_default() {
    let limits = OutputLimits::default();
    assert!(limits.max_entries() > 0);
    assert!(limits.max_bytes() > 0);
}
