//! Public contract of the `ls` tool.

use sandbx_core::SandboxPolicy;
use sandbx_tools::{BuiltinTool, ExecutionContext, ToolError};
use serde_json::json;

fn context(policy: SandboxPolicy) -> ExecutionContext {
    ExecutionContext::new(policy).unwrap()
}

#[test]
fn lists_entries_of_an_allowed_directory() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.txt"), b"a").unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Ls
        .execute(json!({ "path": root.path().to_str().unwrap() }), &ctx)
        .unwrap();

    assert!(out.content.contains("a.txt"), "got: {}", out.content);
    assert!(out.content.contains("sub"), "got: {}", out.content);
}

/// Directories are marked, or the model cannot tell what it can descend into.
#[test]
fn distinguishes_directories_from_files() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.txt"), b"a").unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Ls
        .execute(json!({ "path": root.path().to_str().unwrap() }), &ctx)
        .unwrap();

    assert!(
        out.content.contains("sub/"),
        "directory unmarked: {}",
        out.content
    );
}

#[test]
fn refuses_a_directory_outside_every_allowed_root() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::write(elsewhere.path().join("secret.txt"), b"s").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(allowed.path()));
    let err = BuiltinTool::Ls
        .execute(json!({ "path": elsewhere.path().to_str().unwrap() }), &ctx)
        .unwrap_err();

    assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    assert!(
        !format!("{err}").contains("secret.txt"),
        "leaked an entry name"
    );
}
