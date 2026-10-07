//! Public contract of the `ls` tool.

use sandbx_core::SandboxPolicy;
use sandbx_tools::{BuiltinTool, ExecutionContext, ToolError};
use serde_json::json;

fn context(policy: SandboxPolicy) -> ExecutionContext {
    ExecutionContext::new(policy)
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

    assert!(out.content().contains("a.txt"), "got: {}", out.content());
    assert!(out.content().contains("sub"), "got: {}", out.content());
}

/// Unmarked, the model cannot tell what it may descend into.
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
        out.content().contains("sub/"),
        "directory unmarked: {}",
        out.content()
    );
}

/// `ls` holds a path rather than a handle, so it reaches the guard on its own.
#[test]
fn a_missing_directory_in_a_grant_is_a_failure() {
    let root = tempfile::tempdir().unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let err = BuiltinTool::Ls
        .execute(
            json!({ "path": root.path().join("nodir").to_str().unwrap() }),
            &ctx,
        )
        .unwrap_err();

    assert!(matches!(err, ToolError::Failed { .. }), "got {err:?}");
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
