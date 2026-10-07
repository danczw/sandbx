//! Public contract of the `write` tool.

use sandbx_core::{SandboxPolicy, VettedPath};
use sandbx_tools::{BuiltinTool, ExecutionContext, ToolError};
use serde_json::json;

/// `path`, pinned to the object it names — the shape every grant takes (#212).
fn vetted(path: impl AsRef<std::path::Path>) -> VettedPath {
    VettedPath::vet(path).expect("an existing path to pin the grant to")
}

fn context(policy: SandboxPolicy) -> ExecutionContext {
    ExecutionContext::new(policy)
}

#[test]
fn creates_a_file_inside_an_allowed_root() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("new.txt");

    let ctx = context(SandboxPolicy::default().allow_write(vetted(root.path())));
    BuiltinTool::Write
        .execute(
            json!({ "path": file.to_str().unwrap(), "content": "written" }),
            &ctx,
        )
        .unwrap();

    assert_eq!(std::fs::read_to_string(&file).unwrap(), "written");
}

#[test]
fn refuses_a_path_outside_every_allowed_root() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let target = elsewhere.path().join("planted.txt");

    let ctx = context(SandboxPolicy::default().allow_write(vetted(allowed.path())));
    let err = BuiltinTool::Write
        .execute(
            json!({ "path": target.to_str().unwrap(), "content": "nope" }),
            &ctx,
        )
        .unwrap_err();

    assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    assert!(!target.exists(), "wrote outside the allowed root");
}

/// The directory is the agent's to create; the grant already covers it.
#[test]
fn a_missing_parent_in_a_grant_is_a_failure() {
    let root = tempfile::tempdir().unwrap();

    let ctx = context(SandboxPolicy::default().allow_write(vetted(root.path())));
    let err = BuiltinTool::Write
        .execute(
            json!({ "path": root.path().join("nodir/f.txt").to_str().unwrap(), "content": "x" }),
            &ctx,
        )
        .unwrap_err();

    assert!(matches!(err, ToolError::Failed { .. }), "got {err:?}");
}

#[test]
fn a_missing_parent_outside_a_grant_is_denied() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let target = elsewhere.path().join("nodir/planted.txt");

    let ctx = context(SandboxPolicy::default().allow_write(vetted(allowed.path())));
    let err = BuiltinTool::Write
        .execute(
            json!({ "path": target.to_str().unwrap(), "content": "nope" }),
            &ctx,
        )
        .unwrap_err();

    assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    assert!(!target.exists(), "wrote outside the allowed root");
}

#[test]
fn read_grant_does_not_permit_writing() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("notes.txt");
    std::fs::write(&file, b"original").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(vetted(root.path())));
    let err = BuiltinTool::Write
        .execute(
            json!({ "path": file.to_str().unwrap(), "content": "overwritten" }),
            &ctx,
        )
        .unwrap_err();

    assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "original");
}

/// The agent can plant symlinks in any writable root, so following one would land a
/// write outside the policy.
#[cfg(unix)]
#[test]
fn refuses_to_write_through_a_symlink_leaf() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let outside = elsewhere.path().join("authorized_keys");

    let link = root.path().join("innocent.txt");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let ctx = context(SandboxPolicy::default().allow_write(vetted(root.path())));
    let err = BuiltinTool::Write
        .execute(
            json!({ "path": link.to_str().unwrap(), "content": "pwned" }),
            &ctx,
        )
        .unwrap_err();

    assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    assert!(
        !outside.exists(),
        "write followed a symlink out of the root"
    );
}
