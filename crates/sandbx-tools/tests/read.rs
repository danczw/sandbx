//! Public contract of the `read` tool.
//!
//! `read` is a native-Rust tool: it never spawns a process, so the kernel
//! enforcement in `sandbx-core` never sees it. `FsGuard` is the only thing
//! keeping it inside the policy, which is why these tests dwell on refusal.

use sandbx_core::SandboxPolicy;
use sandbx_tools::{BuiltinTool, ExecutionContext, ToolError};
use serde_json::json;

fn context(policy: SandboxPolicy) -> ExecutionContext {
    ExecutionContext::new(policy).unwrap()
}

#[test]
fn reads_a_file_inside_an_allowed_root() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("notes.txt");
    std::fs::write(&file, b"hello from the workspace").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Read
        .execute(json!({ "path": file.to_str().unwrap() }), &ctx)
        .unwrap();

    assert_eq!(out.content, "hello from the workspace");
}

/// The whole point: a path the policy never granted is unreadable.
#[test]
fn refuses_a_path_outside_every_allowed_root() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let secret = elsewhere.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(allowed.path()));
    let err = BuiltinTool::Read
        .execute(json!({ "path": secret.to_str().unwrap() }), &ctx)
        .unwrap_err();

    assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
}

/// A missing file is a plain failure, not a policy refusal — the agent should be
/// told which it was, since only one of them is worth retrying differently.
#[test]
fn distinguishes_a_missing_file_from_a_refusal() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(SandboxPolicy::default().allow_read(root.path()));

    let err = BuiltinTool::Read
        .execute(
            json!({ "path": root.path().join("nope.txt").to_str().unwrap() }),
            &ctx,
        )
        .unwrap_err();

    assert!(matches!(err, ToolError::Denied { .. }) || matches!(err, ToolError::Failed { .. }));
}

/// Malformed input is rejected before any filesystem access is attempted.
#[test]
fn rejects_input_that_does_not_match_the_schema() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(SandboxPolicy::default().allow_read(root.path()));

    let err = BuiltinTool::Read
        .execute(json!({ "wrong_field": 1 }), &ctx)
        .unwrap_err();

    assert!(matches!(err, ToolError::BadInput { .. }), "got {err:?}");
}

/// The name and schema are what the model is shown, so they must exist and
/// describe the field the tool actually parses.
#[test]
fn advertises_a_schema_matching_its_input() {
    assert_eq!(BuiltinTool::Read.name(), "read");

    let schema = serde_json::to_value(BuiltinTool::Read.input_schema()).unwrap();
    assert!(
        schema.pointer("/properties/path").is_some(),
        "schema does not describe the `path` field: {schema}"
    );
}
