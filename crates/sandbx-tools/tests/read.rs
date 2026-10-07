//! Public contract of the `read` tool.
//!
//! `read` never spawns a process, so the kernel enforcement in `sandbx-core` never
//! sees it. `FsGuard` is the only thing keeping it inside the policy, which is why
//! these dwell on refusal.

use sandbx_core::SandboxPolicy;
use sandbx_tools::{BuiltinTool, ExecutionContext, ToolError};
use serde_json::json;

fn context(policy: SandboxPolicy) -> ExecutionContext {
    ExecutionContext::new(policy)
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

    assert_eq!(out.content(), "hello from the workspace");
}

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

/// Only one of the two is worth the agent retrying differently.
#[test]
fn distinguishes_a_missing_file_from_a_refusal() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let secret = elsewhere.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();
    let ctx = context(SandboxPolicy::default().allow_read(root.path()));

    let missing = BuiltinTool::Read
        .execute(
            json!({ "path": root.path().join("nope.txt").to_str().unwrap() }),
            &ctx,
        )
        .unwrap_err();
    let outside = BuiltinTool::Read
        .execute(json!({ "path": secret.to_str().unwrap() }), &ctx)
        .unwrap_err();

    assert!(
        matches!(missing, ToolError::Failed { .. }),
        "got {missing:?}"
    );
    assert!(
        matches!(outside, ToolError::Denied { .. }),
        "got {outside:?}"
    );
}

/// The variant only reaches the model as text, so the text is what has to differ.
#[test]
fn a_missing_file_reports_why_not_a_refusal() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(SandboxPolicy::default().allow_read(root.path()));

    let err = BuiltinTool::Read
        .execute(
            json!({ "path": root.path().join("nope.txt").to_str().unwrap() }),
            &ctx,
        )
        .unwrap_err()
        .to_string();

    assert!(err.contains("No such file"), "got {err}");
    assert!(!err.contains("refused by the sandbox policy"), "got {err}");
}

/// Rejected before any filesystem access is attempted.
#[test]
fn rejects_input_that_does_not_match_the_schema() {
    let root = tempfile::tempdir().unwrap();
    let ctx = context(SandboxPolicy::default().allow_read(root.path()));

    let err = BuiltinTool::Read
        .execute(json!({ "wrong_field": 1 }), &ctx)
        .unwrap_err();

    assert!(matches!(err, ToolError::BadInput { .. }), "got {err:?}");
}

/// The schema is what the model is shown, so it must name the field the tool parses.
#[test]
fn advertises_a_schema_matching_its_input() {
    assert_eq!(BuiltinTool::Read.name(), "read");

    let schema = BuiltinTool::Read.input_schema();
    assert!(
        schema.pointer("/properties/path").is_some(),
        "schema does not describe the `path` field: {schema}"
    );
}

/// The Messages API rejects a `tool_result` whose text is empty, so a tool returning
/// `""` kills the turn rather than producing an empty one.
#[test]
fn an_empty_file_is_reported_as_empty() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("empty.txt");
    std::fs::write(&file, b"").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Read
        .execute(json!({ "path": file.to_str().unwrap() }), &ctx)
        .unwrap();

    assert!(
        !out.content().trim().is_empty(),
        "empty file returned empty content"
    );
}
