//! Public contract of the `read` tool.
//!
//! `read` never spawns a process, so the kernel enforcement in `sandbx-core` never
//! sees it. `FsGuard` is the only thing keeping it inside the policy, which is why
//! these dwell on refusal.

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
fn reads_a_file_inside_an_allowed_root() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("notes.txt");
    std::fs::write(&file, b"hello from the workspace").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(vetted(root.path())));
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

    let ctx = context(SandboxPolicy::default().allow_read(vetted(allowed.path())));
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
    let ctx = context(SandboxPolicy::default().allow_read(vetted(root.path())));

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
    let ctx = context(SandboxPolicy::default().allow_read(vetted(root.path())));

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
    let ctx = context(SandboxPolicy::default().allow_read(vetted(root.path())));

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

    let ctx = context(SandboxPolicy::default().allow_read(vetted(root.path())));
    let out = BuiltinTool::Read
        .execute(json!({ "path": file.to_str().unwrap() }), &ctx)
        .unwrap();

    assert!(
        !out.content().trim().is_empty(),
        "empty file returned empty content"
    );
}

/// `Denied` and not `Failed`: a moved root is the policy refusing, so the agent's move is to
/// ask about the grant rather than to try another filename. The only thing that would catch
/// a later `RootReplaced => Failed` arm in `guard_error` (#212).
#[test]
fn a_substituted_root_reads_back_as_denied() {
    let work = tempfile::tempdir().unwrap();
    let granted = work.path().join("granted");
    let other = work.path().join("other");
    std::fs::create_dir(&granted).unwrap();
    std::fs::create_dir(&other).unwrap();
    std::fs::write(granted.join("notes.txt"), b"hello").unwrap();
    std::fs::write(other.join("notes.txt"), b"planted").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(vetted(&granted)));
    let path = granted.join("notes.txt");
    let request = json!({ "path": path.to_str().unwrap() });
    assert!(
        BuiltinTool::Read.execute(request.clone(), &ctx).is_ok(),
        "the grant did not read before the substitution"
    );

    std::fs::remove_dir_all(&granted).unwrap();
    std::fs::rename(&other, &granted).unwrap();

    let err = BuiltinTool::Read.execute(request, &ctx).unwrap_err();
    let ToolError::Denied { reason, .. } = &err else {
        panic!("got {err:?}");
    };
    // The `(dev, ino)` pairs the `SandboxError` carries are the operator's, and the vetted one
    // names an object the model can no longer reach, so neither reaches the turn.
    let now_at = VettedPath::vet(&granted).expect("the substitute is a directory too");
    assert!(
        !reason.contains(&now_at.object().to_string()),
        "the model was handed the host's inode numbers: {reason}"
    );
    assert!(
        reason.contains(granted.to_str().unwrap()),
        "the refusal does not say which grant is gone: {reason}"
    );
}
