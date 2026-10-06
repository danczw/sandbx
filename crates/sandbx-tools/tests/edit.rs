//! Public contract of the `edit` tool.

use sandbx_core::SandboxPolicy;
use sandbx_tools::{BuiltinTool, ExecutionContext, ToolError};
use serde_json::json;

fn context(policy: SandboxPolicy) -> ExecutionContext {
    ExecutionContext::new(policy)
}

fn file_with(root: &std::path::Path, body: &str) -> std::path::PathBuf {
    let file = root.join("src.txt");
    std::fs::write(&file, body).unwrap();
    file
}

#[test]
fn replaces_a_unique_occurrence() {
    let root = tempfile::tempdir().unwrap();
    let file = file_with(root.path(), "let x = 1;\nlet y = 2;\n");

    let ctx = context(
        SandboxPolicy::default()
            .allow_read(root.path())
            .allow_write(root.path()),
    );
    BuiltinTool::Edit
        .execute(
            json!({ "path": file.to_str().unwrap(), "old": "let x = 1;", "new": "let x = 42;" }),
            &ctx,
        )
        .unwrap();

    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "let x = 42;\nlet y = 2;\n"
    );
}

#[test]
fn refuses_an_ambiguous_match() {
    let root = tempfile::tempdir().unwrap();
    let original = "a = 1;\na = 1;\n";
    let file = file_with(root.path(), original);

    let ctx = context(
        SandboxPolicy::default()
            .allow_read(root.path())
            .allow_write(root.path()),
    );
    let err = BuiltinTool::Edit
        .execute(
            json!({ "path": file.to_str().unwrap(), "old": "a = 1;", "new": "a = 2;" }),
            &ctx,
        )
        .unwrap_err();

    assert!(matches!(err, ToolError::Failed { .. }), "got {err:?}");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        original,
        "file was modified"
    );
}

/// Loudly, not as a silent no-op: the model believes the edit happened.
#[test]
fn refuses_a_missing_match() {
    let root = tempfile::tempdir().unwrap();
    let original = "unchanged\n";
    let file = file_with(root.path(), original);

    let ctx = context(
        SandboxPolicy::default()
            .allow_read(root.path())
            .allow_write(root.path()),
    );
    let err = BuiltinTool::Edit
        .execute(
            json!({ "path": file.to_str().unwrap(), "old": "absent", "new": "x" }),
            &ctx,
        )
        .unwrap_err();

    assert!(matches!(err, ToolError::Failed { .. }), "got {err:?}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
}

#[test]
fn read_grant_alone_does_not_permit_editing() {
    let root = tempfile::tempdir().unwrap();
    let original = "let x = 1;\n";
    let file = file_with(root.path(), original);

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let err = BuiltinTool::Edit
        .execute(
            json!({ "path": file.to_str().unwrap(), "old": "let x = 1;", "new": "let x = 2;" }),
            &ctx,
        )
        .unwrap_err();

    assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), original);
}

/// The write handle truncates on open, so opening it before the match is known
/// unique would empty the file on every path that reports failure.
#[test]
fn a_refused_edit_leaves_the_file_intact() {
    let root = tempfile::tempdir().unwrap();
    let original = "a = 1;\na = 1;\n";
    let file = file_with(root.path(), original);

    let ctx = context(
        SandboxPolicy::default()
            .allow_read(root.path())
            .allow_write(root.path()),
    );

    assert!(
        BuiltinTool::Edit
            .execute(
                json!({ "path": file.to_str().unwrap(), "old": "a = 1;", "new": "b" }),
                &ctx,
            )
            .is_err()
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), original);

    assert!(
        BuiltinTool::Edit
            .execute(
                json!({ "path": file.to_str().unwrap(), "old": "nowhere", "new": "b" }),
                &ctx,
            )
            .is_err()
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        original,
        "file was truncated by an edit that failed"
    );
}
