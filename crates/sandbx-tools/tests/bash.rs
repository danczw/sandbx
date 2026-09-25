//! Public contract of the `bash` tool.
//!
//! Unlike the other built-ins, `bash` spawns a process, so the kernel does the
//! confining. These assert the policy reaches it — a tool that quietly dropped
//! the policy would still look like it worked.
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]

use sandbx_core::SandboxPolicy;
use sandbx_tools::{BuiltinTool, ExecutionContext, ToolError};
use serde_json::json;

fn context(policy: SandboxPolicy) -> ExecutionContext {
    // The test harness does not dispatch helper mode, so point at a binary that
    // does rather than re-executing this one.
    ExecutionContext::new(policy)
        .unwrap()
        .with_helper(env!("CARGO_BIN_EXE_sandbx-tools-test-helper"))
}

#[test]
fn runs_a_command_and_returns_its_output() {
    let ctx = context(SandboxPolicy::default().allow_system_executables());
    let out = BuiltinTool::Bash
        .execute(json!({ "command": "echo hello" }), &ctx)
        .unwrap();

    assert!(out.content.contains("hello"), "got: {}", out.content);
}

/// A non-zero exit is reported, not swallowed — the model needs to know the
/// command failed.
#[test]
fn surfaces_a_non_zero_exit() {
    let ctx = context(SandboxPolicy::default().allow_system_executables());
    let err = BuiltinTool::Bash
        .execute(json!({ "command": "exit 3" }), &ctx)
        .unwrap_err();

    assert!(matches!(err, ToolError::Failed { .. }), "got {err:?}");
    assert!(format!("{err}").contains('3'), "exit code missing: {err}");
}

/// The policy must actually reach the spawned process.
#[test]
fn the_command_is_confined_by_the_policy() {
    let secret_dir = tempfile::tempdir().unwrap();
    let secret = secret_dir.path().join("secret.txt");
    std::fs::write(&secret, b"SECRET-CONTENTS").unwrap();

    // secret_dir is deliberately not granted.
    let ctx = context(SandboxPolicy::default().allow_system_executables());
    let result = BuiltinTool::Bash.execute(
        json!({ "command": format!("cat {}", secret.display()) }),
        &ctx,
    );

    let rendered = match &result {
        Ok(out) => out.content.clone(),
        Err(error) => error.to_string(),
    };
    assert!(
        !rendered.contains("SECRET-CONTENTS"),
        "ungranted file leaked through bash: {rendered}"
    );
}

/// Granted paths stay reachable, or the test above would pass on a tool that
/// simply never works.
#[test]
fn granted_paths_are_reachable() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("visible.txt"), b"VISIBLE").unwrap();

    let ctx = context(
        SandboxPolicy::default()
            .allow_system_executables()
            .allow_read(dir.path()),
    );
    let out = BuiltinTool::Bash
        .execute(
            json!({ "command": format!("cat {}/visible.txt", dir.path().display()) }),
            &ctx,
        )
        .unwrap();

    assert!(out.content.contains("VISIBLE"), "got: {}", out.content);
}

/// `bash` output is bounded too: the command chooses how much it prints.
#[test]
fn output_is_bounded() {
    let ctx = context(SandboxPolicy::default().allow_system_executables())
        .with_limits(sandbx_tools::OutputLimits::default().with_max_bytes(200));

    let out = BuiltinTool::Bash
        .execute(json!({ "command": "seq 1 100000" }), &ctx)
        .unwrap();

    assert!(out.content.contains("truncated"), "unbounded output");
    assert!(out.content.len() < 1000, "got {} bytes", out.content.len());
}
