use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput, ToolSpec};

/// This tool, as `BuiltinTool` sees it.
pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "bash",
    description: "Run a shell command. Use it for what the other tools do not \
                  cover; prefer a dedicated tool wherever one fits.",
    schema,
    run,
};

/// Argument schema for this tool. Built per call: `schema_for!` allocates, so it
/// cannot be a const value.
fn schema() -> serde_json::Value {
    schemars::schema_for!(BashInput).to_value()
}

/// Parse untyped arguments into this tool's own input struct, then run it.
fn run(input: serde_json::Value, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    execute(crate::parse(input)?, ctx)
}

/// Arguments for the `bash` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BashInput {
    /// Shell command to run.
    pub command: String,
}

/// Run a shell command under the sandbox.
///
/// The only built-in that spawns a process, so unlike its siblings the kernel
/// does the confining: the command comes from
/// [`ExecutionContext::sandboxed_command`], which applies Landlock, a network
/// namespace and a seccomp filter before `exec`.
///
/// Note the command string is passed to `sh -c` verbatim. That is not an
/// injection hole to close — running arbitrary commands *is* the tool's purpose,
/// and the sandbox, not argument parsing, is what bounds the damage.
pub fn execute(input: BashInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let command = ctx
        .sandboxed_command("/bin/sh")
        .arg("-c")
        .arg(&input.command);

    let output = command.output().map_err(|error| {
        let subject = format!("run `{}`", input.command);
        // A wedge and a genuine failure call for different reactions, so they
        // must not arrive as the same variant.
        match error {
            sandbx_core::SandboxError::TimedOut { after } => ToolError::TimedOut { subject, after },
            error => ToolError::Failed {
                subject,
                detail: error.to_string(),
            },
        }
    })?;

    // Borrowed, not owned: on the normal all-valid-UTF-8 path `from_utf8_lossy`
    // hands back the bytes unchanged, and `combine` only needs a `&str`.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        // The largest unbounded source of all: the command chooses how much it
        // prints, and `cat` on a large file would otherwise return every byte of
        // it.
        return Ok(ToolOutput::new(
            ctx.limits().take_bytes(combine(&stdout, &stderr)),
        ));
    }

    // Surface the exit code rather than swallowing it: a command that failed
    // looks identical to one that produced no output otherwise.
    Err(ToolError::Failed {
        subject: format!("run `{}`", input.command),
        detail: format!(
            "exit {}: {}",
            output
                .status
                .code()
                .map_or_else(|| "signal".to_string(), |c| c.to_string()),
            ctx.limits().take_bytes(combine(&stdout, &stderr))
        ),
    })
}

/// Interleave the two streams the model cares about, labelling stderr only when
/// there is some, so ordinary output stays clean.
fn combine(stdout: &str, stderr: &str) -> String {
    match (stdout.trim().is_empty(), stderr.trim().is_empty()) {
        (_, true) => stdout.trim_end().to_string(),
        (true, false) => format!("stderr: {}", stderr.trim_end()),
        (false, false) => format!("{}\nstderr: {}", stdout.trim_end(), stderr.trim_end()),
    }
}
