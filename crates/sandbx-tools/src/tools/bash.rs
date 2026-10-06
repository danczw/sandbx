use serde::Deserialize;

use crate::{ExecutionContext, RiskLevel, ToolError, ToolOutput, ToolSpec};

pub(crate) const SPEC: ToolSpec = ToolSpec {
    name: "bash",
    description: "Run a shell command. Use it for what the other tools do not \
                  cover; prefer a dedicated tool wherever one fits.",
    risk: RiskLevel::Executes,
    schema,
    run,
};

fn schema() -> serde_json::Value {
    schemars::schema_for!(BashInput).to_value()
}

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
/// The only built-in that spawns, so the kernel does the confining:
/// [`ExecutionContext::sandboxed_command`] applies Landlock, a network namespace
/// and a seccomp filter before `exec`. The command string reaches `sh -c` verbatim;
/// running arbitrary commands is the purpose, and the sandbox — not argument
/// parsing — is what bounds the damage.
pub fn execute(input: BashInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let command = ctx
        .sandboxed_command("/bin/sh")
        .arg("-c")
        .arg(&input.command);

    let output = command.output().map_err(|error| {
        let subject = format!("run `{}`", input.command);
        // A wedge and a genuine failure need different reactions from the agent.
        match error {
            sandbx_core::SandboxError::TimedOut { after } => ToolError::TimedOut { subject, after },
            error => ToolError::Failed {
                subject,
                detail: error.to_string(),
            },
        }
    })?;

    // Borrowed: `from_utf8_lossy` copies nothing on the valid-UTF-8 path.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        // The command chooses how much it prints: uncapped, `cat` on a large file
        // returns every byte of it.
        return Ok(ToolOutput::new(
            ctx.limits().take_bytes(combine(&stdout, &stderr)),
        ));
    }

    // Without the exit code, a failed command looks like one that printed nothing.
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

/// Join both streams, labelling stderr only when there is some.
fn combine(stdout: &str, stderr: &str) -> String {
    match (stdout.trim().is_empty(), stderr.trim().is_empty()) {
        (_, true) => stdout.trim_end().to_string(),
        (true, false) => format!("stderr: {}", stderr.trim_end()),
        (false, false) => format!("{}\nstderr: {}", stdout.trim_end(), stderr.trim_end()),
    }
}
