use crate::{SandboxError, SandboxPolicy};

/// Flag introducing a read-only path.
const FLAG_RO: &str = "--ro";
/// Flag introducing a read-write path.
const FLAG_RW: &str = "--rw";
/// Flag introducing a read-and-execute path.
const FLAG_RX: &str = "--rx";
/// Flag permitting network access.
const FLAG_NET: &str = "--allow-network";
/// Everything after this is the command to run, never a helper flag.
const SEPARATOR: &str = "--";

/// A policy plus a command, as carried between sandbx and the helper process.
///
/// The helper runs in a separate process, so the policy has to cross a process
/// boundary. argv is used rather than the environment because the environment is
/// inherited by the sandboxed command itself, where policy details have no
/// business being.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperArgs {
    /// Restrictions the helper must apply to itself.
    pub policy: SandboxPolicy,
    /// Program the helper should become.
    pub program: String,
    /// Arguments for that program.
    pub args: Vec<String>,
}

impl HelperArgs {
    /// Render a policy and command as helper argv.
    pub fn encode(policy: &SandboxPolicy, program: &str, args: &[String]) -> Vec<String> {
        let mut out = Vec::new();

        for path in policy.readable_paths() {
            out.push(FLAG_RO.to_string());
            out.push(path.display().to_string());
        }
        for path in policy.writable_paths() {
            out.push(FLAG_RW.to_string());
            out.push(path.display().to_string());
        }
        for path in policy.executable_paths() {
            out.push(FLAG_RX.to_string());
            out.push(path.display().to_string());
        }
        if policy.allows_network() {
            out.push(FLAG_NET.to_string());
        }

        out.push(SEPARATOR.to_string());
        out.push(program.to_string());
        out.extend(args.iter().cloned());
        out
    }

    /// Parse helper argv back into a policy and command.
    ///
    /// Every failure is a refusal. An unrecognised flag is an error rather than
    /// something to skip: silently ignoring it would mean running with a policy
    /// that differs from the one sandbx intended, which is precisely the situation
    /// the sandbox exists to prevent.
    pub fn decode(argv: &[String]) -> Result<Self, SandboxError> {
        let mut policy = SandboxPolicy::default();
        let mut rest = argv.iter();

        let command: Vec<String> = loop {
            let Some(arg) = rest.next() else {
                return Err(SandboxError::BadHelperArgs {
                    detail: "missing `--` separator before the command",
                });
            };

            match arg.as_str() {
                SEPARATOR => break rest.cloned().collect(),
                FLAG_NET => policy = policy.allow_network(),
                FLAG_RO | FLAG_RW | FLAG_RX => {
                    let path = rest.next().ok_or(SandboxError::BadHelperArgs {
                        detail: "path flag with no path after it",
                    })?;
                    policy = match arg.as_str() {
                        FLAG_RO => policy.allow_read(path),
                        FLAG_RW => policy.allow_write(path),
                        _ => policy.allow_read_execute(path),
                    };
                }
                _ => {
                    return Err(SandboxError::BadHelperArgs {
                        detail: "unrecognised helper flag",
                    });
                }
            }
        };

        let mut command = command.into_iter();
        let program = command.next().ok_or(SandboxError::BadHelperArgs {
            detail: "no command after `--`",
        })?;

        Ok(Self {
            policy,
            program,
            args: command.collect(),
        })
    }
}
