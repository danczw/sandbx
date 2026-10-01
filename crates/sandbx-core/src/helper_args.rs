use crate::{Axis, SandboxError, SandboxPolicy};

const FLAG_NET: &str = "--allow-network";
const FLAG_UNIX: &str = "--allow-unix-sockets";
/// Everything after this is the command to run, never a helper flag.
const SEPARATOR: &str = "--";

/// The flag that introduces a path granted on `axis`.
///
/// The wire format lives here rather than in [`Axis`] itself — the policy type
/// has no business knowing how the helper is invoked — but it is one exhaustive
/// match, so a new axis is a compile error here and nowhere else: [`encode`] and
/// [`decode`] both go through it.
///
/// [`encode`]: HelperArgs::encode
/// [`decode`]: HelperArgs::decode
const fn path_flag(axis: Axis) -> &'static str {
    match axis {
        Axis::Read => "--ro",
        Axis::Write => "--rw",
        Axis::ReadExecute => "--rx",
    }
}

/// The axis `flag` introduces, if it is a path flag at all.
///
/// A lookup over the table rather than a second list of spellings. This is what
/// makes [`path_flag`] the only place an axis names itself on the wire: a flag
/// `encode` can emit is one `decode` accepts, by construction.
fn axis_for(flag: &str) -> Option<Axis> {
    Axis::ALL.into_iter().find(|axis| path_flag(*axis) == flag)
}

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
    /// Arguments for `program`, already split into words. The helper execs
    /// directly, so nothing here is ever seen by a shell.
    pub args: Vec<String>,
}

impl HelperArgs {
    /// Render a policy and command as helper argv.
    pub fn encode(policy: &SandboxPolicy, program: &str, args: &[String]) -> Vec<String> {
        let mut out = Vec::new();

        for (axis, path) in policy.granted_paths() {
            out.push(path_flag(axis).to_string());
            out.push(path.display().to_string());
        }
        if policy.allows_network() {
            out.push(FLAG_NET.to_string());
        }
        if policy.allows_unix_sockets() {
            out.push(FLAG_UNIX.to_string());
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

        // The program is split off inside the loop, where the separator is found,
        // rather than by collecting the tail and re-iterating it to take the head.
        let (program, args) = loop {
            let Some(arg) = rest.next() else {
                return Err(SandboxError::BadHelperArgs {
                    detail: "missing `--` separator before the command",
                });
            };

            match arg.as_str() {
                SEPARATOR => {
                    let program = rest.next().ok_or(SandboxError::BadHelperArgs {
                        detail: "no command after `--`",
                    })?;
                    break (program.clone(), rest.cloned().collect());
                }
                FLAG_NET => policy = policy.allow_network(),
                FLAG_UNIX => policy = policy.allow_unix_sockets(),
                flag => {
                    // One lookup, then one grant: the axis carries which one it
                    // is, so there is no second match here deciding it again —
                    // which is where the two could have disagreed.
                    let axis = axis_for(flag).ok_or(SandboxError::BadHelperArgs {
                        detail: "unrecognised helper flag",
                    })?;
                    let path = rest.next().ok_or(SandboxError::BadHelperArgs {
                        detail: "path flag with no path after it",
                    })?;
                    policy = policy.grant(axis, path);
                }
            }
        };

        Ok(Self {
            policy,
            program,
            args,
        })
    }
}
