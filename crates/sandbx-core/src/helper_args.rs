use crate::{Axis, SandboxError, SandboxPolicy};

const FLAG_NET: &str = "--allow-network";
const FLAG_UNIX: &str = "--allow-unix-sockets";
/// Introduces the *name* of a variable the command may inherit. Never a value.
const FLAG_ENV: &str = "--env";
/// Everything after this is the command to run, never a helper flag.
const SEPARATOR: &str = "--";

/// The flag that introduces a path granted on `axis`.
///
/// The wire format lives here rather than in [`Axis`], the policy type having no business
/// knowing how the helper is invoked, but it is one exhaustive match that both `encode`
/// and `decode` go through, so a new axis is a compile error here and nowhere else.
const fn path_flag(axis: Axis) -> &'static str {
    match axis {
        Axis::Read => "--ro",
        Axis::Write => "--rw",
        Axis::ReadExecute => "--rx",
    }
}

/// The axis `flag` introduces, if it is a path flag at all.
///
/// A lookup over the table rather than a second list of spellings, which makes
/// [`path_flag`] the only place an axis names itself on the wire: a flag `encode` can emit
/// is one `decode` accepts, by construction.
fn axis_for(flag: &str) -> Option<Axis> {
    Axis::ALL.into_iter().find(|axis| path_flag(*axis) == flag)
}

/// A policy plus a command, as carried between sandbx and the helper process.
///
/// The policy crosses a process boundary as argv, which is not private: the command can
/// read its own `/proc/self/cmdline`, so everything here is visible to the process being
/// confined. Hence the rule the environment axis obeys — this carries variable names,
/// never values. The environment cannot be the channel instead, being what the policy now
/// governs: the filter would either leak the policy or eat it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperArgs {
    /// Restrictions the helper must apply to itself.
    pub policy: SandboxPolicy,
    /// Program the helper should become.
    pub program: String,
    /// Arguments for `program`, already split into words. The helper execs directly, so
    /// nothing here is ever seen by a shell.
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
        for name in policy.allowed_env() {
            out.push(FLAG_ENV.to_string());
            out.push(name.clone());
        }

        out.push(SEPARATOR.to_string());
        out.push(program.to_string());
        out.extend(args.iter().cloned());
        out
    }

    /// Parse helper argv back into a policy and command.
    ///
    /// Every failure is a refusal. An unrecognised flag is an error rather than something
    /// to skip: ignoring it would mean running with a policy sandbx did not intend.
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
                FLAG_ENV => {
                    let name = rest.next().ok_or(SandboxError::BadHelperArgs {
                        detail: "env flag with no variable name after it",
                    })?;
                    // `allow_env` would silently skip this, which is right for a caller
                    // composing a policy but wrong here: a name that cannot be encoded did
                    // not come from `encode`, so the argv speaks a different protocol.
                    if name.contains('=') {
                        return Err(SandboxError::BadHelperArgs {
                            detail: "env variable name containing `=`",
                        });
                    }
                    policy = policy.allow_env(name);
                }
                flag => {
                    // One lookup, then one grant: the axis carries which one it is, so
                    // there is no second match here deciding it again.
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
