use crate::{Axis, NetworkPolicy, SandboxError, SandboxPolicy};

const FLAG_NET: &str = "--allow-network";
/// Introduces one allowlisted TCP port, and takes exactly one value.
///
/// Its own flag rather than an optional value on [`FLAG_NET`] the way the CLI spells it: an
/// optional value would make `decode`'s refusal of an unrecognised token a "does this look
/// like a port?" guess. Why, in `context/decision-enforcement-seam.md`.
const FLAG_NET_PORT: &str = "--allow-network-port";
const FLAG_UNIX: &str = "--allow-unix-sockets";
/// Introduces the *name* of a variable the command may inherit. Never a value.
const FLAG_ENV: &str = "--env";
/// Everything after this is the command to run, never a helper flag.
const SEPARATOR: &str = "--";

/// The flag that introduces a path granted on `axis`.
///
/// Here rather than on [`Axis`], the policy type having no business knowing how the helper
/// is invoked; one exhaustive match for both `encode` and `decode`, so a new axis is a
/// compile error here and nowhere else.
const fn path_flag(axis: Axis) -> &'static str {
    match axis {
        Axis::Read => "--ro",
        Axis::Write => "--rw",
        Axis::ReadExecute => "--rx",
    }
}

/// The axis `flag` introduces, if it is a path flag at all.
///
/// A lookup over [`path_flag`] rather than a second list of spellings, so a flag `encode`
/// can emit is one `decode` accepts, by construction.
fn axis_for(flag: &str) -> Option<Axis> {
    Axis::ALL.into_iter().find(|axis| path_flag(*axis) == flag)
}

/// A policy plus a command, as carried between sandbx and the helper process.
///
/// Argv is not private: the command reads its own `/proc/self/cmdline`, so everything here
/// is visible to the process being confined — hence the rule the environment axis obeys,
/// that this carries variable names and never values. The environment cannot be the channel
/// instead, being what the policy now governs: the filter would leak it or eat it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperArgs {
    /// Restrictions the helper must apply to itself.
    pub policy: SandboxPolicy,
    /// Program the helper should become.
    pub program: String,
    /// Arguments for `program`, already split into words; the helper execs directly, so no
    /// shell ever sees these.
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
        // Exhaustive, so a network state added to the policy is a compile error here rather
        // than a grant that silently fails to cross into the stage that enforces it.
        match policy.network() {
            NetworkPolicy::Denied => {}
            NetworkPolicy::AnyPort => out.push(FLAG_NET.to_string()),
            NetworkPolicy::Ports(ports) => {
                for port in ports {
                    out.push(FLAG_NET_PORT.to_string());
                    out.push(port.to_string());
                }
            }
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
    /// Every failure is a refusal: skipping an unrecognised flag would mean running with a
    /// policy sandbx did not intend.
    pub fn decode(argv: &[String]) -> Result<Self, SandboxError> {
        let mut policy = SandboxPolicy::default();
        let mut rest = argv.iter();

        // Split off where the separator is found, rather than by collecting the tail and
        // re-iterating it to take the head.
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
                FLAG_NET_PORT => {
                    let port = rest.next().ok_or(SandboxError::BadHelperArgs {
                        detail: "network port flag with no port after it",
                    })?;
                    // `parse::<u16>` is the range check: out-of-range and not-a-number are
                    // one refusal, with no `as` cast between them to truncate one into the
                    // other.
                    let port: u16 = port.parse().map_err(|_| SandboxError::BadHelperArgs {
                        detail: "network port that is not a number in 1..=65535",
                    })?;
                    // Refused where `allow_network_port` skips it: `encode` never emits 0, so
                    // a 0 here means the argv speaks a different protocol.
                    if port == 0 {
                        return Err(SandboxError::BadHelperArgs {
                            detail: "network port 0, which matches no port",
                        });
                    }
                    policy = policy.allow_network_port(port);
                }
                FLAG_UNIX => policy = policy.allow_unix_sockets(),
                FLAG_ENV => {
                    let name = rest.next().ok_or(SandboxError::BadHelperArgs {
                        detail: "env flag with no variable name after it",
                    })?;
                    // `allow_env` would skip this, right for a caller composing a policy
                    // but wrong here: a name `encode` could not have emitted means the
                    // argv speaks a different protocol.
                    if name.contains('=') {
                        return Err(SandboxError::BadHelperArgs {
                            detail: "env variable name containing `=`",
                        });
                    }
                    policy = policy.allow_env(name);
                }
                flag => {
                    // One lookup, then one grant: the axis carries which one it is, so no
                    // second match here decides it again.
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
