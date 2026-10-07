use crate::{Axis, NetworkPolicy, SandboxError, SandboxPolicy, Sha256Digest};

const FLAG_NET: &str = "--allow-network";
/// Introduces one allowlisted TCP port, and takes exactly one value.
///
/// Its own flag rather than an optional value on [`FLAG_NET`] the way the CLI spells it,
/// which would make `decode`'s refusal of an unrecognised token a guess at whether the token
/// looks like a port. `context/decision-enforcement-seam.md`.
const FLAG_NET_PORT: &str = "--allow-network-port";
const FLAG_UNIX: &str = "--allow-unix-sockets";
/// Introduces the name of a variable the command may inherit. Never a value.
const FLAG_ENV: &str = "--env";
/// Carries the resolver hint and takes no value; the pair it stands for is the policy's.
const FLAG_DNS_OVER_TCP: &str = "--dns-over-tcp";
/// Introduces one name the command may resolve, and takes exactly one value. Never an
/// address: the helper resolves it, the harness does not.
const FLAG_DNS_NAME: &str = "--allow-dns-name";
/// Introduces the SHA-256 the program must hash to, and takes exactly one value. No path:
/// the digest describes the one binary the helper becomes, which `SEPARATOR` already names.
const FLAG_PIN: &str = "--pin-sha256";
/// Everything after this is the command to run, never a helper flag.
const SEPARATOR: &str = "--";

/// The flag that introduces a path granted on `axis`.
///
/// Here rather than on [`Axis`], the policy type having no business knowing how the helper
/// is invoked; one exhaustive match serves both `encode` and `decode`.
const fn path_flag(axis: Axis) -> &'static str {
    match axis {
        Axis::Read => "--ro",
        Axis::Write => "--rw",
        Axis::ReadExecute => "--rx",
    }
}

/// The axis `flag` introduces, if it is a path flag at all.
///
/// A lookup over [`path_flag`] and not a second list of spellings, so a flag `encode` can
/// emit is one `decode` accepts by construction.
fn axis_for(flag: &str) -> Option<Axis> {
    Axis::ALL.into_iter().find(|axis| path_flag(*axis) == flag)
}

/// A policy plus a command, as carried between sandbx and the helper process.
///
/// Argv is not private: the command reads its own `/proc/self/cmdline`, so everything here
/// is visible to the process being confined — hence variable names and never values. The
/// environment cannot carry them instead, being the thing the policy governs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperArgs {
    /// Restrictions the helper must apply to itself.
    pub policy: SandboxPolicy,
    /// Program the helper should become.
    pub program: String,
    /// Arguments for `program`, already split into words; the helper execs directly, so no
    /// shell ever sees these.
    pub args: Vec<String>,
    /// What `program` must hash to, when the caller pinned it.
    ///
    /// Beside `program` and not inside `policy`: the policy says what the command may do,
    /// this says which image may be it.
    pub pin: Option<Sha256Digest>,
}

impl HelperArgs {
    /// Render a policy and command as helper argv.
    ///
    /// `pin` is `None` for a command whose bytes the caller did not name.
    pub fn encode(
        policy: &SandboxPolicy,
        program: &str,
        args: &[String],
        pin: Option<Sha256Digest>,
    ) -> Vec<String> {
        let mut out = Vec::new();

        for (axis, path) in policy.granted_paths() {
            out.push(path_flag(axis).to_string());
            out.push(path.display().to_string());
        }
        // Exhaustive, so a network state added to the policy is a compile error here rather
        // than a grant that fails to cross into the stage that enforces it.
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
        if policy.hints_dns_over_tcp() {
            out.push(FLAG_DNS_OVER_TCP.to_string());
        }
        for name in policy.allowed_env() {
            out.push(FLAG_ENV.to_string());
            out.push(name.clone());
        }
        for name in policy.allowed_dns_names() {
            out.push(FLAG_DNS_NAME.to_string());
            out.push(name.clone());
        }
        if let Some(digest) = pin {
            out.push(FLAG_PIN.to_string());
            out.push(digest.to_string());
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
        let mut pin = None;
        let mut rest = argv.iter();

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
                    // `parse::<u16>` is the range check, so out-of-range and not-a-number
                    // are one refusal with no `as` cast between them to truncate one into
                    // the other.
                    let port: u16 = port.parse().map_err(|_| SandboxError::BadHelperArgs {
                        detail: "network port that is not a number in 1..=65535",
                    })?;
                    // Refused where `allow_network_port` skips it: `encode` never emits 0,
                    // so a 0 here means the argv speaks a different protocol.
                    if port == 0 {
                        return Err(SandboxError::BadHelperArgs {
                            detail: "network port 0, which matches no port",
                        });
                    }
                    policy = policy.allow_network_port(port);
                }
                FLAG_UNIX => policy = policy.allow_unix_sockets(),
                FLAG_DNS_OVER_TCP => policy = policy.hint_dns_over_tcp(),
                FLAG_ENV => {
                    let name = rest.next().ok_or(SandboxError::BadHelperArgs {
                        detail: "env flag with no variable name after it",
                    })?;
                    // Refused where `allow_env` would skip it: a name `encode` could not
                    // have emitted means the argv speaks a different protocol.
                    if name.contains('=') {
                        return Err(SandboxError::BadHelperArgs {
                            detail: "env variable name containing `=`",
                        });
                    }
                    policy = policy.allow_env(name);
                }
                FLAG_DNS_NAME => {
                    let name = rest.next().ok_or(SandboxError::BadHelperArgs {
                        detail: "dns name flag with no name after it",
                    })?;
                    // Refused where `allow_dns` would skip it: such a name would forge a
                    // field or a comment in the hosts file the helper renders from these.
                    if !crate::policy::is_resolvable_name(name) {
                        return Err(SandboxError::BadHelperArgs {
                            detail: "dns name that is empty, over-long, or carries whitespace, \
                                     `#` or a NUL",
                        });
                    }
                    policy = policy.allow_dns(name);
                }
                FLAG_PIN => {
                    let hex = rest.next().ok_or(SandboxError::BadHelperArgs {
                        detail: "pin flag with no digest after it",
                    })?;
                    // The CLI parsed this once already, so anything unparseable here means
                    // the argv speaks a different protocol — as does a second one, which
                    // last-wins would resolve to whichever came later.
                    let digest =
                        Sha256Digest::parse(hex).map_err(|_| SandboxError::BadHelperArgs {
                            detail: "pin digest that is not 64 lowercase hex characters",
                        })?;
                    if pin.replace(digest).is_some() {
                        return Err(SandboxError::BadHelperArgs {
                            detail: "more than one pin flag, which names two images for one \
                                     program",
                        });
                    }
                }
                flag => {
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

        // A pin means the helper opens the file itself, so it resolves the name instead of
        // libc — and a bare name resolved against the policy's own `PATH` would have it
        // hash one file and `execve` another. Refused rather than searched.
        if pin.is_some() && !std::path::Path::new(&program).is_absolute() {
            return Err(SandboxError::BadHelperArgs {
                detail: "a pinned program that is not an absolute path",
            });
        }

        // After the loop, each shape being a pair of flags. `BadHelperArgs` and not
        // `UnboundedResolution`: the harness refuses this policy before it spawns, so an argv
        // carrying one did not come from `encode`.
        if let Some(detail) = policy.unbounded_resolution() {
            return Err(SandboxError::BadHelperArgs { detail });
        }

        Ok(Self {
            policy,
            program,
            args,
            pin,
        })
    }
}
