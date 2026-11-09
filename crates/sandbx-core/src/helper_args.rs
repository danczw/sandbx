//! The argv seam: a policy rendered as helper argv, and parsed back in the re-exec'd helper.
//!
//! Neither side is trusted and nothing in the argv is a boundary, so `decode` refuses what
//! `encode` could not have emitted rather than skipping it: such an argv speaks a different
//! protocol. [`SandboxPolicy::unbounded_resolution`]'s refusal is re-made here for that reason.
//! One shape gets through: an empty `--env` name, which `allow_env` then skips, narrowing
//! the policy.

use crate::{Axis, NetworkPolicy, ObjectId, SandboxError, SandboxPolicy, Sha256Digest, VettedPath};
use std::ffi::OsString;
use std::path::Path;
use std::slice;

const FLAG_NET: &str = "--allow-network";
/// Introduces one allowlisted TCP port, and takes exactly one value. Its own flag rather
/// than an optional value on [`FLAG_NET`] the way the CLI spells it, which would make
/// `decode`'s refusal of an unrecognised token a guess at whether the token looks like a
/// port (`context/decision-policy.md`).
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

/// The flag that introduces a path granted on `axis`. Takes two values, the path and then
/// the `<dev>:<ino>` the harness vetted it as. Mandatory and not optional: "is this token a
/// pin or the next flag?" is the lookahead `context/decision-policy.md` rejects,
/// and an unpinned grant is a case the helper has no answer for. It discloses nothing — a
/// confined command can `stat` any path it can name, Landlock having no right that covers
/// metadata. Here rather than on [`Axis`], the policy type having no business knowing how
/// the helper is invoked; one exhaustive match serves both `encode` and `decode`.
const fn path_flag(axis: Axis) -> &'static str {
    match axis {
        Axis::Read => "--ro",
        Axis::Write => "--rw",
        Axis::ReadExecute => "--rx",
    }
}

/// The axis `flag` introduces, if it is a path flag at all. A lookup over [`path_flag`]
/// and not a second list of spellings, so a flag `encode` can emit is one `decode` accepts
/// by construction.
fn axis_for(flag: &str) -> Option<Axis> {
    Axis::ALL.into_iter().find(|axis| path_flag(*axis) == flag)
}

fn next_arg<'a>(
    rest: &mut slice::Iter<'a, OsString>,
    detail: &'static str,
) -> Result<&'a OsString, SandboxError> {
    rest.next().ok_or(SandboxError::BadHelperArgs { detail })
}

/// [`next_arg`], for every token but a grant's path: `encode` writes only those from a
/// `str`, so one that is not UTF-8 means the argv speaks a different protocol.
fn next_str<'a>(
    rest: &mut slice::Iter<'a, OsString>,
    detail: &'static str,
) -> Result<&'a str, SandboxError> {
    utf8(next_arg(rest, detail)?)
}

fn utf8(arg: &OsString) -> Result<&str, SandboxError> {
    arg.to_str().ok_or(SandboxError::BadHelperArgs {
        detail: "a token that is not UTF-8 outside a granted path",
    })
}

/// A policy plus a command, as carried between sandbx and the helper process. Argv is not
/// private: `/proc` in the sandbox is the host's, so the command reads the supervisor's
/// `/proc/<pid>/cmdline` and everything here is visible to the process being confined —
/// hence variable names and never values. Not its own `cmdline`, which the `exec`
/// overwrites. The environment cannot carry them instead, being what the policy governs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperArgs {
    /// Restrictions the helper must apply to itself.
    pub policy: SandboxPolicy,
    /// Program the helper should become.
    pub program: String,
    /// Arguments for `program`, already split into words; the helper execs directly, so no
    /// shell ever sees these.
    pub args: Vec<String>,
    /// What `program` must hash to, when the caller pinned it. Beside `program` and not
    /// inside `policy`: the policy says what the command may do, this says which image may be it.
    pub pin: Option<Sha256Digest>,
}

impl HelperArgs {
    /// Render a policy and command as helper argv. `pin` is `None` for a command whose
    /// bytes the caller did not name.
    pub fn encode(
        policy: &SandboxPolicy,
        program: &str,
        args: &[String],
        pin: Option<Sha256Digest>,
    ) -> Vec<OsString> {
        let mut out: Vec<OsString> = Vec::new();

        for crate::GrantedPath { axis, vetted } in policy.granted_paths() {
            out.push(path_flag(axis).into());
            // The path's own bytes: a path need not be UTF-8, and a lossy spelling names
            // nothing, or something else, at the other end (#495).
            out.push(vetted.path().as_os_str().to_owned());
            out.push(vetted.object().to_string().into());
        }
        // Exhaustive, so a network state added to the policy is a compile error here rather
        // than a grant that fails to cross into the stage that enforces it.
        match policy.network() {
            NetworkPolicy::Denied => {}
            NetworkPolicy::AnyPort => out.push(FLAG_NET.into()),
            NetworkPolicy::Ports(ports) => {
                for port in ports {
                    out.extend([FLAG_NET_PORT.into(), port.to_string().into()]);
                }
            }
        }
        if policy.allows_unix_sockets() {
            out.push(FLAG_UNIX.into());
        }
        if policy.hints_dns_over_tcp() {
            out.push(FLAG_DNS_OVER_TCP.into());
        }
        for name in policy.allowed_env() {
            out.extend([FLAG_ENV.into(), name.into()]);
        }
        for name in policy.allowed_dns_names() {
            out.extend([FLAG_DNS_NAME.into(), name.into()]);
        }
        if let Some(digest) = pin {
            out.extend([FLAG_PIN.into(), digest.to_string().into()]);
        }

        out.extend([SEPARATOR.into(), program.into()]);
        out.extend(args.iter().map(OsString::from));
        out
    }

    /// Parse helper argv back into a policy and command. Every failure is a refusal:
    /// skipping an unrecognised flag would mean running with a policy sandbx did not intend.
    pub fn decode(argv: &[OsString]) -> Result<Self, SandboxError> {
        let mut policy = SandboxPolicy::default();
        let mut pin = None;
        let mut rest = argv.iter();

        let (program, args) = loop {
            let arg = next_str(&mut rest, "missing `--` separator before the command")?;

            match arg {
                SEPARATOR => {
                    let program = next_str(&mut rest, "no command after `--`")?;
                    let args = rest
                        .map(|arg| utf8(arg).map(str::to_owned))
                        .collect::<Result<_, _>>()?;
                    break (program.to_owned(), args);
                }
                FLAG_NET => policy = policy.allow_network(),
                FLAG_NET_PORT => {
                    let port = next_str(&mut rest, "network port flag with no port after it")?;
                    // `parse::<u16>` is the range check, so out-of-range and not-a-number are
                    // one refusal with no `as` cast between them to truncate one into the other.
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
                    let name = next_str(&mut rest, "env flag with no variable name after it")?;
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
                    let name = next_str(&mut rest, "dns name flag with no name after it")?;
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
                    let hex = next_str(&mut rest, "pin flag with no digest after it")?;
                    // `encode` writes a parsed digest, so anything unparseable here means the
                    // argv speaks a different protocol — as does a second one, which last-wins
                    // would resolve to whichever came later.
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
                    let path = next_arg(&mut rest, "path flag with no path after it")?;
                    // Refused and not inferred: a grant the helper cannot confirm against the
                    // object the harness vetted is one this decoder has no answer for
                    // (`context/decision-policy.md`).
                    let pin = next_str(&mut rest, "granted path with no object pin after it")?;
                    let object = ObjectId::parse(pin).ok_or(SandboxError::BadHelperArgs {
                        detail: "object pin that is not a device and an inode parted by `:`",
                    })?;
                    policy = policy.grant(axis, VettedPath::from_wire(path, object));
                }
            }
        };

        // A pin means the helper opens the file itself, resolving the name instead of libc —
        // a bare name resolved against the policy's own `PATH` could hash one file and
        // `execve` another.
        if pin.is_some() && !Path::new(&program).is_absolute() {
            return Err(SandboxError::BadHelperArgs {
                detail: "a pinned program that is not an absolute path",
            });
        }

        // `BadHelperArgs`, not `UnboundedResolution`: the harness refuses this policy before
        // it spawns, so an argv carrying one did not come from `encode`.
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
