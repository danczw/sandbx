//! What can stop a subcommand before it has an answer.

mod auth;

use std::path::PathBuf;

use sandbx_agent::TurnError;
use sandbx_core::SandboxError;
use sandbx_providers::ProviderError;
use sandbx_session::SessionError;

pub use auth::AuthError;

/// What to type instead, appended to every [`PolicyError`] that refused the derived default
/// so two of them cannot advise differently. A refusal of a flag says what to change about it.
const ADVICE: &str = "pass --allow-read PATH and --allow-write PATH \
                      for the tree the command needs";

/// Why `sandbx hash` printed no digest.
///
/// One field and no variants: a path that cannot be opened and one that cannot be read
/// through are the same answer to the operator, and the errno distinguishes them.
#[derive(Debug)]
pub struct HashError {
    pub(crate) path: PathBuf,
    pub(crate) source: std::io::Error,
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "could not hash {}: {}", self.path.display(), self.source)
    }
}

impl std::error::Error for HashError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Why the flags described no policy.
///
/// Every variant refuses rather than falling back to a narrower policy, which would make
/// an ordinary command fail for a reason the message could not explain; see
/// `context/decision-default-policy.md`.
#[derive(Debug)]
pub enum PolicyError {
    /// The process state the default is derived from could not be read.
    Unavailable {
        /// What could not be read, for the operator to act on.
        detail: &'static str,
        /// The underlying OS failure.
        source: std::io::Error,
    },

    /// The working directory is the home directory, or holds it.
    HomeDirectory {
        /// The directory a default would have been rooted at.
        cwd: PathBuf,
        /// The home directory that is it, or is inside it.
        home: PathBuf,
    },

    /// The working directory is where home directories live, or holds it.
    HomeParent {
        /// The directory a default would have been rooted at.
        cwd: PathBuf,
    },

    /// With no `HOME` naming a home directory, the cwd could not be ruled out as one.
    UnnamedHome {
        /// The directory a default would have been rooted at.
        cwd: PathBuf,
        /// The absolute `$HOME` rejected as no home, or `None` when there was none to name.
        home: Option<PathBuf>,
    },

    /// The working directory holds a path every command is already granted execute on.
    SystemExecutables {
        /// The directory a default would have been rooted at.
        cwd: PathBuf,
        /// The granted path found inside it.
        path: PathBuf,
    },

    /// The working directory is the filesystem root.
    FilesystemRoot,

    /// `--allow-env` named a variable the policy sets itself.
    ImposedVariable {
        /// The variable both flags claim.
        name: String,
    },

    /// `agent-run`'s `--allow-env` named the credential the harness spends itself.
    ///
    /// `&'static str`, so no shape of this variant can carry a key.
    HarnessCredential {
        /// The one name refused, from `auth::ENV_VAR`.
        name: &'static str,
    },

    /// A path flag covered somewhere sandbx keeps state of its own.
    ///
    /// `&'static str` for `holds`, so no shape of this variant can carry a key.
    GrantReachesOwned {
        /// The path as the flag gave it, before resolving.
        granted: PathBuf,
        /// The sandbx-owned path the grant reaches.
        owned: PathBuf,
        /// What sandbx keeps there, for the message to name.
        holds: &'static str,
    },

    /// A relative path flag could not be resolved, the working directory it is relative to
    /// being unreadable.
    ///
    /// Separate from [`Unavailable`](Self::Unavailable), whose advice is to pass the path
    /// flags: here they were passed, and what is missing is an absolute spelling.
    UnresolvableGrant {
        /// The path as the flag gave it.
        granted: PathBuf,
        /// Why the working directory could not be read.
        source: std::io::Error,
    },

    /// A path flag named something that could not be pinned to the object it names, so the
    /// grant the helper would check against does not exist (#212).
    ///
    /// Separate from [`UnresolvableGrant`](Self::UnresolvableGrant), where the flag's own
    /// spelling was unusable: here the spelling is fine and what it names is not.
    UnpinnableGrant {
        /// The path as the flag gave it, which is what the operator can go and change.
        granted: PathBuf,
        /// What vetting it reported.
        source: SandboxError,
    },

    /// A path flag resolved to one path when the refusals were checked and to another when the
    /// pin was taken, so the grant is not the one that was judged (#212).
    ///
    /// Both resolutions are a `canonicalize` of one name, so only a path moving mid-run
    /// reaches this.
    GrantMovedWhileVetting {
        /// The path as the flag gave it, which is what the operator can go and change.
        granted: PathBuf,
        /// What it named when the path refusals ran.
        checked: PathBuf,
        /// What it named a moment later, when it was pinned.
        vetted: PathBuf,
    },

    /// A no-flag run was made from a working directory reaching one of those paths.
    ///
    /// Separate from [`GrantReachesOwned`](Self::GrantReachesOwned): the operator granted
    /// nothing, so the advice is the one every working-directory refusal gives.
    CwdReachesOwned {
        /// Where sandbx was run from.
        cwd: PathBuf,
        /// The sandbx-owned path it reaches.
        owned: PathBuf,
        /// What sandbx keeps there, for the message to name.
        holds: &'static str,
    },

    /// `--allow-dns` was given alongside `--dns-over-tcp`.
    ///
    /// The five `Dns…` variants are each a shape that leaves a nameserver reachable, which
    /// answers for every name — so the allowlist bounds nothing.
    /// `context/decision-egress-proxy.md`.
    DnsWithResolverHint,

    /// `--allow-dns` was given alongside bare `--allow-network`.
    DnsWithEveryPort,

    /// `--allow-dns` was given alongside a port allowlist naming 53.
    DnsWithNameserverPort,

    /// `--allow-dns` was given with no IP egress at all.
    DnsWithoutEgress,

    /// `--allow-dns` was given alongside `--allow-unix-sockets`.
    DnsWithUnixSockets,

    /// A path flag named a file `--allow-dns` replaces with sandbx's own.
    ///
    /// Not one of the five: the allowlist still bounds what it says. The grant is the problem
    /// — it pins a rule to the host's file, and the bind leaves the command reading another.
    DnsGrantsBoundFile {
        /// The path as the flag gave it, before resolving.
        granted: PathBuf,
    },

    /// `--pin-sha256` was given more than once.
    RepeatedPin,

    /// `--pin-sha256` was given for a program that is not an absolute path.
    PinNeedsAbsoluteProgram {
        /// The program as it was typed.
        program: String,
    },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable { detail, source } => write!(f, "{detail}: {source} — {ADVICE}"),
            Self::HomeParent { cwd } => write!(
                f,
                "refusing to derive a policy from {}, which is where home directories live \
                 — {ADVICE}",
                cwd.display()
            ),
            // Naming the value matters where it is set and still rejected — `HOME=/home` is
            // where homes live, not one of them, and "no usable HOME" reads as unset.
            Self::UnnamedHome {
                cwd,
                home: Some(home),
            } => write!(
                f,
                "refusing to derive a policy from {}: HOME={} names no home directory, \
                 so sandbx cannot tell it from one — {ADVICE}",
                cwd.display(),
                home.display()
            ),
            Self::UnnamedHome { cwd, home: None } => write!(
                f,
                "refusing to derive a policy from {}: with no HOME naming a home directory, \
                 sandbx cannot tell it from one — {ADVICE}",
                cwd.display()
            ),
            Self::SystemExecutables { cwd, path } => write!(
                f,
                "refusing to derive a policy from {}: it holds {}, which every command may \
                 already execute, so a write grant there rewrites what runs next — {ADVICE}",
                cwd.display(),
                path.display()
            ),
            Self::HomeDirectory { cwd, home } if cwd == home => write!(
                f,
                "refusing to derive a policy from your home directory {} — {ADVICE}",
                home.display()
            ),
            Self::HomeDirectory { cwd, home } => write!(
                f,
                "refusing to derive a policy from {}, which holds your home directory {} — {ADVICE}",
                cwd.display(),
                home.display()
            ),
            Self::FilesystemRoot => {
                write!(
                    f,
                    "refusing to derive a policy from the filesystem root — {ADVICE}"
                )
            }
            // No `ADVICE`: this refusal is about neither a path nor the working directory.
            Self::ImposedVariable { name } => write!(
                f,
                "--dns-over-tcp sets {name} itself, so --allow-env {name} would be dropped \
                 rather than honoured — pass one of the two, not both"
            ),
            Self::HarnessCredential { name } => write!(
                f,
                "agent-run refuses --allow-env {name}: sandbx makes the provider call \
                 itself, so no tool call needs that value, and naming it hands the key to \
                 a process the model chose the arguments for — drop the flag, or use \
                 sandbox-run, where the program and its arguments are yours"
            ),
            // No `ADVICE` through here: the flags it names are the ones just refused, so these
            // arms say what to change about them instead.
            Self::GrantReachesOwned {
                granted,
                owned,
                holds,
            } if granted == owned => write!(
                f,
                "refusing to grant {}, where sandbx keeps {holds} — grant the tree the \
                 command needs, which is never one sandbx keeps its own state in",
                owned.display()
            ),
            Self::GrantReachesOwned {
                granted,
                owned,
                holds,
            } => write!(
                f,
                "refusing to grant {}: it reaches {}, where sandbx keeps {holds} — grant \
                 the tree the command needs, which is never one sandbx keeps its own \
                 state in",
                granted.display(),
                owned.display()
            ),
            Self::UnresolvableGrant { granted, source } => write!(
                f,
                "refusing to grant {}: it is relative, and the working directory to resolve \
                 it against could not be read: {source} — write the grant as an absolute path",
                granted.display()
            ),
            Self::UnpinnableGrant { granted, source } => write!(
                f,
                "refusing to grant {}: {source} — a grant is checked against the object it \
                 named, so name a path that exists",
                granted.display()
            ),
            Self::GrantMovedWhileVetting {
                granted,
                checked,
                vetted,
            } => write!(
                f,
                "refusing to grant {}: it named {} when the path refusals were checked and \
                 {} a moment later, so what would be granted is not what was judged — run \
                 it again, from a tree nothing else is rewriting underneath you",
                granted.display(),
                checked.display(),
                vetted.display()
            ),
            Self::CwdReachesOwned { cwd, owned, holds } if cwd == owned => write!(
                f,
                "refusing to derive a policy from {}, where sandbx keeps {holds} and the \
                 default would grant write — {ADVICE}",
                owned.display()
            ),
            Self::CwdReachesOwned { cwd, owned, holds } => write!(
                f,
                "refusing to derive a policy from {}: it reaches {}, where sandbx keeps \
                 {holds}, and the default would grant write over it — {ADVICE}",
                cwd.display(),
                owned.display()
            ),
            // No `ADVICE` through here either: each names the flag it refused and what to
            // write instead of it.
            Self::DnsWithResolverHint => write!(
                f,
                "--allow-dns leaves the command no nameserver at all, and --dns-over-tcp asks \
                 one over TCP — pass one of the two, not both"
            ),
            Self::DnsWithEveryPort => write!(
                f,
                "--allow-dns bounds which names resolve, and bare --allow-network leaves UDP \
                 open, so a command carrying a resolver of its own reaches a nameserver that \
                 answers for every name — name the ports the command connects to, as in \
                 --allow-network 443"
            ),
            Self::DnsWithNameserverPort => write!(
                f,
                "--allow-dns bounds which names resolve, and --allow-network 53 reaches a \
                 nameserver that answers for every name — drop port 53 and keep the ports the \
                 command connects to"
            ),
            Self::DnsWithoutEgress => write!(
                f,
                "--allow-dns bounds which names resolve, and this run has no IP egress to \
                 resolve them for — pass --allow-network PORT as well, or drop the flag"
            ),
            Self::DnsWithUnixSockets => write!(
                f,
                "--allow-dns bounds which names resolve, and --allow-unix-sockets reaches \
                 nscd's socket, which glibc asks before it reads nsswitch.conf and which \
                 answers for every name — pass one of the two, not both"
            ),
            Self::DnsGrantsBoundFile { granted } => write!(
                f,
                "--allow-dns replaces {} with sandbx's own copy, so a grant naming it reaches \
                 a file the command never reads — drop it, and grant the directory instead if \
                 the command needs the rest of it",
                granted.display()
            ),
            Self::RepeatedPin => write!(
                f,
                "one run execs one program, so there is one digest to pin — \
                 pass --pin-sha256 once"
            ),
            Self::PinNeedsAbsoluteProgram { program } => write!(
                f,
                "--pin-sha256 needs an absolute program, and {program} is not one: sandbx \
                 opens the file to hash it, while a bare name is resolved against the PATH \
                 the policy gives the command — write `$PWD/{program}` or \
                 `$(command -v {program})`"
            ),
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HomeDirectory { .. }
            | Self::HomeParent { .. }
            | Self::UnnamedHome { .. }
            | Self::SystemExecutables { .. }
            | Self::FilesystemRoot
            | Self::ImposedVariable { .. }
            | Self::HarnessCredential { .. }
            | Self::GrantReachesOwned { .. }
            | Self::GrantMovedWhileVetting { .. }
            | Self::CwdReachesOwned { .. }
            | Self::DnsWithResolverHint
            | Self::DnsWithEveryPort
            | Self::DnsWithNameserverPort
            | Self::DnsWithoutEgress
            | Self::DnsWithUnixSockets
            | Self::DnsGrantsBoundFile { .. }
            | Self::RepeatedPin
            | Self::PinNeedsAbsoluteProgram { .. } => None,
            Self::Unavailable { source, .. } | Self::UnresolvableGrant { source, .. } => {
                Some(source)
            }
            Self::UnpinnableGrant { source, .. } => Some(source),
        }
    }
}

/// Why `sandbox-run` did not run the command.
///
/// Separate from [`SandboxError`], which `sandbx-core` owns: deriving a policy is the
/// CLI's own step, and core must not grow a variant it never produces.
#[derive(Debug)]
pub enum SandboxRunError {
    /// The flags described no policy.
    Policy(PolicyError),

    /// The sandbox itself refused, or the command could not be run under it.
    Sandbox(SandboxError),
}

impl From<PolicyError> for SandboxRunError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<SandboxError> for SandboxRunError {
    fn from(error: SandboxError) -> Self {
        Self::Sandbox(error)
    }
}

impl std::fmt::Display for SandboxRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(error) => write!(f, "{error}"),
            Self::Sandbox(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SandboxRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(error) => Some(error),
            Self::Sandbox(error) => Some(error),
        }
    }
}

/// Why a turn did not finish.
///
/// A failing *tool* is not in here: it comes back to the model as an error result for it
/// to try something else, which is the loop's own contract.
#[derive(Debug)]
pub enum AgentError {
    /// The prompt was blank, which the API rejects as an empty text block.
    EmptyPrompt,

    /// The flags described no policy, so no tool could be bounded.
    Policy(PolicyError),

    /// The runtime the turn needs could not be built.
    Runtime(std::io::Error),

    /// The answer could not be written out — a closed pipe, most often.
    Output(std::io::Error),

    /// No API key could be resolved from the environment or the credential file.
    Credential(AuthError),

    /// The provider client could not be constructed — a rejected base URL, most often.
    Provider(ProviderError),

    /// The session could not be opened, or the finished turn could not be saved.
    ///
    /// A failed save is an error, not a warning: exiting 0 would leave the next
    /// `--session` resuming a conversation missing its last turn.
    Session(SessionError),

    /// `--approve call` was asked for and there is no terminal to ask on.
    NoTerminal {
        /// Opening `/dev/tty`, which is `ENXIO` with no controlling terminal.
        source: std::io::Error,
    },

    /// The turn itself ended without an answer.
    Turn(TurnError),
}

impl From<PolicyError> for AgentError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<AuthError> for AgentError {
    fn from(error: AuthError) -> Self {
        Self::Credential(error)
    }
}

impl From<ProviderError> for AgentError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

impl From<SessionError> for AgentError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<TurnError> for AgentError {
    fn from(error: TurnError) -> Self {
        Self::Turn(error)
    }
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPrompt => write!(f, "the prompt is empty"),
            Self::Policy(error) => write!(f, "{error}"),
            Self::Runtime(error) => write!(f, "building the async runtime: {error}"),
            Self::Output(error) => write!(f, "writing the answer: {error}"),
            Self::Credential(error) => write!(f, "{error}"),
            Self::Provider(error) => write!(f, "{error}"),
            // Forwarded rather than prefixed: the session's own prose already names the
            // path and carries the advice.
            Self::Session(error) => write!(f, "{error}"),
            // The flag is named because dropping it is the whole remedy, and the run
            // refuses rather than serving the weaker regime it asks to replace.
            Self::NoTerminal { source } => write!(
                f,
                "`{}` needs a terminal to ask on and there is none: {source}. \
                 Drop the flag to take the answer from `--allow-tool` instead",
                crate::agent::APPROVE_CALL
            ),
            Self::Turn(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::EmptyPrompt => None,
            Self::Policy(error) => Some(error),
            Self::Runtime(error) | Self::Output(error) => Some(error),
            Self::Credential(error) => Some(error),
            Self::Provider(error) => Some(error),
            Self::Session(error) => Some(error),
            Self::NoTerminal { source } => Some(source),
            Self::Turn(error) => Some(error),
        }
    }
}
