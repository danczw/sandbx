//! What can stop `auth`, or a key resolution on `agent-run`'s way to the provider.

use std::path::PathBuf;

/// Appended to every [`AuthError`] about a missing credential, so refusals do not diverge.
const AUTH_ADVICE: &str = "run `sandbx auth login` or export ANTHROPIC_API_KEY";

/// Why no credential was resolved, stored or removed.
#[derive(Debug)]
pub enum AuthError {
    /// Neither source held a key.
    NoCredential {
        /// The file that was looked in, for the operator to act on.
        path: PathBuf,
    },

    /// Neither `XDG_CONFIG_HOME` nor `HOME` named an absolute directory.
    NoConfigHome,

    /// The credential file is readable by more than its owner.
    Permissions {
        /// The file that was refused.
        path: PathBuf,
        /// The mode it carries.
        mode: u32,
    },

    /// The directory holding the credential file is reachable by more than its owner.
    DirPermissions {
        /// The directory that was refused.
        path: PathBuf,
        /// The mode it carries.
        mode: u32,
    },

    /// The credential file is not valid TOML.
    Malformed {
        /// The file that could not be parsed.
        path: PathBuf,
        /// One-based line the parse failed on, or 0 when the parser reported no position.
        line: usize,
    },

    /// The credential file's `anthropic` key is something other than a table.
    NotATable {
        /// The file holding it.
        path: PathBuf,
    },

    /// The credential file could not be read, written or removed.
    Io {
        /// What was being operated on.
        path: PathBuf,
        /// The underlying OS failure.
        source: std::io::Error,
    },

    /// The rendered file could not be built.
    Encode(toml::ser::Error),

    /// The key could not be read from stdin.
    Stdin(std::io::Error),

    /// `auth login` was asked to read a key from a terminal.
    TtyInput,

    /// Stdin held nothing but whitespace.
    BlankKey,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCredential { path } => write!(
                f,
                "no API key: {} does not hold one and ANTHROPIC_API_KEY is unset — {AUTH_ADVICE}",
                path.display()
            ),
            Self::NoConfigHome => write!(
                f,
                "no API key: neither XDG_CONFIG_HOME nor HOME names an absolute directory, \
                 so there is nowhere to keep one — {AUTH_ADVICE}"
            ),
            // The mode and not just the fact: seeing 644 is what tells an operator a umask
            // or a copy widened it rather than sandbx.
            Self::Permissions { path, mode } => write!(
                f,
                "refusing to read {} at mode {mode:o}: a credential readable by anyone but \
                 you is already disclosed — run `chmod 600 {}`",
                path.display(),
                path.display()
            ),
            Self::DirPermissions { path, mode } => write!(
                f,
                "refusing to read a credential from {} at mode {mode:o}: another user could \
                 replace the file in it — run `chmod 700 {}`",
                path.display(),
                path.display()
            ),
            Self::Malformed { path, line } => write!(
                f,
                "{} is not valid TOML at line {line} — the parser's own message is withheld \
                 because it quotes that line, which may hold the key; fix it by hand, or run \
                 `sandbx auth logout` to remove it",
                path.display()
            ),
            Self::NotATable { path } => write!(
                f,
                "{} has an `anthropic` entry that is not a table, so sandbx will not \
                 replace it — edit or remove it by hand",
                path.display()
            ),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Encode(source) => write!(f, "building the credential file: {source}"),
            Self::Stdin(source) => write!(f, "reading the key from stdin: {source}"),
            Self::TtyInput => write!(
                f,
                "refusing to read a key from the terminal, which would echo it into your \
                 scrollback — pipe it instead: read -rs KEY && printf %s \"$KEY\" | \
                 sandbx auth login"
            ),
            Self::BlankKey => write!(f, "stdin held no key"),
        }
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoCredential { .. }
            | Self::NoConfigHome
            | Self::Permissions { .. }
            | Self::DirPermissions { .. }
            | Self::NotATable { .. }
            | Self::TtyInput
            | Self::BlankKey
            // No source: the `toml` error it came from quotes the offending line.
            | Self::Malformed { .. } => None,
            Self::Io { source, .. } | Self::Stdin(source) => Some(source),
            Self::Encode(source) => Some(source),
        }
    }
}
