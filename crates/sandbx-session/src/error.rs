//! Why a session operation did not happen.
//!
//! No `From` impls, and do not add one: every wrapped failure is paired with the path
//! and operation it came from, which a blanket conversion would discard.

use std::path::PathBuf;

use crate::SessionId;

/// Why a session could not be named, read, or written.
#[derive(Debug)]
pub enum SessionError {
    /// Neither `$XDG_STATE_HOME` nor `$HOME` names an absolute directory.
    NoStateHome,

    /// The id is not one a session can be called.
    InvalidIdentifier {
        /// What was offered, quoted back so a typo is visible.
        value: String,
        /// Which rule it broke.
        reason: &'static str,
    },

    /// The system clock is before the Unix epoch, so no id follows from it.
    Clock,

    /// There is no transcript under that id.
    NotFound {
        /// The id that was asked for.
        id: SessionId,
    },

    /// Every id the clock offered was taken, so it is not advancing.
    Collision {
        /// How many ids were tried.
        attempts: u64,
    },

    /// The first line is not a header, so nothing says the rest is a transcript.
    MissingHeader {
        /// The file that was read.
        path: PathBuf,
    },

    /// Not the format this build reads; refused, since best-effort would drop a field
    /// and so change the history the model is shown.
    UnsupportedVersion {
        /// The file that was read.
        path: PathBuf,
        /// The version it declares.
        version: u32,
    },

    /// A line is not a record; refused rather than skipped, since it may be a message.
    Malformed {
        /// The file that was read.
        path: PathBuf,
        /// Which line, counting from one, so it can be found.
        line: usize,
        /// What the parse objected to.
        source: serde_json::Error,
    },

    /// Writable by somebody else, and refused unlike merely readable: an editable history
    /// is one they choose, and it drives tool calls.
    Writable {
        /// The transcript that was refused.
        path: PathBuf,
        /// The mode it carries.
        mode: u32,
    },

    /// The directory is writable by somebody else, who can rename their own `0600` file
    /// over the transcript whatever the transcript's own mode says.
    DirWritable {
        /// The directory that was refused.
        path: PathBuf,
        /// The mode it carries.
        mode: u32,
    },

    /// A symbolic link: following one vets a different file than it reads, and for the
    /// root, `chmod`s outside the store.
    Symlink {
        /// The link that was refused.
        path: PathBuf,
    },

    /// The transcript, or the directory holding it, belongs to another user.
    ForeignOwner {
        /// What was refused.
        path: PathBuf,
        /// The uid that owns it.
        uid: u32,
    },

    /// Two turns of the same role in a row, or a transcript opening on the model's reply
    /// — both of which only a hand edit can produce.
    Disordered {
        /// The transcript that was refused.
        path: PathBuf,
    },

    /// The turn ends on a prompt nothing answered — neither the model's reply nor the
    /// tool results a turn out of rounds breaks off on, so storing it bricks the session.
    IncompleteTurn,

    /// The turn holds two messages of the same role in a row, joins the stored history on
    /// the role it ends with, or opens an empty transcript on the model's reply — the same
    /// defect `Disordered` catches after a write that cannot be undone.
    DisorderedTurn,

    /// An operation on the store's files failed.
    Io {
        /// What was being read or written.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoStateHome => write!(
                f,
                "no absolute $XDG_STATE_HOME or $HOME, so there is nowhere to keep sessions"
            ),
            Self::InvalidIdentifier { value, reason } => {
                write!(f, "`{value}` is not a session id: {reason}")
            }
            Self::Clock => write!(
                f,
                "the system clock is before the unix epoch, so no session id follows from it"
            ),
            Self::NotFound { id } => write!(f, "there is no session {id}"),
            Self::Collision { attempts } => write!(
                f,
                "every one of {attempts} session ids was taken; the clock is not advancing"
            ),
            Self::MissingHeader { path } => {
                write!(f, "{} does not begin with a session header", path.display())
            }
            Self::UnsupportedVersion { path, version } => write!(
                f,
                "{} is a version {version} transcript, which this build does not read",
                path.display()
            ),
            Self::Malformed { path, line, source } => write!(
                f,
                "line {line} of {} is not a session record: {source}",
                path.display()
            ),
            Self::Writable { path, mode } => write!(
                f,
                "refusing to resume {} at mode {mode:o}: another user could choose what \
                 this conversation says you asked for — run `chmod 600 {}`",
                path.display(),
                path.display()
            ),
            Self::DirWritable { path, mode } => write!(
                f,
                "refusing to resume a session from {} at mode {mode:o}: another user could \
                 replace the transcript in it — run `chmod 700 {}`",
                path.display(),
                path.display()
            ),
            Self::Symlink { path } => write!(
                f,
                "refusing to use {}: it is a symbolic link, so what sandbx would check \
                 is not what it would read or write",
                path.display()
            ),
            Self::ForeignOwner { path, uid } => write!(
                f,
                "refusing to resume {}: it belongs to uid {uid}, not to you",
                path.display()
            ),
            Self::Disordered { path } => write!(
                f,
                "{} must open on a user turn and alternate, bar a turn of tool results \
                 the prompt after it answers beside, and does not — it has been edited \
                 since sandbx wrote it",
                path.display()
            ),
            Self::IncompleteTurn => write!(
                f,
                "the turn ends on a prompt with nothing answering it, \
                 neither a reply nor a tool result, so there is nothing to append"
            ),
            Self::DisorderedTurn => write!(
                f,
                "the turn must open on a user turn, alternate, and join the stored \
                 history on the other role unless that ends on tool results, and does \
                 not — appending it would leave the session unreadable"
            ),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::NoStateHome
            | Self::InvalidIdentifier { .. }
            | Self::Clock
            | Self::NotFound { .. }
            | Self::Collision { .. }
            | Self::MissingHeader { .. }
            | Self::UnsupportedVersion { .. }
            | Self::Writable { .. }
            | Self::DirWritable { .. }
            | Self::Symlink { .. }
            | Self::ForeignOwner { .. }
            | Self::Disordered { .. }
            | Self::IncompleteTurn
            | Self::DisorderedTurn => None,
        }
    }
}
