//! Why a session operation did not happen.
//!
//! No `From` impls, deliberately: every wrapped failure is paired with the path and the
//! operation it came from, which a blanket conversion would discard.

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

    /// Every id the clock offered was already taken.
    ///
    /// Two sessions in the same millisecond is ordinary and retried; this many in a row
    /// means the clock is not advancing.
    Collision {
        /// How many ids were tried.
        attempts: u64,
    },

    /// The first line of the transcript is not a header.
    ///
    /// Refused rather than read from line two: without the header there is nothing
    /// saying the rest of the file is a transcript at all.
    MissingHeader {
        /// The file that was read.
        path: PathBuf,
    },

    /// The transcript was written by a newer format than this build reads.
    ///
    /// Refused rather than read on a best effort: a reader that silently dropped a
    /// field it did not know would change the history the model is shown.
    UnsupportedVersion {
        /// The file that was read.
        path: PathBuf,
        /// The version it declares.
        version: u32,
    },

    /// A line of the transcript is not a record this build understands.
    ///
    /// Refused rather than skipped: an unclassifiable line may be a message, and
    /// dropping it would alter the conversation without saying so.
    Malformed {
        /// The file that was read.
        path: PathBuf,
        /// Which line, counting from one, so it can be found.
        line: usize,
        /// What the parse objected to.
        source: serde_json::Error,
    },

    /// The turn did not end with an assistant message.
    ///
    /// A transcript that ends on a user turn makes the next resume send two user turns
    /// in a row, which the API rejects — a session bricked by a run that exited zero.
    IncompleteTurn,

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
            Self::IncompleteTurn => write!(
                f,
                "the turn did not end with an assistant reply, so there is nothing to append"
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
            | Self::IncompleteTurn => None,
        }
    }
}
