//! Why a session operation did not happen.
//!
//! No `From` impls, deliberately: every wrapped failure is paired with the path and the
//! operation it came from, which a blanket conversion would discard.

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
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoStateHome | Self::InvalidIdentifier { .. } | Self::Clock => None,
        }
    }
}
