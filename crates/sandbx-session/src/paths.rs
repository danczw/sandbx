//! Where transcripts live.
//!
//! The lookup is injected because `set_var` is `unsafe fn` under edition 2024 and the
//! workspace forbids `unsafe_code`, so a test cannot drive a real environment; the
//! credential store in `sandbx-cli` resolves its root the same way.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::SessionError;

/// The session directory, below whichever state home is in play.
const DIRECTORY: &str = "sandbx/sessions";

/// Where transcripts are kept, from `$XDG_STATE_HOME` or `$HOME`.
///
/// Both are required to be absolute, and nothing falls back to the working directory: a
/// transcript there would sit inside the tree a run can grant a tool write over, and the
/// history resumed from it is what the model is told it said.
pub fn sessions_directory(
    lookup: &impl Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, SessionError> {
    if let Some(dir) = lookup("XDG_STATE_HOME").map(PathBuf::from)
        && dir.is_absolute()
    {
        return Ok(dir.join(DIRECTORY));
    }

    let home = lookup("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .ok_or(SessionError::NoStateHome)?;

    Ok(home.join(".local").join("state").join(DIRECTORY))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An environment of the pairs given, and nothing else.
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let pairs: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), OsString::from(*value)))
            .collect();

        move |name| {
            pairs
                .iter()
                .find(|(stored, _)| stored == name)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn xdg_state_home_wins_when_it_is_absolute() {
        let lookup = env(&[("XDG_STATE_HOME", "/var/state"), ("HOME", "/home/u")]);

        assert_eq!(
            sessions_directory(&lookup).unwrap(),
            PathBuf::from("/var/state/sandbx/sessions")
        );
    }

    #[test]
    fn home_supplies_the_default_state_directory() {
        let lookup = env(&[("HOME", "/home/u")]);

        assert_eq!(
            sessions_directory(&lookup).unwrap(),
            PathBuf::from("/home/u/.local/state/sandbx/sessions")
        );
    }

    #[test]
    fn a_relative_state_home_falls_back_to_home() {
        let lookup = env(&[("XDG_STATE_HOME", "state"), ("HOME", "/home/u")]);

        assert_eq!(
            sessions_directory(&lookup).unwrap(),
            PathBuf::from("/home/u/.local/state/sandbx/sessions")
        );
    }

    #[test]
    fn a_blank_variable_counts_as_unset() {
        let lookup = env(&[("XDG_STATE_HOME", ""), ("HOME", "/home/u")]);

        assert_eq!(
            sessions_directory(&lookup).unwrap(),
            PathBuf::from("/home/u/.local/state/sandbx/sessions")
        );
    }

    #[test]
    fn a_relative_home_is_refused_not_resolved() {
        let lookup = env(&[("HOME", "relative")]);

        assert!(matches!(
            sessions_directory(&lookup),
            Err(SessionError::NoStateHome)
        ));
    }

    #[test]
    fn neither_variable_set_is_refused() {
        let lookup = env(&[]);

        assert!(matches!(
            sessions_directory(&lookup),
            Err(SessionError::NoStateHome)
        ));
    }
}
