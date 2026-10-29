//! Where transcripts live.
//!
//! The lookup is injected because `set_var` is `unsafe fn` under edition 2024 and the
//! workspace forbids `unsafe_code`, so a test cannot drive a real environment;
//! `sandbx-auth`'s `config_file` resolves the credential root the same way.

use std::ffi::OsString;
use std::path::PathBuf;

use sandbx_session_error::SessionError;

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
    let absolute = |name| lookup(name).map(PathBuf::from).filter(|d| d.is_absolute());
    if let Some(dir) = absolute("XDG_STATE_HOME") {
        return Ok(dir.join(DIRECTORY));
    }

    let home = absolute("HOME").ok_or(SessionError::NoStateHome)?;

    Ok(home.join(".local").join("state").join(DIRECTORY))
}

#[cfg(test)]
#[path = "session_paths_tests.rs"]
mod tests;
