//! A session's name, and the one rule that makes it safe to put in a path.
//!
//! The inner `String` is private and there are exactly two constructors, so every
//! `SessionId` is a spelling [`FromStr`] accepts — which is what lets
//! the store join one to a directory unchecked. `from_clock` is the half the type does not
//! enforce, skipping the parser; what makes its output legal is that `base36` draws every
//! digit from `ALPHABET` and never returns an empty string. A test pins the composition.

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use sandbx_session_error::SessionError;

/// The characters an id may be spelled with.
const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// The longest an id may be, which bounds the path component a typo can build.
const MAX_LENGTH: usize = 32;

/// A session's name, and a legal path component by construction.
///
/// Base36 of the millisecond it started, and not a sort key: it gains a digit as the
/// clock grows and so sorts by length first. Order a listing by the header timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(String);

impl SessionId {
    /// An id for a session starting now, distinguished from `attempt` earlier tries.
    ///
    /// `attempt` is added to the millisecond rather than suffixed, so a retry after a
    /// same-millisecond collision is still one base36 number.
    pub fn from_clock(attempt: u64) -> Result<Self, SessionError> {
        Ok(Self(base36(clock_millis()?.saturating_add(attempt))))
    }
}

/// Milliseconds since the Unix epoch.
///
/// `u64`, not the `u128` the duration reports: a clock far enough ahead to overflow it
/// is as broken as one before the epoch, and truncating would yield an ordinary-looking
/// id.
pub fn clock_millis() -> Result<u64, SessionError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SessionError::Clock)?;

    u64::try_from(elapsed.as_millis()).map_err(|_| SessionError::Clock)
}

impl FromStr for SessionId {
    type Err = SessionError;

    /// Accepts one to 32 characters of `0-9` and `a-z`, and nothing else.
    ///
    /// An allowlist, not a search for `..`: a denylist's first omission is a traversal.
    fn from_str(value: &str) -> Result<Self, SessionError> {
        let invalid = |reason| SessionError::InvalidIdentifier {
            value: value.to_owned(),
            reason,
        };

        if value.is_empty() {
            return Err(invalid("it is empty"));
        }
        // Bytes, not characters: the alphabet is ASCII, so a multi-byte string fails either way.
        if value.len() > MAX_LENGTH {
            return Err(invalid("it is longer than 32 characters"));
        }
        if !value.bytes().all(|byte| ALPHABET.contains(&byte)) {
            return Err(invalid(
                "a session id is 1 to 32 characters of 0-9 and a-z, and nothing else",
            ));
        }

        Ok(Self(value.to_owned()))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `value` in base 36, lowercase, shortest form.
fn base36(mut value: u64) -> String {
    if value == 0 {
        return "0".to_owned();
    }

    let mut digits = String::new();
    while value > 0 {
        digits.push(char::from(ALPHABET[(value % 36) as usize]));
        value /= 36;
    }

    digits.chars().rev().collect()
}

#[cfg(test)]
#[path = "session_id_tests.rs"]
mod tests;
