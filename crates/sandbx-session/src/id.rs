//! A session's name, and the one rule that makes it safe to put in a path.
//!
//! The inner `String` is private, so a `SessionId` cannot exist without having passed
//! [`FromStr`](std::str::FromStr). That is what lets the store join one to a directory
//! without a check of its own.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::SessionError;

/// The characters an id may be spelled with.
const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// The longest an id may be, which bounds the path component a typo can build.
const MAX_LENGTH: usize = 32;

/// A session's name, and a legal path component by construction.
///
/// Base36 of the millisecond it started. Not a sort key: base36 gains a digit as the
/// clock grows and sorts by length first, so order a listing by the header's timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(String);

impl SessionId {
    /// An id for a session starting now, distinguished from `attempt` earlier tries.
    ///
    /// Two sessions in the same millisecond collide, which the store resolves by
    /// retrying with the attempt count raised. It is added to the millisecond rather
    /// than suffixed, so a retry is still one base36 number.
    pub fn from_clock(attempt: u64) -> Result<Self, SessionError> {
        Ok(Self(base36(clock_millis()?.saturating_add(attempt))))
    }
}

/// Milliseconds since the Unix epoch.
///
/// `u64` rather than the `u128` the duration reports: a clock far enough in the future
/// to overflow it is as broken as one before the epoch, and truncating would hand back
/// an id that looks ordinary.
pub(crate) fn clock_millis() -> Result<u64, SessionError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SessionError::Clock)?;

    u64::try_from(elapsed.as_millis()).map_err(|_| SessionError::Clock)
}

impl std::str::FromStr for SessionId {
    type Err = SessionError;

    /// Accepts one to [`MAX_LENGTH`] characters of `0-9` and `a-z`, and nothing else.
    ///
    /// An allowlist rather than a search for `..`: an id becomes a path component, and a
    /// denylist's first omission is a traversal.
    fn from_str(value: &str) -> Result<Self, SessionError> {
        let invalid = |reason| SessionError::InvalidIdentifier {
            value: value.to_owned(),
            reason,
        };

        if value.is_empty() {
            return Err(invalid("it is empty"));
        }
        // Bytes, not characters: the alphabet is ASCII, so a multi-byte string is over
        // budget on either count.
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

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn base36_is_the_shortest_lowercase_spelling() {
        assert_eq!(base36(0), "0");
        assert_eq!(base36(35), "z");
        assert_eq!(base36(36), "10");
        assert_eq!(base36(u64::MAX), "3w5e11264sgsf");
    }

    #[test]
    fn a_clock_id_is_one_a_path_accepts_back() {
        let id = SessionId::from_clock(0).unwrap();

        assert_eq!(SessionId::from_str(&id.to_string()).unwrap(), id);
    }

    #[test]
    fn a_later_attempt_takes_a_different_id() {
        let first = SessionId::from_clock(0).unwrap();
        let second = SessionId::from_clock(1).unwrap();

        assert_ne!(first, second);
    }
}
