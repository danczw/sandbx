//! Public contract of [`SessionId`].
//!
//! An id becomes a path component under the session root, so these checks stand between
//! a `--session` argument and the filesystem.

use std::str::FromStr;

use sandbx_session::{SessionError, SessionId};

#[test]
fn a_traversing_id_is_refused_before_any_io() {
    for value in [
        "../../etc/passwd",
        "..",
        ".",
        "/etc/passwd",
        "a/b",
        "a\\b",
        "a\0b",
        "a b",
        "a.b",
        "a-b",
        "a_b",
        "UPPER",
        "~",
        "",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // One over the 32-byte bound.
    ] {
        let err = SessionId::from_str(value).unwrap_err();

        assert!(
            matches!(&err, SessionError::InvalidIdentifier { value: offered, .. } if offered == value),
            "{value:?} was not refused as an identifier: {err:?}"
        );
    }
}

#[test]
fn an_id_survives_a_round_trip_through_text() {
    for value in ["0", "a", "1z8k3p7q", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] {
        let id = SessionId::from_str(value).unwrap();

        assert_eq!(id.to_string(), value);
        assert_eq!(SessionId::from_str(&id.to_string()).unwrap(), id);
    }
}
