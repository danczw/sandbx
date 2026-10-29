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
