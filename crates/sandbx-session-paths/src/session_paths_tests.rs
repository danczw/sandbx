use super::sessions_directory;
use sandbx_session_error::SessionError;
use std::ffi::OsString;
use std::path::PathBuf;

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
