use std::ffi::OsString;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};

use super::{Device, ENV_VAR, FILE, Source, config_file, read_key, resolve};
use crate::{AuthError, store};

/// Against a literal: `SECURITY.md`, the README and `--help` name it in prose that
/// cannot follow a rename.
#[test]
fn the_refused_variable_is_spelled_out() {
    assert_eq!(ENV_VAR, "ANTHROPIC_API_KEY");
}

/// An env lookup over a fixed list, standing in for `var_os`.
fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
    let pairs: Vec<(String, String)> = pairs
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect();
    move |name| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| OsString::from(value))
    }
}

/// A credential file holding `key`, through [`store::store`] rather than `fs::write`
/// so the fixture carries the modes [`resolve`] insists on and not the `tempdir`'s own.
fn stored_key(dir: &Path, key: &str) {
    store::store(&dir.join(FILE), &SecretString::from(key.to_string())).unwrap();
}

#[test]
fn xdg_config_home_names_the_file_when_absolute() {
    let path = config_file(&env(&[("XDG_CONFIG_HOME", "/x/conf"), ("HOME", "/home/u")])).unwrap();
    assert_eq!(path, PathBuf::from("/x/conf/sandbx/credentials.toml"));
}

#[test]
fn a_relative_xdg_config_home_falls_back_to_home() {
    let path = config_file(&env(&[("XDG_CONFIG_HOME", "conf"), ("HOME", "/home/u")])).unwrap();
    assert_eq!(
        path,
        PathBuf::from("/home/u/.config/sandbx/credentials.toml"),
        "a relative XDG_CONFIG_HOME would put a credential under the working directory"
    );
}

#[test]
fn home_names_the_file_when_xdg_is_unset() {
    let path = config_file(&env(&[("HOME", "/home/u")])).unwrap();
    assert_eq!(
        path,
        PathBuf::from("/home/u/.config/sandbx/credentials.toml")
    );
}

#[test]
fn neither_variable_set_is_refused_not_guessed() {
    assert!(matches!(
        config_file(&env(&[])),
        Err(AuthError::NoConfigHome)
    ));
}

#[test]
fn a_relative_home_is_refused_too() {
    assert!(matches!(
        config_file(&env(&[("HOME", "u")])),
        Err(AuthError::NoConfigHome)
    ));
}

#[test]
fn the_environment_answers_before_the_file() {
    let dir = tempfile::tempdir().unwrap();
    stored_key(dir.path(), "from-file");

    let (key, source) = resolve(&env(&[
        ("ANTHROPIC_API_KEY", "from-env"),
        ("XDG_CONFIG_HOME", dir.path().to_str().unwrap()),
    ]))
    .unwrap();

    assert_eq!(key.expose_secret(), "from-env");
    assert!(matches!(source, Source::Env));
}

#[test]
fn the_file_answers_when_the_environment_is_unset() {
    let dir = tempfile::tempdir().unwrap();
    stored_key(dir.path(), "from-file");

    let (key, source) =
        resolve(&env(&[("XDG_CONFIG_HOME", dir.path().to_str().unwrap())])).unwrap();

    assert_eq!(key.expose_secret(), "from-file");
    assert!(matches!(source, Source::File(_)));
}

#[test]
fn a_blank_environment_value_falls_through_to_the_file() {
    let dir = tempfile::tempdir().unwrap();
    stored_key(dir.path(), "from-file");

    let (key, _) = resolve(&env(&[
        ("ANTHROPIC_API_KEY", "   "),
        ("XDG_CONFIG_HOME", dir.path().to_str().unwrap()),
    ]))
    .unwrap();

    assert_eq!(key.expose_secret(), "from-file");
}

/// Trimmed rather than refused, so the worst case is a clean 401 and not a
/// `HeaderValue` rejection.
#[test]
fn a_padded_environment_value_is_trimmed() {
    let (key, _) = resolve(&env(&[("ANTHROPIC_API_KEY", "  sk-ant-test\n")])).unwrap();

    assert_eq!(key.expose_secret(), "sk-ant-test");
}

#[test]
fn a_non_utf8_environment_value_falls_through() {
    use std::os::unix::ffi::OsStringExt;

    let dir = tempfile::tempdir().unwrap();
    stored_key(dir.path(), "from-file");
    let home = dir.path().as_os_str().to_owned();
    let lookup = move |name: &str| match name {
        "ANTHROPIC_API_KEY" => Some(OsString::from_vec(vec![b's', b'k', 0xff])),
        "XDG_CONFIG_HOME" => Some(home.clone()),
        _ => None,
    };

    let (key, _) = resolve(&lookup).unwrap();

    assert_eq!(key.expose_secret(), "from-file");
}

#[test]
fn no_source_reports_the_path_it_looked_in() {
    let dir = tempfile::tempdir().unwrap();
    let error = resolve(&env(&[("XDG_CONFIG_HOME", dir.path().to_str().unwrap())])).unwrap_err();
    assert!(matches!(error, AuthError::NoCredential { .. }));
}

#[test]
fn read_key_takes_a_piped_key() {
    let key = read_key(&b"sk-ant-test\n"[..], Device::Redirected).unwrap();
    assert_eq!(key.expose_secret(), "sk-ant-test");
}

#[test]
fn read_key_refuses_a_tty_rather_than_prompting() {
    assert!(matches!(
        read_key(&b"sk-ant-test"[..], Device::Terminal),
        Err(AuthError::TtyInput)
    ));
}

#[test]
fn read_key_refuses_an_empty_stdin() {
    assert!(matches!(
        read_key(&b""[..], Device::Redirected),
        Err(AuthError::BlankKey)
    ));
}

#[test]
fn read_key_refuses_whitespace_alone() {
    assert!(matches!(
        read_key(&b" \n\t"[..], Device::Redirected),
        Err(AuthError::BlankKey)
    ));
}
