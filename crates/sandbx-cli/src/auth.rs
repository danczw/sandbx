//! `auth`: where the provider key comes from when it is not in the environment.
//!
//! Environment first, then a file at `0600` in a directory at `0700`, refused rather than
//! read when either is wider. `login` takes the key on stdin and refuses a tty. See
//! `context/decision-credentials.md`.

mod store;

use std::ffi::OsString;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use secrecy::SecretString;

use crate::AuthError;

/// Checked before the file, and the one name `agent-run` refuses to `--allow-env`
/// — see `context/decision-tool-credentials.md`.
pub(crate) const ENV_VAR: &str = "ANTHROPIC_API_KEY";

/// The credential file, below whichever config home is in play.
const FILE: &str = "sandbx/credentials.toml";

/// `auth status` found no credential: neither a failure nor success, since a script asks
/// by reading the code.
///
/// Distinct from the 2 an `AuthError` exits with, so `auth status || auth login` cannot
/// read a refused file as an absent one.
const UNAUTHENTICATED: i32 = 1;

/// `sandbx auth <login|logout|status>`
#[derive(Debug, clap::Args)]
pub struct Auth {
    /// What to do with the stored credential.
    #[command(subcommand)]
    action: Action,
}

/// The three things `auth` can do.
#[derive(Debug, clap::Subcommand)]
enum Action {
    /// Store an API key, read from stdin.
    ///
    /// Refuses to prompt: stdin must be a pipe or a file, so the key is never echoed to
    /// the terminal and never reaches your shell's history. Pass it without putting it in
    /// an argument or a history entry:
    ///
    /// ```text
    /// read -rs KEY && printf %s "$KEY" | sandbx auth login
    /// ```
    ///
    /// The key is written to `$XDG_CONFIG_HOME/sandbx/credentials.toml`, or
    /// `~/.config/sandbx/credentials.toml`, with mode 0600 in a directory with mode 0700.
    /// It is stored in cleartext: anything running as you, and root, can read it. An
    /// existing file is rewritten in place, keeping any entry this command did not write.
    Login,

    /// Remove the stored API key.
    ///
    /// Leaves `ANTHROPIC_API_KEY` alone — if that is exported, `agent-run` still
    /// authenticates after this. The file is deleted when nothing else is left in it.
    Logout,

    /// Say which source `agent-run` would authenticate with, and never print the key.
    ///
    /// Exits 0 when a key was found, 1 when neither source has one, and 2 when a source
    /// could not be read at all — a file whose mode was refused is not an absent key, and
    /// a script that treats the two alike would log in over a credential it never saw.
    Status,
}

impl Auth {
    /// Run the subcommand, reporting what it did on stderr and never the key.
    pub fn execute(&self) -> Result<i32, AuthError> {
        let lookup = |name: &str| std::env::var_os(name);

        match self.action {
            Action::Login => {
                let path = config_file(&lookup)?;
                let stdin = std::io::stdin();
                let key = read_key(stdin.lock(), stdin.is_terminal())?;
                store::store(&path, &key)?;
                eprintln!("sandbx: key stored in {}", path.display());
                Ok(0)
            }

            Action::Logout => {
                let path = config_file(&lookup)?;
                if store::discard(&path)? {
                    eprintln!("sandbx: key removed from {}", path.display());
                } else {
                    eprintln!("sandbx: no key was stored in {}", path.display());
                }
                Ok(0)
            }

            Action::Status => match resolve(&lookup) {
                Ok((_, Source::Env)) => {
                    println!("authenticated from the environment: {ENV_VAR}");
                    Ok(0)
                }
                Ok((_, Source::File(path))) => {
                    println!("authenticated from {}", path.display());
                    Ok(0)
                }
                Err(AuthError::NoCredential { .. }) => {
                    println!("not authenticated");
                    Ok(UNAUTHENTICATED)
                }
                Err(error) => Err(error),
            },
        }
    }
}

/// Which source answered.
#[derive(Debug)]
enum Source {
    /// [`ENV_VAR`] held a key.
    Env,

    /// The credential file held one, at this path.
    File(PathBuf),
}

/// The key `agent-run` authenticates with, from whichever source has one.
pub(crate) fn api_key() -> Result<SecretString, AuthError> {
    resolve(&|name| std::env::var_os(name)).map(|(key, _)| key)
}

/// The key and the source that answered, environment first.
///
/// The file is located only once the environment has come up empty, so an exported key
/// works on a host with no config home for [`config_file`] to name.
fn resolve(
    lookup: &impl Fn(&str) -> Option<OsString>,
) -> Result<(SecretString, Source), AuthError> {
    if let Some(key) = env_key(lookup) {
        return Ok((key, Source::Env));
    }

    let path = config_file(lookup)?;
    match store::stored(&path)? {
        Some(key) => Ok((key, Source::File(path))),
        None => Err(AuthError::NoCredential { path }),
    }
}

/// [`ENV_VAR`]'s value, or `None` when it is unset, blank or not UTF-8.
///
/// Through `resolve_api_key` so the trim-and-treat-blank-as-absent rule has one
/// implementation. A blank value falls through to the file rather than failing.
fn env_key(lookup: &impl Fn(&str) -> Option<OsString>) -> Option<SecretString> {
    sandbx_providers::resolve_api_key(ENV_VAR, |name| {
        lookup(name)
            .and_then(|value| value.into_string().ok())
            .ok_or(std::env::VarError::NotPresent)
    })
    .ok()
}

/// Where the credential file is, from `$XDG_CONFIG_HOME` or `$HOME`.
///
/// Both must be absolute. XDG says a relative `$XDG_CONFIG_HOME` is to be ignored, and
/// joining one to the cwd would put a credential in whatever tree the agent was pointed at.
fn config_file(lookup: &impl Fn(&str) -> Option<OsString>) -> Result<PathBuf, AuthError> {
    if let Some(dir) = lookup("XDG_CONFIG_HOME").map(PathBuf::from)
        && dir.is_absolute()
    {
        return Ok(dir.join(FILE));
    }

    let home = lookup("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .ok_or(AuthError::NoConfigHome)?;

    Ok(home.join(".config").join(FILE))
}

/// The key from `input`, refusing a tty rather than prompting for it.
///
/// Trimmed and blank-checked like [`env_key`]: a `printf` without `%s`, or a `$(cat key)`,
/// carries a newline `HeaderValue` would later reject as an opaque transport error.
fn read_key(mut input: impl Read, tty: bool) -> Result<SecretString, AuthError> {
    if tty {
        return Err(AuthError::TtyInput);
    }

    let mut raw = String::new();
    input.read_to_string(&mut raw).map_err(AuthError::Stdin)?;

    let key = raw.trim();
    if key.is_empty() {
        return Err(AuthError::BlankKey);
    }

    Ok(SecretString::from(key.to_string()))
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

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
    fn stored_key(dir: &std::path::Path, key: &str) {
        store::store(&dir.join(FILE), &SecretString::from(key.to_string())).unwrap();
    }

    #[test]
    fn xdg_config_home_names_the_file_when_absolute() {
        let path =
            config_file(&env(&[("XDG_CONFIG_HOME", "/x/conf"), ("HOME", "/home/u")])).unwrap();
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

    #[test]
    fn no_source_reports_the_path_it_looked_in() {
        let dir = tempfile::tempdir().unwrap();
        let error =
            resolve(&env(&[("XDG_CONFIG_HOME", dir.path().to_str().unwrap())])).unwrap_err();
        assert!(matches!(error, AuthError::NoCredential { .. }));
    }

    #[test]
    fn read_key_takes_a_piped_key() {
        let key = read_key(&b"sk-ant-test\n"[..], false).unwrap();
        assert_eq!(key.expose_secret(), "sk-ant-test");
    }

    #[test]
    fn read_key_refuses_a_tty_rather_than_prompting() {
        assert!(matches!(
            read_key(&b"sk-ant-test"[..], true),
            Err(AuthError::TtyInput)
        ));
    }

    #[test]
    fn read_key_refuses_an_empty_stdin() {
        assert!(matches!(
            read_key(&b""[..], false),
            Err(AuthError::BlankKey)
        ));
    }

    #[test]
    fn read_key_refuses_whitespace_alone() {
        assert!(matches!(
            read_key(&b" \n\t"[..], false),
            Err(AuthError::BlankKey)
        ));
    }
}
