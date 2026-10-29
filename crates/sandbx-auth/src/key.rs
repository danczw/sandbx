//! Where the provider key comes from, and the `auth` subcommand that puts it there.
//!
//! Environment first, then the credential file. `Auth`'s doc comments are rendered
//! `--help` text, not commentary.

use std::ffi::OsString;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;

use secrecy::SecretString;

use crate::{AuthError, store};

/// Checked before the file, and the one name `agent-run` refuses to `--allow-env`
/// — see `context/decision-credentials.md`.
pub const ENV_VAR: &str = "ANTHROPIC_API_KEY";

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
pub fn api_key() -> Result<SecretString, AuthError> {
    resolve(&|name| std::env::var_os(name)).map(|(key, _)| key)
}

/// The key and the source that answered, environment first.
///
/// The file is located only once the environment has come up empty, so an exported key
/// works on a host with no config home for [`config_file`] to name. The lookup is injected
/// because `set_var` is an `unsafe fn` under edition 2024 and the workspace forbids
/// `unsafe_code` in test binaries too, so a test cannot drive a real environment.
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

/// [`ENV_VAR`]'s value, or `None` when it is unset, blank or not UTF-8, so a blank value
/// falls through to the file rather than failing.
fn env_key(lookup: &impl Fn(&str) -> Option<OsString>) -> Option<SecretString> {
    lookup(ENV_VAR)?
        .into_string()
        .ok()
        .as_deref()
        .and_then(nonblank)
}

/// `raw` trimmed, or `None` when nothing is left. An unpopulated CI secret is `""`, and
/// `$(cat key)` keeps a newline `HeaderValue` would reject much later as an opaque
/// transport error.
pub(super) fn nonblank(raw: &str) -> Option<SecretString> {
    let key = raw.trim();
    (!key.is_empty()).then(|| SecretString::from(key.to_owned()))
}

/// Where the credential file is, from `$XDG_CONFIG_HOME` or `$HOME`.
///
/// Both must be absolute. XDG says a relative `$XDG_CONFIG_HOME` is to be ignored, and
/// joining one to the cwd would put a credential in whatever tree the agent was pointed at.
pub fn config_file(lookup: &impl Fn(&str) -> Option<OsString>) -> Result<PathBuf, AuthError> {
    let absolute = |name| lookup(name).map(PathBuf::from).filter(|d| d.is_absolute());
    if let Some(dir) = absolute("XDG_CONFIG_HOME") {
        return Ok(dir.join(FILE));
    }

    let home = absolute("HOME").ok_or(AuthError::NoConfigHome)?;

    Ok(home.join(".config").join(FILE))
}

/// The key from `input` through [`nonblank`], refusing a tty rather than prompting for it.
fn read_key(mut input: impl Read, tty: bool) -> Result<SecretString, AuthError> {
    if tty {
        return Err(AuthError::TtyInput);
    }

    let mut raw = String::new();
    input.read_to_string(&mut raw).map_err(AuthError::Stdin)?;

    nonblank(&raw).ok_or(AuthError::BlankKey)
}

#[cfg(test)]
#[path = "key_tests.rs"]
mod tests;
