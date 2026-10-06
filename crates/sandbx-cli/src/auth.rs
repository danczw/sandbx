//! `auth`: where the provider key comes from when it is not in the environment.
//!
//! Two sources, environment first, then a file at `0600` — refused rather than read when
//! its mode is wider. `login` takes the key on stdin and refuses a tty, so a key never
//! reaches the terminal or the shell's history. See `context/decision-credentials.md`.

use std::ffi::OsString;
use std::io::{IsTerminal, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};

use crate::AuthError;

/// The variable checked before the file, and the name `--allow-env` would have to repeat
/// to hand the value to a tool.
const ENV_VAR: &str = "ANTHROPIC_API_KEY";

/// The credential file, below whichever config home is in play.
const FILE: &str = "sandbx/credentials.toml";

/// The table the Anthropic key lives in, and the key within it.
const TABLE: &str = "anthropic";
const ENTRY: &str = "api_key";

/// Every bit outside the owner's, which the file may not have set.
const SHARED_BITS: u32 = 0o077;

/// The mode the file is created and rewritten with.
const OWNER_ONLY: u32 = 0o600;

/// The mode the directory holding it is created with.
const DIR_OWNER_ONLY: u32 = 0o700;

/// `auth status` found no credential. Not a failure to report, but not success either: a
/// script asking whether this host is authenticated reads the code, not the line.
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
    /// Exits 0 when a key was found, 1 when neither source has one.
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
                store(&path, &key)?;
                eprintln!("sandbx: key stored in {}", path.display());
                Ok(0)
            }

            Action::Logout => {
                let path = config_file(&lookup)?;
                if discard(&path)? {
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
    match stored(&path)? {
        Some(key) => Ok((key, Source::File(path))),
        None => Err(AuthError::NoCredential { path }),
    }
}

/// [`ENV_VAR`]'s value, or `None` when it is unset, blank or not UTF-8.
///
/// Through `resolve_api_key` so the trim-and-treat-blank-as-absent rule has one
/// implementation. A blank value falls through to the file rather than failing, which
/// `auth status` is what makes legible.
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
/// Both are required to be absolute. XDG says a relative `$XDG_CONFIG_HOME` is to be
/// ignored, and joining one to the working directory would put a credential in whatever
/// tree the agent was pointed at.
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

/// The key the file holds, `None` when there is no file or no entry in it.
fn stored(path: &Path) -> Result<Option<SecretString>, AuthError> {
    let Some(table) = read(path)? else {
        return Ok(None);
    };

    Ok(table
        .get(TABLE)
        .and_then(|provider| provider.get(ENTRY))
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(|key| SecretString::from(key.to_string())))
}

/// The file as a table, or `None` when it is absent.
///
/// Refuses a file any group or other bit is set on. Stat'd through the open descriptor
/// rather than by path: checking the mode first and opening second would vet one file and
/// read another.
fn read(path: &Path) -> Result<Option<toml::Table>, AuthError> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(AuthError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let mode = file
        .metadata()
        .map_err(|source| AuthError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions()
        .mode();

    if mode & SHARED_BITS != 0 {
        return Err(AuthError::Permissions {
            path: path.to_path_buf(),
            mode: mode & 0o7777,
        });
    }

    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|source| AuthError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    let table = text.parse().map_err(|source| AuthError::Malformed {
        path: path.to_path_buf(),
        source,
    })?;

    Ok(Some(table))
}

/// Write `key` to the file, keeping every entry this did not write.
fn store(path: &Path, key: &SecretString) -> Result<(), AuthError> {
    // Read before create, so a file whose mode is already too wide is refused rather than
    // silently replaced along with whatever else it held.
    let mut table = read(path)?.unwrap_or_default();

    let provider = table
        .entry(TABLE)
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    match provider {
        toml::Value::Table(provider) => {
            provider.insert(
                ENTRY.to_string(),
                toml::Value::String(key.expose_secret().to_string()),
            );
        }
        // A `[anthropic]` that is not a table is the operator's own edit, and replacing it
        // would discard what they put there.
        _ => {
            return Err(AuthError::NotATable {
                path: path.to_path_buf(),
            });
        }
    }

    write(path, &table)
}

/// Drop the stored key, reporting whether there was one, and remove a file left empty.
fn discard(path: &Path) -> Result<bool, AuthError> {
    let Some(mut table) = read(path)? else {
        return Ok(false);
    };

    let removed = match table.get_mut(TABLE) {
        Some(toml::Value::Table(provider)) => provider.remove(ENTRY).is_some(),
        _ => false,
    };

    // Only once it is empty: a `[anthropic]` holding something else is not this
    // command's to delete.
    if table
        .get(TABLE)
        .and_then(toml::Value::as_table)
        .is_some_and(toml::Table::is_empty)
    {
        table.remove(TABLE);
    }

    if table.is_empty() {
        std::fs::remove_file(path).map_err(|source| AuthError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        return Ok(removed);
    }

    write(path, &table)?;
    Ok(removed)
}

/// Render `table` over `path` at [`OWNER_ONLY`], creating the directory at
/// [`DIR_OWNER_ONLY`].
///
/// Through a temporary file in the same directory, then a rename: `OpenOptionsExt::mode`
/// applies only when a file is created, so truncating an existing one would leave whatever
/// mode it already had. The rename also means a failed write cannot leave a half-written
/// credential behind.
fn write(path: &Path, table: &toml::Table) -> Result<(), AuthError> {
    let text = toml::to_string(table).map_err(AuthError::Encode)?;

    let dir = path.parent().ok_or(AuthError::NoConfigHome)?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_OWNER_ONLY)
        .create(dir)
        .map_err(|source| AuthError::Io {
            path: dir.to_path_buf(),
            source,
        })?;

    let io = |source| AuthError::Io {
        path: path.to_path_buf(),
        source,
    };

    let mut temp = tempfile::NamedTempFile::new_in(dir).map_err(io)?;
    // Set rather than assumed: `NamedTempFile` is 0600 on unix, but the guarantee this
    // file needs is stated here, not in a dependency's documentation.
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(OWNER_ONLY))
        .map_err(io)?;
    temp.write_all(text.as_bytes()).map_err(io)?;
    temp.flush().map_err(io)?;
    temp.persist(path).map_err(|error| io(error.error))?;

    Ok(())
}

/// The key from `input`, refusing a tty rather than prompting for it.
///
/// Trimmed and blank-checked like [`env_key`]: a `printf` without `%s`, or a `$(cat key)`,
/// carries a newline that `HeaderValue` would reject much later as an opaque transport
/// error.
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
    use super::*;

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

    fn write_at(path: &Path, text: &str, mode: u32) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
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
        let path = dir.path().join("sandbx/credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"from-file\"\n", 0o600);

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
        let path = dir.path().join("sandbx/credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"from-file\"\n", 0o600);

        let (key, source) =
            resolve(&env(&[("XDG_CONFIG_HOME", dir.path().to_str().unwrap())])).unwrap();

        assert_eq!(key.expose_secret(), "from-file");
        assert!(matches!(source, Source::File(_)));
    }

    #[test]
    fn a_blank_environment_value_falls_through_to_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sandbx/credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"from-file\"\n", 0o600);

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
    fn a_group_readable_file_is_refused_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"k\"\n", 0o640);

        assert!(
            matches!(stored(&path), Err(AuthError::Permissions { mode, .. }) if mode == 0o640),
            "a credential readable by the group was read instead of refused"
        );
    }

    #[test]
    fn a_world_readable_file_is_refused_too() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"k\"\n", 0o604);

        assert!(matches!(stored(&path), Err(AuthError::Permissions { .. })));
    }

    #[test]
    fn an_owner_only_file_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"k\"\n", 0o600);

        assert_eq!(stored(&path).unwrap().unwrap().expose_secret(), "k");
    }

    #[test]
    fn an_absent_file_is_absent_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(stored(&dir.path().join("nope.toml")).unwrap().is_none());
    }

    #[test]
    fn a_file_without_the_entry_holds_no_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[other]\nkey = \"k\"\n", 0o600);

        assert!(stored(&path).unwrap().is_none());
    }

    #[test]
    fn a_blank_stored_key_holds_no_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"  \"\n", 0o600);

        assert!(stored(&path).unwrap().is_none());
    }

    #[test]
    fn unparsable_toml_is_reported_against_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "this is not toml", 0o600);

        assert!(matches!(stored(&path), Err(AuthError::Malformed { .. })));
    }

    #[test]
    fn store_creates_the_file_and_its_directory_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sandbx/credentials.toml");

        store(&path, &SecretString::from("k".to_string())).unwrap();

        assert_eq!(mode_of(&path), OWNER_ONLY);
        assert_eq!(mode_of(path.parent().unwrap()), DIR_OWNER_ONLY);
        assert_eq!(stored(&path).unwrap().unwrap().expose_secret(), "k");
    }

    #[test]
    fn store_over_a_readable_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"old\"\n", 0o644);

        assert!(matches!(
            store(&path, &SecretString::from("new".to_string())),
            Err(AuthError::Permissions { .. })
        ));
    }

    #[test]
    fn store_keeps_a_table_it_did_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[other]\nkey = \"keep\"\n", 0o600);

        store(&path, &SecretString::from("k".to_string())).unwrap();

        let table = read(&path).unwrap().unwrap();
        assert!(
            table.contains_key("other"),
            "rewriting the file dropped a table this binary does not know"
        );
    }

    #[test]
    fn store_narrows_the_mode_of_a_file_it_rewrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"old\"\n", 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        store(&path, &SecretString::from("new".to_string())).unwrap();

        assert_eq!(mode_of(&path), OWNER_ONLY);
        assert_eq!(stored(&path).unwrap().unwrap().expose_secret(), "new");
    }

    #[test]
    fn discard_removes_a_file_holding_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"k\"\n", 0o600);

        assert!(discard(&path).unwrap());
        assert!(!path.exists(), "an emptied credential file was left behind");
    }

    #[test]
    fn discard_keeps_a_file_holding_another_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(
            &path,
            "[anthropic]\napi_key = \"k\"\n\n[other]\nkey = \"keep\"\n",
            0o600,
        );

        assert!(discard(&path).unwrap());
        let table = read(&path).unwrap().unwrap();
        assert!(!table.contains_key(TABLE));
        assert!(table.contains_key("other"));
    }

    #[test]
    fn discard_reports_nothing_when_there_was_no_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!discard(&dir.path().join("nope.toml")).unwrap());
    }

    #[test]
    fn discard_reports_nothing_when_there_was_no_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[other]\nkey = \"keep\"\n", 0o600);

        assert!(!discard(&path).unwrap());
        assert!(path.exists());
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

    #[test]
    fn a_stored_key_never_appears_in_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"sk-ant-secret\"\n", 0o644);

        let error = stored(&path).unwrap_err();
        assert!(
            !format!("{error}").contains("sk-ant-secret"),
            "a refusal printed the credential it refused to read"
        );
    }
}
