//! The credential file: its format, and the modes it is read and written under.
//!
//! Separate from the chain above it because the two change for different reasons — that
//! one owns which source answers, this one owns what is on disk. Several steps below are
//! ordering requirements rather than style; each says so where it stands.

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

use secrecy::{ExposeSecret, SecretString};

use crate::AuthError;

/// The table the Anthropic key lives in, and the key within it.
const TABLE: &str = "anthropic";
const ENTRY: &str = "api_key";

/// The mode the file is created and rewritten with.
const OWNER_ONLY: u32 = 0o600;

/// The mode the directory holding it is created with.
const DIR_OWNER_ONLY: u32 = 0o700;

/// Every bit outside the owner's, which neither the file nor its directory may have set.
const SHARED_BITS: u32 = 0o077;

/// Whether a credential file wider than its owner may still be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shared {
    /// Refuse it. Resolving a key that another user could have substituted is the thing
    /// the mode check exists to prevent.
    Refuse,
    /// Read it anyway. `logout` removes a disclosed key rather than leaving it in place
    /// because it is disclosed, which would make the mode check protect the attacker.
    Tolerate,
}

/// The key the file holds, `None` when there is no file or no entry in it.
pub(super) fn stored(path: &Path) -> Result<Option<SecretString>, AuthError> {
    let Some(table) = read(path, Shared::Refuse)? else {
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
/// Refuses a file, or a directory holding it, that any group or other bit is set on —
/// unless `shared` tolerates it. A writable directory is enough on its own: another user
/// can rename a `0600` file of their own over the credential, which this would then read
/// as the operator's.
///
/// Stat'd through the open descriptor rather than by path: checking the mode first and
/// opening second would vet one file and read another.
fn read(path: &Path, shared: Shared) -> Result<Option<toml::Table>, AuthError> {
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

    if shared == Shared::Refuse {
        if mode & SHARED_BITS != 0 {
            return Err(AuthError::Permissions {
                path: path.to_path_buf(),
                mode: mode & 0o7777,
            });
        }

        if let Some(dir) = path.parent() {
            let dir_mode = std::fs::metadata(dir)
                .map_err(|source| AuthError::Io {
                    path: dir.to_path_buf(),
                    source,
                })?
                .permissions()
                .mode();

            if dir_mode & SHARED_BITS != 0 {
                return Err(AuthError::DirPermissions {
                    path: dir.to_path_buf(),
                    mode: dir_mode & 0o7777,
                });
            }
        }
    }

    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|source| AuthError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    let table = text.parse().map_err(|error| AuthError::Malformed {
        path: path.to_path_buf(),
        line: line_of(&text, &error),
    })?;

    Ok(Some(table))
}

/// The one-based line `error` points at, or 0 when it carries no span.
///
/// The position is extracted here and the `toml` error dropped, because its `Display`
/// quotes the line it failed on — which for an unquoted `api_key` is the key itself.
fn line_of(text: &str, error: &toml::de::Error) -> usize {
    error.span().map_or(0, |span| {
        text[..span.start.min(text.len())].lines().count().max(1)
    })
}

/// Write `key` to the file, keeping every entry this did not write.
pub(super) fn store(path: &Path, key: &SecretString) -> Result<(), AuthError> {
    // Read before create, so a file whose mode is already too wide is refused rather than
    // silently replaced along with whatever else it held.
    let mut table = read(path, Shared::Refuse)?.unwrap_or_default();

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
pub(super) fn discard(path: &Path) -> Result<bool, AuthError> {
    let Some(mut table) = read(path, Shared::Tolerate)? else {
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
    let dir_io = |source| AuthError::Io {
        path: dir.to_path_buf(),
        source,
    };

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_OWNER_ONLY)
        .create(dir)
        .map_err(dir_io)?;
    // Again, by a separate call: `DirBuilder::mode` is masked by the umask, and it is a
    // no-op entirely when the directory already exists — so neither a 0022 umask nor a
    // directory someone else created leaves the credential in a 0700 one.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(DIR_OWNER_ONLY))
        .map_err(dir_io)?;

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
    // Before the rename, not after: ext4 journals the rename ahead of the data, so a crash
    // here would otherwise leave an empty file where `login` just reported a stored key.
    temp.as_file().sync_all().map_err(io)?;
    temp.persist(path).map_err(|error| io(error.error))?;

    // The rename itself, so the entry survives a crash and not just the bytes behind it.
    std::fs::File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(dir_io)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A credential file at `mode`, in an owner-only directory.
    ///
    /// The directory too, because `tempdir` is 0755 and [`read`] refuses a shared one —
    /// a fixture left at 0755 would test the directory check instead of what it meant to.
    fn write_at(path: &Path, text: &str, mode: u32) {
        let dir = path.parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(DIR_OWNER_ONLY)).unwrap();
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
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

        let table = read(&path, Shared::Refuse).unwrap().unwrap();
        assert!(
            table.contains_key("other"),
            "rewriting the file dropped a table this binary does not know"
        );
    }

    /// Narrowing is unreachable — [`read`] refuses a wider file first — so what a rewrite
    /// has to be held to is that it does not *widen* one.
    #[test]
    fn a_rewrite_leaves_the_mode_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"old\"\n", 0o600);

        store(&path, &SecretString::from("new".to_string())).unwrap();

        assert_eq!(mode_of(&path), OWNER_ONLY);
        assert_eq!(stored(&path).unwrap().unwrap().expose_secret(), "new");
    }

    /// The directory is the other half of the claim: 0600 inside a directory another user
    /// may write is a file they can rename away and replace.
    #[test]
    fn store_narrows_a_directory_it_did_not_create() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sandbx");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o755)).unwrap();

        store(
            &config.join("credentials.toml"),
            &SecretString::from("k".to_string()),
        )
        .unwrap();

        assert_eq!(mode_of(&config), DIR_OWNER_ONLY);
    }

    #[test]
    fn a_shared_directory_is_refused_even_at_mode_600() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sandbx");
        let path = config.join("credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"k\"\n", 0o600);
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o757)).unwrap();

        let refused = matches!(stored(&path), Err(AuthError::DirPermissions { .. }));
        // Restored before the assert, or `TempDir::drop` cannot clean up after a failure.
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            refused,
            "a credential in a world-writable directory was read"
        );
    }

    /// The one command whose job is to remove a disclosed key must not be stopped by the
    /// disclosure; refusing would leave the key on disk and advise narrowing a file the
    /// operator asked to delete.
    #[test]
    fn discard_removes_a_key_from_a_file_it_would_refuse_to_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"k\"\n", 0o644);

        assert!(discard(&path).unwrap());
        assert!(!path.exists());
    }

    /// A rewrite on the `logout` path narrows what it leaves behind, which is the one place
    /// a mode does get repaired — there is no credential left in the file to protect.
    #[test]
    fn discard_narrows_a_shared_file_it_keeps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(
            &path,
            "[anthropic]\napi_key = \"k\"\n\n[other]\nkey = \"keep\"\n",
            0o644,
        );

        assert!(discard(&path).unwrap());
        assert_eq!(mode_of(&path), OWNER_ONLY);
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
        let table = read(&path, Shared::Refuse).unwrap().unwrap();
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
    fn a_stored_key_never_appears_in_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        write_at(&path, "[anthropic]\napi_key = \"sk-ant-secret\"\n", 0o644);

        let error = stored(&path).unwrap_err();
        assert!(
            !format!("{error}").contains("sk-ant-secret"),
            "a refusal printed the credential it refused to read"
        );

        let unquoted = dir.path().join("unquoted.toml");
        write_at(&unquoted, "[anthropic]\napi_key = sk-ant-secret\n", 0o600);

        let error = stored(&unquoted).unwrap_err();
        assert!(
            !format!("{error}").contains("sk-ant-secret"),
            "a parse failure printed the line it failed on, which holds the key"
        );
    }
}
