//! The credential file: its TOML shape, and the modes it is read and written under.
//!
//! [`crate::key`] owns which source answers; this owns what is on disk, and the ordering
//! the `0600` guarantee depends on.

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
    /// Refuse it — a key another user could have substituted is what the check prevents.
    Refuse,
    /// Read it anyway: refusing `logout` would leave a disclosed key on disk.
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
        .and_then(crate::key::nonblank))
}

/// The file as a table, or `None` when it is absent.
///
/// Refuses a file, or the directory holding it, with any group or other bit set, unless
/// `shared` tolerates it: a writable directory is one another user can rename their own
/// `0600` file into. Both modes come from a descriptor rather than a path — a mode checked
/// before the open vets one file and reads another.
fn read(path: &Path, shared: Shared) -> Result<Option<toml::Table>, AuthError> {
    let io = |source| AuthError::Io {
        path: path.to_path_buf(),
        source,
    };

    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io(source)),
    };

    let mode = file.metadata().map_err(io)?.permissions().mode();

    if shared == Shared::Refuse {
        if mode & SHARED_BITS != 0 {
            return Err(AuthError::Permissions {
                path: path.to_path_buf(),
                mode: mode & 0o7777,
            });
        }

        // Canonicalised: `path.parent()` is lexical, so a symlinked `credentials.toml`
        // would have the link's directory vetted and the key's never looked at.
        let resolved = std::fs::canonicalize(path).map_err(io)?;

        if let Some(dir) = resolved.parent() {
            let dir_mode = dir_mode_of(dir)?;
            if dir_mode & SHARED_BITS != 0 {
                return Err(AuthError::DirPermissions {
                    path: dir.to_path_buf(),
                    mode: dir_mode & 0o7777,
                });
            }
        }
    }

    let mut text = String::new();
    file.read_to_string(&mut text).map_err(io)?;

    let table = text.parse().map_err(|error| AuthError::Malformed {
        path: path.to_path_buf(),
        line: line_of(&text, &error),
    })?;

    Ok(Some(table))
}

/// `dir`'s mode, through a descriptor on it — see [`read`] for why not by path.
fn dir_mode_of(dir: &Path) -> Result<u32, AuthError> {
    let io = |source| AuthError::Io {
        path: dir.to_path_buf(),
        source,
    };

    Ok(std::fs::File::open(dir)
        .map_err(io)?
        .metadata()
        .map_err(io)?
        .permissions()
        .mode())
}

/// The one-based line `error` points at, or 0 when it carries no span.
///
/// The `toml` error is dropped because its `Display` quotes the line it failed on — which
/// for an unquoted `api_key` is the key itself.
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

    // A `[anthropic]` that is not a table is the operator's own edit, and replacing it
    // would discard what they put there.
    let toml::Value::Table(provider) = table
        .entry(TABLE)
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
    else {
        return Err(AuthError::NotATable {
            path: path.to_path_buf(),
        });
    };
    provider.insert(
        ENTRY.to_string(),
        toml::Value::String(key.expose_secret().to_string()),
    );

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
    } else {
        write(path, &table)?;
    }
    Ok(removed)
}

/// Render `table` over `path` at [`OWNER_ONLY`], creating the directory at
/// [`DIR_OWNER_ONLY`].
///
/// Through a temporary file in the same directory, then a rename: `OpenOptionsExt::mode`
/// applies only at creation, so truncating an existing file would keep its old mode, and
/// the rename leaves nothing half-written behind a failure.
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

    // A separate call, through one descriptor reused for the fsync below: `DirBuilder::mode`
    // is masked by the umask, and a no-op entirely when the directory already exists.
    let handle = std::fs::File::open(dir).map_err(dir_io)?;
    handle
        .set_permissions(std::fs::Permissions::from_mode(DIR_OWNER_ONLY))
        .map_err(dir_io)?;

    let io = |source| AuthError::Io {
        path: path.to_path_buf(),
        source,
    };

    let mut temp = tempfile::NamedTempFile::new_in(dir).map_err(io)?;
    // `NamedTempFile` is 0600 on unix, but this file's guarantee is not a dependency's to
    // make.
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(OWNER_ONLY))
        .map_err(io)?;
    temp.write_all(text.as_bytes()).map_err(io)?;
    // Before the rename, not after: ext4 journals the rename ahead of the data, so a crash
    // here would otherwise leave an empty file where `login` just reported a stored key.
    temp.as_file().sync_all().map_err(io)?;
    temp.persist(path).map_err(|error| io(error.error))?;

    // The rename itself, so the entry survives a crash and not just the bytes behind it.
    handle.sync_all().map_err(dir_io)?;

    Ok(())
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
