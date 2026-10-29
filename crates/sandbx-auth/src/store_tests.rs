use std::fs;
use std::fs::Permissions;
use std::os::unix::fs as unix_fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use secrecy::{ExposeSecret, SecretString};

use super::{DIR_OWNER_ONLY, OWNER_ONLY, Shared, TABLE, discard, read, store, stored};
use crate::AuthError;

/// A credential file at `mode`, in an owner-only directory — `tempdir` is 0755, which
/// [`read`] refuses, so a fixture left at it would test the directory check instead.
fn write_at(path: &Path, text: &str, mode: u32) {
    let dir = path.parent().unwrap();
    fs::create_dir_all(dir).unwrap();
    fs::set_permissions(dir, Permissions::from_mode(DIR_OWNER_ONLY)).unwrap();
    fs::write(path, text).unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
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

/// Narrowing is unreachable ([`read`] refuses a wider file first), so the bar is that
/// a rewrite does not widen one.
#[test]
fn a_rewrite_leaves_the_mode_owner_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.toml");
    write_at(&path, "[anthropic]\napi_key = \"old\"\n", 0o600);

    store(&path, &SecretString::from("new".to_string())).unwrap();

    assert_eq!(mode_of(&path), OWNER_ONLY);
    assert_eq!(stored(&path).unwrap().unwrap().expose_secret(), "new");
}

/// 0600 inside a directory another user may write is a file they can rename away.
#[test]
fn store_narrows_a_directory_it_did_not_create() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("sandbx");
    fs::create_dir_all(&config).unwrap();
    fs::set_permissions(&config, Permissions::from_mode(0o755)).unwrap();

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
    fs::set_permissions(&config, Permissions::from_mode(0o757)).unwrap();

    let refused = matches!(stored(&path), Err(AuthError::DirPermissions { .. }));
    // Restored before the assert, or `TempDir::drop` cannot clean up after a failure.
    fs::set_permissions(&config, Permissions::from_mode(0o700)).unwrap();

    assert!(
        refused,
        "a credential in a world-writable directory was read"
    );
}

/// The link's directory is owner-only here; the shared one holds the key.
#[test]
fn a_symlink_is_vetted_where_it_points_not_where_it_sits() {
    let dir = tempfile::tempdir().unwrap();
    let shared = dir.path().join("shared");
    let target = shared.join("credentials.toml");
    write_at(&target, "[anthropic]\napi_key = \"k\"\n", 0o600);
    fs::set_permissions(&shared, Permissions::from_mode(0o757)).unwrap();

    let link = dir.path().join("sandbx/credentials.toml");
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    fs::set_permissions(
        link.parent().unwrap(),
        Permissions::from_mode(DIR_OWNER_ONLY),
    )
    .unwrap();
    unix_fs::symlink(&target, &link).unwrap();

    let refused = matches!(stored(&link), Err(AuthError::DirPermissions { .. }));
    // Restored before the assert, or `TempDir::drop` cannot clean up after a failure.
    fs::set_permissions(&shared, Permissions::from_mode(0o700)).unwrap();

    assert!(
        refused,
        "a credential symlinked into a world-writable directory was read"
    );
}

/// Refusing would leave the disclosed key on disk and advise narrowing a file being
/// deleted.
#[test]
fn discard_removes_a_key_from_a_file_it_would_refuse_to_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credentials.toml");
    write_at(&path, "[anthropic]\napi_key = \"k\"\n", 0o644);

    assert!(discard(&path).unwrap());
    assert!(!path.exists());
}

/// The one place a mode is repaired: no credential is left in the file to protect.
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
