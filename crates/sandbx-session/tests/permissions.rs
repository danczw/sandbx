//! What the store creates, and what it refuses to read back.
//!
//! The rule splits by bit: a transcript somebody else can *write* is refused, because a
//! history another user chose is replayed to a model that calls tools; one they can only
//! *read* resumes and reports, because by then the disclosure has happened and a
//! conversation cannot be rotated.
//!
//! A foreign owner is refused as well. Nothing here drives that arm: it needs a file
//! owned by a second uid, which a test running as one user cannot make.

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use sandbx_session::{CompletedTurn, Content, Message, Role, SessionError, SessionStore};

fn store() -> (tempfile::TempDir, SessionStore) {
    let root = tempfile::tempdir().unwrap();
    let store = SessionStore::new(root.path().join("sessions"));
    (root, store)
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

fn exchange() -> Vec<Message> {
    [Role::User, Role::Assistant]
        .into_iter()
        .map(|role| Message {
            role,
            content: vec![Content::Text {
                text: "hi".to_owned(),
            }],
        })
        .collect()
}

/// One session with one turn in it.
fn spoken_to(store: &SessionStore) -> sandbx_session::SessionId {
    let mut session = store.create().unwrap();
    session
        .append(CompletedTurn {
            messages: &exchange(),
            observed: None,
            withheld: 0,
        })
        .unwrap();
    session.id().clone()
}

#[test]
fn a_new_transcript_is_unwritable_to_others() {
    let (_root, store) = store();
    let session = store.create().unwrap();

    // Not `mode == 0o600`: `OpenOptionsExt::mode` is masked by the umask, which can only
    // clear bits. The claim is that no group or other bit is set.
    assert_eq!(mode_of(session.path()) & 0o077, 0);
}

#[test]
fn the_sessions_directory_is_owner_only() {
    let (_root, store) = store();
    store.create().unwrap();

    assert_eq!(mode_of(store.root()) & 0o077, 0);
}

#[test]
fn a_directory_that_already_existed_wide_is_narrowed() {
    let (_root, store) = store();
    std::fs::create_dir_all(store.root()).unwrap();
    chmod(store.root(), 0o777);

    // `DirBuilderExt::mode` is ignored for a directory that already exists, so without an
    // explicit narrowing every session after the first would be created in a world-
    // writable directory and only refused later, on resume.
    store.create().unwrap();

    assert_eq!(mode_of(store.root()) & 0o077, 0);
}

#[test]
fn a_writable_transcript_is_refused() {
    let (_root, store) = store();
    let id = spoken_to(&store);
    let path = store.root().join(format!("{id}.jsonl"));
    chmod(&path, 0o622);

    let err = store.resume(&id).unwrap_err();

    assert!(
        matches!(err, SessionError::Writable { mode: 0o622, .. }),
        "got {err:?}"
    );
}

#[test]
fn a_writable_directory_is_refused() {
    let (_root, store) = store();
    let id = spoken_to(&store);
    chmod(store.root(), 0o722);

    let err = store.resume(&id).unwrap_err();

    // Refused on the directory even though the transcript itself is still 0600: whoever
    // may write the directory can rename a file of their own over it.
    assert!(
        matches!(err, SessionError::DirWritable { mode: 0o722, .. }),
        "got {err:?}"
    );

    chmod(store.root(), 0o700);
}

#[test]
fn a_readable_transcript_resumes_and_reports() {
    let (_root, store) = store();
    let id = spoken_to(&store);
    let path = store.root().join(format!("{id}.jsonl"));
    chmod(&path, 0o644);

    let session = store.resume(&id).unwrap();

    assert!(session.shared_read());
    assert_eq!(session.messages().len(), 2);
}

#[test]
fn an_owner_only_transcript_reports_nothing() {
    let (_root, store) = store();
    let id = spoken_to(&store);
    chmod(&store.root().join(format!("{id}.jsonl")), 0o600);

    assert!(!store.resume(&id).unwrap().shared_read());
}
