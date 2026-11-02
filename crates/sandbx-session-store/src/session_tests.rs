use std::fs::File;
use std::io::ErrorKind;

use sandbx_session_error::SessionError;
use sandbx_session_message::{CompletedTurn, Content, Message, Role, Usage};

use crate::SessionStore;

fn exchange(ask: &str, reply: &str) -> Vec<Message> {
    [(Role::User, ask), (Role::Assistant, reply)]
        .into_iter()
        .map(|(role, text)| Message {
            role,
            content: vec![Content::Text {
                text: text.to_owned(),
            }],
        })
        .collect()
}

fn usage(input: u32) -> Usage {
    Usage {
        input_tokens: Some(input),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    }
}

/// A turn the file refused leaves the session's accounting where the file has it, so a
/// session that carries on and one resumed from disk agree. `/dev/full` refuses every
/// write with `ENOSPC`, which is the failure a full disk gives an append.
#[test]
fn a_turn_the_file_refused_is_not_counted() {
    let root = tempfile::tempdir().expect("a temp dir");
    let store = SessionStore::new(root.path().join("sessions"));
    let mut session = store.create().expect("a session");

    session
        .append(CompletedTurn {
            messages: &exchange("a", "1"),
            observed: Some(usage(100)),
            withheld: 1,
        })
        .expect("the first turn is stored");

    session.file = File::options()
        .append(true)
        .open("/dev/full")
        .expect("/dev/full");
    let refused = session.append(CompletedTurn {
        messages: &exchange("b", "2"),
        observed: Some(usage(900)),
        withheld: 5,
    });

    // The write's refusal and no other: a turn refused before the write would leave the
    // accounting alone too, and prove nothing about the order.
    assert!(
        matches!(
            &refused,
            Err(SessionError::Io { source, .. }) if source.kind() == ErrorKind::StorageFull
        ),
        "not the write's ENOSPC: {refused:?}"
    );
    assert_eq!(
        session.observed(),
        Some(usage(100)),
        "the refused turn's count was taken"
    );
    assert_eq!(session.withheld(), 1, "the refused turn's cut was taken");
    assert_eq!(
        session.messages().len(),
        2,
        "the refused turn's messages were kept"
    );

    let resumed = store.resume(session.id()).expect("the stored turn resumes");
    assert_eq!(
        (resumed.observed(), resumed.withheld(), resumed.messages()),
        (session.observed(), session.withheld(), session.messages()),
        "the live session and the file disagree"
    );
}
