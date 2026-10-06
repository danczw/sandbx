//! Cases the code review turned up: torn appends, hand-edited role order, and a turn
//! that measured a prompt without producing a message.
//!
//! Alongside `transcript.rs` rather than inside it only because that file already covers
//! the happy path and the refusals the format itself defines; these are recovery rules.

use sandbx_session::{CompletedTurn, Content, Message, Role, SessionError, SessionStore, Usage};

fn store() -> (tempfile::TempDir, SessionStore) {
    let root = tempfile::tempdir().unwrap();
    let store = SessionStore::new(root.path().join("sessions"));
    (root, store)
}

fn said(role: Role, text: &str) -> Message {
    Message {
        role,
        content: vec![Content::Text {
            text: text.to_owned(),
        }],
    }
}

fn exchange(ask: &str, reply: &str) -> Vec<Message> {
    vec![said(Role::User, ask), said(Role::Assistant, reply)]
}

/// One session with one turn in it, and the path it was written to.
fn spoken_to(store: &SessionStore) -> (sandbx_session::SessionId, std::path::PathBuf) {
    let mut session = store.create().unwrap();
    session
        .append(CompletedTurn {
            messages: &exchange("a", "1"),
            observed: None,
            withheld: 0,
        })
        .unwrap();

    (session.id().clone(), session.path().to_owned())
}

/// ENOSPC part-way through an append is the realistic cause. Every record `write` emits
/// is newline-terminated, so a file not ending in one stopped mid-write — and refusing
/// the whole transcript would make one torn append cost the conversation.
#[test]
fn a_torn_final_line_is_dropped() {
    let (_root, store) = store();
    let (id, path) = spoken_to(&store);

    let whole = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{whole}{{\"type\":\"mes")).unwrap();

    let resumed = store.resume(&id).unwrap();

    assert_eq!(resumed.messages(), exchange("a", "1"));
}

/// Nothing is left to replay, so the header is as absent as it is for an empty file.
#[test]
fn a_transcript_of_nothing_but_a_torn_line_is_refused() {
    let (_root, store) = store();
    let (id, path) = spoken_to(&store);

    std::fs::write(&path, "{\"type\":\"hea").unwrap();

    let err = store.resume(&id).unwrap_err();

    assert!(
        matches!(err, SessionError::MissingHeader { .. }),
        "got {err:?}"
    );
}

/// `settled` sees only the last role, so an interior pair reached the provider as the
/// 400 the check exists to prevent.
#[test]
fn an_interior_pair_of_user_turns_is_refused() {
    let (_root, store) = store();
    let (id, path) = spoken_to(&store);

    // Appended so the history still ends on the model: only a check over the whole
    // history sees the break.
    let mut body = std::fs::read_to_string(&path).unwrap();
    for role in ["user", "user", "assistant"] {
        body.push_str(&format!(
            "{{\"type\":\"message\",\"role\":\"{role}\",\"content\":[]}}\n"
        ));
    }
    std::fs::write(&path, body).unwrap();

    let err = store.resume(&id).unwrap_err();

    assert!(
        matches!(err, SessionError::Disordered { .. }),
        "got {err:?}"
    );
}

/// A round that reported what the prompt cost and produced no blocks. The accounting
/// line is the only place that figure can live, so the turn still writes one.
#[test]
fn a_turn_with_no_messages_still_records_what_it_cost() {
    let (_root, store) = store();
    let mut session = store.create().unwrap();
    let observed = Usage {
        input_tokens: Some(1204),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    };

    session
        .append(CompletedTurn {
            messages: &[],
            observed: Some(observed),
            withheld: 0,
        })
        .unwrap();
    let id = session.id().clone();

    let resumed = store.resume(&id).unwrap();

    assert_eq!(resumed.observed(), Some(observed));
    assert!(resumed.messages().is_empty());
}
