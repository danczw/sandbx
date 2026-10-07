//! Public contract of [`SessionStore`]: what a transcript holds, and what it refuses.

use std::str::FromStr;

use sandbx_session::{
    CompletedTurn, Content, Message, Role, SessionError, SessionId, SessionStore, Usage,
};

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

fn usage(input: u32) -> Usage {
    Usage {
        input_tokens: Some(input),
        cache_read_input_tokens: None,
        cache_creation_input_tokens: None,
    }
}

/// A turn of `[user, assistant]` prose, which is the shape every append needs.
fn exchange(ask: &str, reply: &str) -> Vec<Message> {
    vec![said(Role::User, ask), said(Role::Assistant, reply)]
}

#[test]
fn a_stored_turn_comes_back_as_it_went_in() {
    let (_root, store) = store();
    let messages = vec![
        said(Role::User, "what is in /srv?"),
        Message {
            role: Role::Assistant,
            content: vec![Content::ToolUse {
                id: "toolu_01".to_owned(),
                name: "ls".to_owned(),
                input: serde_json::json!({ "path": "/srv" }),
            }],
        },
        Message {
            role: Role::User,
            content: vec![Content::ToolResult {
                tool_use_id: "toolu_01".to_owned(),
                content: "bin  etc".to_owned(),
                is_error: None,
            }],
        },
        said(Role::Assistant, "bin and etc"),
    ];

    let mut session = store.create().unwrap();
    let id = session.id().clone();
    session
        .append(CompletedTurn {
            messages: &messages,
            observed: Some(usage(1204)),
            withheld: 0,
        })
        .unwrap();

    let resumed = store.resume(&id).unwrap();

    assert_eq!(resumed.messages(), messages.as_slice());
    assert_eq!(resumed.observed(), Some(usage(1204)));
    assert_eq!(resumed.withheld(), 0);
}

#[test]
fn a_second_turn_appends_and_moves_nothing() {
    let (_root, store) = store();
    let mut session = store.create().unwrap();
    session
        .append(CompletedTurn {
            messages: &exchange("first", "one"),
            observed: Some(usage(10)),
            withheld: 0,
        })
        .unwrap();

    let before = std::fs::read(session.path()).unwrap();
    session
        .append(CompletedTurn {
            messages: &exchange("second", "two"),
            observed: Some(usage(20)),
            withheld: 0,
        })
        .unwrap();
    let after = std::fs::read(session.path()).unwrap();

    // Byte-identical prefix, not merely the same messages: `withheld` indexes the
    // history, so a rewrite that moved a prefix would move what it counts.
    assert_eq!(&after[..before.len()], before.as_slice());
    assert!(after.len() > before.len());
}

#[test]
fn the_reloaded_cut_is_the_last_turns_cut() {
    let (_root, store) = store();
    let mut session = store.create().unwrap();
    for (ask, reply, withheld) in [("a", "1", 0), ("b", "2", 4), ("c", "3", 2)] {
        session
            .append(CompletedTurn {
                messages: &exchange(ask, reply),
                observed: Some(usage(100)),
                withheld,
            })
            .unwrap();
    }
    let id = session.id().clone();

    assert_eq!(store.resume(&id).unwrap().withheld(), 2);
}

#[test]
fn a_turn_reporting_nothing_keeps_the_figure() {
    let (_root, store) = store();
    let mut session = store.create().unwrap();
    session
        .append(CompletedTurn {
            messages: &exchange("a", "1"),
            observed: Some(usage(1204)),
            withheld: 0,
        })
        .unwrap();
    session
        .append(CompletedTurn {
            messages: &exchange("b", "2"),
            observed: None,
            withheld: 0,
        })
        .unwrap();
    let id = session.id().clone();

    assert_eq!(session.observed(), Some(usage(1204)));
    assert_eq!(store.resume(&id).unwrap().observed(), Some(usage(1204)));
}

#[test]
fn a_turn_with_no_reply_is_refused_not_written() {
    let (_root, store) = store();
    let mut session = store.create().unwrap();
    let before = std::fs::read(session.path()).unwrap();

    // A prompt with nothing answering it. Not the message-less turn, which leaves the
    // last role where it was and so keeps its accounting line — see
    // `recovery.rs::a_turn_with_no_messages_still_records_what_it_cost`.
    let err = session
        .append(CompletedTurn {
            messages: &[said(Role::User, "unanswered")],
            observed: Some(usage(10)),
            withheld: 0,
        })
        .unwrap_err();

    assert!(matches!(err, SessionError::IncompleteTurn), "got {err:?}");
    assert_eq!(std::fs::read(session.path()).unwrap(), before);
}

/// Refused before the write, the file being append-only: a later resume cannot undo it.
#[test]
fn a_turn_that_would_be_unreadable_is_refused() {
    let (_root, store) = store();
    let mut session = store.create().unwrap();
    session
        .append(CompletedTurn {
            messages: &exchange("hi", "hello"),
            observed: None,
            withheld: 0,
        })
        .unwrap();
    let before = std::fs::read(session.path()).unwrap();

    // Settled and alternating on its own, but joins a stored assistant message to another.
    let joined = session
        .append(CompletedTurn {
            messages: &[said(Role::Assistant, "unprompted")],
            observed: None,
            withheld: 0,
        })
        .unwrap_err();

    // The other half: follows the stored history cleanly, and is still a pair inside.
    let inside = session
        .append(CompletedTurn {
            messages: &[
                said(Role::User, "first"),
                said(Role::User, "second"),
                said(Role::Assistant, "which?"),
            ],
            observed: None,
            withheld: 0,
        })
        .unwrap_err();

    assert!(
        matches!(joined, SessionError::DisorderedTurn),
        "got {joined:?}"
    );
    assert!(
        matches!(inside, SessionError::DisorderedTurn),
        "got {inside:?}"
    );
    assert_eq!(std::fs::read(session.path()).unwrap(), before);

    // The point of refusing before the write: what `append` turned away, `resume` still
    // reads.
    assert_eq!(store.resume(session.id()).unwrap().messages().len(), 2);
}

/// Alternating and settled both hold for this batch, so neither predicate catches it.
#[test]
fn a_first_turn_may_not_open_on_the_models_reply() {
    let (_root, store) = store();
    let mut session = store.create().unwrap();

    let err = session
        .append(CompletedTurn {
            messages: &[
                said(Role::Assistant, "unprompted"),
                said(Role::User, "what?"),
                said(Role::Assistant, "that"),
            ],
            observed: None,
            withheld: 0,
        })
        .unwrap_err();

    assert!(matches!(err, SessionError::DisorderedTurn), "got {err:?}");
    assert_eq!(store.resume(session.id()).unwrap().messages().len(), 0);
}

/// The same defect reached by a hand edit instead, where there is nothing left to refuse
/// before the write.
#[test]
fn a_transcript_opening_on_a_reply_is_refused() {
    let (_root, store) = store();
    let mut session = store.create().unwrap();
    session
        .append(CompletedTurn {
            messages: &exchange("a", "1"),
            observed: None,
            withheld: 0,
        })
        .unwrap();
    let id = session.id().clone();
    let path = session.path().to_owned();

    // After the header, so the stored exchange is pushed behind a reply to nothing.
    let body = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<&str> = body.lines().collect();
    lines.insert(
        1,
        "{\"type\":\"message\",\"role\":\"assistant\",\"content\":[]}",
    );
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let err = store.resume(&id).unwrap_err();

    assert!(
        matches!(err, SessionError::Disordered { .. }),
        "got {err:?}"
    );
}

#[test]
fn two_sessions_never_take_the_same_id() {
    let (_root, store) = store();

    let first = store.create().unwrap();
    let second = store.create().unwrap();

    assert_ne!(first.id(), second.id());
    assert_ne!(first.path(), second.path());
}

#[test]
fn a_new_session_resumes_before_it_has_said_anything() {
    let (_root, store) = store();
    let id = store.create().unwrap().id().clone();

    let resumed = store.resume(&id).unwrap();

    assert!(resumed.messages().is_empty());
    assert_eq!(resumed.observed(), None);
}

#[test]
fn an_unknown_id_is_refused_not_started() {
    let (_root, store) = store();
    let absent = SessionId::from_str("zzzzzzzz").unwrap();

    let err = store.resume(&absent).unwrap_err();

    assert!(
        matches!(&err, SessionError::NotFound { id } if id == &absent),
        "got {err:?}"
    );
    assert!(!store.root().join("zzzzzzzz.jsonl").exists());
}

#[test]
fn a_future_version_is_refused_not_guessed() {
    let (_root, store) = store();
    let id = store.create().unwrap().id().clone();
    let path = store.root().join(format!("{id}.jsonl"));
    std::fs::write(
        &path,
        format!("{{\"type\":\"header\",\"version\":2,\"id\":\"{id}\",\"created_at_millis\":0}}\n"),
    )
    .unwrap();

    let err = store.resume(&id).unwrap_err();

    assert!(
        matches!(err, SessionError::UnsupportedVersion { version: 2, .. }),
        "got {err:?}"
    );
}

#[test]
fn a_transcript_without_a_header_is_refused() {
    let (_root, store) = store();
    let id = store.create().unwrap().id().clone();
    let path = store.root().join(format!("{id}.jsonl"));
    std::fs::write(
        &path,
        "{\"type\":\"message\",\"role\":\"user\",\"content\":[]}\n",
    )
    .unwrap();

    let err = store.resume(&id).unwrap_err();

    assert!(
        matches!(err, SessionError::MissingHeader { .. }),
        "got {err:?}"
    );
}

#[test]
fn an_unparsable_line_names_the_line_it_is_on() {
    let (_root, store) = store();
    let mut session = store.create().unwrap();
    session
        .append(CompletedTurn {
            messages: &exchange("a", "1"),
            observed: None,
            withheld: 0,
        })
        .unwrap();
    let id = session.id().clone();
    let path = session.path().to_owned();

    // Header, two messages, accounting, then a fifth line that is not a record. Newline-
    // terminated, so it is not the tolerated torn append of `recovery.rs`.
    let whole = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{whole}{{\"type\":\"mes\n")).unwrap();

    let err = store.resume(&id).unwrap_err();

    assert!(
        matches!(err, SessionError::Malformed { line: 5, .. }),
        "got {err:?}"
    );
}

#[test]
fn a_transcript_ending_on_a_user_turn_is_refused() {
    let (_root, store) = store();
    let mut session = store.create().unwrap();
    session
        .append(CompletedTurn {
            messages: &exchange("a", "1"),
            observed: None,
            withheld: 0,
        })
        .unwrap();
    let id = session.id().clone();
    let path = session.path().to_owned();

    let mut body = std::fs::read_to_string(&path).unwrap();
    body.push_str("{\"type\":\"message\",\"role\":\"user\",\"content\":[]}\n");
    std::fs::write(&path, body).unwrap();

    let err = store.resume(&id).unwrap_err();

    assert!(matches!(err, SessionError::IncompleteTurn), "got {err:?}");
}
