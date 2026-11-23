use std::ffi::OsString;
use std::path::Path;

use sandbx_prompt::{ContentBlock, RequestMessage, Role};
use sandbx_session_error::SessionError;
use sandbx_session_message::TurnStop;
use sandbx_session_store::SessionStore;

use super::Conversation;
use crate::SessionChoice;

/// An environment whose only state home is `root`.
fn under(root: &Path) -> impl Fn(&str) -> Option<OsString> {
    let root = root.as_os_str().to_owned();
    move |name| (name == "XDG_STATE_HOME").then(|| root.clone())
}

fn said(role: Role, text: &str) -> RequestMessage {
    RequestMessage {
        role,
        content: vec![ContentBlock::Text {
            text: text.to_owned(),
        }],
    }
}

/// A round that stopped on a call it ran and never answered: a transcript ending on
/// results.
fn stopped_on_a_call() -> Vec<RequestMessage> {
    vec![
        RequestMessage {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: "toolu_01".to_owned(),
                name: "ls".to_owned(),
                input: serde_json::json!({ "path": "/srv" }),
            }],
        },
        RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "toolu_01".to_owned(),
                content: "notes.txt".to_owned(),
                is_error: None,
            }],
        },
    ]
}

/// The floor a turn reports names the merged request; what is stored names the
/// transcript, where the results the prompt joined are a message of their own (#188).
#[test]
fn a_resumed_cut_is_stored_in_transcript_numbering() {
    let root = tempfile::tempdir().expect("a temp dir");
    let lookup = under(root.path());

    let first =
        Conversation::open(SessionChoice::New, "go".to_owned(), &lookup).expect("a new session");
    let id = first.id().expect("a session was asked for").clone();
    let recorded = first
        .record(&stopped_on_a_call(), None, 0, TurnStop::RoundLimit)
        .expect("a session records");
    recorded.appended.expect("it stores");

    let resumed = Conversation::open(SessionChoice::Resume(&id), "next".to_owned(), &lookup)
        .expect("it resumes");
    // "go", the call, and its results travelling with "next".
    assert_eq!(resumed.history().len(), 3);
    let recorded = resumed
        .record(
            &[said(Role::Assistant, "done")],
            None,
            2,
            TurnStop::Answered,
        )
        .expect("a session records");
    recorded.appended.expect("it stores");

    // Onto "next", the results before it shed with their call.
    assert_eq!(recorded.withheld, 3);
    let stored = SessionStore::new(root.path().join("sandbx/sessions"))
        .resume(&id)
        .expect("it resumes");
    assert_eq!(stored.withheld(), 3);
    assert_eq!(stored.messages().len(), 5);
}

#[test]
fn an_off_conversation_records_nothing() {
    let nowhere = |_: &str| None;
    let off =
        Conversation::open(SessionChoice::Off, "hi".to_owned(), &nowhere).expect("nothing to open");

    assert!(off.id().is_none());
    assert_eq!(off.history(), [said(Role::User, "hi")]);
    assert!(
        off.record(
            &[said(Role::Assistant, "hello")],
            None,
            0,
            TurnStop::Answered
        )
        .is_none()
    );
}

/// The prompt with no reply ends on a user turn, which no resume could follow.
#[test]
fn a_turn_with_no_reply_is_refused_and_named() {
    let root = tempfile::tempdir().expect("a temp dir");
    let conversation = Conversation::open(SessionChoice::New, "hi".to_owned(), &under(root.path()))
        .expect("a new session");
    let id = conversation.id().expect("a session").clone();

    let recorded = conversation
        .record(&[], None, 0, TurnStop::Interrupted)
        .expect("a session records");

    assert_eq!(recorded.id, id);
    assert!(matches!(
        recorded.appended,
        Err(SessionError::IncompleteTurn)
    ));
}
