//! What every test root here starts from. A `common/mod.rs` and not `common.rs`, so Cargo
//! does not build it as a test root of its own.

use sandbx_session_message::{Content, Message, Role};
use sandbx_session_store::SessionStore;

/// A store under a fresh temporary directory.
pub(crate) fn store() -> Store {
    let root = tempfile::tempdir().expect("a temp dir");
    let store = SessionStore::new(root.path().join("sessions"));
    Store { root, store }
}

/// A store, and the directory its root sits in, which has to outlive the store.
pub(crate) struct Store {
    #[allow(
        dead_code,
        reason = "read by permissions.rs; the other roots hold it for its Drop"
    )]
    pub(crate) root: tempfile::TempDir,
    pub(crate) store: SessionStore,
}

/// One block of prose from `role`.
pub(crate) fn said(role: Role, text: &str) -> Message {
    Message {
        role,
        content: vec![Content::Text {
            text: text.to_owned(),
        }],
    }
}

/// A turn of `[user, assistant]` prose, which is the shape every append needs.
#[allow(
    dead_code,
    reason = "permissions.rs has a zero-argument one of its own"
)]
pub(crate) fn exchange(ask: &str, reply: &str) -> Vec<Message> {
    vec![said(Role::User, ask), said(Role::Assistant, reply)]
}

/// A call and its answer, the pair a turn that runs out of rounds breaks off on.
#[allow(
    dead_code,
    reason = "used by transcript.rs and recovery.rs; permissions.rs builds none"
)]
fn called(id: &str) -> Vec<Message> {
    vec![
        Message {
            role: Role::Assistant,
            content: vec![Content::ToolUse {
                id: id.to_owned(),
                name: "ls".to_owned(),
                input: serde_json::json!({ "path": "/srv" }),
            }],
        },
        answered(id),
    ]
}

/// A result answering call `id`.
#[allow(
    dead_code,
    reason = "used by transcript.rs and recovery.rs; permissions.rs builds none"
)]
pub(crate) fn answered(id: &str) -> Message {
    Message {
        role: Role::User,
        content: vec![Content::ToolResult {
            tool_use_id: id.to_owned(),
            content: "notes.txt".to_owned(),
            is_error: None,
        }],
    }
}

/// A turn out of rounds: a prompt, a call, and its result, with no reply after it.
#[allow(
    dead_code,
    reason = "used by transcript.rs and recovery.rs; permissions.rs builds none"
)]
pub(crate) fn out_of_rounds(ask: &str, id: &str) -> Vec<Message> {
    let mut messages = vec![said(Role::User, ask)];
    messages.extend(called(id));
    messages
}
