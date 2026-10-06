//! Where a conversation is kept between runs, and the translation at the edge of it.
//!
//! `sandbx-session` keeps shapes of its own, so this module is the seam. Every match
//! below destructures by field name with no `_` arm: a new [`ContentBlock`] variant is a
//! compile error here rather than a block silently missing from a saved conversation.
//! Free functions and not `From` impls, both types being foreign to this crate.

use sandbx_agent::PromptUsage;
use sandbx_providers::{ContentBlock, RequestMessage, Role};
use sandbx_session::{
    Content, Message, Role as StoredRole, Session, SessionError, SessionId, SessionStore, Usage,
};

/// What `--session` asked for.
#[derive(Debug, Clone, Copy)]
pub enum SessionChoice<'a> {
    /// The flag was absent: nothing is read and nothing is written.
    Off,

    /// The flag was bare: start one, and say on stderr what to pass to come back.
    New,

    /// The flag named a session to continue.
    Resume(&'a SessionId),
}

/// Open the session `choice` describes, reporting it on stderr.
///
/// Called before the first request, so a refused mode or an id with nothing behind it
/// costs nothing — but after the client, which no new transcript should outlive.
///
/// # Errors
///
/// Every [`SessionError`] the store can raise.
pub fn open(choice: SessionChoice<'_>) -> Result<Option<Session>, SessionError> {
    let session = match choice {
        SessionChoice::Off => return Ok(None),
        SessionChoice::New => {
            let session = store()?.create()?;
            // The id twice, because the second half is the line somebody copies.
            eprintln!(
                "sandbx: session {id} started; resume it with --session {id}",
                id = session.id()
            );
            session
        }
        SessionChoice::Resume(id) => {
            let session = store()?.resume(id)?;
            eprintln!(
                "sandbx: session {} resumed, {} messages",
                session.id(),
                session.messages().len()
            );
            session
        }
    };

    if session.shared_read() {
        eprintln!(
            "sandbx: session {} is readable by others; `chmod 600 {}` to narrow it",
            session.id(),
            session.path().display()
        );
    }

    Ok(Some(session))
}

/// The store under this process's environment.
///
/// `var_os` is read here and not injected, unlike in `sandbx-session` itself: this is the
/// one place that wants the real environment, and a test drives the store directly.
fn store() -> Result<SessionStore, SessionError> {
    SessionStore::from_env(&|name| std::env::var_os(name))
}

/// A stored conversation, in the shape a request carries it.
#[must_use]
pub fn request_history(stored: &[Message]) -> Vec<RequestMessage> {
    stored
        .iter()
        .map(|message| RequestMessage {
            role: match message.role {
                StoredRole::User => Role::User,
                StoredRole::Assistant => Role::Assistant,
            },
            content: message.content.iter().map(request_block).collect(),
        })
        .collect()
}

/// One stored block, in the shape a request carries it.
fn request_block(stored: &Content) -> ContentBlock {
    match stored {
        Content::Text { text } => ContentBlock::Text { text: text.clone() },
        Content::ToolUse { id, name, input } => ContentBlock::ToolUse {
            id: id.clone(),
            name: name.clone(),
            input: input.clone(),
        },
        Content::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => ContentBlock::ToolResult {
            tool_use_id: tool_use_id.clone(),
            content: content.clone(),
            is_error: *is_error,
        },
    }
}

/// A turn the loop produced, in the shape the transcript stores it.
#[must_use]
pub fn stored_messages(sent: &[RequestMessage]) -> Vec<Message> {
    sent.iter()
        .map(|message| Message {
            role: match message.role {
                Role::User => StoredRole::User,
                Role::Assistant => StoredRole::Assistant,
            },
            content: message.content.iter().map(stored_block).collect(),
        })
        .collect()
}

/// One sent block, in the shape the transcript stores it.
fn stored_block(sent: &ContentBlock) -> Content {
    match sent {
        ContentBlock::Text { text } => Content::Text { text: text.clone() },
        ContentBlock::ToolUse { id, name, input } => Content::ToolUse {
            id: id.clone(),
            name: name.clone(),
            input: input.clone(),
        },
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => Content::ToolResult {
            tool_use_id: tool_use_id.clone(),
            content: content.clone(),
            is_error: *is_error,
        },
    }
}

/// What a resumed session last measured, in the shape the turn loop takes it.
#[must_use]
pub fn request_usage(stored: Usage) -> PromptUsage {
    PromptUsage {
        input_tokens: stored.input_tokens,
        cache_read_input_tokens: stored.cache_read_input_tokens,
        cache_creation_input_tokens: stored.cache_creation_input_tokens,
    }
}

/// What a turn measured, in the shape the transcript stores it.
#[must_use]
pub fn stored_usage(observed: PromptUsage) -> Usage {
    Usage {
        input_tokens: observed.input_tokens,
        cache_read_input_tokens: observed.cache_read_input_tokens,
        cache_creation_input_tokens: observed.cache_creation_input_tokens,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks() -> Vec<ContentBlock> {
        vec![
            ContentBlock::Text {
                text: "what is in /srv?".to_owned(),
            },
            ContentBlock::ToolUse {
                id: "toolu_01".to_owned(),
                name: "ls".to_owned(),
                input: serde_json::json!({ "path": "/srv" }),
            },
            ContentBlock::ToolResult {
                tool_use_id: "toolu_01".to_owned(),
                content: "notes.txt".to_owned(),
                is_error: None,
            },
            ContentBlock::ToolResult {
                tool_use_id: "toolu_02".to_owned(),
                content: "denied".to_owned(),
                is_error: Some(true),
            },
        ]
    }

    #[test]
    fn every_block_kind_survives_the_round_trip() {
        let sent = [RequestMessage {
            role: Role::Assistant,
            content: blocks(),
        }];

        let back = request_history(&stored_messages(&sent));

        // Compared through the stored shapes, which derive `PartialEq` where the provider
        // types do not — the asymmetry is the reason the stored types exist.
        assert_eq!(stored_messages(&back), stored_messages(&sent));
        assert_eq!(stored_messages(&back)[0].content.len(), 4);
    }

    #[test]
    fn a_failed_tool_result_stays_failed() {
        let stored = stored_messages(&[RequestMessage {
            role: Role::User,
            content: blocks(),
        }]);

        let Content::ToolResult { is_error, .. } = &stored[0].content[3] else {
            panic!("the fourth block is a tool result");
        };
        assert_eq!(*is_error, Some(true));
    }

    #[test]
    fn a_figure_nobody_reported_stays_unreported() {
        let observed = PromptUsage {
            input_tokens: Some(1204),
            cache_read_input_tokens: None,
            cache_creation_input_tokens: None,
        };

        let back = request_usage(stored_usage(observed));

        assert_eq!(back.input_tokens, Some(1204));
        assert_eq!(back.cache_read_input_tokens, None);
        assert_eq!(back.cache_creation_input_tokens, None);
    }
}
