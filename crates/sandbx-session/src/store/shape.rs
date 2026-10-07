//! Which orders of messages a transcript may hold, and which the API refuses.
//!
//! Separate from the sequence that applies them because these answer to the Messages
//! API's rules about a request, and `store.rs` to the filesystem's about a file. Every
//! one is a predicate over messages alone: no path, no mode, no descriptor.

use crate::{Content, Message, Role};

/// True when no two neighbouring messages carry the same role, except where
/// [`answers_only`] allows it.
///
/// Says nothing about which role comes first: an even-length history opening on the
/// model's reply alternates and ends settled, so [`opens`] is a condition of its own.
pub(super) fn alternating(messages: &[Message]) -> bool {
    messages.windows(2).all(|pair| joins(&pair[0], &pair[1]))
}

/// True when the history starts where the API requires: on a user turn.
///
/// An empty one is true, having no first role yet — [`follows`] is what holds the rule
/// over the batch that eventually supplies it.
pub(super) fn opens(messages: &[Message]) -> bool {
    messages.first().map(|message| message.role) != Some(Role::Assistant)
}

/// True when `batch` can follow `stored` without putting two turns of the same role
/// together — the one join [`alternating`] cannot see, each half being alternating alone.
pub(super) fn follows(stored: &[Message], batch: &[Message]) -> bool {
    match (stored.last(), batch.first()) {
        (Some(last), Some(first)) => joins(last, first),
        // Nothing to join, so `batch` is the transcript's opening and [`opens`] is the
        // rule over it instead.
        (None, _) => opens(batch),
        // An empty batch joins nothing.
        _ => true,
    }
}

/// True when the history may be stored and read back: [`settled`], or ending on tool
/// calls the model ran out of rounds before answering (#188).
///
/// Composed beside [`settled`] rather than written into it: the two guards this is used
/// by cannot disagree — `append` writing what `resume` refuses is a session bricked by a
/// run that exited non-zero — but a caller wanting "ended on an answer" means that, and
/// a round limit is the one thing this admits that is not one.
pub(super) fn resumable(messages: &[Message]) -> bool {
    settled(messages) || messages.last().is_some_and(answers_only)
}

/// True when `message` is a turn of nothing but answers to tool calls — the shape a turn
/// out of rounds ends on, and the one user turn another user turn may follow.
///
/// Empty content is not it: an unanswered call is a block, and a user turn with no blocks
/// at all is a hand edit either way.
pub(super) fn answers_only(message: &Message) -> bool {
    !message.content.is_empty()
        && message
            .content
            .iter()
            .all(|block| matches!(block, Content::ToolResult { .. }))
}

/// True when the history ends where a conversation may be left: on the model's reply.
/// An empty history is not settled, which refuses a prompt with no answer behind it.
fn settled(messages: &[Message]) -> bool {
    messages.last().map(|message| message.role) == Some(Role::Assistant)
}

/// True when `later` may directly follow `earlier`.
///
/// Two user turns in a row are the pair the API rejects, with one exception: a turn of
/// nothing but tool results is one the request carries *merged* into the turn after it,
/// so the pair never reaches the wire. That is what makes a round-limited turn storable
/// and the prompt that resumes it appendable (#188).
fn joins(earlier: &Message, later: &Message) -> bool {
    earlier.role != later.role
        || (earlier.role == Role::User && answers_only(earlier) && !answers_only(later))
}
