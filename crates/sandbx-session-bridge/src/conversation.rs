//! A conversation from the history a run sends to the turn it stores.

use std::ffi::OsString;

use sandbx_compact::PromptUsage;
use sandbx_prompt::{ContentBlock, RequestMessage, Role};
use sandbx_session_error::SessionError;
use sandbx_session_id::SessionId;
use sandbx_session_message::{CompletedTurn, TurnStop};
use sandbx_session_store::Session;

use crate::{
    Merged, SessionChoice, merge_user_runs, open, request_history, request_usage, stored_messages,
    stored_usage,
};

/// One run's conversation: the stored history, the prompt that joins it, and the session
/// the finished turn goes back to.
///
/// `withheld` is an index, and the request and the transcript number messages differently,
/// so it goes in through [`Conversation::withheld`] in the request's numbering and comes
/// back out of [`Conversation::record`] in the transcript's.
pub struct Conversation {
    /// `None` under [`SessionChoice::Off`]: nothing was read and nothing will be written.
    session: Option<Session>,

    /// The prompt, kept to be stored ahead of the turn's own messages.
    asked: RequestMessage,

    /// The history the request carries, prompt included.
    merged: Merged,
}

/// What [`Conversation::record`] did with a finished turn.
#[must_use]
pub struct Recorded {
    /// The session the turn went to.
    pub id: SessionId,

    /// The compaction floor as stored, in the transcript's numbering.
    pub withheld: usize,

    /// The append's result. [`SessionError::IncompleteTurn`] is a turn that produced nothing
    /// to store, which a caller reports rather than fails on.
    pub appended: Result<(), SessionError>,
}

impl Conversation {
    /// Open the session `choice` describes, reporting it on stderr, and join `prompt` to
    /// its history.
    ///
    /// Before the first request, so a refused mode or an id with nothing behind it costs
    /// nothing. `lookup` locates the store; outside tests it must be the real environment,
    /// which `sandbx-grants` reads to refuse a grant over the same directory.
    ///
    /// # Errors
    ///
    /// Every [`SessionError`] the store can raise.
    pub fn open(
        choice: SessionChoice<'_>,
        prompt: String,
        lookup: &impl Fn(&str) -> Option<OsString>,
    ) -> Result<Self, SessionError> {
        let session = open(choice, lookup)?;
        let asked = RequestMessage {
            role: Role::User,
            content: vec![ContentBlock::Text { text: prompt }],
        };

        // Stored turns first: the new prompt is the conversation's latest, not its own
        // request.
        let mut history = session
            .as_ref()
            .map_or_else(Vec::new, |session| request_history(session.messages()));
        history.push(asked.clone());
        // Merged, not appended: a stored turn out of rounds ends on tool results, which the
        // prompt joins rather than follows (#188).
        let merged = merge_user_runs(history, session.as_ref().map_or(0, Session::withheld));

        Ok(Self {
            session,
            asked,
            merged,
        })
    }

    /// The session's id, `None` when there is none.
    #[must_use]
    pub fn id(&self) -> Option<&SessionId> {
        self.session.as_ref().map(Session::id)
    }

    /// What the request carries, each run of user messages collapsed into one.
    #[must_use]
    pub fn history(&self) -> &[RequestMessage] {
        &self.merged.history
    }

    /// The stored compaction floor in [`Conversation::history`]'s numbering, which is what
    /// a `Turn` takes.
    #[must_use]
    pub fn withheld(&self) -> usize {
        self.merged.withheld
    }

    /// What the resumed conversation last measured, `None` without one.
    #[must_use]
    pub fn observed(&self) -> Option<PromptUsage> {
        self.session
            .as_ref()
            .and_then(Session::observed)
            .map(request_usage)
    }

    /// Append the prompt and a finished turn's `messages` to the session, or `None` when
    /// there is no session.
    ///
    /// The prompt is stored from here, not from `messages`: a turn's messages are what it
    /// produced, so a transcript built from them alone would hold the model's replies with
    /// nothing they replied to. `withheld` is the turn's figure, in the request's numbering,
    /// and `stop` is the caller's, a turn's own stop being unable to say a cap was
    /// summarised or who interrupted it.
    #[must_use = "an append that failed is only in `Recorded::appended`"]
    pub fn record(
        self,
        messages: &[RequestMessage],
        usage: Option<PromptUsage>,
        withheld: usize,
        stop: TurnStop,
    ) -> Option<Recorded> {
        let mut session = self.session?;
        let withheld = self.merged.unmerged(withheld);

        let mut stored = stored_messages(&[self.asked]);
        stored.extend(stored_messages(messages));
        let appended = session.append(CompletedTurn {
            messages: &stored,
            observed: usage.map(stored_usage),
            withheld,
            stop,
        });

        Some(Recorded {
            id: session.id().clone(),
            withheld,
            appended,
        })
    }
}

#[cfg(test)]
#[path = "conversation_tests.rs"]
mod tests;
