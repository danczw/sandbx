//! A line of a transcript, and how a file of them replays into a session.
//!
//! Append-only and never rewritten, because `withheld` is an index into the history: a store
//! that rewrote the conversation on every save would invalidate every figure it had written.
//!
//! What a reader does not understand it refuses rather than reads on a best effort, since a
//! dropped record changes the history the model is shown: an unknown version fails, and so
//! does an unknown `type`, a line nobody can classify being possibly a message. An unknown
//! *field* is ignored, and so is an unknown `stop`: a stop is a diagnosis, not history, and
//! one a later build names reads as none recorded.

use std::path::Path;

use sandbx_session_message::{Message, TurnStop, Usage};
use serde::{Deserialize, Deserializer, Serialize};

use sandbx_session_error::SessionError;

/// The format this build writes, and the only one it reads.
pub(crate) const VERSION: u32 = 1;

/// One line of a transcript, internally tagged: a message line is the message's own
/// fields plus a `type`, and an unknown `type` fails the parse rather than skipping.
///
/// `Turn` is a line of its own rather than a field on the last message because a first round
/// that produced no content still reports usage, leaving no message to hang it on.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Record {
    Header(Header),
    Message(Message),
    Turn(Accounting),
}

/// What the first line of every transcript says about the rest of it.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Header {
    pub(crate) version: u32,
    pub(crate) id: String,
    pub(crate) created_at_millis: u64,
}

/// What one turn cost, what it had to leave out, and how it ended.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct Accounting {
    pub(crate) observed: Option<Usage>,
    pub(crate) withheld: usize,
    /// `None` on a line written before the field existed, which is why it tolerates a
    /// missing key rather than bumping [`VERSION`]: a bump refuses every transcript to date.
    /// `None` too on a turn with no messages, which has none of its own to describe.
    #[serde(default, deserialize_with = "tolerant")]
    pub(crate) stop: Option<TurnStop>,
}

/// A `stop` this build cannot name, read as none recorded rather than refusing the line.
///
/// Through a `Value`, so a failed parse leaves no half-read input behind.
fn tolerant<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<TurnStop>, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(TurnStop::deserialize(value).ok())
}

impl Accounting {
    /// Fold one turn's figures in: `observed` keeps the last figure reported, `withheld`
    /// whatever the last turn cut, `stop` the last one recorded. The one copy of the rule,
    /// which [`fold`] replays and `Session::append` applies, so a resumed session and a
    /// continued one agree.
    ///
    /// Nothing reads these figures while compaction is off, and no flag turns it on (#302).
    /// Do not delete them as dead weight: they are recoverable only when the turn produces
    /// them, and a session resumed without them could not tell whether its history fills
    /// the window.
    pub(crate) fn absorb(&mut self, turn: Self) {
        self.observed = turn.observed.or(self.observed);
        self.withheld = turn.withheld;
        self.stop = turn.stop.or(self.stop);
    }
}

/// Replay a transcript into the state the next turn starts from.
///
/// The accounting is folded by [`Accounting::absorb`], as a session in memory folds it.
pub(crate) fn fold(path: &Path, body: &str) -> Result<Replayed, SessionError> {
    if body.is_empty() {
        return Err(SessionError::MissingHeader {
            path: path.to_owned(),
        });
    }

    let path = path.to_owned();
    let mut messages = Vec::new();
    let mut accounting = Accounting::default();
    let mut headed = false;

    // No newline after the last line means an append that did not finish, and dropping
    // it restores the last consistent state. That line only: an interior line that will
    // not parse may be a message, so it refuses. Refusing the torn one too would make one
    // interrupted append cost the whole conversation.
    let torn = !body.ends_with('\n');
    let last = body.lines().count().saturating_sub(1);

    for (index, text) in body.lines().enumerate() {
        let record: Record = match serde_json::from_str(text) {
            Ok(record) => record,
            Err(_) if torn && index == last => break,
            Err(source) => {
                return Err(SessionError::Malformed {
                    path,
                    line: index + 1,
                    source,
                });
            }
        };

        // Ahead of the match, so it reads every header and not only line 0's: a later one
        // declaring a version this build cannot read is a file it cannot replay.
        if let Record::Header(header) = &record
            && header.version != VERSION
        {
            return Err(SessionError::UnsupportedVersion {
                path,
                version: header.version,
            });
        }

        match (index, record) {
            (0, Record::Header(_)) => headed = true,
            (0, _) => {
                return Err(SessionError::MissingHeader { path });
            }
            // Cleared, because a stop describes the messages before its line: an append
            // torn after its results would otherwise carry the previous turn's.
            (_, Record::Message(message)) => {
                messages.push(message);
                accounting.stop = None;
            }
            (_, Record::Turn(turn)) => accounting.absorb(turn),
            // Its version was read above; nothing else a second header carries would
            // change what is replayed.
            (_, Record::Header(_)) => {}
        }
    }

    // Reached when the only line was a torn one, so the header was never read.
    if !headed {
        return Err(SessionError::MissingHeader { path });
    }

    Ok(Replayed {
        messages,
        accounting,
    })
}

/// What [`fold`] replays a transcript into.
#[derive(Debug)]
pub(crate) struct Replayed {
    pub(crate) messages: Vec<Message>,
    pub(crate) accounting: Accounting,
}

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;
