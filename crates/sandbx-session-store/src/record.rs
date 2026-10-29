//! A line of a transcript, and how a file of them replays into a session.

use std::path::Path;

use sandbx_session_message::{Message, Usage};
use serde::{Deserialize, Serialize};

use sandbx_session_error::SessionError;

/// The format this build writes, and the only one it reads.
pub(super) const VERSION: u32 = 1;

/// One line of a transcript, internally tagged: a message line is the message's own
/// fields plus a `type`, and an unknown `type` fails the parse rather than skipping.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum Record {
    Header(Header),
    Message(Message),
    Turn(Accounting),
}

/// What the first line of every transcript says about the rest of it.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Header {
    pub(super) version: u32,
    pub(super) id: String,
    pub(super) created_at_millis: u64,
}

/// What one turn cost, and what it had to leave out.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Accounting {
    pub(super) observed: Option<Usage>,
    pub(super) withheld: usize,
}

/// Replay a transcript into the state the next turn starts from.
///
/// The accounting fold is what the turn loop does in memory — `observed` keeps the last
/// figure reported, `withheld` whatever the last turn cut — so a resumed session and a
/// continued one carry the same numbers.
pub(super) fn fold(
    path: &Path,
    body: &str,
) -> Result<(Vec<Message>, Option<Usage>, usize), SessionError> {
    if body.is_empty() {
        return Err(SessionError::MissingHeader {
            path: path.to_owned(),
        });
    }

    let path = path.to_owned();
    let mut messages = Vec::new();
    let mut observed = None;
    let mut withheld = 0;
    let mut headed = false;

    // No newline after the last line means an append that did not finish, and dropping
    // it restores the last consistent state. That line only: an interior line that will
    // not parse may be a message, so it refuses.
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
            (_, Record::Message(message)) => messages.push(message),
            (_, Record::Turn(accounting)) => {
                observed = accounting.observed.or(observed);
                withheld = accounting.withheld;
            }
            // Its version was read above; nothing else a second header carries would
            // change what is replayed.
            (_, Record::Header(_)) => {}
        }
    }

    // Reached when the only line was a torn one, so the header was never read.
    if !headed {
        return Err(SessionError::MissingHeader { path });
    }

    Ok((messages, observed, withheld))
}

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;
