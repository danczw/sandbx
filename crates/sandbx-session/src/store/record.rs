//! A line of a transcript, and how a file of them replays into a session.
//!
//! Separate from the store because it changes for a different reason: the store changes
//! when the rules for opening a file change, this when the format does.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{Message, SessionError, Usage};

/// The format this build writes, and the only one it reads.
pub(super) const VERSION: u32 = 1;

/// One line of a transcript.
///
/// Internally tagged, so a message line is the message's own fields plus a `type`, and
/// an unknown `type` fails the parse rather than being skipped.
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
/// The accounting fold is the same operation the turn loop performs in memory —
/// `observed` keeps the last figure anyone reported, `withheld` is whatever the last
/// turn cut — so a resumed session and a continued one carry the same numbers.
pub(super) fn fold(
    path: &Path,
    body: &str,
) -> Result<(Vec<Message>, Option<Usage>, usize), SessionError> {
    if body.is_empty() {
        return Err(SessionError::MissingHeader {
            path: path.to_owned(),
        });
    }

    let mut messages = Vec::new();
    let mut observed = None;
    let mut withheld = 0;
    let mut headed = false;

    // No newline after the last line means an append that did not finish, and dropping it
    // restores the state the file was last consistent in. That one line only: an interior
    // line that will not parse may be a message, so it refuses.
    let torn = !body.ends_with('\n');
    let last = body.lines().count().saturating_sub(1);

    for (index, text) in body.lines().enumerate() {
        let record: Record = match serde_json::from_str(text) {
            Ok(record) => record,
            Err(_) if torn && index == last => break,
            Err(source) => {
                return Err(SessionError::Malformed {
                    path: path.to_owned(),
                    line: index + 1,
                    source,
                });
            }
        };

        match (index, record) {
            (0, Record::Header(header)) => {
                if header.version != VERSION {
                    return Err(SessionError::UnsupportedVersion {
                        path: path.to_owned(),
                        version: header.version,
                    });
                }
                headed = true;
            }
            (0, _) => {
                return Err(SessionError::MissingHeader {
                    path: path.to_owned(),
                });
            }
            (_, Record::Message(message)) => messages.push(message),
            (_, Record::Turn(accounting)) => {
                observed = accounting.observed.or(observed);
                withheld = accounting.withheld;
            }
            // A second header says nothing about the conversation, so nothing it could
            // say would change what is replayed.
            (_, Record::Header(_)) => {}
        }
    }

    // Reached when the only line was a torn one, so the header was never read.
    if !headed {
        return Err(SessionError::MissingHeader {
            path: path.to_owned(),
        });
    }

    Ok((messages, observed, withheld))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Content, Role};

    #[test]
    fn a_turn_line_carries_its_own_type() {
        let record = Record::Turn(Accounting {
            observed: Some(Usage {
                input_tokens: Some(1204),
                cache_read_input_tokens: None,
                cache_creation_input_tokens: None,
            }),
            withheld: 2,
        });

        assert_eq!(
            serde_json::to_value(&record).unwrap(),
            serde_json::json!({
                "type": "turn",
                "observed": {
                    "input_tokens": 1204,
                    "cache_read_input_tokens": null,
                    "cache_creation_input_tokens": null,
                },
                "withheld": 2,
            })
        );
    }

    #[test]
    fn a_message_line_is_the_message_plus_a_type() {
        let record = Record::Message(Message {
            role: Role::User,
            content: vec![Content::Text {
                text: "what is in /srv?".to_owned(),
            }],
        });

        assert_eq!(
            serde_json::to_value(&record).unwrap(),
            serde_json::json!({
                "type": "message",
                "role": "user",
                "content": [{ "type": "text", "text": "what is in /srv?" }],
            })
        );
    }

    #[test]
    fn an_unknown_record_type_is_not_a_record() {
        let line = r#"{"type":"compaction","dropped":4}"#;

        assert!(serde_json::from_str::<Record>(line).is_err());
    }
}
