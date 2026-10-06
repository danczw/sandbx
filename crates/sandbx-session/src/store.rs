//! The store, a session, and the line format between them.
//!
//! A transcript is append-only, and that is load-bearing rather than tidy: `withheld` is
//! an index into the history, so it stays exact only as long as nothing moves a prefix.
//! Everything here is therefore either a read of the whole file or a write to its end.

use std::ffi::OsString;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::id::clock_millis;
use crate::{CompletedTurn, Message, Role, SessionError, SessionId, Usage, sessions_directory};

/// The format this build writes, and the only one it reads.
const VERSION: u32 = 1;

/// The mode a transcript is created with.
const OWNER_ONLY: u32 = 0o600;

/// The mode the directory holding them is created with.
const DIR_OWNER_ONLY: u32 = 0o700;

/// The bits that let somebody else write, which refuse a resume.
///
/// Split from [`READABLE_BITS`] rather than sharing `sandbx-cli`'s single `SHARED_BITS`,
/// and deliberately: a credential can be rotated once it has leaked, a conversation
/// cannot, so refusing to *read* a wide transcript protects nothing that is still
/// protectable. What a resume can still prevent is somebody else choosing the history a
/// tool-calling model is told it produced.
const WRITABLE_BITS: u32 = 0o022;

/// The bits that let somebody else read, which resume and report.
const READABLE_BITS: u32 = 0o044;

/// How many ids to try before concluding the clock is stuck.
///
/// Two sessions starting in the same millisecond is ordinary, so a taken id is a retry
/// rather than a failure.
const ATTEMPTS: u64 = 1000;

/// The directory transcripts live in.
#[derive(Debug, Clone)]
pub struct SessionStore {
    root: PathBuf,
}

impl SessionStore {
    /// A store over `root`, which is created on the first [`create`](Self::create).
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// A store under [`sessions_directory`].
    pub fn from_env(lookup: &impl Fn(&str) -> Option<OsString>) -> Result<Self, SessionError> {
        Ok(Self::new(sessions_directory(lookup)?))
    }

    /// Where this store keeps its transcripts.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Start a session, creating the root and the transcript.
    ///
    /// `create_new` is what makes the id unique: the filesystem, not a prior check,
    /// decides whether the name was free.
    pub fn create(&self) -> Result<Session, SessionError> {
        DirBuilder::new()
            .recursive(true)
            .mode(DIR_OWNER_ONLY)
            .create(&self.root)
            .map_err(|source| SessionError::Io {
                path: self.root.clone(),
                source,
            })?;

        for attempt in 0..ATTEMPTS {
            let id = SessionId::from_clock(attempt)?;
            let path = self.path_for(&id);

            match OpenOptions::new()
                .append(true)
                .create_new(true)
                .mode(OWNER_ONLY)
                .open(&path)
            {
                Ok(file) => {
                    let mut session = Session {
                        id,
                        path,
                        file,
                        messages: Vec::new(),
                        observed: None,
                        withheld: 0,
                        shared_read: false,
                    };
                    let header = Record::Header(Header {
                        version: VERSION,
                        id: session.id.to_string(),
                        created_at_millis: clock_millis()?,
                    });
                    session.write(&[header])?;
                    return Ok(session);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(SessionError::Io { path, source }),
            }
        }

        Err(SessionError::Collision { attempts: ATTEMPTS })
    }

    /// Reopen a session and read back everything it holds.
    ///
    /// Refuses a transcript, or a directory holding it, that somebody else can write or
    /// that somebody else owns. The directory is vetted first: one another user may write
    /// lets them rename their own `0600` file over the transcript, whatever mode the
    /// transcript itself carries.
    ///
    /// Everything is stat'd through an open descriptor rather than by path, so the file
    /// that is vetted is the file that is read.
    pub fn resume(&self, id: &SessionId) -> Result<Session, SessionError> {
        let path = self.path_for(id);
        let owner = nix::unistd::getuid().as_raw();

        let directory = open(&self.root, id)?;
        let (mode, uid) = ownership(&directory, &self.root)?;
        if mode & WRITABLE_BITS != 0 {
            return Err(SessionError::DirWritable {
                path: self.root.clone(),
                mode,
            });
        }
        if uid != owner {
            return Err(SessionError::ForeignOwner {
                path: self.root.clone(),
                uid,
            });
        }

        let mut file = open(&path, id)?;
        let (mode, uid) = ownership(&file, &path)?;
        if mode & WRITABLE_BITS != 0 {
            return Err(SessionError::Writable {
                path: path.clone(),
                mode,
            });
        }
        if uid != owner {
            return Err(SessionError::ForeignOwner {
                path: path.clone(),
                uid,
            });
        }
        let shared_read = mode & READABLE_BITS != 0;

        let mut body = String::new();
        file.read_to_string(&mut body)
            .map_err(|source| SessionError::Io {
                path: path.clone(),
                source,
            })?;

        let (messages, observed, withheld) = fold(&path, &body)?;
        // Re-checked on the way in, not just on the way out: a hand-edited transcript
        // ending on a user turn would take a provider 400 on the next request. A
        // transcript with no messages at all is fine — that is a session created and
        // not yet talked to.
        if !messages.is_empty() && !settled(&messages) {
            return Err(SessionError::IncompleteTurn);
        }

        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(|source| SessionError::Io {
                path: path.clone(),
                source,
            })?;

        Ok(Session {
            id: id.clone(),
            path,
            file,
            messages,
            observed,
            withheld,
            shared_read,
        })
    }

    /// The transcript an id names. Needs no check of its own: a [`SessionId`] cannot
    /// exist without having passed its own parser.
    fn path_for(&self, id: &SessionId) -> PathBuf {
        self.root.join(format!("{id}.jsonl"))
    }
}

/// One session, open for appending.
#[derive(Debug)]
pub struct Session {
    id: SessionId,
    path: PathBuf,
    file: File,
    messages: Vec<Message>,
    observed: Option<Usage>,
    withheld: usize,
    shared_read: bool,
}

impl Session {
    /// What to pass `--session` to come back to this conversation.
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// The transcript on disk, for a message that tells someone where it is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The conversation so far, oldest first.
    #[must_use]
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// What the provider last counted the prompt at, if any turn said.
    #[must_use]
    pub fn observed(&self) -> Option<Usage> {
        self.observed
    }

    /// How many leading messages the last turn left out to make the request fit.
    #[must_use]
    pub fn withheld(&self) -> usize {
        self.withheld
    }

    /// True when somebody else can read the transcript, which resumed anyway.
    ///
    /// Worth telling the operator about and not worth refusing over: by the time this is
    /// known the conversation has already been readable, and a transcript cannot be
    /// rotated the way a leaked credential can.
    #[must_use]
    pub fn shared_read(&self) -> bool {
        self.shared_read
    }

    /// Add a finished turn to the end of the transcript.
    ///
    /// Refuses a turn that does not end on an assistant message, because the next
    /// resume would send two user turns in a row.
    pub fn append(&mut self, turn: CompletedTurn<'_>) -> Result<(), SessionError> {
        if !settled(turn.messages) {
            return Err(SessionError::IncompleteTurn);
        }

        let mut records: Vec<Record> = turn
            .messages
            .iter()
            .map(|message| Record::Message(message.clone()))
            .collect();
        // Always its own record, never folded onto a message line: a first round that
        // produced no content still reports what the prompt cost.
        records.push(Record::Turn(Accounting {
            observed: turn.observed,
            withheld: turn.withheld,
        }));

        self.write(&records)?;

        self.messages.extend(turn.messages.iter().cloned());
        self.observed = turn.observed.or(self.observed);
        self.withheld = turn.withheld;

        Ok(())
    }

    /// Append records as lines, in one write, so a short write tears at most one turn.
    fn write(&mut self, records: &[Record]) -> Result<(), SessionError> {
        let mut lines = String::new();
        for record in records {
            // Reported as an I/O failure rather than given a variant: nothing a record
            // holds can fail to serialize, so there is no case for a caller to act on.
            let line = serde_json::to_string(record).map_err(|error| SessionError::Io {
                path: self.path.clone(),
                source: std::io::Error::other(error),
            })?;
            lines.push_str(&line);
            lines.push('\n');
        }

        self.file
            .write_all(lines.as_bytes())
            .map_err(|source| SessionError::Io {
                path: self.path.clone(),
                source,
            })
    }
}

/// Open `path`, reading an absent one as the session not existing.
///
/// A directory opens read-only on Linux, which is all a `fstat` of it needs.
fn open(path: &Path, id: &SessionId) -> Result<File, SessionError> {
    File::open(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            SessionError::NotFound { id: id.clone() }
        } else {
            SessionError::Io {
                path: path.to_owned(),
                source,
            }
        }
    })
}

/// The permission bits and owner of an open file, from the descriptor.
fn ownership(file: &File, path: &Path) -> Result<(u32, u32), SessionError> {
    let metadata = file.metadata().map_err(|source| SessionError::Io {
        path: path.to_owned(),
        source,
    })?;

    // Masked to the permission bits: the raw mode carries the file type too, which no
    // message should print as part of an octal mode.
    Ok((metadata.permissions().mode() & 0o7777, metadata.uid()))
}

/// True when the history ends where a conversation may be left: on the model's reply.
///
/// An empty history is not settled. For a turn being appended that is the whole point —
/// a turn that produced no reply at all would otherwise contribute an accounting line
/// and no messages.
fn settled(messages: &[Message]) -> bool {
    messages.last().map(|message| message.role) == Some(Role::Assistant)
}

/// Replay a transcript into the state the next turn starts from.
///
/// The accounting fold is the same operation the turn loop performs in memory —
/// `observed` keeps the last figure anyone reported, `withheld` is whatever the last
/// turn cut — so a resumed session and a continued one carry the same numbers.
fn fold(path: &Path, body: &str) -> Result<(Vec<Message>, Option<Usage>, usize), SessionError> {
    if body.is_empty() {
        return Err(SessionError::MissingHeader {
            path: path.to_owned(),
        });
    }

    let mut messages = Vec::new();
    let mut observed = None;
    let mut withheld = 0;

    for (index, text) in body.lines().enumerate() {
        let record: Record =
            serde_json::from_str(text).map_err(|source| SessionError::Malformed {
                path: path.to_owned(),
                line: index + 1,
                source,
            })?;

        match (index, record) {
            (0, Record::Header(header)) => {
                if header.version != VERSION {
                    return Err(SessionError::UnsupportedVersion {
                        path: path.to_owned(),
                        version: header.version,
                    });
                }
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

    Ok((messages, observed, withheld))
}

/// One line of a transcript.
///
/// Internally tagged, so a message line is the message's own fields plus a `type`, and
/// an unknown `type` fails the parse rather than being skipped.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    Header(Header),
    Message(Message),
    Turn(Accounting),
}

/// What the first line of every transcript says about the rest of it.
#[derive(Debug, Serialize, Deserialize)]
struct Header {
    version: u32,
    id: String,
    created_at_millis: u64,
}

/// What one turn cost, and what it had to leave out.
#[derive(Debug, Serialize, Deserialize)]
struct Accounting {
    observed: Option<Usage>,
    withheld: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Content;

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
