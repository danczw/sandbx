//! The store and a session: which files exist, who may read them, and where a write
//! goes.
//!
//! Append-only because `withheld` indexes the history, exact only while nothing moves a
//! prefix, so every operation reads the whole file or writes to its end.

mod record;
mod vet;

use std::ffi::OsString;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use record::{Accounting, Header, Record, VERSION, fold};
use vet::{
    DIR_OWNER_ONLY, DIR_SHARED_BITS, OWNER_ONLY, READABLE_BITS, WRITABLE_BITS, open_root,
    open_transcript, ownership, reopen_for_append,
};

use crate::id::clock_millis;
use crate::{CompletedTurn, Message, Role, SessionError, SessionId, Usage, sessions_directory};

/// How many ids to try before concluding the clock is stuck, two sessions starting in
/// the same millisecond being ordinary.
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

    /// Start a session, creating the root `0700` and the transcript `0600`.
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
        self.narrow_root()?;

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
    /// Refuses a transcript, or its directory, somebody else can write or owns. The
    /// directory goes first, since writing it allows a rename over the transcript
    /// whatever its mode. Every mode and uid is read through an open descriptor, so the
    /// file vetted is the file read.
    pub fn resume(&self, id: &SessionId) -> Result<Session, SessionError> {
        let path = self.path_for(id);
        let owner = nix::unistd::getuid().as_raw();

        // No root at all means no session by that id: what was asked about.
        let directory = match open_root(&self.root) {
            Err(SessionError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => {
                return Err(SessionError::NotFound { id: id.clone() });
            }
            other => other?,
        };
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

        let mut file = open_transcript(&path, id)?;
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
        // The whole history, not just its end: a hand-edited file can hold a pair of user
        // turns anywhere. No messages at all is a session not yet talked to.
        if !messages.is_empty() {
            if !settled(&messages) {
                return Err(SessionError::IncompleteTurn);
            }
            if !alternating(&messages) {
                return Err(SessionError::Disordered { path: path.clone() });
            }
        }

        let file = reopen_for_append(&path)?;

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

    /// Bring the root down to `0700`, refusing one somebody else owns.
    ///
    /// `DirBuilderExt::mode` is ignored for a directory that already exists, so a widened
    /// `sessions/` would stay wide. Narrowed, not refused: nothing is in it yet.
    fn narrow_root(&self) -> Result<(), SessionError> {
        let directory = open_root(&self.root)?;
        let (mode, uid) = ownership(&directory, &self.root)?;

        if uid != nix::unistd::getuid().as_raw() {
            return Err(SessionError::ForeignOwner {
                path: self.root.clone(),
                uid,
            });
        }
        if mode & DIR_SHARED_BITS == 0 {
            return Ok(());
        }

        // `fchmod` on the descriptor just stat'd, not `chmod` by path, so the directory
        // narrowed is the one vetted.
        directory
            .set_permissions(std::fs::Permissions::from_mode(DIR_OWNER_ONLY))
            .map_err(|source| SessionError::Io {
                path: self.root.clone(),
                source,
            })
    }

    /// The transcript an id names. No check of its own: a [`SessionId`] cannot exist
    /// without having passed its own parser.
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

    /// True when somebody else can read the transcript, which resumed anyway: by the
    /// time it is known the conversation has been readable, and it cannot be rotated.
    #[must_use]
    pub fn shared_read(&self) -> bool {
        self.shared_read
    }

    /// Add a finished turn to the end of the transcript.
    ///
    /// Refuses a turn not ending on an assistant message, since the next resume would
    /// send two user turns in a row. A turn with no messages leaves the last role where
    /// it was, so it writes its accounting line and nothing else.
    pub fn append(&mut self, turn: CompletedTurn<'_>) -> Result<(), SessionError> {
        if !turn.messages.is_empty() && !settled(turn.messages) {
            return Err(SessionError::IncompleteTurn);
        }

        let mut records: Vec<Record> = turn
            .messages
            .iter()
            .map(|message| Record::Message(message.clone()))
            .collect();
        // Its own record, never folded onto a message line: a round that produced no
        // content still reports what the prompt cost and has no message to hang it on.
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

    /// Append records as lines, in one write, so a torn write lands at the end of the
    /// file, where [`fold`] can drop the partial line rather than refuse the transcript.
    fn write(&mut self, records: &[Record]) -> Result<(), SessionError> {
        let mut lines = String::new();
        for record in records {
            // An I/O failure, not a variant of its own: nothing a record holds can fail
            // to serialize, so there is no case for a caller to act on.
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

/// True when no two neighbouring messages carry the same role, which together with
/// [`settled`] also pins the first message as the user's.
fn alternating(messages: &[Message]) -> bool {
    messages.windows(2).all(|pair| pair[0].role != pair[1].role)
}

/// True when the history ends where a conversation may be left: on the model's reply.
/// An empty history is not settled, which refuses a prompt with no answer behind it.
fn settled(messages: &[Message]) -> bool {
    messages.last().map(|message| message.role) == Some(Role::Assistant)
}
