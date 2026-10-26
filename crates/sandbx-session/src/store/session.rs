//! The store and a session: which files exist, who may read them, and where a write
//! goes.
//!
//! Append-only because `withheld` indexes the history, exact only while nothing moves a
//! prefix, so every operation reads the whole file or writes to its end.

use std::fs::{DirBuilder, File};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::OFlag;
use sandbx_session_message::{CompletedTurn, Message, Usage};

use crate::id::clock_millis;
use crate::{SessionError, SessionId};

use super::record::{Accounting, Header, Record, VERSION, fold};
use super::shape::{alternating, answers_only, follows, opens, resumable};
use super::vet::{
    DIR_OWNER_ONLY, DIR_SHARED_BITS, READABLE_BITS, WRITABLE_BITS, open_at, open_nofollow,
    ownership,
};

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

    /// Where this store keeps its transcripts.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Start a session, creating the root `0700` and the transcript `0600`.
    ///
    /// `O_EXCL` is what makes the id unique: the filesystem, not a prior check,
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
        let directory = self.narrow_root()?;
        let create = OFlag::O_WRONLY | OFlag::O_APPEND | OFlag::O_CREAT | OFlag::O_EXCL;

        for attempt in 0..ATTEMPTS {
            let id = SessionId::from_clock(attempt)?;
            let (name, path) = self.transcript(&id);

            match open_at(&directory, &name, &path, create) {
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
                Err(SessionError::Io { source, .. })
                    if source.kind() == ErrorKind::AlreadyExists =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        Err(SessionError::Collision { attempts: ATTEMPTS })
    }

    /// Reopen a session and read back everything it holds.
    ///
    /// Refuses a transcript or directory somebody else can write or owns, directory first
    /// since writing it lets a rename replace the transcript regardless of its mode. Mode
    /// and uid come from the open descriptor, and the transcript is opened through the
    /// root's, so the file and directory vetted are the ones read.
    pub fn resume(&self, id: &SessionId) -> Result<Session, SessionError> {
        let (name, path) = self.transcript(id);

        // A missing root or transcript is no session by that id, which is what was asked.
        let absent = |error| match error {
            SessionError::Io { source, .. } if source.kind() == ErrorKind::NotFound => {
                SessionError::NotFound { id: id.to_string() }
            }
            other => other,
        };
        let directory = open_nofollow(&self.root).map_err(absent)?;
        let mode = ownership(&directory, &self.root)?;
        if mode & WRITABLE_BITS != 0 {
            return Err(SessionError::DirWritable {
                path: self.root.clone(),
                mode,
            });
        }

        let mut file = open_at(&directory, &name, &path, OFlag::O_RDONLY).map_err(absent)?;
        let mode = ownership(&file, &path)?;
        if mode & WRITABLE_BITS != 0 {
            return Err(SessionError::Writable { path, mode });
        }
        let shared_read = mode & READABLE_BITS != 0;

        let mut body = String::new();
        file.read_to_string(&mut body)
            .map_err(|source| SessionError::Io {
                path: path.clone(),
                source,
            })?;

        let (messages, observed, withheld) = fold(&path, &body)?;
        // The whole history, not just its end: a hand-edited file can hold an illegal pair
        // of user turns anywhere, or open on the model's reply.
        if !messages.is_empty() {
            if !resumable(&messages) {
                return Err(SessionError::Unresumable { path: path.clone() });
            }
            if !alternating(&messages) || !opens(&messages) {
                return Err(SessionError::Disordered { path: path.clone() });
            }
        }

        let file = open_at(&directory, &name, &path, OFlag::O_WRONLY | OFlag::O_APPEND)?;

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
    /// `sessions/` would stay wide. Narrowed, not refused: nothing is in it yet. Returns the
    /// vetted descriptor, for the transcript to be created through.
    fn narrow_root(&self) -> Result<File, SessionError> {
        let directory = open_nofollow(&self.root)?;
        let mode = ownership(&directory, &self.root)?;
        if mode & DIR_SHARED_BITS == 0 {
            return Ok(directory);
        }

        // `fchmod` on the descriptor just stat'd, not `chmod` by path, so the directory
        // narrowed is the one vetted.
        directory
            .set_permissions(std::fs::Permissions::from_mode(DIR_OWNER_ONLY))
            .map_err(|source| SessionError::Io {
                path: self.root.clone(),
                source,
            })?;
        Ok(directory)
    }

    /// The transcript an id names, in the root and as a path. No check of its own: a
    /// [`SessionId`] cannot exist without having passed its own parser.
    fn transcript(&self, id: &SessionId) -> (String, PathBuf) {
        let name = format!("{id}.jsonl");
        let path = self.root.join(&name);
        (name, path)
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

    /// True when the conversation breaks off on tool calls the model never answered,
    /// which is a turn that ran out of rounds (#188).
    #[must_use]
    pub fn pending_call(&self) -> bool {
        self.messages.last().is_some_and(answers_only)
    }

    /// True when somebody else can read the transcript, which resumed anyway: by the
    /// time it is known the conversation has been readable, and it cannot be rotated.
    #[must_use]
    pub fn shared_read(&self) -> bool {
        self.shared_read
    }

    /// Add a finished turn to the end of the transcript.
    ///
    /// Refuses a turn ending on an unanswered user message; an empty turn still writes
    /// its accounting line, leaving the last role unchanged.
    ///
    /// Checks both of [`SessionStore::resume`]'s conditions — within the batch and against
    /// what is already stored — since the file is append-only: a disordered write can't be
    /// undone, and every later resume would refuse it.
    pub fn append(&mut self, turn: CompletedTurn<'_>) -> Result<(), SessionError> {
        if !turn.messages.is_empty() {
            if !resumable(turn.messages) {
                return Err(SessionError::IncompleteTurn);
            }
            if !alternating(turn.messages) || !follows(&self.messages, turn.messages) {
                return Err(SessionError::DisorderedTurn);
            }
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
        let mut lines = Vec::new();
        for record in records {
            // Mapped to `Io`, not its own variant: nothing a record holds can fail to serialize.
            serde_json::to_writer(&mut lines, record).map_err(|error| SessionError::Io {
                path: self.path.clone(),
                source: std::io::Error::other(error),
            })?;
            lines.push(b'\n');
        }

        self.file
            .write_all(&lines)
            .map_err(|source| SessionError::Io {
                path: self.path.clone(),
                source,
            })
    }
}
