//! The store and a session: which files exist, who may read them, and where a write
//! goes.
//!
//! Append-only, and not for tidiness: `withheld` is an index into the history, exact
//! only while nothing moves a prefix. So every operation here reads the whole file or
//! writes to its end.

mod record;

use std::ffi::OsString;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use record::{Accounting, Header, Record, VERSION, fold};

use crate::id::clock_millis;
use crate::{CompletedTurn, Message, Role, SessionError, SessionId, Usage, sessions_directory};

/// The mode a transcript is created with.
const OWNER_ONLY: u32 = 0o600;

/// The mode the directory holding them is created with.
const DIR_OWNER_ONLY: u32 = 0o700;

/// The bits that let somebody else write, which refuse a resume.
///
/// Kept apart from [`READABLE_BITS`] rather than sharing `auth/store.rs`'s single
/// `SHARED_BITS`: a leaked credential rotates and a conversation does not, so only the
/// write bits are worth refusing over — see `context/decision-on-disk-state.md`.
const WRITABLE_BITS: u32 = 0o022;

/// The bits that let somebody else read, which resume and report.
const READABLE_BITS: u32 = 0o044;

/// Every bit outside the owner's, which the root is narrowed to shed.
///
/// Wider than [`WRITABLE_BITS`]: a transcript's name is clock-derived and so guessable,
/// and group/other execute alone lets somebody else traverse to one.
const DIR_SHARED_BITS: u32 = 0o077;

/// How many ids to try before concluding the clock is stuck.
///
/// Two sessions starting in the same millisecond is ordinary, so a taken id retries.
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
    /// Refuses a transcript, or the directory holding it, that somebody else can write or
    /// owns. The directory goes first: one another user may write lets them rename their
    /// own `0600` file over the transcript, whatever mode it carries. Every mode and uid
    /// is read through an open descriptor, so the file vetted is the file read.
    pub fn resume(&self, id: &SessionId) -> Result<Session, SessionError> {
        let path = self.path_for(id);
        let owner = nix::unistd::getuid().as_raw();

        // No root at all means no session by that id: the operator asked about a session,
        // not about a directory.
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
        // The whole history, not just its end: an append can only break the last role,
        // but a hand-edited file can hold a pair of user turns anywhere, which the API
        // refuses the same way. No messages at all is a session not yet talked to.
        if !messages.is_empty() {
            if !settled(&messages) {
                return Err(SessionError::IncompleteTurn);
            }
            if !alternating(&messages) {
                return Err(SessionError::Disordered { path: path.clone() });
            }
        }

        // `O_NOFOLLOW` again, not just on the read: a link planted between the two opens
        // would make the appended-to file a different one than the vetted descriptor.
        let file = OpenOptions::new()
            .append(true)
            .custom_flags(no_follow())
            .open(&path)
            .map_err(|source| opening(&path, source))?;

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
    /// `DirBuilderExt::mode` is ignored outright for a directory that already exists, so
    /// a `sessions/` somebody widened would otherwise stay wide for every session after
    /// it. Narrowed here and refused by [`resume`](Self::resume): nothing is in the
    /// directory yet that a refusal would protect.
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

        // `fchmod` on the descriptor just stat'd, not `chmod` by path, for the reason
        // every mode here is read that way.
        directory
            .set_permissions(std::fs::Permissions::from_mode(DIR_OWNER_ONLY))
            .map_err(|source| SessionError::Io {
                path: self.root.clone(),
                source,
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
    /// Reported rather than refused: by the time it is known the conversation has already
    /// been readable, and a transcript does not rotate the way a credential does.
    #[must_use]
    pub fn shared_read(&self) -> bool {
        self.shared_read
    }

    /// Add a finished turn to the end of the transcript.
    ///
    /// Refuses a turn not ending on an assistant message: the next resume would send two
    /// user turns in a row. A turn with no messages leaves the last role where it was, so
    /// it writes its accounting line and nothing else.
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
        // content still reports what the prompt cost, and has no message to hang it on.
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

/// `O_NOFOLLOW`, so the leaf of a path this store vets is never a symbolic link.
///
/// The last component only, so a symlinked ancestor still opens — `~/.local/state` is an
/// operator's business.
fn no_follow() -> i32 {
    nix::fcntl::OFlag::O_NOFOLLOW.bits()
}

/// Translate an open failure, naming a link that [`no_follow`] refused.
///
/// By errno and not `ErrorKind::FilesystemLoop`, which is unstable. `ELOOP` from these
/// opens can only be the leaf, every component above it having been followed normally.
fn opening(path: &Path, source: std::io::Error) -> SessionError {
    if source.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32) {
        return SessionError::Symlink {
            path: path.to_owned(),
        };
    }

    SessionError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Open the directory holding transcripts, refusing one that is a symbolic link.
///
/// [`narrow_root`](SessionStore::narrow_root) `fchmod`s this descriptor, so following a
/// link would narrow a directory outside the store.
///
/// No `O_DIRECTORY`: paired with `O_NOFOLLOW` the kernel reports a symlinked directory as
/// `ENOTDIR`, which a root that is a plain file reports too, and the two are worth
/// telling apart.
fn open_root(root: &Path) -> Result<File, SessionError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(no_follow())
        .open(root)
        .map_err(|source| opening(root, source))
}

/// Open a transcript, refusing one that is a symbolic link.
///
/// A link makes the descriptor a different file than the path vetted: the mode and owner
/// would come from the target, the vetted directory from where the link sits.
fn open_transcript(path: &Path, id: &SessionId) -> Result<File, SessionError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(no_follow())
        .open(path)
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                return SessionError::NotFound { id: id.clone() };
            }

            opening(path, source)
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

/// True when no two neighbouring messages carry the same role.
///
/// With two roles that is alternation, which together with [`settled`] also pins the first
/// message as the user's: an alternating history ending on the model begins on them.
fn alternating(messages: &[Message]) -> bool {
    messages.windows(2).all(|pair| pair[0].role != pair[1].role)
}

/// True when the history ends where a conversation may be left: on the model's reply.
///
/// An empty history is not settled, which is what refuses a prompt with no answer behind
/// it. A message-*less* turn is screened out before this is reached.
fn settled(messages: &[Message]) -> bool {
    messages.last().map(|message| message.role) == Some(Role::Assistant)
}
