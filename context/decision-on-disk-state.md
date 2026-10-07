# Decision: what sandbx writes to disk, and who may read it

Two roots, each owned by one crate, each created `0700` with its files `0600`.

| Root | Holds | Owner |
|---|---|---|
| `$XDG_CONFIG_HOME/sandbx/`, else `~/.config/sandbx/` | `credentials.toml` | `sandbx-cli/src/auth/store.rs` |
| `$XDG_STATE_HOME/sandbx/sessions/`, else `~/.local/state/sandbx/sessions/` | `<id>.jsonl`, one per session | `sandbx-session/src/paths.rs` |

Config and state are split because XDG splits them, and the split earns its
keep here: a credential is something you put there, a transcript is something
that accumulates. `~/.local/state` is what the spec reserves for data that
persists between runs and is not worth backing up or sharing between machines.

Neither root is ever resolved against the working directory. A relative
`$XDG_*_HOME` falls back to `$HOME`, `$HOME` must itself be absolute, and
neither being absolute is an error rather than a guess. For the credential that
keeps a key out of whatever tree the agent was pointed at; for a transcript it
is sharper still, because a no-flag `agent-run` grants a tool write over the
working directory — a transcript inside it would be a history the model's own
tools could choose.

## The mode rule differs between the two, deliberately

| Bits | Credential | Transcript |
|---|---|---|
| group/other **write** (`0o022`) | refuse | refuse |
| group/other **read** (`0o044`) | refuse | resume, and say so on stderr |

The asymmetry is recovery. A leaked key can be rotated, so refusing to *use* one
whose mode says it may have leaked is a control that still buys something. A
leaked conversation cannot be rotated: by the time the mode is read the
disclosure has happened, and refusing would only lock an operator out of their
own history over a umask they have already paid for. ssh draws the same line —
it refuses a private key on a shared bit and says nothing about `known_hosts`.

What a resume *can* still prevent is substitution. A transcript another user can
write is a history another user chose, and it is replayed to a model that calls
tools; that is the one novel hazard in session persistence and the read path is
the only place it can be caught. So `sandbx-session` names `WRITABLE_BITS` and
`READABLE_BITS` separately where `auth/store.rs` has a single `SHARED_BITS`. Do not
unify them.

Both paths check the containing directory as well. A directory another user may
write lets them rename their own `0600` file over the target whatever its own
mode says — this is what ssh's `StrictModes` checks a home directory for, and it
is the stronger of the two checks. Every mode is read through an open descriptor
(`File::metadata`, so `fstat`), never by path: checking the mode first and
opening second vets one file and reads another.

A symbolic link defeats that on its own, and the two paths close it differently
because they find the directory differently. The credential path takes the
directory from `canonicalize`, not `Path::parent`, which is lexical: a symlinked
`credentials.toml` would otherwise have the directory holding the *link* vetted
and the one holding the key never looked at. The session store does not derive a
parent at all — it checks its own root — so a link there would leave the right
directory vetted and the wrong file read. It opens the transcript `O_NOFOLLOW`
instead and refuses a link outright, on both the read and the reopen for append.
`O_NOFOLLOW` covers the last component only, so a symlinked state directory, which
an operator may well have, still opens; `$XDG_STATE_HOME` is the supported way to
put the store elsewhere.

The root gets the same treatment, and needs it more: its mode is not only read but
*narrowed*, so following a link there would `fchmod` whatever it points at —
a shared directory, if that is what it is — down to `0700`. It is opened without
`O_DIRECTORY`, deliberately: paired with `O_NOFOLLOW` the kernel reports a
symlinked directory as `ENOTDIR` rather than `ELOOP`, and a root that is a plain
file reports `ENOTDIR` too, so the flag would merge two refusals worth keeping
apart.

Ownership is where the two diverge again: a transcript whose `st_uid` is not the
running uid is refused, an API key file's is not read at all. Reaching a
foreign-owned `credentials.toml` means controlling `$HOME` or
`$XDG_CONFIG_HOME`, by which point the attacker chooses the path and could as
easily own the file; the check would not be the thing standing in the way. It is
not an asymmetry to close by symmetry — the transcript check is there because it
is free, the store's root being derived rather than configurable.

The directory's mode is also not left to `DirBuilderExt::mode`, which is
ignored outright for a directory that already exists — so a root somebody
widened, or that predates the first run, would stay wide for every session
after it. Both crates narrow it with an explicit `fchmod`. The session store
narrows on `create` and *refuses* on `resume`, which is not an inconsistency:
at create time the directory holds nothing a refusal would protect, and at
resume time it holds the transcript about to be replayed to the model.

### What a parse failure is allowed to say

A torn transcript line reports `serde_json`'s own error as its `source`, where
the credential file deliberately drops `toml`'s — `toml` quotes the whole
failing line, which for a malformed `credentials.toml` is the key itself.
`serde_json` quotes at most the one offending token (`Unexpected::Str` formats
as `string "…"`), never the surrounding line, and the reader it reaches is the
owner of the transcript on their own terminal. Dropping it would cost the line
and column that are the only useful thing to say about a torn file.

## The gap the mode check cannot close

A tool running inside your own `agent-run`, granted write over the session root,
rewrites the transcript with your uid and leaves the mode at `0600`. Nothing the
read path can see distinguishes that from you editing it, so the defence is not
here: the CLI refuses the grant instead, for a path reaching the sessions
directory on either run subcommand (#173, `decision-harness-owned-paths.md`).
That leaves the mode check what it can actually answer — a transcript another
user owns or can write — and it stays, because a grant is not the only way one
gets there.

## Why a transcript is a file of lines

Append-only JSONL, one record per line, never rewritten. `withheld` — how many
leading messages a turn left out to fit the context window — is an *index* into
the history (`guide-turn-loop.md`), so it is exact only as long as nothing moves
a prefix. A store that rewrote the whole conversation on every save would
invalidate every figure it had already written.

Three record kinds: a `header` carrying the format version, a `message`, and a
`turn` carrying what the prompt cost and what it cut. The turn record is its own
line rather than a field on the last message because a first round that produced
no content still reports usage — the turn loop returns an empty message list
with a real figure — so there is no message to hang it on.

A declared version with an unknown value is refused rather than read on a best
effort: a reader that silently dropped a field it did not understand would
change the history the model is shown, which is the one thing a transcript
exists to get right. For the same reason an unknown record `type` fails the
parse instead of being skipped, while an unknown *field* is ignored — a line
nobody can classify may be a message, and dropping it would alter the
conversation without saying so.

The one line that may be dropped is an unterminated last one. Every record is
written with its newline, so a file not ending in one stopped mid-write —
`ENOSPC`, usually. Dropping just that line restores the state the file was last
consistent in; refusing it, as the first cut of this did, made one torn append
cost the whole conversation, unresumable until somebody hand-edited it. A line
that parses badly *with* a newline after it was written whole and still refuses.

A transcript must be empty or start on a user message and end on an assistant one,
with no two neighbouring messages sharing a role. All three are checked on the way
in and again on the way out. `append` checks the batch, and the join between it and
what is stored; `resume` checks the whole history, because a hand-edited file can
hold a pair of user turns anywhere and the API rejects an interior pair exactly as
it rejects a trailing one — a session otherwise bricked by a run that exited zero.

The opening role is its own condition, not a corollary of the other two: a history
of even length that opens on the model's reply alternates and ends settled, and the
API still refuses it.

The two guards have to agree, and for a while they did not: `append` checked only
the end, on the reasoning that the end was all it could break. It could also
join its first message onto a stored one of the same role, or carry an interior
pair of its own. The file is append-only, so either one is written and then
refused by every later resume, with nothing to undo it.

A turn carrying *no* messages is neither of those things: it leaves the last role
where it was, so it writes its accounting line and nothing else, which is what
keeps the figure a blockless first round reported. A caller that prepends its own
prompt — `agent-run` does — is refused instead, and re-measures the prompt when
it is sent again.

## `observed` and `withheld` are stored before anything reads them

`agent-run` exposes no context-window budget and `TurnLimits::default()` has
`compaction: None`, so the figures a transcript carries are inert today. They
are written anyway, because they are only recoverable at the moment the turn
produces them: a session resumed without them would start from zero and could
not tell whether its own history already fills the window. The fold that
reloads them is literally the turn loop's own `observed.or(previous)`, which is
what makes a resumed conversation and a continued one carry the same numbers.
Do not delete it as dead weight.
