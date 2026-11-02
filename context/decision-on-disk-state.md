# Decision: what sandbx writes to disk, and who may read it

Two roots, each owned by one crate, each created `0700` with its files `0600`.

| Root | Holds | Owner |
|---|---|---|
| `$XDG_CONFIG_HOME/sandbx/`, else `~/.config/sandbx/` | `credentials.toml` | `sandbx-auth/src/store.rs` |
| `$XDG_STATE_HOME/sandbx/sessions/`, else `~/.local/state/sandbx/sessions/` | `<id>.jsonl`, one per session | `sandbx-session-paths/src/lib.rs` |

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
| group/other **execute** (`0o011`) | refuse | untested |

The asymmetry is recovery. A leaked key can be rotated, so refusing to *use* one
whose mode says it may have leaked is a control that still buys something. A
leaked conversation cannot be rotated: by the time the mode is read the
disclosure has happened, and refusing would only lock an operator out of their
own history over a umask they have already paid for. ssh draws the same line —
it refuses a private key on a shared bit and says nothing about `known_hosts`.

What a resume *can* still prevent is substitution. A transcript another user can
write is a history another user chose, and it is replayed to a model that calls
tools; that is the one novel hazard in session persistence and the read path is
the only place it can be caught. So `sandbx-session-store` names `WRITABLE_BITS`
and `READABLE_BITS` separately where `sandbx-auth`'s `store.rs` has a single
`SHARED_BITS`. Do not unify them.

That single `SHARED_BITS` is the whole of `0o077`, read off `credentials.toml` and
off its canonicalised parent, so group/other execute alone refuses a load. The two
session halves cover `0o022` and `0o044` and leave `0o011` out: `create` sheds it
from the root (`DIR_SHARED_BITS`) and no resume reads it.

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
instead and refuses a link outright, on the create, the read and the reopen for
append alike. Each of those is an `openat` on the descriptor the root was vetted
through, never the path again, so a rename of `sessions/` or an ancestor after the
check cannot leave one directory vetted and another read (#317).
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
running uid, real and effective alike, is refused, an API key file's is not read
at all. Under a setuid launch the two differ, so the store refuses everything
there rather than admit either one's files to the other. Reaching a foreign-owned
`credentials.toml` means controlling `$HOME` or `$XDG_CONFIG_HOME`, by which point
the attacker chooses the path and could as easily own the file; the check would
not be the thing standing in the way. It is not an asymmetry to close by symmetry
— the transcript check is there because it is free, the store's root being derived
rather than configurable.

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
directory on either run subcommand (#173, `decision-policy.md`).
That leaves the mode check what it can actually answer — a transcript another
user owns or can write — and it stays, because a grant is not the only way one
gets there.

## The transcript format

The line format and which orders of messages a transcript may hold are
`sandbx-session-store`'s: its `record.rs` and `shape.rs` say why the file is
append-only, what a reader refuses, why a torn last line is dropped, and why a
user turn of nothing but tool results may end one (#188).

The one rule that spans crates: a pair of user turns is legal on disk only
because `sandbx-session-bridge`'s `merge_user_runs` collapses it into the one
message the API takes, results first, before it reaches the wire. That merge is
the one thing `agent-run` does to its history that moves a prefix's indices, and
`withheld` is an index, so `Merged` carries both spaces: the floor goes in
translated, and the figure the turn reports comes back out through
`Merged::unmerged` before it is stored. `sandbx-compact`'s `//!` has why that
figure's exactness is load-bearing.
