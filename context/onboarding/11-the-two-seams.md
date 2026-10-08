# There are two enforcement seams, and most tools cross only the first

This chapter is the bottom row of View 3's boundary table in
[04 — the architecture](04-the-architecture.md): *the two enforcement seams*. It
is also the fork drawn in View 2, under "Where a tool call actually reaches the
filesystem" — the one that chapter calls the single most important thing to
carry away. Read that fork again before this page, because everything below is
the detail behind its two branches.

The correction a newcomer needs is this. "sandbx uses Landlock" describes one
branch of the fork. Six of the seven built-in tools never take it. For those six
there is no kernel ruleset, no seccomp filter and no namespace, because they
never spawn a process for any of that to apply to — the boundary is a Rust value
checking paths in the harness's own address space. The authority for both seams
is [decision-enforcement-seam.md](../decision-enforcement-seam.md), whose first
line is worth keeping in view: *where policy stops being data and becomes
something the kernel holds*. Across seam 1 it never becomes something the kernel
holds at all.

## Seam 1 — `FsGuard`, in-process

The seven built-ins are a closed enum, `BuiltinTool` in
[`tools/src/lib.rs`](../../crates/sandbx-tools/src/lib.rs) — see `ALL`. Which
side of the fork each takes:

| tool | how it reaches the filesystem |
|---|---|
| `read` | `FsGuard::open_read`, via the crate-private `read_file` |
| `write` | `FsGuard::open_write` |
| `edit` | `read_file`, then `FsGuard::open_write` |
| `ls` | `FsGuard::read_dir` |
| `grep` | `FsGuard::walk_readable`, then `read_file` per file |
| `find` | `FsGuard::walk_readable` |
| `bash` | `SandboxedCommand` — the three processes, Landlock and seccomp |

So `bash` is the one tool the kernel boundary exists for, and
[`fs_guard.rs`](../../crates/sandbx-core/src/fs_guard.rs) is the whole of
enforcement for the other six.

A guard is built from a policy by `FsGuard::new`, and all it does is sort:

```rust
for (axis, granted) in policy.granted_paths() {
    let crate::Grants {
        read,
        write,
        execute: _,
    } = axis.grants();

    if read {
        readable.push(granted.clone());
    }
    if write {
        writable.push(granted.clone());
    }
}
```

Two lists, not three. There is no `executable` list because nothing in-process
`exec`s — but a `ReadExecute` grant still lands in `readable`, because
`Axis::grants` says that axis confers read. Which axis feeds which list is never
decided here; it is read off the one table in
[decision-axis-table.md](../decision-axis-table.md), which
[12 — a flag to a kernel rule](12-a-flag-to-a-kernel-rule.md) picks up.

Six entry points hang off the guard, and the difference between them is the
whole subject of this chapter.

| entry point | hands back | used by |
|---|---|---|
| `open_read` | `std::fs::File`, opened `O_NOFOLLOW` | `read`, `grep` |
| `open_write` | `std::fs::File`, opened `O_NOFOLLOW` | `write`, `edit` |
| `read_dir` | `std::fs::ReadDir` | `ls` |
| `walk_readable` | `ReadableWalk { files, truncated }` | `grep`, `find` |
| `check_read` | a resolved `PathBuf` | nothing |
| `check_write` | a resolved `PathBuf` | nothing |

### Tools hold handles, not paths

The first four rows hand back something already open. That is deliberate and it
is the reason the seam is worth trusting at all: a function that returns a
*path* has to be followed by the caller opening that path, and in the gap
between the check and the open the leaf can be swapped for a symlink pointing
anywhere. The check passed on one object and the open lands on another.

`open_read` and `open_write` close that gap by performing the open themselves,
with `O_NOFOLLOW` set — see `open` in
[`fs_guard.rs`](../../crates/sandbx-core/src/fs_guard.rs). A leaf swapped for a
symlink after the check fails the open with `ELOOP` rather than following it out
of the root. The flag's limit is stated in `open_read`'s own doc comment and
matters later: `O_NOFOLLOW` guards the **final component only**, so a swapped
*parent* needs resolution that walks descriptor by descriptor.

The discipline is centralised rather than repeated. `read_file` in
[`tools/src/lib.rs`](../../crates/sandbx-tools/src/lib.rs) holds the only
`open_read` call in the tools crate, and its comment says why: so no in-process
tool can read a file by forgetting it. `read` and `grep` both go through it;
`edit` goes through it for its read half and `open_write` for its write half,
because read and write are granted independently and an edit on a read-only root
has to fail even though its read half succeeded.

### `ls` is the exception, and the handle buys it nothing

`read_dir` hands back a `ReadDir`, which is a handle — but there is no
`O_NOFOLLOW` form of a directory read, so that handle closes the window no more
than a path would. Its doc comment says exactly that. What `read_dir` *does* buy
is the audit record: the entry point lives in `sandbx-core` because the audit
target is that crate's alone, so the decision is recorded next to where it is
made rather than in the caller.

Its return type is worth a second look, because it is a shape this codebase uses
deliberately:

```rust
pub fn read_dir(&self, path: &Path) -> Result<std::io::Result<std::fs::ReadDir>, SandboxError> {
```

The outer `Result` is the policy's verdict and the inner one is the host's. A
nested `Result` reads as clumsy until you see what collapsing it would cost:
"you may not look there" and "that directory is not there" would become one
error, and `ls.rs` could no longer report them apart — which it does, through
`crate::guard_error` for the outer and `crate::failed` for the inner.

### The root is confirmed, not re-resolved

This is the part most readers get wrong on a first pass, so it is worth slowing
down. A root in `readable` or `writable` is the grant's own `VettedPath`,
carrying the `(dev, ino)` pair it was vetted as. `FsGuard::new` does **no I/O**
at all.

That is not laziness. A granted path resolves to itself, by the invariant
`SandboxPolicy::grant` maintains, so there is nothing left to resolve — and a
second `canonicalize` here would be the same substitution bug one size down.
When the guard did re-resolve each root per access, a granted root replaced by a
symlink had the guard adopt the *link's target* as its root (#212).

So containment is two questions and both must answer yes: is the requested path
lexically inside a root, and does that root still hold the object the grant
carries? The second is measured now, through an `O_PATH` descriptor — see
`confirm` in
[`policy/vetted.rs`](../../crates/sandbx-core/src/policy/vetted.rs):

```rust
pub(crate) fn confirm(&self) -> Confirmation {
    let Ok(opened) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(&self.path)
    else {
        return Confirmation::Unmeasurable;
    };

    match ObjectId::of_fd(&opened) {
        Ok(object) if object == self.object => Confirmation::Vetted,
        Ok(object) => Confirmation::Replaced(object),
        Err(_) => Confirmation::Unmeasurable,
    }
}
```

`O_PATH` is why this is cheap and why it is honest: the open is a lookup rather
than an access, so confirming a root needs no read right on it, and the `fstat`
goes through the descriptor rather than the name, which is the one measurement a
rename cannot step between. A mismatch is the refusal the constant
`ROOT_REPLACED` names — the in-process twin of the helper's `grant_replaced`,
decided here because there is no descriptor to hand on and no second process to
relay it ([decision-grant-identity.md](../decision-grant-identity.md)).

Three details of that measurement are each load-bearing.

- **It is measured once per access and carried into the refusal.** `contains`
  returns `Containment`, whose `Outside` variant carries an
  `Option<Replacement>` — the root whose spelling matched and whose object did
  not, with both object ids in it. The alternative is a `bool` plus a second
  measurement to find out *which* root moved, and two measurements can disagree:
  the disagreeing case emits the wrong refusal for a root that confirms by the
  time it is asked again.
- **A root that cannot be measured at all accuses nothing and grants nothing.**
  `Confirmation::Unmeasurable` has an empty arm in `contains`. A deleted root is
  not a substituted one, so the scan simply continues and the path reads as out
  of bounds rather than as a swap.
- **The scan short-circuits on the first root that is both lexical and
  confirmed.** Grants nest and overlap, and a replaced root must not deny a path
  that some other grant still legitimately covers.

One more subtlety: the lexical half is tested in *two* forms, not one, in
`moved_root`. `Path::starts_with` compares whole components, so
`root/link/../..` names the root while collapsing out of it; and `other/../root`
matches only after collapsing. `collapsed` does that purely lexically and is
explicitly *not* a `canonicalize` — a `..` above a symlink collapses to the
link's parent here and to its target's parent in the kernel, which is why both
forms are tested and neither replaces the spelling.

### A refusal says nothing, except inside a grant

`canonicalize` fails differently for a path that is missing (ENOENT), one whose
parent you cannot read (EACCES), and one that resolves perfectly well somewhere
out of bounds. Handing that difference back to the caller turns the guard into a
filesystem oracle: a loop of refused paths reads back as a map of the host.

The reason this matters more here than in an ordinary library is where the
refusal goes. It travels back to the model inside a `tool_result`. A model
acting on text it read out of a file — prompt injection — is the attacker in
that picture, and probing is free. So **every refusal outside the roots is the
same refusal**, and there is one function that issues it. `deny` in
[`fs_guard.rs`](../../crates/sandbx-core/src/fs_guard.rs) is the single site for
both labels, and its comment gives the rule: present and absent reading apart
would itself be a one-bit oracle.

`permit` shows the ordering that keeps it closed:

```rust
if let Some(moved) = moved_root(requested, roots) {
    return Err(deny(Some(moved), requested, access));
}

// And no reason comes off the resolution: a link planted in a root that *confirms*
// resolves into one that does not, which is the same bit the other way round.
match contains(&resolved, roots) {
    Containment::Inside => Ok(resolved),
    Containment::Outside(_) => Err(deny(None, requested, access)),
}
```

The root is measured *before* the resolution is judged, and the `Outside` arm
discards the `Replacement` it was handed. Both halves are the same idea: a
reason drawn from where a path resolved is a reason the substitute chose.

`conceal_unless_granted` is the one exception, and it has a single rule. Inside
a confirmed root the caller could already enumerate the area, so "no such file"
is honest there and nowhere else — a run gets `SandboxError::NotFound` instead
of a flat refusal, and the audit trail records `absent` rather than `denied`.
Which errnos count as a name denoting nothing is `names_nothing`: ENOENT,
ENOTDIR and ENAMETOOLONG, by errno rather than by `ErrorKind` because the last
has no stable spelling (#180).

Deciding *which* area a path that does not resolve belongs to is `nearest_area`
— the deepest ancestor that does resolve. But that rule alone cannot see the one
case that matters, which is why there is a second test:

```rust
fn reaches_plainly(requested: &Path, ancestor: &Path) -> bool {
    !requested
        .components()
        .any(|part| part == std::path::Component::ParentDir)
        && requested
            .ancestors()
            .take_while(|step| *step != ancestor)
            .all(|step| !step.symlink_metadata().is_ok_and(|at| at.is_symlink()))
}
```

Only the ancestor resolved, so it speaks for the path below it only as far as
the components in between are what they look like. Plant a dangling symlink
inside a granted root and the ENOENT you get back is its *target's* absence —
which answers "does this host path exist?" for any target you like, from inside
the grant, with the honest answer the concealment was meant to allow. A `..`
leaks nothing by itself, since resolution never passed it, but it would name an
out-of-grant path as absent. Both are refused, and the
nearest-resolving-ancestor rule on its own sees neither.

- **Worth questioning:** `check_read` and `check_write` are `pub` on a type
  `sandbx-core` exports, they bound nothing after the measurement, their own doc
  comments say to prefer the opening forms, and no production code in the
  workspace calls either — every call site is in `crates/sandbx-core/tests/`.
  [decision-enforcement-seam.md](../decision-enforcement-seam.md) marks them "no
  tool" in its own seam diagram and [`SECURITY.md`](../../SECURITY.md) carries
  them as a non-claim, so the exposure is known; what neither prices is why the
  pair stays public once the four window-closing forms exist. The repo refuses
  exactly this trade elsewhere, and says so in as many words:
  [decision-default-policy.md](../decision-default-policy.md) keeps
  `vetted_root` and its helpers private with inline tests rather than making a
  seam public so an integration test could drive it, calling that the trade
  [guide-module-layout.md](../guide-module-layout.md) forbids. Here the same
  trade appears to have gone the other way, on the mechanism where losing the
  race is the actual hazard.

## Seam 2 — argv, into the helper

Now the other branch of the fork. When `bash` runs a command, the policy has to
reach a process that does not exist yet and will not share memory with the
harness, because it arrives there by `execve`. It crosses as **argv**, twice:

```
sandbx ──argv──► helper stage 1 (supervisor) ──argv verbatim──► stage 2 ──► apply()
```

The encoding is [`helper_args.rs`](../../crates/sandbx-core/src/helper_args.rs)
— `HelperArgs::encode` on the way out and `HelperArgs::decode` on the way in,
over `HelperArgs { policy, program, args, pin }`. Path grants are three tokens
each:

```rust
const fn path_flag(axis: Axis) -> &'static str {
    match axis {
        Axis::Read => "--ro",
        Axis::Write => "--rw",
        Axis::ReadExecute => "--rx",
    }
}
```

```rust
for (axis, granted) in policy.granted_paths() {
    out.push(path_flag(axis).to_string());
    out.push(granted.path().display().to_string());
    out.push(granted.object().to_string());
}
```

A flag, the path, and the `<dev>:<ino>` the harness vetted it as. The pin is
**mandatory**, not optional, and the comment on `path_flag` says why twice over:
an optional pin makes `decode` guess whether the next token is a pin or the next
flag, and an unpinned grant is a case the helper has no answer for anyway.
`axis_for` is a reverse lookup over `path_flag` rather than a second list of
spellings, so a flag `encode` can emit is one `decode` accepts by construction —
the wire spelling exists in exactly one place.

**Why argv at all, rather than a shared structure?** Because there is no shared
anything: stage 1 and stage 2 are separate `execve`s of the same binary, which
keeps nothing of the caller's memory. The obvious alternative, the environment,
is unavailable for a sharper reason than inconvenience — it is cleared at every
stage (#98) precisely because *the environment is part of what the policy
governs*. Argv is the channel that is left. It is not private: the confined
command can read its own `/proc/self/cmdline`, which is why the rule is that
argv carries variable **names** and never values, and why `--dns-over-tcp` is a
bare flag standing for a constant the policy holds rather than a flag with the
value on it.

**Which side is trusted: neither.** That stance is easier to state than to
believe, so here is what it buys in each direction.

- **The parent does not trust the child.** The helper's own refusals come back
  over an audit channel whose decoder accepts only labels drawn from two closed,
  disjoint sets, with the record count capped and separator characters stripped
  on the way out
  ([decision-helper-audit-channel.md](../decision-helper-audit-channel.md)).
  `root_replaced` is deliberately *not* one of the labels a helper may claim,
  because no helper decides it.
- **The child does not trust the parent.** `decode` refuses rather than infers:
  every failure is a refusal, and an unrecognised flag is an error and never
  skipped, since skipping one means running under a policy sandbx did not
  intend. A path flag with no object pin behind it, or a pin that is not a
  device and an inode parted by `:`, is `SandboxError::BadHelperArgs`. And the
  helper only ever *narrows* — nothing in the argv can widen what the harness
  already decided. Stage 2 does take a supervisor pid as a positional token, but
  that is a liveness check and not an authorization one.
- **Argv is handed on verbatim.** Stage 1 decodes the policy for its own use —
  it has to know whether to unshare the network namespace — and then passes the
  original argv through to stage 2 rather than re-encoding it. A re-encode would
  be a second chance for the policy to drift on its way to the stage that
  enforces it.

One shape worth noticing on the way past, because it is the house style from 04
again: `HelperDispatch` in
[`command/dispatch.rs`](../../crates/sandbx-core/src/command/dispatch.rs) has
two variants, `NotHelperMode` and `Failed`, and **no success arm** — plus
`#[must_use]`. There is no value in the program that can represent "helper mode
ran fine, carry on", so a failed helper run cannot fall through into running the
command unconfined.

## What seam 1 still leaves open

[`SECURITY.md`](../../SECURITY.md) carries this as a non-claim, and the chapter
will not improve on its scoping: **the in-process confirmation is a measurement,
not a resolution.** The guard measures a granted root and then performs the
access beneath it, so a substitution that lands between the two is granted on
the object the confirmation saw. Two swaps are open — the root itself, and a
parent directory a walk reopens by path. The windows differ in width by tool: a
few syscalls for the five per-path tools, and the whole traversal for `find` and
`grep`, whose `walk_readable` confirms its root once and then descends. The
guard's own doc comment names that as the widest window of the six and says why
it is not re-confirmed per directory: doing so would refuse mid-result.

Closing either needs the access to run off a directory descriptor, with
`openat2(dirfd, …, RESOLVE_BENEATH)` for every step below it (#230). The
`FsGuard` TOCTOU row of [guide-sandboxing.md](../guide-sandboxing.md) has the
shapes.

Note what is *not* in that window. A granted directory renamed away and replaced
by another real directory under the same name is refused, by both layers,
because both compare an object and not a name. A granted name that has become a
symlink is a root to neither layer. The open window is narrower and more
specific than "the guard can be raced", and the difference is exactly what the
two documents above are careful about.

- **Worth questioning:** seam 2 cannot be bypassed by accident, because
  `clippy.toml` denies `std::process::Command::new` workspace-wide with
  `disallowed_methods` — a direct spawn is a build failure, and the one exempt
  factory is named in the config. Seam 1 has no equivalent. Nothing stops a
  seventh in-process tool from calling `std::fs::File::open` directly; it would
  compile, pass review that was not looking for it, and leave no trail, since
  the audit record is emitted by the guard it skipped. Today the chokepoint
  holds — `read_file` is the only `open_read` call site in the tools crate, and
  nothing there reaches `std::fs` at all. But that is convention, where
  [04](04-the-architecture.md) names this repo's recurring move as converting
  "did we remember?" into a build failure, and `BuiltinTool`'s closed enum only
  forces a new tool to be *handled* everywhere, not to be handled through the
  guard. The mechanism to close it is already configured and in use one seam
  over.

## You should now be able to explain

- Why "sandbx uses Landlock" is a description of one tool out of seven, and what
  enforces the other six.
- Why `open_read` returning a `File` rather than a `PathBuf` is a security
  property and not an ergonomic one, and what `O_NOFOLLOW` does and does not
  cover.
- Why `ls` gets a handle that buys it nothing, and what `read_dir` does buy.
- Why `FsGuard::new` performs no I/O, and what went wrong when the guard
  re-resolved a root's spelling per access.
- Why the root's object is measured once and carried into the refusal rather
  than measured again to label it.
- Why every refusal outside the roots is the same refusal, where the refusal
  ends up, and the one place a more specific answer is allowed.
- What `reaches_plainly` catches that "the nearest ancestor that resolves"
  cannot see on its own.
- Why the policy crosses into the helper as argv, why that means names and never
  values, and what "neither side is trusted" buys in each direction.
- Which substitution window seam 1 still leaves open, how wide it is for a walk
  versus a single read, and what shape of substitution is *not* in it.
