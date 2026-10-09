# One flag, traced to the rule the kernel holds

This chapter walks View 2 of [04 — the architecture](04-the-architecture.md) —
"one request, end to end" — down the right-hand branch of its fork, the one
where a tool spawns a process. It crosses both seams named in View 3's boundary
table and both process boundaries drawn in View 1, so it is worth having that
three-process diagram beside you.

[11 — the two seams](11-the-two-seams.md) described the two conversions in the
abstract. This one takes a single flag and follows it the whole way:

```sh
sandbx sandbox-run --allow-read /tmp/x -- cat /tmp/x/notes
```

Everything below is one trace of `--allow-read /tmp/x`. Five stages, each of
which changes the *shape* of the grant, and three of which can refuse the run
outright.

```
--allow-read /tmp/x                       argv, as typed
   │ clap
   ▼
Grants { allow_read: vec!["/tmp/x"] }     one Vec<PathBuf> per path axis
   │ absolute          ──► PathBuf, joined to the cwd if it was relative
   │ resolved          ──► ResolvedPath, deepest resolvable ancestor replaced
   │ bound_by_resolver ──► bool, noted now and refused with the DNS flags
   │ reaches_owned     ──► Option<&OwnedPath>; Some is a refusal
   │ pinned            ──► VettedPath, the only answer that is kept
   ▼
SandboxPolicy { readable: [VettedPath], … }    no I/O here at all
   │ HelperArgs::encode
   ▼
--ro /tmp/x <dev>:<ino>                   argv again, three tokens
   │ stage 1 decodes for its own use, then passes argv verbatim
   ▼
stage 2: HelperArgs::decode ──► SandboxPolicy  rebuilt with no I/O
   │ requested ──► fs_rules ──► rights_for
   ▼
(Axis::Read, RuleTarget::Granted(&VettedPath), BitFlags<AccessFs>)
   │ open_grant: PathFd, read back, pin confirmed
   ▼
PathBeneath::new(fd, rights) ──► restrict_self ──► enforcement_verdict
```

## Stage 1 — the flag

`--allow-read` is clap, and nothing more:

```rust
#[arg(long = "allow-read", value_name = "PATH")]
allow_read: Vec<PathBuf>,
```

That is in [`grants.rs`](../../crates/sandbx-cli/src/grants.rs), on the `Grants`
struct — the one flattened into every subcommand that confines something, so
`sandbox-run` and `agent-run` cannot disagree about what a flag means. The field
is a `Vec`, because the flag repeats; the doc comment above it *is* the `--help`
text, and it is where the replacement rule is told to the operator.

Three path axes mean three such fields, and the code never touches them by name.
`Grants::paths(axis)` is an exhaustive match from `Axis` to the matching `Vec`,
and the loop that follows runs over `Axis::ALL`. That is the compile-time gate
pattern from 04 applied to argv: a fourth path axis is a build failure here
rather than a flag silently parsed and never granted.

## Stage 2 — the vetting chain, in call order

Five functions turn the typed path into something a policy will accept. They all
live in [`grants/root.rs`](../../crates/sandbx-cli/src/grants/root.rs), all
`pub(super)`, and the first thing to know about them is that **the order they
appear in the file is not the order they run.** Trace the chain in
`Grants::policy`, not the module:

| # | function | takes | gives back |
|---|---|---|---|
| 1 | `absolute` | the path as typed, plus a `cwd` closure | `Result<PathBuf, PolicyError>` |
| 2 | `resolved` | that absolute path | `ResolvedPath`, total — never fails |
| 3 | `bound_by_resolver` | both spellings | `bool`, noted for later |
| 4 | `reaches_owned` | a `ResolvedPath`, plus the owned paths | `Option<&OwnedPath>` |
| 5 | `pinned` | a `ResolvedPath`, plus the typed path | `Result<VettedPath, PolicyError>` |

**`absolute` joins a relative flag to the working directory** — this process's,
while it is still the one that knows it. The grant crosses the argv seam in this
form, so what it names must not depend on where the helper happens to stand
(#205). `resolved` cannot stand in for this step: its walk bottoms out at the
empty path, which would leave a relative grant relative. A working directory
that cannot be read refuses the grant rather than standing in as nothing, which
would match no owned path at stage 4 (#203).

**`resolved` replaces the deepest resolvable ancestor with what it resolves
to,** then re-joins whatever was left. Not a `canonicalize`, which needs every
component to exist: a credential nobody has stored yet does not exist, and
comparing canonical forms alone would miss the host where `/home` is a symlink
to `/var/home`. The function is total — a path that resolves nowhere comes back
unchanged — which is what lets stages 3 and 4 be plain predicates.

**And it is the only way to hold a `ResolvedPath`**, which is what stages 4 and
5 take. The type is a one-field wrapper over a `PathBuf` with a `path()`
accessor, no `Deref` and a private field, so the one producer in the module is
the only road in. What that buys has its own section below, where the
requirement it replaced is traced.

**`bound_by_resolver` asks whether the flag names a file sandbx's own bounded
resolver will bind-mount over.** It tests both spellings on purpose: the
resolved form catches a flag spelled relative or through a symlink, the typed
form catches one that cannot be canonicalized at all. The answer is *noted* here
and refused further down, alongside the DNS flags, so that an operator with no
egress at all hears the more fundamental thing first.

**`reaches_owned` is the next place the run can be refused** — `absolute`
already can, over an unreadable working directory, where this refusal is over
the grant itself. It is the subject
of [decision-harness-owned-paths.md](../decision-harness-owned-paths.md) and the
later section of this chapter; for now, note that it answers in `Option` and
that `Grants::policy` turns `Some` into `PolicyError::GrantReachesOwned` naming
the path **as typed**, so the operator can go and change the thing they wrote.

**`pinned` is the step that measures an object**, and the only one. Not the only
one that reads the filesystem: `resolved` canonicalizes, `reaches_owned` calls
`resolved` on each owned path, and `bound_by_resolver` canonicalizes the
resolver files it compares against. What is `pinned`'s alone is that its answer
*outlives the function*: it returns the grant itself, both halves of it, while
everything the other three learned is spent on one comparison and dropped — the
resolved spelling included, since the path the policy ends up holding is the one
`vet` canonicalized and not the one `resolved` built.

```rust
pub(super) fn pinned(granted: &ResolvedPath, typed: &Path) -> Result<VettedPath, PolicyError> {
    let granted = granted.path();

    let vetted = VettedPath::vet(granted).map_err(|source| PolicyError::UnpinnableGrant {
        granted: typed.to_path_buf(),
        source,
    })?;

    if vetted.path() != granted {
        return Err(PolicyError::GrantMovedWhileVetting {
            granted: typed.to_path_buf(),
            checked: granted.to_path_buf(),
            vetted: vetted.path().to_path_buf(),
        });
    }

    Ok(vetted)
}
```

`VettedPath::vet` canonicalizes and then `stat`s, and it is the only producer of
a `VettedPath` that performs any I/O at all. The comparison after it is the part
worth sitting with. `granted` arrived `resolved` — the parameter type says so,
not a comment — and `vet` resolves again, so if a component was swapped for a
symlink in between, the two spellings differ.
Every refusal above ran against the first spelling, and the policy would hold
the second: a path no check here ever saw, pinned to whatever object is at it.
That is `GrantMovedWhileVetting`, and it is a refusal rather than a re-run of
the checks.

The shape the chain produces:

```rust
pub struct VettedPath {
    path: PathBuf,
    object: ObjectId,
}
```

Both fields private, with `path()` and `object()` to read them, and exactly two
functions in the workspace construct one. The public producer is the one that
does the work:

```rust
    pub fn vet(path: impl AsRef<Path>) -> Result<Self, SandboxError> {
        // … canonicalize, then `ObjectId::of_path` on the result …
```

That signature is the mechanism that makes the ordering above unskippable, and
it is worth reading for what it *omits*. There is no `VettedPath::new`, no
constructor taking a path and an object side by side, no `pub` field and no
`Default`, so nothing outside
[`vetted.rs`](../../crates/sandbx-core/src/policy/vetted.rs) can write a grant
into existence — `policy.grant(Axis::Read, PathBuf::from("/tmp/x"))` does not
compile, and neither does assembling one from a path plus a `(dev, ino)` an
embedder measured themselves. The second producer, `from_wire`, skips the I/O
and is `pub(crate)`: the helper's route in is not an embedder's. `ObjectId` is a
`dev` and an `ino`, "compared and never interpreted" as its own doc comment puts
it.

### The module boundary is itself worth a look

`grants.rs` was split (#250) into the flag surface and
[`grants/root.rs`](../../crates/sandbx-cli/src/grants/root.rs), which owns root
derivation and path vetting; behaviour did not change. What changed is a
*visibility*. The five functions above are `pub(super)` — visible to `grants.rs`
and nothing else — while `vetted_root`, `named_homes`, the `Homes` type and the
`$HOME` predicates are private to `root.rs`, with their tests inline beside
them.

That is this repo narrowing a surface rather than widening one, and it is the
trade [guide-module-layout.md](../guide-module-layout.md) asks for.
[decision-default-policy.md](../decision-default-policy.md) states the
counterfactual in as many words: making that seam public so an integration test
could drive the refusals is the trade the guide forbids. A reader coming from a
codebase where "make it `pub` so the test can reach it" is routine should notice
that the tests moved to the code instead.

## Stage 3 — into the policy

```rust
let granted = pinned(&granted, path)?;
policy = policy.grant(axis, granted.clone());

// Beyond the flag's own axis: an unreadable rewrite target is a trap. Keyed to
// what the axis confers, not `Write`, so a later write-conferring axis inherits it.
if axis.grants().write {
    policy = policy.grant(Axis::Read, granted);
}
```

`SandboxPolicy::grant` in [`policy.rs`](../../crates/sandbx-core/src/policy.rs)
is the one place a path enters a policy, and its signature is the one a caller
writes against:

```rust
    pub fn grant(mut self, axis: Axis, path: VettedPath) -> Self {
        // … push onto the `Vec` for `axis` …
```

Two properties of it carry the whole design.

- **It takes a `VettedPath` and not a `Path`.** There is no construction path
  that reaches a policy holding an unpinned grant, which means the helper has no
  unpinned case to have a policy about. An unpinned grant is a compile error
  rather than a run that would not start.
- **It performs no I/O.** That reads as an optimisation and is not one: *the
  helper decodes a policy through this same function*. Resolving or `stat`ing
  here would measure whatever the links point at by the time the helper runs —
  which is the process a grant is meant to be safe from.

That second point is the invariant the whole chapter rests on, and it is why the
chain above had to finish before `grant` was called: **a granted path resolves
to itself.** Every later consumer may rely on it, and [11](11-the-two-seams.md)
showed one that does — `FsGuard::new` resolves nothing, because there is nothing
left to resolve.

The `if axis.grants().write` arm is the CLI's one documented departure from the
axis table: `--allow-write` grants `Read` as well, because a tool that can
rewrite a tree it cannot read back is a trap rather than a safeguard. Keyed to
what the axis *confers* rather than to the `Write` variant, and the narrow
write-only form stays reachable through `SandboxPolicy::allow_write` for an
embedder who wants a drop directory (#49).
[decision-axis-table.md](../decision-axis-table.md) records it under "The CLI
departs from the table, once".

For our trace, `Axis::Read` confers read alone, so one grant goes in and the
policy now holds:

```rust
SandboxPolicy { readable: vec![VettedPath { path: "/tmp/x", object }], … }
```

## Stage 4 — across the argv seam

`SandboxedCommand::command_line` in
[`command.rs`](../../crates/sandbx-core/src/command.rs) is where the policy
becomes argv, and only the last of the three things it does is rendering. First
it asks two questions of the policy as a whole — `unbounded_resolution` and
`grant_bound_by_resolver` — and refuses before a single token is written.
[18](18-crate-core.md) owns that pair; what matters to the trace is that they
are asked *here*, in the core crate rather than in the CLI, so an embedder who
takes this argv and spawns it themselves meets the refusals too — and that
`/tmp/x` survives one further check after `Grants::policy` blessed it. Then it
names the helper — `/proc/self/exe`, left unresolved, which is why the argv
below begins with that spelling, and [08](08-the-two-stage-helper.md) has why it
is not resolved. Only then does it write `HELPER_FLAG` and `AUDIT_STDIN_FLAG` —
ahead of the policy, because `dispatch_helper_mode` splits the first off and
`exec_sandboxed` the second, both before `decode` sees a token — and then
everything `HelperArgs::encode` emits. Our one grant becomes three tokens:

```
--ro /tmp/x <dev>:<ino>
```

`--ro` comes from the single `path_flag(axis)` match that
[11](11-the-two-seams.md) quoted. The pair is written decimal, `dev` then `ino`,
by `ObjectId`'s `Display`. It is deliberately host-specific and deliberately
unstable: neither half survives a remount, and that is the property that makes
the pair worth carrying rather than a defect in it — an object that moved is not
the one that was vetted, whatever it is now called.

Those three tokens are not the whole of what crosses, and the argv is worth
seeing in full once, because it is the only place the policy exists as a flat
list of bytes. Read off `/proc/<pid>/cmdline` of the stage-1 helper during
`sandbx sandbox-run --allow-read /tmp/x -- sleep 4` — this chapter's command,
with a program that stays alive long enough to look at — from a debug build of
`sandbx-cli` on a merged-`/usr` host. The line breaks are this page's; the real
thing is one NUL-parted token after another:

```console
$ tr '\0' ' ' < /proc/<stage-1-pid>/cmdline
/proc/self/exe --sandbx-core-exec --sandbx-audit-stdin
--ro /tmp/x 2096:1267999
--rx /usr 2096:73730 --rx /usr/bin 2096:1427
--rx /usr/lib 2096:2239 --rx /usr/lib64 2096:14481
--env PATH --env HOME --env TERM --env LANG
--env LC_ALL --env LC_CTYPE --env TZ
-- sleep 4
```

Three things fall out of reading it. The read grant comes **first**, because
`encode` walks `granted_paths`, which iterates `Axis::ALL` — and that is the
order `fs_rules` will build rules in at stage 5. The four `--rx` entries are
`allow_system_executables`, vetted and pinned by the very same `VettedPath::vet`
a typed flag reaches, which is why `/bin`, `/lib` and `/lib64` arrive spelled
`/usr/bin`, `/usr/lib` and `/usr/lib64` on this host: a grant has to name what
it opens. And every `--env` token is a *name*, with no value anywhere on the
line — the confined command reads its own `/proc/self/cmdline`, so a value here
would be a disclosure to the process the policy is about.

One thing the argv deliberately does not carry is where the command starts.
`output` chdirs to the policy's `working_root` — [18](18-crate-core.md) has the
rule it picks by — as it builds the helper command, so our `cat` begins in
`/tmp/x`. An embedder spawning `command_line`'s argv by hand inherits their own
directory instead, which that method's doc comment states as an obligation
rather than leaving to be discovered.

On the far side, `HelperArgs::decode` rebuilds a `SandboxPolicy` from those
tokens, and the producer it uses is `VettedPath::from_wire` — crate-private,
with **no I/O at all**. The helper does not re-resolve and does not re-`stat`;
it carries the harness's answer forward and checks it later, once, against a
descriptor. Two producers, one with I/O in the harness and one without in the
helper, is the shape [decision-grant-identity.md](../decision-grant-identity.md)
exists to explain.

Stage 1 of the helper decodes the policy for its own purposes — it has to know
whether to unshare the network namespace — and then hands the **original argv**
through to stage 2 rather than re-encoding it. A re-encode would be a second
chance for the policy to drift on its way to the stage that enforces it.

## Stage 5 — out as a rule the kernel holds

Stage 2 of the helper calls `apply` in
[`helper/mod.rs`](../../crates/sandbx-core/src/helper/mod.rs). The order there
is load-bearing from the first line, and
[guide-sandboxing.md](../guide-sandboxing.md) is its authority; what concerns
our grant is `requested`, then one loop.

`requested` negotiates the ABI internally and hands back a
`Requested { handled, rules, net }`. Keeping the negotiation inside it is the
point: no ABI value is in scope in `apply`, so the handled set cannot come from
a different one than the rules. The rules themselves come from `fs_rules` in
[`ruleset/rights.rs`](../../crates/sandbx-core/src/helper/ruleset/rights.rs),
one tuple per grant, in `granted_paths` order:

```rust
(crate::Axis, RuleTarget<'_>, landlock::BitFlags<landlock::AccessFs>)
```

`RuleTarget` has two variants, `Granted(&VettedPath)` and
`Installed(&'static Path)` — a path the operator granted, versus one this
process bind-mounted a moment ago for the bounded resolver. They get the same
kind of rule and differ only in what can be confirmed about them.

The rights come from `rights_for(axis, target_is_dir, abi)`, derived from
`Axis::grants` so a new axis needs no edit there, and each primitive is a
**subtraction** rather than a set written out:

- read is `from_read(abi)` minus `Execute`, because `from_read` bundles
  `Execute` in with `ReadFile`/`ReadDir` and no axis but `ReadExecute` says
  *run*;
- write is `from_all(abi)` minus the whole read set and minus `ResolveUnix` —
  not merely minus `Execute`, which would confer read at the kernel while
  `FsGuard` refuses it and break the write-only drop directory the library
  promises. `ResolveUnix`, new at ABI V9, is conferred instead by
  `--allow-unix-sockets`, over the policy rather than this axis — writing a
  file is not dialling a socket;
- execute is the single bit, so it adds on top of read without widening anything
  else.

Directory-only rights are invalid on a regular file, so the set is *intersected*
with what the target can carry rather than substituted. The axis rides along in
the tuple even though the kernel is never told it, because Landlock **unions**
the rules it is given for a path: `(path, rights)` alone would not be the
effective right set for any path named on two axes, which `--allow-write`
produces every time.

Then the loop, which is where our flag stops being data:

```rust
for (_, target, rights) in rules {
    let fd = open_grant(&target)?;
    ruleset = ruleset
        .add_rule(PathBeneath::new(fd, rights))
        .map_err(landlock_failed)?;
}
```

`open_grant` in
[`ruleset/opened.rs`](../../crates/sandbx-core/src/helper/ruleset/opened.rs) is
the only way this crate obtains a `PathFd`, so neither of its two confirmations
can be skipped by adding a rule somewhere else. It opens with
`O_PATH | O_CLOEXEC` and no `O_NOFOLLOW`, then asks two separate questions:

1. **Does it read back as the spelling it was told to open?** `reads_back` reads
   `/proc/self/fd/<n>`; a mismatch is `GrantRedirected`, naming what was
   substituted for what. This catches a symlink redirected between the harness's
   judgement and the helper's open (#205).
2. **Is it the object the harness vetted?** `ObjectId::of_fd` — an `fstat`
   through the descriptor — against `granted.object()`; a mismatch is
   `GrantReplaced`. This catches a `rename(2)`, which leaves the spelling
   identical and so passes the first question (#212). `Installed` skips it,
   because the object was made in this process and a pin taken here would be the
   process agreeing with itself.

And then the window closes rather than narrowing, which is the sentence to
remember out of this whole chapter: `PathBeneath` holds the **descriptor**, so
the kernel attaches the rule to that inode. A later rename moves the name and
not the rule. This is where the right-hand branch of the fork ends up somewhere
the left-hand branch, with its measure-then-open guard, does not.

`restrict_self()` installs the ruleset and
`enforcement_verdict(status.ruleset)?` reads the result: under the
`HardRequirement` compatibility level set at the top of `apply`, a ruleset the
kernel took only partly is an error rather than a quietly weaker sandbox.

## The no-flag default, and why a flag replaces it

Now the other half of the question, because `--allow-read /tmp/x` does not only
*add* a grant — it takes one away.

```rust
if !self.paths_given() {
    // Inside the branch: a run that typed its own flags never depends on `HOME`.
    let root = current_root(policy.executable_paths(), &owned)?;
    let root = pinned(&root, root.path())?;
    policy = policy.allow_read(root.clone()).allow_write(root);
}
```

With no path flag at all, a run derives read **and write** on the working
directory. Give any path flag and that branch does not execute, so the flags you
typed become the whole of the filesystem policy. `paths_given` runs over
`Axis::ALL`, so a fourth path axis joins the rule rather than being forgotten
into a default that widens it.

[decision-default-policy.md](../decision-default-policy.md) is clear that what
decided this was the failure mode and not the ergonomics. The alternative was an
unconditional default plus a `--no-default-policy` opt-out, and under that shape
`sandbx agent-run --allow-read /srv` — a deliberately tight, hand-written policy
— *silently gains write over the whole working tree*. Suppression's failure mode
is the mirror image and is the safe one: the operator gets less than they
expected and hears about it at once, as a refusal naming the path the grant
lacked. The record's own summary is the line worth carrying: **narrow and loud
beats wide and silent.** It also notes that nothing here forecloses going the
other way, since unconditional-plus-opt-out is a strict widening of this.

Note too that `pinned(&root, root.path())?` on the derived path is the same
function the flag route calls, passing the resolved path where the flag route
passes `path`, the spelling the operator typed and the one a refusal names — a
derived grant has no typed spelling of its own. It is pinned exactly as a typed
one is; there is no second, laxer road into the policy.

Some working directories are refused rather than derived from — `vetted_root`
answers that, and it refuses **in the order written**: the filesystem root, then
`$HOME` or a directory holding it, then one of `/home`, `/Users`, `/var/home`
and `/root` or a directory holding one of those, then a home-looking directory
where `$HOME` settled nothing, then an overlap with the system binaries, then a
cwd reaching something sandbx owns. That third refusal is the one gated on no
variable at all, and deliberately: a service account whose `HOME=/var/lib/svc`
would otherwise let `/home` through, where a derived root is write over every
user's home whatever the variable happens to name. `current_root` is
`vetted_root` over this process's own state. The guard governs only what sandbx
*derives* and never what you ask for, which is why every refusal in the family
names the two flags to type instead.

## What a grant may not reach

Two paths are the harness's own: the session transcripts a resumed run replays
to the model, and the credential file `auth login` writes. `owned_paths` derives
them from the config and state homes in play, each with a `holds: &'static str`
saying what it is for — `&'static` so that no shape of the refusal can carry a
key into a message.

`reaches_owned` tests containment **both ways round**, because a Landlock right
covers a subtree: a grant *above* the session directory hands over every
transcript, and a grant naming one transcript inside it hands over that history
— the file whose contents become what the model is told it said. `starts_with`
compares whole components, not bytes, so `~/.config/sandbx-notes` still derives.

```rust
owned.iter().find(|owned| {
    let path = resolved(&owned.path);

    path.path().starts_with(granted) || granted.starts_with(path.path())
})
```

Four properties of this refusal are each deliberate, and
[decision-harness-owned-paths.md](../decision-harness-owned-paths.md) argues all
four.

- **It fires in both subcommands or neither,** on every path axis, since
  `Grants` is shared.
- **It does not ask whether anything is stored there.** An existence-sensitive
  refusal is a race: `agent-run --session` creates the transcript during the
  very run the policy was derived for, so a filesystem check would answer
  "nothing there" and then put something there, and the same argv would be
  refused on its second invocation and not its first. It is also a verdict no
  test can pin without building the state it is testing for.
- **There is no exact-path hatch.**
  `--allow-read ~/.config/sandbx/credentials.toml` is refused rather than
  honoured as the narrowest possible form of the request. Naming the file *is*
  the request the refusal exists for, and a hatch at the exact path would be a
  hatch for an injected flag in any wrapper script that builds an argv — in the
  one spelling that reads most like deliberate care.
- **The derived default is the same hazard by another route,** so `vetted_root`
  calls `reaches_owned` on the cwd too. A no-flag run from inside the session
  directory would otherwise derive read and write over the history.

So `--allow-read ~` and `--allow-read /` are refused, with no override flag. The
honest form of an override is moving the state: point `XDG_STATE_HOME` elsewhere
and what sandbx owns moves, and the refusal moves with it.

Subtraction was never on the table as an alternative, and the reason is the
mechanism rather than taste: Landlock unions rules and has no way to express an
exclusion, so "grant `/` except this file" is not a policy the kernel can hold.

**The same key reached through `/proc` is closed by a different mechanism
entirely,** which is worth seeing because it shows where a path refusal stops.
`/proc/<harness-pid>/environ` is not a grant and no path check governs it. So
sandbx clears its own dumpable flag at startup — `conceal_process_state` in
[`concealment.rs`](../../crates/sandbx-core/src/concealment.rs), via
`prctl(PR_SET_DUMPABLE, 0)`. The kernel reparents the process's `/proc` entry to
root, so `environ`, `mem`, `maps` and `fd/` fail `__ptrace_may_access` even for
a reader running as you. It is called from
[`main.rs`](../../crates/sandbx-cli/src/main.rs) immediately after parsing and
before any subcommand, so no code path reaches a policy with the flag still set.
[`SECURITY.md`](../../SECURITY.md) carries the pair as one claim and the record
puts it plainly: this is a different mechanism, not more of the path refusal.

- **Worth questioning:** the departure at `axis.grants().write` is keyed so that
  "a future write-conferring axis inherits the affordance instead of silently
  missing it", and [decision-axis-table.md](../decision-axis-table.md) presents
  that as the safe default. It is the safe default for *forgetting*; it is also
  an automatic widening. Whoever adds a fifth axis that confers write gets a
  read grant from the CLI without ever opening `grants.rs`, which is the
  opposite of every other new-axis story in that record — where the point is
  that a new axis must visit each site that decides something about it, and the
  test suite fails until it does. The two goals conflict here and only one is
  priced. A `match` on `Axis` with a comment on each arm would fail to compile
  for the new axis and get the same outcome with the decision made deliberately.

## Why stage 2 returns a type and not a `PathBuf`

`reaches_owned` needs its `granted` argument to have come through `resolved`,
and for a while the way that requirement was held was a doc comment plus
`debug_assert!(granted == resolved(granted), …)` — the workspace's only
assertion outside a test module. A `debug_assert!` is compiled out of a release
build, so in the artefact that ships, the precondition on the refusal that
protects the credential file and the transcripts was held by convention. Both
callers complied, so there was no defect to fix. What there was, was a third
caller waiting to be written.

[decision-harness-owned-paths.md](../decision-harness-owned-paths.md) reasons
carefully about *which* spelling must reach the comparison — "vetting one
spelling and granting another is the window this closes" (#205) — and the owned
side normalises itself inside the function. The caller's side is what
`ResolvedPath` makes unforgeable, and the pattern was already in the tree one
layer down: `VettedPath` is precisely a path that cannot be unpinned, because
`grant` accepts nothing else. So the fix (#248) is that shape and not that type
— `VettedPath` cannot carry it, because `vet` canonicalizes and `resolved`
exists to name a path whose leaf does not exist yet. A second wrapper, then,
built to the first one's rules: private field, exactly one producer, a `path()`
accessor and no `Deref`, so there is no way to hand `reaches_owned` a path that
only looks resolved.

What that changes for a reader is where to look for the requirement. It is in
the signature, which means a third call site inside `grants` that forgets it
does not compile — and there is no new test, because a compile-time guarantee
has no runtime failure mode to assert on. Two existing tests changed shape, and
**one of them had been passing by accident**: `an_absolute_grant_needs_no_cwd`
handed `reaches_owned` an unresolved path and satisfied the old assertion only
because `/srv/app` happens not to exist on the test host, so `resolved` returned
it unchanged. That is what a `debug_assert!` over a filesystem predicate cannot
tell you — whether the precondition held, or the host merely agreed with it.

## The pin is the flag that becomes no rule at all

One flag on `sandbox-run` goes through none of the five stages above.
`--pin-sha256` is parsed by the same clap layer and crosses the same argv seam,
and then it stops: no `Axis`, no `VettedPath`, no `PathBeneath`, nothing the
kernel is ever told. The ruleset a pinned run installs is byte-for-byte the one
an unpinned run installs.
[decision-pinned-entry-point.md](../decision-pinned-entry-point.md) is the
authority, and its opening move is the one to carry away: `SandboxPolicy` says
what a confined process may *do*, and both enforcement layers derive from
`Axis::grants`, so a digest made into an axis row would have to answer what it
confers — and the answer is nothing.

The gap it closes is one `--allow-exec` leaves open deliberately. A path grant
is standing permission to run whatever is at that path when the command starts,
so `--allow-exec ./target/debug/mytool --allow-write ./target` — the natural
pair for "run the thing you just built" — is also the pair that lets the command
choose its own binary, because in an agent session the second tool call can
rewrite what the first one built (#146).

**The operator-facing shape is two commands.** `sandbx hash PATH` prints a
digest in the form the flag takes, and `--pin-sha256 HEX` refuses the run unless
the program named after `--` hashes to it:

```console
$ sandbx sandbox-run --allow-exec /tmp/demo \
    --pin-sha256 "$(sandbx hash /tmp/demo/tool)" -- /tmp/demo/tool
```

`Hash::execute` in [`hash.rs`](../../crates/sandbx-cli/src/hash.rs) writes the
hex and a newline and nothing else, so the substitution above composes with no
`cut`, and it writes through `write_all` rather than `println!` — which panics
on a closed stdout once `SIGPIPE` is ignored.

**`hash` is the one subcommand that confines nothing,** which looks like a hole
in a harness whose whole claim is that it confines things, and is not one. A pin
has to be taken *before* there is a policy to take it under — the digest is an
input to the policy, so a subcommand that confined the reading would need the
very policy the digest is going into. What `hash` does is open one file as
you, hash it, and print sixty-four characters: exactly `sha256sum`, reaching
nothing you could not already read, deriving no policy and spawning nothing. The
digest is no secret either, since anyone who can read the bytes can compute it.
`conceal_process_state` still runs ahead of it, from
[`main.rs`](../../crates/sandbx-cli/src/main.rs), because that call sits before
the subcommand match rather than inside an arm of it.

**A pin grants nothing, and that is the likeliest way to misread the flag.** It
is not a path grant and it does not stand in for one: a pinned program with no
`--allow-exec` covering it still cannot run, because the right to execute comes
only from `Axis::ReadExecute` and the single bit `rights_for` adds for it. The
flag sits on `SandboxRun` and not on the `Grants` both run subcommands flatten,
so it is outside `paths_given()` — which means a pin cannot suppress the
working-directory default either. A flag that grants nothing must not narrow
anything. It is absent from `agent-run` for a second reason: there the program
is the model's to choose, so the flag would parse, document a guarantee and pin
nothing.

**The descriptor and not the path is the whole mechanism.** The naive
implementation hashes a path and then `execve`s that path — two lookups of one
name, with a window between them that is exactly the window the flag exists to
close. `open_verified` in [`digest.rs`](../../crates/sandbx-core/src/digest.rs)
opens once and keeps the handle:

```rust
let mut file = std::fs::File::open(program).map_err(unreadable)?;

let actual = Sha256Digest::of_file(&mut file).map_err(unreadable)?;

if actual != expected {
    return Err(crate::SandboxError::PinMismatch {
        program: program.to_string(),
        expected,
        actual,
    });
}
```

`Sha256Digest::of_file` takes a `&mut std::fs::File` and never a path, which
makes the honest route the only one the type permits — there is no form of it
that could re-open a name. The handle is then given back to the caller, which
names it for the `exec` through `fd_path`:

```rust
pub(crate) fn fd_path(file: &std::fs::File) -> std::path::PathBuf {
    use std::os::fd::{AsFd, AsRawFd};

    std::path::PathBuf::from(format!("/proc/self/fd/{}", file.as_fd().as_raw_fd()))
}
```

The bytes hashed and the bytes executed are reached through the same open file,
so there is no second resolution for a swap to land in.
[07](07-kernel-primer.md) has `O_PATH` and the `/proc/self/fd` magic link; this
is that trick put to a different use, and the handle here is an ordinary
readable one because reading it is the point. It is also the discipline
[11](11-the-two-seams.md) names at the guard — hold a handle, not a name —
applied to the one operation the guard never sees. Two further facts are what
make it hold: the handle must outlive the `exec`, which is what keeps
`/proc/self/fd/N` a valid name, and Landlock dereferences the magic link, so the
`execve` is still checked against the program's real path and a pinned run needs
no grant on `/proc`. [`SECURITY.md`](../../SECURITY.md) carries that second
dependency as a stated one.

**Two shapes are refused rather than run unchecked.** Both refusals carry
advice, because neither is something an operator could diagnose from the failure
they would otherwise get.

- **A `#!` script.** The digest would be honest — those are the script's bytes —
  and the run would still die. `binfmt_script` substitutes `bprm->interp` for
  argv[0] and calls `remove_arg_zero`, so the interpreter re-opens the path
  sandbx exec'd, which is `/proc/self/fd/N` and by then a closed descriptor; the
  run fails as `cannot open /proc/self/fd/4`, naming nothing anybody could act
  on. Clearing `FD_CLOEXEC` would make it start and was rejected: the script
  would then see `$0 = /proc/self/fd/N`, breaking `dirname $0` and every
  multi-call dispatch, and a security flag must not change what the program
  observes about itself. The deeper reason is that the pin was measuring the
  wrong thing anyway — a script's bytes say nothing about the interpreter that
  will run them — so `PinnedScript`'s message gives the shape that works: pin an
  ELF binary, or run the interpreter as the program and pass the script as an
  argument, where the interpreter is the entry point and the script is outside
  the pin.
- **A program you may execute but not read.** A mode-111 binary runs unpinned
  and cannot be pinned, hashing needing a read that execute alone does not give.
  That is `PinUnreadable`, its own variant so that the failure says "a pin
  needs read access, which execute alone does not give" rather than letting a
  `Permission denied` from the open read as a failed exec.

Their order is in the snippet above and is deliberate: the digest comparison
runs *first*, so bytes that were never the pinned ones report the mismatch, and
only an image that genuinely *is* the pinned one is refused for being a script.
`a_swapped_script_reports_the_mismatch` in `digest.rs` holds that down.

**The check sits after `apply`, in the process that becomes the command.** Not
in the harness: `restrict_and_exec` in
[`helper/mod.rs`](../../crates/sandbx-core/src/helper/mod.rs) is stage 2 of the
re-exec, PID 1 of the new PID namespace, and it calls `apply` — Landlock,
seccomp, hardening — and only then opens the program.

```rust
let image = request
    .pin
    .map(|expected| crate::digest::open_verified(&request.program, expected))
    .transpose()?;
```

Opening first would hash a file no grant covers and report a mismatch where the
honest answer is a denied read. After `apply`, the descriptor is *provably* one
the policy authorizes: the read that produced the digest was itself subject to
the ruleset the kernel now holds, so a pin cannot become a way to read a byte
the policy would have refused. The pin is checked inside the cage rather than
beside it — which is the other half of why it needs no rule of its own. One
unconditional line after the open keeps it invisible to the program:

```rust
command.arg0(&request.program);
```

Without it `$0` would be the procfs path, which `ps` and a multi-call binary
both read. A matching pin changes nothing the command can observe about itself.

**The mechanism's edge is the one `execve`.** The digest covers the bytes sandbx
itself executes and nothing that image then spawns, which
[`SECURITY.md`](../../SECURITY.md) states as a non-claim and #146 is the issue
behind. A pinned `/usr/bin/python3` is still arbitrary code — the digest fixes
the interpreter and says nothing about the script it is handed — and after the
`execve` the program may spawn anything the filesystem policy permits, the
`/usr`, `/bin`, `/lib` and `/lib64` floor the CLI grants by default included.
[17](17-gaps-and-open-questions.md) carries it as a gap row rather than a
defect, which is the right reading: a pin over a process tree is a different
mechanism, not more of this one.

**On the trail a pin is one boolean, written before it was checked.**
`AuditEvent::spawned` in [`audit.rs`](../../crates/sandbx-core/src/audit.rs)
takes `pinned` as a parameter rather than deriving it, a digest not being
policy, and `SandboxedCommand::output` passes `self.pin.is_some()` — in the
harness, before the helper has hashed anything. So `pinned=true` records that a
digest *had* to match and not that it did; whether it did is the second record
of the pair, an `exited` against a `failed` carrying `reason="pin_mismatch"`.
That is the same intent-not-outcome reading `decision="spawned"` has throughout
[14](14-audit-sessions-credentials.md). A boolean and not the digest, for a
reason worth keeping: the digest is already in `/proc/self/cmdline`, and what an
auditor cannot recover is that it was checked.

- **Worth questioning:** the script refusal is two bytes wide and the hazard is
  not. `starts_with_shebang` tests for `#!` because that is the format
  [decision-pinned-entry-point.md](../decision-pinned-entry-point.md) reasons
  about, and the refusal's own message states the correct general rule — pin an
  ELF binary — but only a `#!` image ever reaches it. Any other format the
  kernel routes to an interpreter has the same shape of problem: `binfmt_misc`
  hands its interpreter the path the kernel was given, as an argument, and that
  path is the procfs name of a descriptor closed by then. So a pinned image that
  is neither ELF nor `#!` gets precisely the bare `cannot open /proc/self/fd/N`
  the record added a refusal in order to avoid, with none of the advice
  attached. Testing for the ELF magic rather than the shebang magic would refuse
  the whole class by the rule the message already gives, and would cost a pinned
  ELF nothing.

## You should now be able to explain

- The five functions a path flag passes through, in the order they run, and what
  each one changes about the grant's shape.
- Why `absolute` cannot be folded into `resolved`, and why `resolved` is not a
  `canonicalize`.
- What `pinned` compares after vetting, and which substitution that comparison
  catches — and why it is the only step whose answer outlives it, though three
  of the five read the filesystem.
- Why `VettedPath::vet` is the only route an embedder has to a grant, and which
  two things the type's shape makes impossible to write.
- Why `SandboxPolicy::grant` takes a `VettedPath` rather than a path, and why it
  performs no I/O even though the harness could afford to.
- What "a granted path resolves to itself" licenses downstream, and name one
  consumer that relies on it.
- What the three tokens of `--ro /tmp/x <dev>:<ino>` are, and why an unstable
  `(dev, ino)` pair is the point rather than a weakness.
- What `command_line` refuses before it renders a token, why those two questions
  are asked in the core crate, and what else is on the wire beside the grant you
  typed — including the one thing the argv deliberately does not carry.
- The two separate questions `open_grant` asks, which substitution each one
  catches, and why `Installed` is exempt from the second.
- Why `PathBeneath` holding a descriptor closes a window that the in-process
  guard only narrows.
- Why `--pin-sha256` is not an `Axis` row, what a pin grants, and what still has
  to be typed beside it for a pinned program to run at all.
- How `open_verified` and `fd_path` leave no second path lookup for a swap to
  land in, and why `arg0` is restored unconditionally afterwards.
- Why the digest is checked after `apply` and in the process that becomes the
  command, and which two images are refused rather than pinned.
- Why typing one path flag removes the working-directory default, and the
  failure mode of the alternative.
- Why a grant reaching a harness-owned path is refused in both directions and
  with no exact-path hatch, and why the same hazard through `/proc` needed a
  different mechanism.
- Why `resolved` returns a type rather than a `PathBuf`, what a `debug_assert!`
  held before it, and why the replacement needed a second wrapper rather than
  `VettedPath`.

## Next

[13 — the turn loop and the gate](13-turn-loop-and-gate.md), which climbs above
the policy to the thing that decides whether a tool call is attempted at all.
Everything up to here bounds what a call may touch; that chapter is about
whether the call happens.
