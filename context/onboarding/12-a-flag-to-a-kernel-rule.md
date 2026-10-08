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
   │ resolved          ──► PathBuf, deepest resolvable ancestor replaced
   │ bound_by_resolver ──► bool, noted now and refused with the DNS flags
   │ reaches_owned     ──► Option<&OwnedPath>; Some is a refusal
   │ pinned            ──► VettedPath, the only step that stats
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
| 2 | `resolved` | that absolute path | `PathBuf`, total — never fails |
| 3 | `bound_by_resolver` | both spellings | `bool`, noted for later |
| 4 | `reaches_owned` | the resolved path, plus the owned paths | `Option<&OwnedPath>` |
| 5 | `pinned` | the resolved path, plus the typed one | `Result<VettedPath, PolicyError>` |

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

**`bound_by_resolver` asks whether the flag names a file sandbx's own bounded
resolver will bind-mount over.** It tests both spellings on purpose: the
resolved form catches a flag spelled relative or through a symlink, the typed
form catches one that cannot be canonicalized at all. The answer is *noted* here
and refused further down, alongside the DNS flags, so that an operator with no
egress at all hears the more fundamental thing first.

**`reaches_owned` is the first place the run can be refused.** It is the subject
of [decision-harness-owned-paths.md](../decision-harness-owned-paths.md) and the
later section of this chapter; for now, note that it answers in `Option` and
that `Grants::policy` turns `Some` into `PolicyError::GrantReachesOwned` naming
the path **as typed**, so the operator can go and change the thing they wrote.

**`pinned` is the step that touches the filesystem**, and the only one:

```rust
pub(super) fn pinned(granted: &Path, typed: &Path) -> Result<VettedPath, PolicyError> {
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
worth sitting with. `granted` arrived `resolved`, and `vet` resolves again — so
if a component was swapped for a symlink in between, the two spellings differ.
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

Both fields private, with `path()` and `object()` to read them. `ObjectId` is a
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
is the one place a path enters a policy, and two properties of it carry the
whole design.

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
[`command.rs`](../../crates/sandbx-core/src/command.rs) builds the helper's
argv: `HELPER_FLAG` and `AUDIT_STDIN_FLAG` first, then everything
`HelperArgs::encode` emits. Our one grant becomes three tokens:

```
--ro /tmp/x <dev>:<ino>
```

`--ro` comes from the single `path_flag(axis)` match that
[11](11-the-two-seams.md) quoted. The pair is written decimal, `dev` then `ino`,
by `ObjectId`'s `Display`. It is deliberately host-specific and deliberately
unstable: neither half survives a remount, and that is the property that makes
the pair worth carrying rather than a defect in it — an object that moved is not
the one that was vetted, whatever it is now called.

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
- write is `from_all(abi)` minus the whole read set — not merely minus
  `Execute`, which would confer read at the kernel while `FsGuard` refuses it
  and break the write-only drop directory the library promises;
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
    let root = pinned(&root, &root)?;
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

Note too that `pinned(&root, &root)?` on the derived path is the same function
the flag route calls, with the same spelling in both arguments. A derived grant
is pinned exactly as a typed one is; there is no second, laxer road into the
policy.

Some working directories are refused rather than derived from — `vetted_root`
answers that, and it refuses **in the order written**: the filesystem root, then
`$HOME` or a directory holding it, then a home-looking directory where `$HOME`
settled nothing, then an overlap with the system binaries, then a cwd reaching
something sandbx owns. `current_root` is `vetted_root` over this process's own
state. The guard governs only what sandbx *derives* and never what you ask for,
which is why every refusal in the family names the two flags to type instead.

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
    path.starts_with(granted) || granted.starts_with(&path)
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

- **Worth questioning:** `reaches_owned` requires its `granted` argument to have
  arrived through `resolved`, and the way that requirement is held is a doc
  comment plus `debug_assert!(granted == resolved(granted), …)`. The published
  binary is a release build, so in the artefact that ships, the precondition on
  the refusal that protects the credential file and the transcripts is enforced
  by convention.
  [decision-harness-owned-paths.md](../decision-harness-owned-paths.md) reasons
  carefully about *which* spelling must reach the comparison — "vetting one
  spelling and granting another is the window this closes" — and the owned side
  normalises itself inside the function. What the record does not weigh is
  making the caller's side unforgeable, which this codebase already knows how to
  do: `VettedPath` is precisely a path that cannot be unpinned, because `grant`
  accepts nothing else. A `Resolved` newtype returned by `resolved` and demanded
  by `reaches_owned` would turn today's debug-only assertion into the same kind
  of build failure, in the one place where the two production callers are the
  only thing standing between a lexical mismatch and a grant over the session
  history.

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

## You should now be able to explain

- The five functions a path flag passes through, in the order they run, and what
  each one changes about the grant's shape.
- Why `absolute` cannot be folded into `resolved`, and why `resolved` is not a
  `canonicalize`.
- What `pinned` compares after vetting, and which substitution that comparison
  catches.
- Why `SandboxPolicy::grant` takes a `VettedPath` rather than a path, and why it
  performs no I/O even though the harness could afford to.
- What "a granted path resolves to itself" licenses downstream, and name one
  consumer that relies on it.
- What the three tokens of `--ro /tmp/x <dev>:<ino>` are, and why an unstable
  `(dev, ino)` pair is the point rather than a weakness.
- The two separate questions `open_grant` asks, which substitution each one
  catches, and why `Installed` is exempt from the second.
- Why `PathBeneath` holding a descriptor closes a window that the in-process
  guard only narrows.
- Why typing one path flag removes the working-directory default, and the
  failure mode of the alternative.
- Why a grant reaching a harness-owned path is refused in both directions and
  with no exact-path hatch, and why the same hazard through `/proc` needed a
  different mechanism.
