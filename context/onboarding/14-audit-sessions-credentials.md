# What is recorded, and who may read it

Three boxes at once, because they are the same question asked about three files.
[04 — the architecture](04-the-architecture.md) closes its request path with one
sentence: "a decision is recorded through `tracing` under `AUDIT_TARGET`, one
made *inside* the helper is relayed back over the helper's own channel, and the
finished turn is appended to a session transcript as JSONL." This chapter is
that sentence, plus the credential that paid for the round. Two rows of 04's
"where each box's detail lives" table own the authoritative accounts:
[guide-logging.md](../guide-logging.md) with
[decision-helper-audit-channel.md](../decision-helper-audit-channel.md), and
[decision-on-disk-state.md](../decision-on-disk-state.md).

One thread runs through all four: **a record is useful in proportion to what it
refuses to hold.** The trail holds metadata and no output. The helper's channel
holds a closed label set and a capped detail. The credential is never printed
and the file it lives in is refused rather than repaired. The transcript is the
one exception — it holds content by definition — and that is exactly why its
rules differ from the credential's.

## Two streams, one pipeline, split by target

There is one `tracing` subscriber in the whole process tree, built in
[`cli/src/logging.rs`](../../crates/sandbx-cli/src/logging.rs) — see
`subscriber` and `init`. Two kinds of event go through it:

```
diagnostics   ──► default targets      ──► for whoever is debugging sandbx
audit trail   ──► "sandbx::audit"      ──► for whoever asks what the agent did
```

The split is by **target**, not by level, and that is a decision rather than a
convenience. `AUDIT_TARGET` is a `pub const` in
[`core/src/audit.rs`](../../crates/sandbx-core/src/audit.rs), so filtering on it
is a supported operation for whoever consumes the trail. Separating by level
instead would mean the trail *is* whatever happens to be above the threshold,
and two unrelated things — "how verbose do I want sandbx to be" and "show me
what the agent touched" — would be the same knob.

Every audit event is at `INFO`, and the reason is in the failure it was fixed
after: the two `Degraded` sites once used a raw `tracing::debug!` on the audit
target, so a hardening step that silently did not take effect went missing below
the default filter. A trail at `DEBUG` is absent for everyone who did not opt
in, which is precisely when a record matters.

The filter itself is doing two jobs:

```rust
        // A global filter rather than a per-layer `with_filter`: same effect with one
        // layer, but this form contributes a real `max_level_hint`, which lets
        // `tracing` skip every `debug!` callsite in the workspace statically.
        .with(Targets::new().with_target(sandbx_core::AUDIT_TARGET, LevelFilter::INFO))
```

The *target* half keeps `sandbx-core`'s own `debug!` out, so making the trail
visible does not make the internals visible. The `INFO` half keeps anything that
merely borrowed the target out of the record. And the choice of a global filter
over a per-layer one is a performance property with a security shape: a real
`max_level_hint` lets `tracing` skip every `debug!` callsite statically, which
is what makes "always on, no flag" affordable.

Three more properties of the sink, each with a counterexample attached:

- **Stderr, not stdout**, because `SandboxRun::execute` forwards a sandboxed
  command's stdout verbatim and a record there would corrupt a pipeline.
- **Installed inside the `with_helper_dispatch` closure.** Above it, the helper
  process — which is this same binary — would write sandbx's own audit records
  into the output of the command being sandboxed.
- **Global, not `set_default`.** Tools run on `spawn_blocking`, so the thread
  that emits is not the thread that asked, and a thread-local subscriber
  captures nothing a tool emitted. This is why
  `sandbx-agent/tests/audit_trail.rs` is a test binary of its own: a process
  installs exactly one global subscriber.

## The trail records the access, not the verdict

`AuditEvent` has seven variants and `emit` is one `match` writing one
`tracing::info!` per variant, each with a literal `decision = "…"`. The field
names are a wire format in all but name.

The load-bearing decision is which *proposition* a record states. The guard
natively produces a verdict — it decides on resolution, before any syscall — and
that is the cheaper reading, and the one the code had by accident. It was
rejected (#182, #187). `allowed` is emitted *after* the open, the walk or the
`read_dir` succeeds, so the trail answers "what did the agent see" rather than
"what did the policy decide".
[decision-audit-records-access.md](../decision-audit-records-access.md) is the
record; three consequences fall out of it that a reader of a trail depends on:

- **A check that performs no access records nothing.** `check_read` emits a
  refusal and no pass. A bare check succeeding is not an event.
- **An absence is its own value.** `absent` is a path that names nothing
  *inside* a root already granted — what a model guessing filenames leaves
  behind, and nothing else on the trail would show the guesses. It carries no
  `reason`, because nothing refused it.
- **`absent` never escapes a grant.** A path missing *outside* every root stays
  `denied`, indistinguishable from any other refusal. Naming the absence there
  would hand back over the trail exactly what the refusal conceals.

That last one is the pattern to carry away: the trail is an output, so what it
declines to say is part of the policy. The same instinct governs the metadata
rule. `Spawned` records counts, never paths — how many roots were readable, not
which — and derives those counts through an exhaustive `match` on `Axis::ALL`,
so a new axis fails to compile rather than going silently uncounted (#51).
`Spawned.pinned` is a boolean and not the digest, with the reason stated as a
principle worth remembering:

> Not the digest, already in `/proc/self/cmdline`; what an auditor cannot
> recover is that it was checked.

- **Worth questioning:** by that principle the trail is missing the command. A
  `bash` call spawns `/bin/sh -c <the model's string>`, and `Spawned.program` is
  `"/bin/sh"` for every one of them; the string itself appears in no audit
  field. So the one stream [guide-logging.md](../guide-logging.md) describes as
  "for whoever asks 'what did the agent do to my machine'" cannot answer what
  any command was. The guide's rule is "metadata only, never output… output is
  where secrets live", which is sound about output and is doing different work
  here: a command string is an *input*, chosen by the model, and
  `/proc/self/cmdline` — the guide's own reason for omitting the digest — is
  gone the moment the process exits, so this is exactly the class the `pinned`
  field was added for. The one real counter-argument is width, since a record of
  fixed width is one a filter can rely on (#146); but the gate already caps and
  strips a model-chosen argument to a fixed length for the consent prompt, so
  the machinery for a bounded `command` field is in the repo and reusable. Under
  `tui` the gap is visible as a defect rather than an argument, which is what
  #234 is about.
- **Worth questioning:** a gate refusal reaches the audit target at all.
  [decision-approval-gate.md](../decision-approval-gate.md) states it plainly —
  "No audit record either. `AuditEvent::Denied` records what the sandbox refused
  to let a *running* tool touch; a call that never ran touched nothing" — and
  offers two substitutes: "The operator's record is the one line per call and
  the transcript's is the `tool_result`." Both are real, and neither is on
  `sandbx::audit`. So the single filtering operation this subsystem prescribes —
  split the two streams on the target — discards every refusal, and an auditor
  who follows the instruction gets a trail in which the agent only ever
  succeeded. The record's reasoning is about the meaning of `Denied`, which is
  sound; it does not weigh a value of its own.
  [decision-audit-records-access.md](../decision-audit-records-access.md) notes
  that `decision=` is a wire field where "adding a value is additive", so the
  cheap direction is available and unexamined, and the strongest form of the
  objection is the asymmetry: a `bash` the *policy* refuses is on the trail, and
  a `bash` the *operator* refuses is not.

## The helper has no subscriber, so its half rides fd 0

`emit`'s own doc names the trap, and it is a `tracing` behaviour worth knowing
independently of sandbx:

> Records nothing unless a subscriber is listening on [`AUDIT_TARGET`]:
> `tracing` drops an event with no subscriber, silently and at every level.

The re-exec'd helper installs none, and *must not*: its stdout and stderr are
pipes sandbx replays verbatim, and stage 2 inherits them before becoming the
command, so a subscriber there would write sandbx's audit records into the
output of the program being sandboxed. That is why the level fix of #89 bought
nothing on its own — a record that survives the filter still needs somewhere to
land (#95).

The carrier is the **stdin slot**, and the reason is a `std` limitation rather
than a preference: `unsafe_code = "forbid"` is workspace-wide, adopting an
inherited raw fd child-side needs `OwnedFd::from_raw_fd` or
`BorrowedFd::borrow_raw`, and both are `unsafe`. The only descriptors `std`
hands a child without `unsafe` are 0, 1 and 2 — and 1 and 2 are the command's
output.

So: sandbx creates a pipe and puts the write end in stage 1's fd 0.
[`core/src/degradation.rs`](../../crates/sandbx-core/src/degradation.rs) owns
both ends of the format — `label<TAB>detail` lines — `hardening.rs` *returns*
what degraded instead of emitting it, and sandbx decodes and emits the audit
events itself. One subscriber in the tree, one timestamp source, and the
command's streams stay byte-exact.

Four details make it a boundary rather than a pipe:

- **Stage 2 claims fd 0 before it becomes the command.** It moves the channel
  into a close-on-exec duplicate and puts `/dev/null` in the slot, so the
  sandboxed command has no handle on the channel and a successful `exec` closes
  the duplicate. This is the barrier on the path untrusted code actually takes,
  and `the_command_cannot_write_the_audit_channel` is what holds it.
- **The label set is closed at the reader.** `Degradation` has three variants
  and `HelperRefusal` its own set, and `decode` accepts only those labels — so
  nothing that can write the channel can name a mechanism sandbx did not define.
  What a record *means* is decided by `degradation.rs`, never by whatever wrote
  the line. `detail` is free text and capped.
- **Not blocking is structural, not lucky.** Nothing drains the pipe while the
  helper writes, because sandbx reads only once the helper has been waited on. A
  write that filled the buffer would deadlock the very run it is reporting on.
  So the format is bounded by design: `RECORD_LIMIT` is derived from
  `Degradation::ALL`, and `DETAIL_LIMIT` is a few hundred characters, two orders
  of magnitude inside a default Linux pipe buffer — and the cap is unit-tested,
  so the bound is a property of the format rather than a hope about errno
  strings.
- **It is not a boundary in the sense Landlock is**, and the record says so:
  stage 1 holds the write end on its own fd 0 for its whole lifetime, and
  `/proc` is the host's un-remounted, so a policy granting write over `/proc`
  exposes the channel as `/proc/<stage1-pid>/fd/0`. The closed label set still
  bounds the mechanism; `detail` would be forgeable. Left as a documented limit,
  and [`SECURITY.md`](../../SECURITY.md) carries it.

The cost that is easiest to trip over later: **everything the channel carries is
timestamped after `spawned`**, because sandbx reads after waiting. The trail is
complete but not in causal order.

## 0700 and 0600, and the direction a wrong mode fails in

sandbx owns two directories, and
[decision-on-disk-state.md](../decision-on-disk-state.md) opens with the shape:
"Two roots, each owned by one crate, each created `0700` with its files `0600`."
Config holds the credential, state holds the transcripts, and the XDG split
earns its keep — a credential is something you put there, a transcript is
something that accumulates.

Four rules apply to both, and each one closes a specific trick:

- **Neither root is ever resolved against the working directory.** A relative
  `$XDG_*_HOME` falls back to `$HOME`, `$HOME` must itself be absolute, and
  neither being absolute is an error rather than a guess. For the transcript
  this is sharper than it looks, and `sessions_directory`'s own doc says why: a
  no-flag `agent-run` grants a tool write over the working directory, and "the
  history resumed from it is what the model is told it said."
- **Every mode is read through an open descriptor** — `File::metadata`, so
  `fstat` — never by path. Checking the mode first and opening second vets one
  file and reads another.
- **The containing directory is checked too**, and it is the stronger of the two
  checks: a directory another user may write lets them rename their own `0600`
  file over the target whatever the target's own mode says. This is what ssh's
  `StrictModes` checks a home directory for.
- **A link is refused, by two different routes**, because the two paths find the
  directory differently. The credential path takes its directory from
  `canonicalize` rather than `Path::parent`, which is lexical — a symlinked
  `credentials.toml` would otherwise have the directory holding the *link*
  vetted and the one holding the key never looked at. The session store checks
  its own root instead and opens the transcript `O_NOFOLLOW`, refusing a link
  outright on both the read and the reopen for append.

Then the rule that differs, deliberately:

| bits | credential | transcript |
|---|---|---|
| group/other **write** (`0o022`) | refuse | refuse |
| group/other **read** (`0o044`) | refuse | resume, and say so on stderr |

**The asymmetry is recovery.** A leaked key can be rotated, so refusing to *use*
one whose mode says it may have leaked still buys something. A leaked
conversation cannot be rotated: by the time the mode is read the disclosure has
happened, and refusing would only lock an operator out of their own history over
a umask they have already paid for. What a resume can still prevent is
**substitution** — a transcript another user can write is a history another user
chose, replayed to a model that calls tools. Hence two constants where the
credential store has one, and
[`session/src/store/vet.rs`](../../crates/sandbx-session/src/store/vet.rs) says
not to merge them:

```rust
/// The bits that let somebody else write, which refuse a resume.
///
/// Split from [`READABLE_BITS`], not shared with `auth/store.rs`'s `SHARED_BITS`: a leaked
/// credential rotates and a conversation does not; see `context/decision-on-disk-state.md`.
pub(super) const WRITABLE_BITS: u32 = 0o022;
```

**Refused, never repaired.** This is the direction worth internalising, because
the instinct runs the other way: a tool finding a too-wide mode usually fixes
it. Here a wide `credentials.toml` makes sandbx *refuse to read it*, and a quiet
`chmod` back to `0600` would hide that the key needs rotating — the mode is
evidence, and repairing it destroys the evidence while leaving the exposure. The
one tolerant command is `auth logout`, and the enum spells out both answers:

```rust
/// Whether a credential file wider than its owner may still be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shared {
    /// Refuse it — a key another user could have substituted is what the check prevents.
    Refuse,
    /// Read it anyway: refusing `logout` would leave a disclosed key on disk.
    Tolerate,
}
```

The session root is the one place a mode is **narrowed**, and only at create
time: `narrow_root` does an `fchmod` on the descriptor it just stat'd, not a
`chmod` by path, "so the directory narrowed is the one vetted". `resume` refuses
instead, and the record explains why that is not an inconsistency — at create
time the directory holds nothing a refusal would protect, and at resume time it
holds the transcript about to be replayed to the model. The explicit `fchmod` is
also not optional: `DirBuilderExt::mode` is ignored outright for a directory
that already exists, so a root somebody widened would otherwise stay wide
forever.

One more thing a parse failure is allowed to say. A torn transcript line reports
`serde_json`'s error as its `source`; the credential file deliberately drops
`toml`'s, because `toml`'s `Display` quotes the whole failing line — which for a
malformed `credentials.toml` is the key itself.

## Where a key may come from, and what a tool is handed

[decision-credentials.md](../decision-credentials.md) describes three tiers, of
which two are live.

| tier | where | status |
|---|---|---|
| 1 | `ANTHROPIC_API_KEY` in the environment | live, tried first |
| 2 | the OS keyring | dropped, with five reasons on the record |
| 3 | `credentials.toml` under the config home, `0600` in a `0700` directory | live |

"The two live tiers are tried in that order, and the order is the point."
[`cli/src/auth.rs`](../../crates/sandbx-cli/src/auth.rs) — see `resolve` —
states it as a property of *when the file is located*: "The file is located only
once the environment has come up empty, so an exported key works on a host with
no config home for `config_file` to name."

Two small rules that save a long debugging session each:

- **A set-but-blank variable counts as absent**, and whitespace is trimmed. An
  unpopulated CI secret yields `Ok("")`, and a `$(cat key)` keeps a trailing
  newline that `HeaderValue` rejects much later as an opaque transport error.
  Both are handled once, in `resolve_api_key` in
  [`credentials.rs`](../../crates/sandbx-providers/src/credentials.rs).
- **The lookup is injected** rather than calling `std::env::var` directly,
  because `set_var` is an `unsafe fn` under edition 2024 and the workspace
  forbids `unsafe_code` in test binaries too. The same trick appears in
  `sessions_directory` and `config_file`. When you see a `lookup` parameter in
  this repo, that is why.

The key is wrapped in `secrecy::SecretString` the moment it is resolved, and the
guide is careful about what that does and does not buy:

> **It does implement `Debug`** — printing a redaction, which is the entire
> reason the key is wrapped in it… `Display` is not implemented, so `{}` is a
> compile error.
>
> So the no-leak guarantee rests on a **runtime test**
> (`debug_output_does_not_leak_the_api_key`), not on the compiler.

Now the part that matters for the agent. **A sandboxed tool is handed no
credential at all.** The environment a `bash` call runs in is the
`--allow-env` allowlist and nothing else, and one name is refused outright:

```rust
/// Checked before the file, and the one name `agent-run` refuses to `--allow-env`
/// — see `context/decision-tool-credentials.md`.
pub(crate) const ENV_VAR: &str = "ANTHROPIC_API_KEY";
```

That refusal is decidable from argv alone, which is why it can exist at all —
[decision-tool-credentials.md](../decision-tool-credentials.md) establishes the
rule that the two run subcommands may differ by a *refusal*, never by a policy.
And in `AgentRun::policy` it is checked **first**, ahead of the
working-directory guard, because a working-directory refusal landing before it
would mask it.

By name and not by pattern, which the record is explicit about: a denylist over
`*_KEY`, `*_TOKEN`, `*_SECRET` is a *prediction* about naming, and the honest
claim is the one constant the harness itself dereferences.

The path routes are closed separately, by
[decision-harness-owned-paths.md](../decision-harness-owned-paths.md), and this
is the piece most readers do not expect. `--allow-read ~/.config` would hand a
tool the credential file (#184); `--allow-write` over the session root would let
one turn choose what the next turn is told it said (#173). Subtraction was never
available — Landlock composes rules by union and has no exclusion form, so a
ruleset cannot say "everything under `$HOME` except one path"; adding the
narrower rule *adds* access. So both on-disk roots are refused instead, in
either direction, by `reaches_owned` in
[`cli/src/grants/root.rs`](../../crates/sandbx-cli/src/grants/root.rs) — a grant
above the root and a grant naming one file inside it both fail. The operator's
escape is not a flag: point `XDG_STATE_HOME` elsewhere and the refusal moves
with it, which says where the state went instead of leaving sandbx holding state
inside a tree it just handed away.

`/proc/<harness-pid>/environ` is the third route (#192), and it is closed by
sandbx hiding its own process rather than by refusing `/proc`, because a path
refusal would cost `sandbox-run` a legitimate use for a hazard that is not about
a path at all.

## The session store

[`sandbx-session`](../../crates/sandbx-session/) is a small crate with a strict
remit: a name, a directory, a file of lines, and the rules for reading one back.

### An id is an allowlist, and that is what makes it a path component

`SessionId` wraps a private `String`, so one cannot exist without having passed
`FromStr` — which is what lets `path_for` join it to a directory unchecked:

```rust
    /// Accepts one to 32 characters of `0-9` and `a-z`, and nothing else.
    ///
    /// An allowlist, not a search for `..`: a denylist's first omission is a traversal.
    fn from_str(value: &str) -> Result<Self, SessionError> {
```

Read that comment as a general rule. A denylist checking for `..`, `/` and a
leading `-` is a list you have to keep complete forever; an allowlist of 36
characters is complete by construction, and `--session` takes its value straight
off argv. The id is base36 of the millisecond it started, and its doc warns it
is **not a sort key** — it gains a digit as the clock grows, so it sorts by
length first. Order a listing by the header timestamp instead.

### The roots it will use, and the one it will not

`sessions_directory` tries `$XDG_STATE_HOME` if absolute, then `$HOME` if
absolute, joining `.local/state/sandbx/sessions`, and otherwise returns
`NoStateHome`. The error is the interesting branch: a host with nowhere to keep
state gets a refusal rather than a fallback, and the fallback it refuses to make
is the working directory — for the reason quoted above, that a transcript there
sits inside the tree a no-flag run grants a tool write over.

### Append-only lines, and the fold that replays them

A transcript is a JSONL file: one record per line, internally tagged, appended
and never rewritten. `Record` has three kinds — a `Header` that must be line 0,
a `Message`, and a `Turn` carrying what the round cost — and an unknown `type`
fails the parse rather than being skipped.

Why lines rather than one JSON document: an append is one `write_all` of one
buffer, so a crash mid-write can only truncate the tail. `fold` in
[`store/record.rs`](../../crates/sandbx-session/src/store/record.rs) turns that
into a rule with exactly one exception:

```rust
    // No newline after the last line means an append that did not finish, and dropping
    // it restores the last consistent state. That line only: an interior line that will
    // not parse may be a message, so it refuses.
    let torn = !body.ends_with('\n');
```

The missing trailing newline is the signal, and the forgiveness applies to the
**last** line only. An interior line that will not parse is a `Malformed` error
with a line number, because it may be a message, and silently dropping a message
would change what the model is told it said. If the only line was a torn one the
header was never read, and `MissingHeader` says so.

`resume` runs its checks in an order that is the usual house pattern — the
directory before the file, because a directory another user may write makes the
file's own mode irrelevant:

| step | refuses |
|---|---|
| open the root | a missing root is `NotFound` for that id, which is what was asked |
| root mode and uid | `WRITABLE_BITS`, or a `ForeignOwner` |
| open the transcript `O_NOFOLLOW` | a symlinked leaf, reported by errno rather than the unstable `ErrorKind::FilesystemLoop` |
| transcript mode and uid | `WRITABLE_BITS`, or a `ForeignOwner`. `READABLE_BITS` sets a flag and resumes |
| `fold` | a torn interior line, a bad header, an unsupported version |
| shape | an unanswered `tool_use`, a non-alternating history, one that opens on the model's reply |

The shape checks run over **the whole history, not just its end**, because a
hand-edited file can hold an illegal pair of user turns anywhere. They are shape
and not provenance: no `tool_use_id` is matched against the call it claims to
answer.

There is a gap the mode check cannot close, and it is worth knowing where the
defence actually lives. A tool running inside your own `agent-run`, granted
write over the session root, rewrites the transcript with your uid and leaves
the mode at `0600`. Nothing the read path can see distinguishes that from you
editing it — so the CLI refuses the grant instead (#173), which is the
`reaches_owned` mechanism above. The mode check keeps what it can actually
answer: a transcript another user owns or can write.

### The stored types are this crate's own

`Message`, `Role`, `Content` and `Usage` in
[`session/src/message.rs`](../../crates/sandbx-session/src/message.rs) look like
duplicates of the provider crate's types, and the module doc explains that they
are deliberate:

> Mirrors `sandbx_providers`'s `RequestMessage`, `Role` and `ContentBlock`, and
> `sandbx_agent`'s `PromptUsage`, declared again so this crate depends on no
> other; `sandbx-cli` translates, and fails to compile on a new block kind.

Two things are bought by that duplication, and both are about a file that
outlives the build that wrote it. First, the on-disk format stops being a
hostage to a vendor type: a provider adding a content block cannot silently
change what a transcript means, and the translation in `sandbx-cli` is where a
new block kind has to be decided about — as a compile error. Second,
`sandbx-session` depends on no other workspace crate, so the crate that owns the
file format cannot be changed by changing something else.

The cost is real and is the thing to look for when you touch either side: the
two type sets have to be kept in correspondence by hand, and the only thing
enforcing it is that the translation does not compile when they diverge.

## You should now be able to explain

- Why the audit trail is separated from diagnostics by target rather than by
  level, and what each half of `Targets::new().with_target(…)` keeps out.
- Why every audit event is at `INFO`, in terms of the defect that made it so.
- Why `allowed` is emitted after the open rather than after the check, and what
  `absent` exists to record.
- Why `absent` is never used for a path outside a grant.
- Why the helper installs no subscriber, and why that is load-bearing rather
  than an oversight.
- Why the helper's channel is in the stdin slot specifically, and what stage 2
  does to it before becoming the command.
- Why a too-wide `credentials.toml` makes sandbx refuse rather than `chmod` it
  back, and which single command tolerates it.
- Why the transcript tolerates a shared *read* bit where the credential does
  not.
- Where an API key may come from, in what order, and the one environment
  variable name `agent-run` refuses to pass a tool.
- Why `--allow-read ~/.config` is refused rather than carved out.
- Why a `SessionId` is an allowlist and what that buys the code that joins it to
  a path.
- Why a transcript is a file of lines, and which single line a parse is allowed
  to forgive.
- Why `sandbx-session` declares its own message types instead of using the
  provider crate's.

## Next

[15 — the seven tools, and the screen](15-tools-and-the-screen.md): what each
built-in may touch, what bounds one, and the surface a turn is reported on when
it is not a pipe.
