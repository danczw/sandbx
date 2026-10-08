# Every gap here is either ticketed or named out loud

This chapter is the only one that stands in no single box of
[04 — the architecture](04-the-architecture.md). It stands at the *edges* of
every box in 04's third view — the six named boundaries — because a gap is what
one of them does not reach. 04 draws where the lines are; this chapter walks the
far side of each.

Two maps, and they are different kinds of document.

- **The project's own.** What `SECURITY.md`, the guides and the decision records
  already say is missing or coarse, each against the issue number that scopes it
  where one exists.
- **The reader's.** The objections the earlier chapters raised in their **Worth
  questioning:** bullets, each resolved against the decision record that already
  considered it — or marked genuinely open.

The reason to keep them apart is that they ask for different things. An entry on
the first map needs no argument; somebody already made it, and it is written
down. An entry on the second is a claim that something was not weighed, and it
has to show the record it read.

## The project's own map

### Gaps with an issue number

| gap | what the issue scopes | cited in |
|---|---|---|
| `FsGuard` measures a root and then performs the access beneath it | #230 — the window, and the `openat2(dirfd, …, RESOLVE_BENEATH)` shape that closes it | [`SECURITY.md`](../../SECURITY.md), [guide-sandboxing.md](../guide-sandboxing.md) |
| approval is per tool per run, not per call, by default | #165 — the scope of an approval, and the twenty-prompt turn a per-call default would cost | [`SECURITY.md`](../../SECURITY.md), [decision-approval-gate.md](../decision-approval-gate.md) |
| a pin covers the entry point, not what it goes on to run | #146 — what a digest over one image does and does not fix | [`SECURITY.md`](../../SECURITY.md), [decision-pinned-entry-point.md](../decision-pinned-entry-point.md) |
| a stored credential is protected from other users, not from the agent | #184 — the config-directory route to the key, and the refusal that closes it | [`SECURITY.md`](../../SECURITY.md), [decision-harness-owned-paths.md](../decision-harness-owned-paths.md) |
| an interrupted turn leaves no transcript of itself | #133 — what a stopped turn loses, and the live-session shape that would not lose it | [`SECURITY.md`](../../SECURITY.md), [decision-approval-gate.md](../decision-approval-gate.md) |
| a running tool call cannot be interrupted | #26 — cancellation, against a blocking task that runs to completion once spawned | [`SECURITY.md`](../../SECURITY.md), [guide-turn-loop.md](../guide-turn-loop.md), [guide-tools.md](../guide-tools.md), [guide-tui.md](../guide-tui.md) |
| a port allowlist bounds the port and not the host | #145 — destinations, and the resolver grant that bounds names instead | [`SECURITY.md`](../../SECURITY.md), [decision-egress-proxy.md](../decision-egress-proxy.md), [decision-port-allowlist.md](../decision-port-allowlist.md) |
| x32 is killed as an ABI rather than enumerated per call | #117 — the mask over the syscall number, and the four calls that sit at different x32 numbers | [guide-sandboxing.md](../guide-sandboxing.md) |

Two of those rows deserve a note, because reading the table without them
misleads in opposite directions.

**#117 is not a gap at all, and finding that out is the exercise.** It is cited
where the *mechanism* is explained — a mask over the syscall number rather than
a list of x32 numbers, hand-assembled as classic BPF because the filter
library's conditions address syscall arguments and the number is reachable only
as a filter key. The residual it carries is a behaviour, not a hole: x32 dies by
signal instead of getting an `EPERM`, which is the intended outcome for an ABI
whose numbers mean something else. A number beside a sentence is not evidence
that the sentence describes a weakness, and the only way to know which it is is
to read where it is cited.

**#230 is the row that is a boundary's own edge.** It sits under the property
that says the path a grant was vetted as is the path the kernel is told about —
the one property both enforcement seams implement, by different means. The seam
that spawns closes the window with a readback and an object pin before it hands
the kernel anything; the in-process seam re-measures and *then* opens, so the
window is a few syscalls for the five per-path tools and the whole traversal for
the two that walk. Same property, two mechanisms, one of them not yet closed.

### Gaps carried without an issue number

These are written down and have no number beside them. The distinction matters
more than it looks: a gap nobody has written down is invisible, a gap documented
without a number is visible but unfilable-against, and a gap *declined on a
record* is neither — it is a decision, and treating it as a gap is a misreading.
All five below are in the middle category.

- **The harness is unconfined.** The one process that parses untrusted input —
  the model's output, and file contents arriving as tool results — carries no
  ruleset and no filter. It is an explicit non-claim in
  [`SECURITY.md`](../../SECURITY.md) rather than something to be discovered, and
  that is the whole of its treatment: no number, and no record arguing either
  side. [04](04-the-architecture.md) raises it as an objection, and this chapter
  carries it below as an open one.
- **The helper's supervisor stage is unconfined.** Also an explicit non-claim,
  and structurally so: stage 1 has to be able to spawn the stage that installs
  the ruleset, which is why there are three processes rather than two. This one
  has no number because there is nothing to file — the alternative would be a
  process that confines itself before creating the child that is supposed to be
  confined.
- **The capability bounding set is dropped best-effort.** Clearing it needs
  `CAP_SETPCAP`, which an LSM may strip from a user namespace an unprivileged
  process created, so on such a host the set stays as inherited. The run
  continues with a `degraded` record on the audit trail at `INFO` rather than
  refusing, because with the other four sets empty and `no_new_privs` set the
  kernel will not let an `execve`d binary raise a capability — so the bit cannot
  be spent. `drop_bounding_set` in
  [`hardening.rs`](../../crates/sandbx-core/src/helper/hardening.rs) is where
  that is decided, and [guide-sandboxing.md](../guide-sandboxing.md) carries it
  in its own known-gaps table with the test that pins it on any host.
- **Nothing bounds CPU, memory or process count.** cgroups are not in place, and
  the only `setrlimit` anywhere in the workspace is `RLIMIT_CORE = 0`, which is
  a disclosure control rather than a resource bound. So a fork bomb runs
  unbounded for the length of the call; what *is* bounded is that it does not
  outlive it, by the PID namespace and the kill chain in
  [guide-process-lifetime.md](../guide-process-lifetime.md) — which is also
  where the absence is stated plainly. `bash` has a wall-clock default and
  `sandbox-run` an opt-in `--timeout`; neither is a resource limit.
- **Unix sockets are one toggle.** `--allow-unix-sockets` grants every pathname
  socket the filesystem policy can reach — an agent socket, a container daemon's
  socket, the session bus — because seccomp cannot follow the pointer to
  `connect`'s path and Landlock gained a path-scoped right only at a level the
  negotiation cannot reach in practice.
  [guide-sandboxing.md](../guide-sandboxing.md) names both the right and the
  fact that hard-requiring a whole ABI level means that right would bring no
  automatic narrowing even once it is available: the grant has to be written.

One more sits a layer up and is the clearest case of the middle category: **tool
calls run one at a time, and two tools sharing one `ExecutionContext` have no
ordering semantics.** [guide-turn-loop.md](../guide-turn-loop.md) says
`answer_calls` runs them sequentially and
[decision-approval-gate.md](../decision-approval-gate.md) leans on it — the
gate's whole no-racing argument depends on it — but neither cites a number for
it, and nothing in `context/` or `SECURITY.md` does. The tracker's own entry is
#242. Until a `context/` sentence names it, the behaviour is documented, the
dependency on it is documented, and the two cannot be joined up by anybody
reading the repo alone.

And the contrast case, so the categories stay distinct: a credential held by the
OS keyring is *not* on this map.
[decision-credentials.md](../decision-credentials.md) prices it and declines it
outright, saying in as many words that there is no issue for it. That is the
shape `CLAUDE.md` asks for — a decision that held goes in a record, not a
"planned" line in a doc — and reading it as a gap would invert its meaning.

## The reader's own map

Each **Worth questioning:** bullet in the chapters on disk, resolved. The
verdict is one of three: *answered* by a record that weighed it, *partly
answered* by a record that weighed a neighbouring question, or *open* — no
record asks.

Grouped by the chapter that raised it, so a chapter written later adds a `###`
of its own and nothing above it moves. A chapter with no section raised no
objection — [03](03-the-landscape.md) is the deliberate case, since critique of
another project is out of this set's scope and its closing comparison states
sandbx's own costs as description rather than as a complaint.

### From 01 — what sandbx is

- **The Linux-only trade.** Per-run, per-path precision is bought by refusing to
  run where the kernel will not cooperate, while a container-based harness runs
  anywhere a container runs. **Open.** The decision records argue the *shape* of
  the boundary — which primitive, which axis, which refusal — and none argues
  the choice to own one. There is no record to engage, which is itself the
  finding: the project's foundational trade is the one trade with no
  `decision-*.md`.
- **Whether the derived default should be shared as well as the flags.** Under
  `sandbox-run` a human chose the command; under `agent-run` a model did,
  perhaps at the direction of text it read out of a file. A read-only derived
  default for `agent-run` would keep one `Grants` and make the asymmetry
  explicit. **Answered, by a record the aside does not cite.**
  [decision-tool-credentials.md](../decision-tool-credentials.md) sets the rule
  that the two run subcommands may differ by a *refusal* and never by a policy:
  `agent-run` may return an error where `sandbox-run` succeeds, but it may never
  return a quietly narrower success. A read-only default for one subcommand is
  exactly that forbidden shape, and
  [decision-harness-owned-paths.md](../decision-harness-owned-paths.md) applies
  the same rule when it puts its own guard on both subcommands "because a
  refusal is all it may be". The objection survives only if reframed as a
  refusal — an `agent-run` with no path flag erroring and naming the two flags
  to type — which is a different proposal from the one the aside makes.

### From 02 — what a harness is

- **An unmodeled wire tag is dropped without a word.** The unknown arms of the
  raw event and delta enums, and the text-or-unknown arm of a block start, all
  evaluate to nothing, and `sandbx-providers` has no `tracing` dependency, so no
  sink could record one if they wanted to. **Partly answered.**
  [decision-provider-seam.md](../decision-provider-seam.md) names SSE
  accumulation as exactly where a wrapper crate helps least and closes by
  stating the weakness it leaves rather than designing around it — but the
  weakness it names is the accumulation's difficulty, not a fold able to discard
  a block silently. The consequence is sharper than it looks: a reasoning
  block's signature covers every message before it, so an assistant message that
  differs from what the model produced is precisely what that check catches, and
  it would fail with nothing pointing at the cause.
- **Nothing in the shipped binary can switch compaction on.** The default is
  none, both sites that build the limits override only the round count, and
  there is no flag. The deepening-cut path is exercised only by a test.
  **Partly answered.** [guide-turn-loop.md](../guide-turn-loop.md) prices the
  *default* fully — compaction is the only lossy bound, and its right value is
  not the crate's to guess, because the model is a freeform string with no
  context-window table behind it. That argument holds and the chapter grants it.
  It does not reach the absence of any way for the operator to state the value,
  and the operator is the one who chose the model.

### From 04 — the architecture

- **Whether the harness could confine itself with Landlock once the policy is
  derived.** By the time the execution context is built, the harness's own needs
  are known: its session directory, its credential file, egress to the provider,
  the granted roots, and execute on its own image. **Open.** No record asks it;
  every one of them reasons about confining *the command*.
  [decision-harness-owned-paths.md](../decision-harness-owned-paths.md) is the
  nearest neighbour and answers a different question — how to keep a *grant* off
  the harness's files, not how to keep the harness off anything. The aside
  states the hard part with the idea, which is the form that makes it worth
  filing: a ruleset is irreversible, so any path discovered later would have to
  move ahead of it or stop being possible.

### From 05 — the seven crates

- **The lint opt-in is per crate and cargo cannot require it.** An eighth crate
  omitting the workspace lints inherits no forbidden `unsafe`, no mandatory docs
  and no spawn ban, and neither the build nor CI would say so. **Open, and the
  aside is right that there is nothing to choose between** — the gap is cargo's,
  so no record is missing. What makes it filable is the mechanism the repo
  already owns:
  [`context_docs.rs`](../../crates/sandbx-core/tests/context_docs.rs) is a Rust
  test that walks the repo and asserts a property of files outside its own
  crate, and a test reading every crate manifest would borrow that walk.

### From 06 — claims and non-claims

- **The scope sentence does not name the in-process layer.** Read on its own the
  claim table says "Landlock" over a product in which six of seven tools never
  reach Landlock. **Partly answered.**
  [decision-enforcement-seam.md](../decision-enforcement-seam.md) opens by
  insisting there are two seams and that most tools cross only the first, so the
  fact is recorded; what no record weighs is whether the normative document's
  own scope sentence should carry it, which is where a reader starts.
- **The installed binary is the one harness-owned path no refusal covers.** A
  no-flag run from a user-level install prefix derives write over the directory
  holding the binary. **Partly answered, and the records disagree about the
  frame.** [decision-default-policy.md](../decision-default-policy.md) removed
  the guard that would have caught it and is explicit about the residue, on the
  ground that the old check compared a name nothing is reached by and fired in
  ordinary use; that reasoning is about the spawn *inside* this run, which the
  inode closes.
  [decision-harness-owned-paths.md](../decision-harness-owned-paths.md) frames
  on-disk state the harness owns as refusable from argv, and does not weigh the
  binary in those terms.

### From 07 — the kernel primer

- **Nothing records which ABI rung the negotiation took.** The same policy
  enforces a different handled set on two kernels, and the only evidence of the
  difference is the command's own `EACCES`. **Partly answered.**
  [decision-helper-audit-channel.md](../decision-helper-audit-channel.md) chose
  a one-way channel carrying mechanism names from a closed set precisely so the
  command cannot forge a record — reasoning about forgeability, which a rung is
  not subject to, since it is the kernel's answer to a probe. A fixed-vocabulary
  record naming the rung looks compatible with everything that record decided,
  which is the argument to put to it.

### From 08 — the two-stage helper

- **The inner stage's flag is public, so half the helper is reachable on its
  own.** Invoked directly, the lifetime arming binds to the invoking shell, the
  parent confirmation passes for anyone who passes their own pid, and `apply`
  then installs a real ruleset and a real filter around a process still in the
  host's network namespace — so a policy that denies network, which relies on
  the empty namespace rather than on the filter, loses that part entirely.
  **Partly answered, and correctly scoped by the aside itself:** this
  contradicts no claim, because every claim is scoped to a command run through
  `SandboxedCommand`, and anyone who can choose sandbx's argv could run the
  command directly. The objection is about the public surface.
  [decision-enforcement-seam.md](../decision-enforcement-seam.md) is the record
  to argue with — it reasons about the argv seam on the premise that neither
  side is trusted and that the helper can only ever narrow — and a stage that
  narrows less while still succeeding is the one outcome the dispatch enum's
  shape cannot catch.

### From 09 — Landlock

- **No flag can produce the write-only directory the rights subtraction exists
  to protect.** `--allow-write` grants read alongside write, so the asymmetry
  the longest comment in the rights module defends is invisible to every
  operator. **Partly answered.**
  [decision-axis-table.md](../decision-axis-table.md) settles the CLI's one
  departure from the axis table by noting the narrow form stays reachable
  through the library (#49) — a real property about the flags not drifting — and
  does not weigh whether an operator who wants a drop directory has any way to
  ask for one.
- **The remedy that needs no pin was rejected on a lint.** Inheriting the
  harness's own `O_PATH` descriptor through the `exec` would leave nothing to
  re-resolve helper-side. **Answered, and the record says what it answered on.**
  [decision-grant-identity.md](../decision-grant-identity.md) declines it
  because receiving and passing a descriptor both need `unsafe` against a
  workspace-wide `forbid`, and states in as many words that this is rejected on
  the lint and not on the design. What it does not do is price the lint against
  the two limits its own costs section enumerates — a reused inode, and an
  anonymous device number — neither of which a held descriptor has. That is the
  open half.

### From 10 — seccomp

- **The one flag that both narrows and widens the boundary says only the
  narrowing out loud.** A port allowlist makes the network grant true, so the
  network namespace is not unshared and the command lands in the host's — host
  loopback reachable on an allowlisted port, and the host's abstract unix socket
  namespace no longer isolated. **Partly answered.**
  [decision-port-allowlist.md](../decision-port-allowlist.md) is plain that the
  namespace drop is forced and concludes "narrower on remote ports, wider on
  what is local", which [`SECURITY.md`](../../SECURITY.md) repeats. What neither
  weighs is that the flag carries none of it: a port list reads as a narrower
  network grant, and the widening arrives as a side effect of asking for less.
  [decision-default-policy.md](../decision-default-policy.md) settles a close
  cousin with "narrow and loud beats wide and silent", and the missing step is
  the loudness rather than the mechanism.

### From 11 — the two seams

- **`check_read` and `check_write` stay public although nothing in production
  calls them.** They bound nothing after the measurement, their own docs say to
  prefer the opening forms, and every call site is a test. **Open.**
  [decision-enforcement-seam.md](../decision-enforcement-seam.md) marks them "no
  tool" and [`SECURITY.md`](../../SECURITY.md) carries them as a non-claim, so
  the exposure is known; neither prices why the pair stays public once the
  window-closing forms exist, and
  [decision-default-policy.md](../decision-default-policy.md) refuses the same
  trade elsewhere by keeping a seam private rather than widening it for a test.
- **Seam 1 has no chokepoint lint.** A direct spawn is a build failure because
  `clippy.toml` denies the constructor workspace-wide; nothing stops a future
  in-process tool from opening a file directly, and the audit record is emitted
  by the guard it would skip. **Open.** No record weighs it. The argument
  against the status quo is 04's own: this repo's recurring move is converting
  "did we remember?" into a build failure, and the closed `BuiltinTool` enum
  forces a new tool to be *handled* everywhere, not to be handled through the
  guard.

### From 12 — a flag to a kernel rule

- **The owned-path refusal's precondition is held by a debug assertion.** Its
  comparison requires the granted side to have arrived already resolved, and
  what holds that is a doc comment plus a `debug_assert!` — which is compiled
  out of the release build that ships. **Partly answered.**
  [decision-harness-owned-paths.md](../decision-harness-owned-paths.md) reasons
  carefully about *which* spelling must reach the comparison, and the owned side
  normalises itself inside the function; what it does not weigh is making the
  caller's side unforgeable, which this codebase already knows how to do.
  `VettedPath` is exactly that move one layer down — a path that cannot be
  unpinned, because `grant` accepts nothing else — so a newtype returned by the
  resolver and demanded by the comparison would turn a debug-only assertion into
  a build failure.
- **Keying the CLI's one departure to a derived boolean widens automatically.**
  A fifth axis that confers write would inherit the CLI's read grant without
  anybody opening the flag module. **Partly answered, and the sibling of 09's
  drop-directory objection above — same departure, opposite direction.**
  [decision-axis-table.md](../decision-axis-table.md) presents the keying as the
  safe default, which it is for *forgetting*; every other new-axis story in that
  record turns on a new axis having to visit each site that decides something
  about it, with the suite failing until it does. The two goals conflict here
  and only one is priced.

### From 13 — the turn loop and the gate

- **The refusal text names one remedy and not the safer one.** An unapproved
  tool's refusal names the tool-allow flag and never the per-call approval mode.
  **Partly answered.** [decision-approval-gate.md](../decision-approval-gate.md)
  rests the whole decision to offer the model all seven tools on that message
  existing — a tool the model was never offered cannot tell the operator which
  flag to pass — and weighs whether the signal exists, not what it says. What it
  says is the less supervised of the two remedies, offered to an operator who
  has just been told a model wanted a shell.
- **A refusal decidable from argv is repeated to the round limit.** The verdict
  is recoverable by design, so the loop keeps opening a stream although argv is
  fixed for the run and no later round could be approved either. **Partly
  answered.** The same record states the cost precisely and treats it as the
  reason the abort verdict had to become a public variant rather than a latch in
  the CLI; the argument is simply not applied to the flag case, where it is
  *more* decidable. Its stated reason for keeping it recoverable — a tool no
  flag approved is a decision — is a claim about the verdict's identity, not
  about repeating it. #218's defect was filed against a turn that re-opened a
  stream with nobody to answer.

### From 14 — audit, sessions, credentials

- **The trail never records a `bash` command's text.** Every spawn records the
  shell as the program, so the one model-chosen input in the whole turn is the
  one thing the record omits. **Partly answered.**
  [guide-logging.md](../guide-logging.md) sets the metadata-only rule, and the
  fixed-width record is a real counter-argument (#146). But the pin field's own
  stated principle points the other way — not the digest, which is already in
  the process's own command line, but the fact that it was checked, because that
  is what an auditor cannot otherwise recover — and a command line is gone at
  exit. The gate already caps and strips a subject for display (#234).
- **A gate refusal reaches nothing on the audit target.** **Partly answered.**
  [decision-approval-gate.md](../decision-approval-gate.md) is sound about why
  a denial is not an access and so has no access to record;
  [decision-audit-records-access.md](../decision-audit-records-access.md) makes
  the decision field a wire field where adding a value is additive. Neither asks
  whether the refusal deserves a value of its own. In its sharp form: a `bash`
  the *policy* refuses is on the trail, and a `bash` the *operator* refuses is
  not — so an auditor who follows the one filtering instruction the subsystem
  prescribes reads a trail in which the agent only ever succeeded.

### From 15 — tools and the screen

- **Two tools read a whole file with no size cap, where the searching one has
  had one all along.** **Partly answered.**
  [decision-bounding-tool-work.md](../decision-bounding-tool-work.md) names the
  gap in its own words and does not price a fix. Two properties established
  elsewhere in this set compound it: the allocation happens on a thread that
  cannot be cancelled (#26), and the read-only risk level means the smaller of
  the two runs with no flag and no question. The record could have argued that a
  cap breaks a correctness contract — a silently skipped file in a search is
  tolerable where a silently truncated read is not — but that is an argument for
  failing loudly above a size, not for no bound.
  [`SECURITY.md`](../../SECURITY.md) claims no memory bound, so the claim is
  honest and only the mechanism is in question.
- **An interrupted turn and a round-limited turn share one exit code.**
  **Partly answered.** [guide-tui.md](../guide-tui.md) justifies it in four
  words, that this is what it is. The two differ in their post-conditions, which
  is the thing a script branches on: a round-limited turn appended to the
  session and left nothing running, while an interrupted one stored nothing and
  may have a shell still writing files.
  [decision-approval-gate.md](../decision-approval-gate.md) already made the
  distinguishability argument in this exact direction, and that the screen
  cannot currently reach the third code is not a reason to reuse the second —
  it is the condition under which the same record chose to add a code before
  anything could produce it (#218).

### From 16 — how the repo is maintained

- **The context-docs test cannot see this chapter set.** It reads `context/`
  with one non-recursive directory listing filtered to `.md` files, so the
  `onboarding/` subdirectory is skipped whole and a chapter citing a guide or
  record that does not exist passes. **Open.** No record states the test's
  scope; the strongest argument the file supplies against a wider read is its
  own root-docs one — a glob picks up untracked files, so the set under test
  would differ per checkout — and that is answerable by naming the subdirectory
  exactly as the root docs are named.

Later chapters will add to this list. A new `###` for the chapter, and a bullet
per aside carrying the same verdict vocabulary, is the whole of what appending
costs.

## From an objection to a filed issue

This chapter files nothing, and that is deliberate: the step between an
objection and an issue is a human one. [`CLAUDE.md`](../../CLAUDE.md) sets the
path.

1. **Draft it, and wait.** The maintainer's okay comes before `gh issue create`,
   not after. An objection that has not been agreed is a paragraph in a chapter,
   which is where the ones above live.
2. **Write the title as the defect, not the feature.** The security-labelled
   issues in this repo read as sentences about what goes wrong — a grant checked
   in one process and opened in another, a refusal that reads as an exit code 1
   — rather than as the fix. A title that names the mechanism is one a reader
   can check against the code.
3. **Label it.** A `crate:*` label per crate the change materially touches, and
   none at all where the change is workspace-wide or lands outside `crates/`. A
   security-relevant one takes `security` and a severity; one about the audit
   trail takes `audit`.
4. **Milestone it, or do not.** Milestones are releases, one per tag: work being
   worked on *now* takes the next release, and a closed issue takes the one it
   shipped in. **No milestone is not a defect — it means unscheduled**, which is
   the honest state of most of the second map above.
5. **Assign it.** House convention on this repo is that an issue is assigned
   when it is created.

Two things not to do. Do not write "planned" into a `context/` doc — that is the
line `CLAUDE.md` replaces with an issue, because an issue can be closed and a
doc line cannot. And do not write a status next to a number anywhere in
`context/`: whether an issue above is open is a question for GitHub, and a
sentence that answered it starts being wrong the day it merges.

One case leaves this path entirely. **A mechanism that does not match a claim in
`SECURITY.md` is a finding, not an objection.** `CLAUDE.md` requires one of the
two to change — the claim is weakened, or the mechanism is widened to match — so
it goes to the maintainer directly rather than becoming a bullet in a chapter.
The same is true of a non-claim that is *too pessimistic*: a document that
understates what the code does is drift in the cheaper direction, but it is
still drift, and leaving it makes every other sentence in the document slightly
less worth believing.

## You should now be able to explain

- Why a gap with an issue number, a gap documented without one, and a thing
  declined on a decision record are three different states rather than two.
- Why an issue number cited beside a sentence is not evidence that the sentence
  describes a weakness, and how to tell which it is.
- Which two processes are unconfined, which of the two is unconfined
  structurally, and why neither carries a number.
- What bounds a fork bomb started by a sandboxed command, and what does not.
- The rule that decides the shared-derived-default objection, and why the
  objection survives only when restated as a refusal.
- Which of the collected objections have no decision record to engage at all,
  and why that absence is the strongest part of the case for filing them.
- The five steps from an agreed objection to a filed issue, and the one kind of
  finding that skips them.

## Next

Nothing in this directory — this is the last chapter. What follows the set is
the numbered reading order at the end of
[guide-repo-map.md](../guide-repo-map.md), which names every `guide-*.md` and
`decision-*.md` in [`context/`](../) and is the second pass these eighteen files
were the on-ramp to. Read in that direction, a guide that opened cold on day one
should now read as a reference rather than as a wall.
