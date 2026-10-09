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
| tool calls run one at a time, and two sharing one `ExecutionContext` have no ordering semantics | #242 — sequential execution as a constraint rather than a choice, which the per-call gate's no-racing argument rests on | [guide-turn-loop.md](../guide-turn-loop.md), [decision-approval-gate.md](../decision-approval-gate.md) |
| `--allow-unix-sockets` may stop being sufficient on its own on a newer kernel | #259 — the path condition a V9 `ResolveUnix` adds to a flag documented as all-or-nothing | [guide-sandboxing.md](../guide-sandboxing.md), [decision-axis-table.md](../decision-axis-table.md) |

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
window is two adjacent syscalls across the four single-path tools and the whole
traversal for the two that walk. Same property, two mechanisms, one of them not
yet closed.

### Gaps carried without an issue number

These are written down and have no number beside them. The distinction matters
more than it looks: a gap nobody has written down is invisible, a gap documented
without a number is visible but unfilable-against, and a gap *declined on a
record* is neither — it is a decision, and treating it as a gap is a misreading.
All four below are in the middle category, and the category is not stable: two
entries that sat here while this set was being written have since acquired
numbers and moved into the table above, which is the movement it is meant to
make easy.

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

The two that left are worth reading as a pair, because they left for opposite
reasons. **Sequential tool execution** (#242) was documented in
[guide-turn-loop.md](../guide-turn-loop.md) and leaned on by
[decision-approval-gate.md](../decision-approval-gate.md) — the gate's whole
no-racing argument rests on it — with no number joining the two, so a reader of
the repo alone could not tell a constraint from a design choice. Both now cite
the number, and nothing about the behaviour changed. **Unix sockets as one
toggle** (#259) went the other way: the gap turned out to be stated backwards.
`--allow-unix-sockets` does grant every pathname socket the filesystem policy
can reach — an agent socket, a container daemon's socket, the session bus — but
the residual-gaps row said a V9 `ResolveUnix` would bring no automatic narrowing
and that a grant would have to be written, and both halves are wrong:
`handled_access` is `AccessFs::from_all(abi)`, so on a kernel settling at V9 the
right lands in the handled set and `connect(2)` is denied unless an axis confers
it, and the write axis confers it with nothing written. The consequence nothing
predicted is the one worth carrying: the same command with the same flags works
today and fails on a newer kernel, which is what the number is for. The
mechanism is [09](09-landlock.md)'s write-axis asymmetry, reached from the other
end.

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
- **The script refusal is two bytes wide and the hazard is not.**
  `starts_with_shebang` tests for `#!`, so a pinned image in any other format
  the kernel routes to an interpreter reaches the exec and gets the bare
  `cannot open /proc/self/fd/N` that the refusal exists to replace. **Partly
  answered.**
  [decision-pinned-entry-point.md](../decision-pinned-entry-point.md)
  reasons about the `#!` case, and the refusal's own message already states the
  correct general rule — pin an ELF binary — so the rule is right and only its
  test is narrow. Testing for the ELF magic instead would refuse the whole
  `binfmt_misc` class by the rule the message already gives, and would cost a
  pinned ELF nothing.

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
- **A summarised cap leaves no durable trace that it was a cap.** `merge` takes
  the wrap-up round's `stop` and a stored turn carries no stop reason at all, so
  a transcript where the model chose to answer and one where the harness made it
  answer are the same shape. **Partly answered.**
  [decision-round-limit-answer.md](../decision-round-limit-answer.md) prices the
  live channels and accepts that a script cannot tell the two apart, because
  "stderr is what distinguishes them" — and stderr is exactly what a session
  does not keep. Its storage section treats that half as settled by #188, which
  made a capped turn storable rather than recognisable.

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

### From 18 — the core crate

- **Concealment is detached from the thing it protects.** Everything else in
  this crate turns a rule a human would have to remember into something the
  compiler or the kernel holds; concealment is a `pub fn` that `main.rs` happens
  to call, and omitting it compiles, passes every test in the workspace and
  silently republishes the key. **Partly answered.**
  [decision-harness-owned-paths.md](../decision-harness-owned-paths.md) argues
  for the mechanism and for where the call sits, and does not weigh making the
  step unskippable. Nor is the wiring pinned — the test drives a purpose-built
  probe, which is evidence the `prctl` works rather than that `sandbx` calls it.
- **The refusal labels are a documented compatibility surface pinned almost
  nowhere.** `HelperRefusal::label`'s own doc says a trail is filtered by these
  strings, and two `context/` docs spell several of them out in prose; three are
  hard-coded in test assertions and the rest would survive a rename. **Partly
  answered.**
  [decision-helper-audit-channel.md](../decision-helper-audit-channel.md)
  thought carefully about the adjacent problem — it declines to state a *count*
  of the excluded reasons, deriving membership from the variants instead. The
  spelling is the half that argument does not reach, and
  [16](16-how-the-repo-is-maintained.md) describes the mechanism the repo
  already owns for exactly this.

### From 19 — the tools crate

- **A guarded read that fails is skipped with no marker.** `grep`'s per-file arm
  discards the error, which is right for the binary-file case it was written for
  and also swallows every refusal, so a grant substituted mid-walk comes back as
  "no matches". **Partly answered.**
  [decision-bounding-tool-work.md](../decision-bounding-tool-work.md) built its
  two-marker scheme against precisely this confusion — "a search that silently
  gave up looks identical to one that found 4,000 matches and showed 200" — but
  reasons only about the budgets, never about a candidate the guard refuses. The
  fix needs no new vocabulary.
- **A non-zero exit is an error for the whole call.** Right for `cargo build`,
  wrong for the family where a status *is* the answer, and the loss is upstream
  rather than in the model's view: `Outcome::Ran` is never recorded, so the
  operator's line and the trail both read "failed" about a command that did what
  it was asked. **Partly answered.** `error.rs` states the split as being by the
  agent's next move, and the record has drawn that distinction once already in
  the other direction (#180); no equivalent reasoning exists for an exit code,
  and the test that pins the behaviour does not argue for it.

### From 20 — the providers crate

- **The neutral half of the crate is held by convention, not by a check.**
  **Partly answered.** [decision-provider-seam.md](../decision-provider-seam.md)
  lists four mechanisms and each is genuinely enforced by the compiler; what it
  does not price is that the vendor's *name* has no enforcement at all, while
  the claim about it is stated absolutely in the places a maintainer reaches for
  first. The repo owns the shape of the answer in two existing prose-pinning
  tests, and the record's argument against inventing abstractions for a backend
  that does not exist does not reach this, because a grep is not an abstraction.
- **The frame cap stops at a layer boundary.** The SSE layer bounds a single
  frame precisely because an unbounded buffer is OOM-killed with no diagnostic,
  and the fold that concatenates those frames has no cap, so a gateway streaming
  valid in-cap fragments forever allocates until the process dies. **Partly
  answered.** What bounds it today is a wall-clock timeout owned by a *different
  crate*, which a library caller using this one directly does not get.
  [`SECURITY.md`](../../SECURITY.md) claims no memory bound, so the claim is
  honest and only the mechanism is in question; the record states the one
  weakness it accepts and this is not among them.

### From 21 — the agent crate

- **`Outcome` cannot tell a verdict the gate gave from one the loop gave on its
  behalf.** A call refused unasked behind an abort latch arrives in the same
  shape as a call the gate decided, and the CLI renders both as "refused".
  **Partly answered.** [decision-approval-gate.md](../decision-approval-gate.md)
  makes that exact distinction load-bearing one section earlier — those calls
  "are refused *unasked* rather than allowed on the strength of a verdict nobody
  gave" — and the enum then spends a variant on telling a policy refusal from a
  gate refusal, the same class of distinction, and nothing on this one.
- **Compaction's correctness condition is one no test in the repo can check.**
  The condition is that the API would still accept the request; what the suite
  compares it against is the repo's own model of what the API rejects, asserted
  through a script that accepts every request handed to it. **Open.** No record
  weighs the untestable condition, which is a different objection from the
  missing flag that [02](02-what-a-harness-is.md) raises — a flag would also be
  the first thing that could falsify the model. The cheap version is one
  recorded live run through a library caller, with the request bodies kept.

### From 22 — the session crate

- **A second header is skipped without its version being read.** The version
  gate runs only on line 0, so a transcript concatenated or hand-edited to carry
  a later header resumes with lines a v1 reader does not understand. **Partly
  answered.** [decision-on-disk-state.md](../decision-on-disk-state.md) refuses
  exactly that outcome when the version sits on line 0, because "a reader that
  silently dropped a field it did not understand would change the history the
  model is shown"; it weighs an unknown version and an unknown record type, and
  not a repeated header. The read path already assumes a transcript may have
  been edited — that assumption is why the shape checks run over the whole
  history rather than its end.
- **The create path repairs a wide root, where the rule one bit away refuses.**
  **Partly answered.** The record answers for the narrowing with "at create time
  the directory holds nothing a refusal would protect", which is sound about the
  session being created and silent about the directory's existing contents: a
  `sessions/` found world-writable may have held every earlier transcript while
  it was wide, and nothing records that it was. The asymmetry is sharpest
  against the transcript rule — a merely readable transcript resumes *and* sets
  a field, precisely so the operator hears about a disclosure that cannot be
  undone.
- **One refusal serves two call sites and is worded for one of them.**
  `IncompleteTurn` is raised by `append` and by `resume`, and its message ends
  "so there is nothing to append" — on the resume path nothing was being
  appended and a hand-edited transcript is what is wrong. It names no path,
  where every other refusal about a file does, and `sandbx-cli` compounds it
  from the other side by treating the variant as benign on the append path.
  **Open.** [decision-on-disk-state.md](../decision-on-disk-state.md) settles
  what `resume` must check and says nothing about what it reports when the check
  fails, so the record has not been asked whether the two cases want two
  variants.

### From 23 — the tui crate

- **The dependency graph carries less of the isolation than the guide implies.**
  Four crates' vocabulary is ruled out by a missing edge; the provider crate's
  client and credential resolver are not, so for those the guarantee is
  discipline where for the policy and the gate it is the compiler. **Partly
  answered.** [decision-provider-seam.md](../decision-provider-seam.md) argues
  by its own method — it sealed the vendor boundary by leaving `Prompt` with no
  `Serialize`, so nothing above can post a neutral type — and the same move is
  open here, priced against an eighth crate in a workspace whose seven are a
  feature.
- **The gutter authenticates sandbx's voice and nothing authenticates the
  operator's.** The prompt's mark is ASCII and let through deliberately, where
  the verdict mark has a backstop, and a wrapped continuation row starts in
  column 0 — so a row beginning with the prompt mark renders in the operator's
  own grammar. **Partly answered.** `GUTTER_MARK`'s comment gives the reason for
  letting it through, and [guide-tui.md](../guide-tui.md) already names the fix
  for the other mark: a gutter in an area of its own. Weaker than forging a
  verdict — misattributed authorship rather than consent — and not nothing
  either, the pane being the only record a `bash` call's text gets (#234).
- **A latched draw failure replaces the code the turn earned.** `drive` returns
  `AgentError::Screen` where one latched, which maps to 1 — so a turn cut short
  at its round bound exits 1 rather than 2 if the screen died anywhere in it,
  while the account naming the bound still reaches stderr. `agent-run` does the
  same with a closed stdout, in the same order, so it is a consistent choice
  rather than one subcommand's oversight. **Open.**
  [decision-approval-gate.md](../decision-approval-gate.md) weighs a third code
  against reusing the second, on the grounds that reuse would leave the defect
  "distinguishable only by grepping stderr" (#218) — and on this path the code a
  script reads is the output device's and the stop it configured is what is left
  on stderr to be grepped. The asymmetry is the thing nothing has weighed.

### From 24 — the cli crate

- **One grant failing its own identity check is dropped in silence.** It is the
  only place in the crate where that condition produces neither a refusal nor a
  line on stderr, and two policy errors exist for the same condition a moment
  earlier. **Partly answered.**
  [decision-grant-identity.md](../decision-grant-identity.md) is explicit that
  the window fails closed and that refusing is the right outcome, and weighs the
  window's security rather than its diagnosis. Nothing is unsafe — the guard
  measures the matched root per access — but the operator's answer is a model
  that quietly stops being told about a directory they granted.
- **`--no-wrap-up` is accepted and inert under `tui`.** The crate elsewhere
  treats one flag meaning two things across two subcommands as the thing to
  avoid, and refuses `--approve call` under `tui` rather than downgrading it
  (#225). **Open.**
  [decision-round-limit-answer.md](../decision-round-limit-answer.md) does not
  weigh `tui` at all: its case for the round rests on the alternative leaving
  "the common case with nothing on stdout", and `tui` does not use stdout for
  the answer. The record has not been asked whether the pane should get the
  summary, or whether the flag should be refused there the way `--approve call`
  is.

Appending to this list costs a new `###` for the chapter and a bullet per aside
carrying the same verdict vocabulary — which is what the seven crate chapters
did.

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

This is the last chapter of the read-through, and the end of the argument. What
is left in this directory is the crate reference — [18](18-crate-core.md)
onwards, one chapter per crate, read when you land in one rather than in order.

What follows the set is the numbered reading order at the end of
[guide-repo-map.md](../guide-repo-map.md), which names every `guide-*.md` and
`decision-*.md` in [`context/`](../) and is the second pass the read-through was
the on-ramp to. Read in that direction, a guide that opened cold on day one
should now read as a reference rather than as a wall.
