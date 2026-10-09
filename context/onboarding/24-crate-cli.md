# sandbx-cli is where argv becomes a policy, and the only crate with a binary

[`sandbx-cli`](../../crates/sandbx-cli/) is process 0 in
[04](04-the-architecture.md)'s View 1 — the unconfined one that "parses argv,
derives the policy, asks the model, decides, records". It is the only crate that
depends on all six others and the only one that produces a binary, so every box
in that drawing is reached from here. Read
[04](04-the-architecture.md)'s *The CLI architecture* section first: it states
the lib-plus-bin split, the five subcommands, and what `tui` shares with
`agent-run`. This chapter zooms into that section, file by file.

## The module tree, and who covers what

Twenty-one source files under [`src/`](../../crates/sandbx-cli/src/), ten
integration files under `tests/`, and six thematic chapters already owning
parts of them. So this table is the navigational centre of the chapter rather
than a decoration: it says what each file holds and, where another chapter
explains the mechanism, which one. The paths carry the nesting:
`grants/root.rs` is `grants.rs`'s only child, `agent.rs` has six, and `auth.rs`
and `error.rs` have one each.

| file | holds | covered in |
|---|---|---|
| [`lib.rs`](../../crates/sandbx-cli/src/lib.rs) | `Cli`, `Command`, and the `pub use` list that is the library's whole API | here |
| [`main.rs`](../../crates/sandbx-cli/src/main.rs) | helper dispatch, the tokio runtime, the exit-code mapping | here, and [08](08-the-two-stage-helper.md) for the dispatch |
| [`grants.rs`](../../crates/sandbx-cli/src/grants.rs) | every `--allow-…` flag, the axis loop, and the one widening it applies | [12](12-a-flag-to-a-kernel-rule.md) |
| [`grants/root.rs`](../../crates/sandbx-cli/src/grants/root.rs) | where a no-flag run may root a default, and what a path flag is vetted against | [12](12-a-flag-to-a-kernel-rule.md) |
| [`sandbox.rs`](../../crates/sandbx-cli/src/sandbox.rs) | `sandbox-run`: one of the two `SandboxedCommand` build sites in the workspace | [05](05-seven-crates.md), [12](12-a-flag-to-a-kernel-rule.md) |
| [`hash.rs`](../../crates/sandbx-cli/src/hash.rs) | the one subcommand that confines nothing | [12](12-a-flag-to-a-kernel-rule.md) |
| [`agent.rs`](../../crates/sandbx-cli/src/agent.rs) | `agent-run`'s flags and the one sequence that consumes them | here |
| [`agent/gate.rs`](../../crates/sandbx-cli/src/agent/gate.rs) | which tools `--allow-tool` approved, and `ArgvGate` | [13](13-turn-loop-and-gate.md) |
| [`agent/prompt.rs`](../../crates/sandbx-cli/src/agent/prompt.rs) | the terminal question, typeahead, and bidi stripping | [13](13-turn-loop-and-gate.md) |
| [`agent/orientation.rs`](../../crates/sandbx-cli/src/agent/orientation.rs) | the system prompt naming the approved tools and the granted roots | here |
| [`agent/render.rs`](../../crates/sandbx-cli/src/agent/render.rs) | the stdout/stderr split, and `finish`'s code | here, and [13](13-turn-loop-and-gate.md) for `finish`'s ordering |
| [`agent/wrapup.rs`](../../crates/sandbx-cli/src/agent/wrapup.rs) | the wrap-up round's mechanics | here; [13](13-turn-loop-and-gate.md) for why it is spent |
| [`agent/tui.rs`](../../crates/sandbx-cli/src/agent/tui.rs) | the `tui` subcommand, the interrupt, the drawing gate | [15](15-tools-and-the-screen.md), [23](23-crate-tui.md) |
| [`auth.rs`](../../crates/sandbx-cli/src/auth.rs) | the two key sources and `login`/`logout`/`status` | here |
| [`auth/store.rs`](../../crates/sandbx-cli/src/auth/store.rs) | the credential file: read, store, discard, and the modes | here; [14](14-audit-sessions-credentials.md) for the tiers |
| [`session.rs`](../../crates/sandbx-cli/src/session.rs) | `--session`, and the translation to and from the stored shapes | here, and [22](22-crate-session.md) |
| [`logging.rs`](../../crates/sandbx-cli/src/logging.rs) | the one `tracing` subscriber, and the hold the screen takes | [14](14-audit-sessions-credentials.md) |
| [`error.rs`](../../crates/sandbx-cli/src/error.rs) | `AgentError`, `SandboxRunError`, `PolicyError`, `HashError` | here |
| [`error/auth.rs`](../../crates/sandbx-cli/src/error/auth.rs) | `AuthError` | here |

## lib.rs is the clap surface and nothing else

The library root declares eight modules, re-exports twelve types, and holds two
clap derives. That is the file. No work happens in it, which is the point:
`Cli::parse` is reachable from a unit test, so "what does this argv grant" is a
question answered without a sandbox-capable kernel.

```rust
#[derive(Debug, clap::Parser)]
#[command(
    name = "sandbx",
    version,
    about = "A security-first AI coding agent harness",
    // Or clap derives the long help from the doc comment below and prints its note
    // about test visibility; `None` falls back to `about` for both forms.
    long_about = None
)]
/// A parsed `sandbx` invocation.
///
/// Public so a test can inspect what an argv grants without spawning anything.
pub struct Cli {
```

Its one field is the subcommand. `Command` is a five-variant enum, each variant
carrying the `Args` struct that owns its flags: `SandboxRun`, `AgentRun`, `Tui`,
`Hash`, `Auth`. Every variant carries a long `///` block, and those blocks *are*
the `--help` text — which is why `long_about = None` is set above, and why the
`Hash` variant's doc explains the circularity ("the digest has to exist before
there is a policy to pin anything under") rather than a comment doing it.
Reading `lib.rs` top to bottom is the fastest way to learn the CLI's behaviour.

The structural fact is what `Command`'s variants do *not* each declare. The
`--allow-…` flags live once, in `Grants`, and every subcommand that confines
something flattens that one struct:

```rust
#[derive(Debug, clap::Args)]
pub struct SandboxRun {
    #[command(flatten)]
    grants: Grants,
```

`AgentRun` opens identically, and `Tui` flattens `AgentRun` whole. So there is
one definition of `--allow-read`, one parser for it and one derivation from it,
which is why it means the same thing under `sandbox-run` and under `agent-run`.
Two copies would not have been duplication so much as a policy difference
wearing the same spelling: a widening applied in one place and not the other,
with nothing in the help text to distinguish them.
[12](12-a-flag-to-a-kernel-rule.md) traces one of those flags from argv to a
kernel rule. Two flags stay off `Grants` deliberately — `--timeout` and
`--pin-sha256` are `SandboxRun`'s own, the second because `agent-run` flattens
`Grants` with no fixed program for a digest to pin.

Which settles where a new flag goes. On `Grants` if it confines anything, so
every subcommand that confines gets it in the same breath; on `AgentRun` if it
shapes a turn, which `Tui` — whose whole body is one field, `run: AgentRun` —
then has without declaring a line of its own; and on a variant's own `Args`
struct only where no other subcommand could mean it.

## main.rs does four things, in an order that is three of them

```rust
fn main() -> std::process::ExitCode {
    // Must precede argument parsing: `SandboxedCommand` re-execs this binary as its
    // helper, which restricts itself and becomes the target command instead of falling through.
    sandbx_core::with_helper_dispatch(std::env::args_os(), || {
```

**Helper dispatch is first, and that ordering is load-bearing.** This binary is
also the helper: `SandboxedCommand` re-execs `/proc/self/exe` with
`--sandbx-core-exec`, and a process arriving that way must take the helper path
and become the target command rather than fall through into `Cli::parse`.
[08](08-the-two-stage-helper.md) has the two flags, the dispatch enum with no
success variant, and why the re-exec is this binary at all.

Inside that closure the order is `logging::init`, then `Cli::parse`, then
`conceal_process_state`, then the dispatch — and three of those four are where
they are for a reason of their own. Logging is initialised there because in
helper mode this process becomes the sandboxed command, whose stderr is
forwarded verbatim, so a subscriber installed above would write into it.
`conceal_process_state` is called there so the flag is sandbx's own rather than
a sandboxed command's — and after parsing, so a refusal exits with the
subcommand's code. Then the dispatch: five arms, two wrapped in `block_on`.

The runtime is built once, in `block_on`, whose doc comment explains both
choices: `new_current_thread` "because `spawn_blocking` is all the loop asks of
the scheduler", so the flavour stays the binary's and the agent crate can ask
for `rt` without `rt-multi-thread`; and `enable_all` rather than `enable_time`
for both drivers — the timer behind the per-round timeout, and the IO the
provider's connector opens on.

```rust
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        // Named at the one call site that can produce it rather than by a blanket
        // `From`, which would label any later io error as this one.
        .map_err(sandbx_cli::AgentError::Runtime)?
        .block_on(future)
```

Those seven lines are the whole of the crate's async boundary. `main` is a
synchronous `fn`, this is the only `block_on` in the workspace outside a test
module, and the two subcommands that await anything reach a runtime through this
builder or not at all — so there is no second flavour for a later subcommand to
pick, and `AgentError::Runtime` has exactly one site that can produce it.

### The exit-code mapping

`report` turns a subcommand's `Result<i32, _>` into an `ExitCode`, and
`failure_code` says what an `Err` costs for *that* subcommand:

```rust
fn failure_code(command: &Command) -> u8 {
    match command {
        Command::Auth(_) => 2,
        Command::SandboxRun(_) | Command::AgentRun(_) | Command::Tui(_) | Command::Hash(_) => 1,
    }
}
```

Read the whole thing as one mapping:

| what happened | code | decided by |
|---|---|---|
| the command under `sandbox-run` exited | its own code | `sandbx_core::exit_code`, passed through |
| a turn ended on an answer | 0 | `Render::finish` |
| a bound the operator chose cut the turn short | 2 | `INCOMPLETE` in `agent.rs` |
| a keypress ended a turn on the screen | 2 | the same `INCOMPLETE`, from `tui`'s `select!` |
| the operator could no longer be asked | 3 | `NO_CONSENT` in `agent.rs` |
| `auth status` found no key in either source | 1 | `UNAUTHENTICATED` in `auth.rs` |
| any `Err` under `sandbox-run`, `agent-run`, `tui`, `hash` | 1 | `failure_code` |
| any `Err` under `auth` | 2 | `failure_code` |
| an `Ok(code)` that does not fit a `u8` | the subcommand's failure code | `report` |

Both constants live in `agent.rs`, but under `tui` the code comes from `ending`
rather than from `Render::finish` — and `ending` is the one mapping in the crate
that reads `TurnStop` *non*-exhaustively, closing on `_ => 0` with a comment
saying it is deliberate: a stop it has no account of must not be given a code
`agent-run` already claims. [13](13-turn-loop-and-gate.md) has that argument,
and [15](15-tools-and-the-screen.md) has what the interrupt's `2` costs a caller
that a round limit's `2` does not.

Nothing downstream of `ending` may take the code back. A screen that stopped
redrawing mid-turn latches its failure, and `reported` — the free function
`Tui::drive` hands that pair to — prints it as one more stderr line and returns
the code regardless; [23](23-crate-tui.md) has why a broken *view* is not a
broken *result*.

The two oddities are both about a script being able to branch. `3` exists
because a run that stopped with nobody left to approve a tool call is neither a
failure nor a bound, and a caller cannot learn it any other way (#218). And
`auth` spends `2` on failure because `auth status` has already spent `1` on "no
key anywhere" — so `sandbx auth status || sandbx auth login` cannot read a
credential file it was refused as an absent one.

## agent.rs and its six submodules, as one pipeline

This is the crate's centre of gravity, and `agent.rs` is frank about its size:
over the module budget on purpose, "the pieces are already in `gate`, `prompt`,
`render`, `tui` and `wrapup`, and what is left is the argv surface and the one
sequence that consumes it". See
[guide-module-layout.md](../guide-module-layout.md) for what that budget is and
when an overrun is declared rather than split.

`sandbx-cli` holds every `run_turn` call site in the workspace outside
`sandbx-agent` itself — three of them: `AgentRun::drive`, `Tui::drive` and
`wrapup::Next::run`. What follows is one `agent-run` walking its own modules in
order.

`main.rs` reaches none of those three. It calls `AgentRun::execute`, which is a
fixed order of refusals and openings and then one hop into `drive`, where
`run_turn` actually is — and the order is the content. An empty prompt is
refused first, the API answering a blank text block with a 400, so letting it
through buys a round trip to be told what was knowable before it. The policy
comes before the client, so a refused policy never reads the credential; and
`orientation::system_prompt` is handed that same `SandboxPolicy` value rather
than a second `self.policy()?`, because re-reading `getcwd` from a cwd that
moved meanwhile "would name the model a root the sandbox did not grant". The
terminal comes before both the credential and the session, so a `--approve call`
run with nothing to ask on opens neither. The client comes before
`session::open`, because the credential chain can fail for want of a key and a
session opened first would leave a header-only transcript nothing deletes.
`Tui::execute` is the same sequence with `drawable` — which refuses `--approve
call`, then a stdout that is not a terminal — ahead of the policy, for the same
reason: a run that cannot be drawn must not read a credential on the way to
finding that out.

`drive` is where the pipeline below is assembled, and its signature is why all
of it is testable without a key:

```rust
    async fn drive<W: Write, E: Write>(
        &self,
        mut open: impl AsyncFnMut(Prompt) -> Result<EventStream, ProviderError>,
```

The stream opener, the `Channels<W, E>` carrying stdout, stderr and the optional
terminal, and the session are all arguments, so a unit test hands `drive` a
closure returning a canned `EventStream` and two `Vec<u8>`s for the channels,
then reads back the request that would have gone out and the bytes that reached
stdout. `Tui::drive` takes its opener for the same reason, its doc comment
saying so by pointing here.

### orientation.rs — the harness volunteers its own constraints

Before the first request goes out, `system_prompt` builds a system message that
tells the model which tools are approved and which directories its tools can
reach. The module exists because that changes for a different reason than the
rest of `agent-run`, and the reason it exists at all is round economy: a run
that names its roots and its tools up front spends no rounds probing refused
paths or reaching for refused tools (#178, #197).

Three optional sections, joined by a blank line, in a fixed order:

```rust
    let said = [
        (approved.len() < BuiltinTool::ALL.len()).then(|| tools_line(&approved)),
        (!roots.is_empty()).then(|| roots_line(&named(&roots), start.as_deref())),
        operator.map(ToString::to_string),
    ];
```

What is *not* said is as deliberate as what is. The tools section is omitted
when every built-in is approved, because naming all of them would describe a
boundary the run does not have. The roots section admits the system binaries
exist without listing them — "Apart from the system binaries a command needs to
start, every other path is refused" — `work_roots` leaving them out on the
grounds that an enumerated `/usr`, `/bin`, `/lib`, `/lib64` is "a host map in a
transcript". The flags are never named: the prompt says which tools are
approved, not that `--allow-tool` is what approved them, so nothing invites the
model to ask for a different invocation. And `--system` is *appended* rather
than replacing, because an operator who overrode the roots by accident would be
back to probing. The tools line also calls the unapproved tools "offered but
refused" rather than absent, which is a correctness point about the request: all
seven schemas are sent, so a model told these were its only tools would see the
list in front of it contradicting the sentence.

`work_roots` does one more thing worth knowing, because it is a second
resolution of paths the policy already resolved: it re-runs `VettedPath::vet`
over each granted path and `continue`s past any grant that no longer resolves to
the object it was vetted as, naming it in no sentence (#212). It also collapses
`(read, read, write)` to `(read, write)`, since `Grants::policy` grants read
alongside every write-conferring axis, and spells the axes for a reader rather
than a type — `Axis::ReadExecute` becomes "run".

- **Worth questioning:** that silent `continue` is the one place in the crate
  where a grant failing its own identity check produces neither a refusal nor a
  line on stderr. The same condition is a refusal a moment earlier —
  `PolicyError::UnpinnableGrant` and `PolicyError::GrantMovedWhileVetting` both
  exist for it — and
  [decision-grant-identity.md](../decision-grant-identity.md) is explicit that
  the vet-to-use window "fails closed" and that "refusing is the right
  outcome". Nothing is *unsafe* here: `FsGuard` measures the matched root per
  access, so the dropped root is unreachable regardless. But the record weighs
  the window's security and not its diagnosis, and this is the one site where
  the operator's answer is a model that quietly stops being told about a
  directory they granted — which costs exactly the probing rounds the module
  was written to save. A `eprintln!` beside the `continue` would cost nothing
  and would name the one event nobody can currently observe.

### The gate, in one sentence each

[`gate.rs`](../../crates/sandbx-cli/src/agent/gate.rs) answers, from argv alone,
which tools this run approved — `approves` returns true for any `ReadOnly` tool,
true for a bare `--allow-tool`, and otherwise asks whether the name was listed.
[`prompt.rs`](../../crates/sandbx-cli/src/agent/prompt.rs) is the `--approve
call` question: it opens `/dev/tty` rather than using stderr, discards
typeahead, strips bidi controls from what it echoes, and caps the subject it
shows (#169). Both are [13](13-turn-loop-and-gate.md)'s material, including
`Consent::ask`, why a typo is not consent, and how a `GateAborted` becomes exit
3. Read that chapter; this one does not have a better version of it.

### render.rs — the answer on stdout, everything about it on stderr

The invariant is in the module's first line, and it is the whole design:

> Where a turn's output goes: the answer on stdout, everything about it on
> stderr.

`event` routes `Text` to stdout; `Thinking` to stderr, and only under
`--show-thinking`; and ignores `ToolCallRequested`, `ThinkingBlock`,
`RedactedThinking` and `Usage` outright, because "a call is reported once it has
settled, by the gate, which is the only thing that knows what became of it".
Every per-call verdict, every warning, the tools-approved line and the
end-of-turn note are stderr.

Why it matters: stdout is the pipeable product, stderr the operator's channel.
`sandbx agent-run -- "..." > answer.txt` has to put an answer in that file and
nothing else — no gate verdicts, no round counts, no session-id line to strip.
The module enforces that by knowing nothing about flags, policies or sessions;
it cannot leak a policy detail onto stdout because it has never been told one.

Two mechanical details that look like style and are not. `write` flushes on
every call, because a line-buffered stdout would hold the answer back until the
model happened to emit a newline — the difference between streaming and not. And
the first stdout failure is *latched* in a field rather than propagated, so a
closed pipe does not abandon the turn; what was written is kept in a field
rather than behind a macro, so a test can read back the order it came out in
(#223).

`finish` turns an ending into the process's code: `Aborted` to `NO_CONSENT`,
tested *ahead of* any other ending or a truncation, which become `INCOMPLETE`,
and 0 otherwise. [13](13-turn-loop-and-gate.md) covers why `Aborted` outranks a
bound, and the matching fact that `tui.rs` re-derives this decision rather than
inheriting it.

### wrapup.rs — the second turn a round limit earns

When `run_turn` stops on `TurnStop::RoundLimit`, `agent-run` by default spends
one more request whose only job is prose. The mechanics:

- **The nudge is a system-prompt suffix, not a user message.** The history ends
  on a `tool_result`, and a second user turn would be the consecutive pair the
  API rejects. A suffix is also never stored, so it cannot accumulate in a
  resumed transcript.
- **`tool_choice` is set to `ToolChoice::None`, and the tools stay offered.**
  The schemas are still in the request, so the model sees a consistent world;
  the choice is what forbids a call, and `max_rounds` is 1.
- **The gate for this round is `RefuseAll`, not `ArgvGate`.** Deliberately not
  the run's own gate: a model that ignored both the nudge and `tool_choice`
  would otherwise reach `sandbx-tools` on the strength of a flag meant for the
  turn before this one. It answers `Deny` and never `Abort`, having no channel
  to lose — which is what lets the stop test afterwards read anything but
  `TurnStop::Answered` as a tool having been asked for.
- **A failed wrap-up is reported, not propagated.** On an error, on empty
  messages, or on a stop that is not `Answered`, `Next::run` keeps the first
  turn and returns `false`. A `?` there would turn a turn that did real work
  into exit 1 with its text already on stdout.

The two turns become the one turn a session stores:

```rust
pub(super) fn merge(first: TurnOutcome, second: TurnOutcome) -> TurnOutcome {
    let mut messages = first.messages;
    messages.extend(second.messages);

    TurnOutcome {
        messages,
        usage: second.usage.or(first.usage),
        withheld: second.withheld,
        stop: second.stop,
        round_stop: second.round_stop,
    }
}
```

`usage` falls back, because a token count persists across rounds; `stop` does
not, because a stop reason belongs to exactly one round and the wrap-up's is the
one whose prose is the answer.

`AgentRun::drive` then classifies the result, matching exhaustively on
`TurnStop` so that "a fourth way to end cannot reach `finish` as a clean one".
A round limit becomes one of three `Unfinished` values, chosen from whether the
wrap-up summarised and whether anything was written after the blank line
separating it: `Summarised`, `Discarded` — the round streamed prose and then
failed, so stdout holds text no transcript will account for, which `CutShort`
would deny — or `CutShort`. A `GateAborted` becomes `Aborted` with no wrap-up
attempted at all, skipped rather than refused by a flag, "the wrap-up round
being exactly the request there is no longer anyone to have asked for" (#218).
[13](13-turn-loop-and-gate.md) and
[decision-round-limit-answer.md](../decision-round-limit-answer.md) carry the
argument for spending the round at all.

- **Worth questioning:** `tui` sends no wrap-up round whatever, as its own help
  text says — "`--no-wrap-up` changes nothing: no wrap-up round is sent under
  `tui` at all". That is a difference in the shape of a turn between two
  subcommands built on one flattened flag set, and the crate elsewhere treats
  that exact pattern as the thing to avoid: `Tui` flattens `AgentRun` because
  "one flag meaning two things across two subcommands is how a policy gets
  narrower on one of them and nobody notices", and `--approve call` under `tui`
  is *refused* rather than silently downgraded (#225). An accepted-and-inert
  `--no-wrap-up` is the third option, and the one the codebase argues against.
  [decision-round-limit-answer.md](../decision-round-limit-answer.md) does not
  weigh `tui`: its case for defaulting the round on is that the alternative
  "leaves the common case with nothing on stdout", an argument about stdout,
  which `tui` does not use for the answer. The screen has the same problem in a
  different place — a capped `tui` turn ends on tool work and the operator has
  to ask again — and the record has not been asked whether the pane should get
  the summary too, or whether the flag should be refused under `tui` the way
  `--approve call` is.

### tui.rs — the same turn, on a screen

`Tui` is `AgentRun`'s flags verbatim. What differs is where the turn is
reported, and that a keypress can end one: `logging::hold()` buffers the audit
trail while the screen owns the terminal, `Screen::enter()` precedes
`Keys::listen()` because without raw mode ctrl-c is a signal rather than a key,
and the interrupt is a `tokio::select!` that drops the turn's future where it
stands. Its `Gate` wraps `ArgvGate` and *delegates* the decision rather than
re-deriving it, drawing `gate::line(call)` into the pane instead of printing it,
because the alternate screen does not redirect stderr (#224).
[15](15-tools-and-the-screen.md) covers the behaviour and what interrupting
costs, and [23](23-crate-tui.md) covers the widgets underneath.

## auth.rs and auth/store.rs

Two sources for one key, and `resolve` fixes the order: `ANTHROPIC_API_KEY`
wins, and the file is only *located* — not merely read — once the environment
has come up empty, which is what lets an exported key work "on a host with no
config home for `config_file` to name". The variable's name is also the one name
`agent-run` refuses to `--allow-env`, and `PolicyError::HarnessCredential`
carries it as a `&'static str` so no shape of that variant can hold a key.
`env_key` goes through `sandbx_providers::resolve_api_key`, so trimming and
treating a blank value as absent has one implementation; a blank variable falls
through to the file rather than failing.

`config_file` requires an *absolute* `$XDG_CONFIG_HOME`, falling back to an
absolute `$HOME` plus `.config`, and otherwise raises `NoConfigHome`. The file
is `sandbx/credentials.toml`, and its shape is two lines:

```toml
[anthropic]
api_key = "sk-ant-…"
```

`store.rs` owns that file, and the mode rules are the part worth reading in
place. `OWNER_ONLY` is `0o600`, `DIR_OWNER_ONLY` is `0o700`, and `SHARED_BITS`
is `0o077` — any group or other bit. Three details:

- **The mode is read from a descriptor, never from a path.** `read` opens the
  file first and then calls `file.metadata()`, because "a mode checked before
  the open vets one file and reads another".
- **The directory is vetted through `canonicalize`, not `path.parent()`.**
  `parent` is lexical, so a symlinked `credentials.toml` would have the link's
  directory checked and the key's never looked at. A writable directory is
  enough to refuse on, because it is one another user can rename their own
  `0600` file into.
- **Refuse, never repair.** A too-wide file raises
  `AuthError::Permissions { path, mode }` with the mode printed in octal, and
  nothing is chmod'd. `store` reads before it creates, so a too-wide file is
  refused rather than quietly replaced. The one relaxation is `discard`, which
  passes `Shared::Tolerate` — `auth logout` on a file you cannot safely read is
  still the right thing to let someone do.

`write` is deliberate about three failure modes. `DirBuilder::mode` is masked by
the umask and a no-op when the directory already exists, so the mode is set
again explicitly through an open descriptor. The temporary file's mode is set
rather than inherited, because "`NamedTempFile` is 0600 on unix, but this file's
guarantee is not a dependency's to make". And `sync_all` runs *before* the
rename, since ext4 journals the rename ahead of the data and a crash between the
two would leave an empty file where `login` just reported a stored key.

`auth` exits with three different codes, and that is the subcommand's contract:

| outcome | stream | code |
|---|---|---|
| `status`, key from the environment | stdout, naming `ANTHROPIC_API_KEY` | 0 |
| `status`, key from the file | stdout, naming the path | 0 |
| `status`, neither source has one | stdout, "not authenticated" | 1 |
| `login` or `logout` succeeded | stderr | 0 |
| any `AuthError` at all | stderr | 2 |

The key itself is a `secrecy::SecretString` throughout, whose `Debug` redacts
and which has no `Display`. `login` reads it from stdin and refuses a terminal
(`TtyInput`) rather than prompting, so it is never echoed and never lands in a
shell history. [14](14-audit-sessions-credentials.md) has the three credential
tiers this file sits in.

## session.rs is the translation at the edge

`--session` parses to a three-variant enum — `Off`, `New`, `Resume(&SessionId)`
— from an `Option<Option<SessionId>>`, which is clap's way of spelling
absent/bare/valued. The id is parsed at parse time, so `--session
../../etc/passwd` is refused before any I/O happens at all.

The rest of the module is the seam between `sandbx-providers`' request shapes
and `sandbx-session`'s stored ones, and the module doc states the property it
holds:

> Every match below destructures by field name with no `_` arm: a new
> [`ContentBlock`] variant is a compile error here rather than a block silently
> missing from a saved conversation.

This is where [22](22-crate-session.md)'s declared-not-imported choice pays off.
`sandbx-session` does not depend on `sandbx-providers`; it declares its own
`Content` enum. Those two types therefore have to be mapped by hand, in this
file, and the map is written to fail at `cargo build`:

```rust
fn stored_block(sent: &ContentBlock) -> Option<Content> {
    Some(match sent {
        ContentBlock::Text { text } => Content::Text { text: text.clone() },
        ContentBlock::ToolUse { id, name, input } => Content::ToolUse {
            id: id.clone(),
            name: name.clone(),
            input: input.clone(),
        },
```

and it closes on the one deliberate exclusion:

```rust
        ContentBlock::Thinking { .. } | ContentBlock::RedactedThinking { .. } => return None,
    })
}
```

Had that last arm been `_ => return None`, a sixth content block — the
`ContentBlock` sent has five variants, `sandbx-session`'s `Content` three —
would have compiled and silently vanished from every transcript, the failure the
module doc is describing. Reasoning is excluded because a signature has no
replay value; see
[decision-thinking-replay.md](../decision-thinking-replay.md).

Two more translations earn their complexity. `merge_user_runs` collapses
consecutive user runs, keeping tool results ahead of prose — both the order they
are stored in and the order the API wants — and `Merged` carries an `unmerged`
inverse, because the index a withheld call refers to in request space is not the
index it has in transcript space (#188). And `stored_messages` drops a message
whose content all translated away, since an empty content array is something no
provider accepts, and storing one would fail the *next* resumed turn rather than
this one.

## error.rs — five error types for five surfaces

| type | raised by | shape |
|---|---|---|
| `SandboxRunError` | `sandbox-run` | two variants: `Policy`, `Sandbox` |
| `AgentError` | `agent-run` and `tui` | twelve variants, from `EmptyPrompt` to `Turn` |
| `HashError` | `hash` | a struct, no variants: a path and an `io::Error` |
| `AuthError` | `auth`, and `agent-run` reading a key | eleven variants, in `error/auth.rs` |
| `PolicyError` | `Grants::policy`, a leaf inside the first two | one variant per way a policy can be refused |

What five buys over one enum is a per-subcommand `Display` surface and a
per-subcommand exit code: `main.rs` maps `Auth(_)` to 2 and everything else to 1
precisely because `AuthError` is not reachable through `SandboxRunError`, where
a single enum would have made that a per-variant table — the sort that falls out
of date. `HashError` goes furthest, one struct and no variants, because a path
that cannot be opened and one that cannot be read through are the same answer to
the operator and the errno already distinguishes them.

The hierarchy is not flat, in two ways worth naming. `PolicyError` is a shared
leaf, wrapped by both `SandboxRunError::Policy` and `AgentError::Policy` — the
type-level statement that both subcommands derive their policy the same way. And
`SandboxRunError::Sandbox` wraps `sandbx_core::SandboxError` rather than the CLI
reusing it, because deriving a policy is the CLI's own step and `sandbx-core`
must not grow a variant it never produces. `PolicyError` is also why `error.rs`
declares itself over budget: one `Display` arm per variant, and "the list of
everything that can refuse a run is only readable in one place". Its
derived-default refusals share one `ADVICE` constant so two of them cannot
advise differently; a refusal of a *flag* says what to change about the flag.

One absence is a design statement. A failing tool is not an `AgentError`: it
comes back to the model as an error result for it to try something else, which
is the loop's own contract rather than a way for a run to end.

## The five files this chapter only names

One sentence each, because each has a chapter of its own.
[`grants.rs`](../../crates/sandbx-cli/src/grants.rs) holds every `--allow-…`
flag and the axis loop that turns them into a policy, so the one widening and
the working-directory default exist once rather than once per subcommand.
[`grants/root.rs`](../../crates/sandbx-cli/src/grants/root.rs) holds no flag at
all: it decides where a no-flag run may root a default and what a path flag is
vetted against, and its module doc warns that two of its orders are load-bearing
and neither belongs to one function. Both are
[12](12-a-flag-to-a-kernel-rule.md)'s whole subject, traced from argv to a
kernel rule. [`hash.rs`](../../crates/sandbx-cli/src/hash.rs) is the one
subcommand that confines nothing: a `Sha256Digest::of_file` and a `write_all` —
not `println!`, which panics on a closed stdout with `SIGPIPE` ignored — and
[12](12-a-flag-to-a-kernel-rule.md) covers what its output pins.
[`sandbox.rs`](../../crates/sandbx-cli/src/sandbox.rs) is one of the workspace's
two `SandboxedCommand` build sites; see [05](05-seven-crates.md) for why there
are only two. And [`logging.rs`](../../crates/sandbx-cli/src/logging.rs) owns
the workspace's only `tracing` subscriber plus the hold the screen takes over
it, which is [14](14-audit-sessions-credentials.md)'s material.

## Where the tests are

Unit tests sit in the module they test, except where a file has enough of them
to warrant its own: `agent/gate.rs` and `agent/prompt.rs` both have `tests.rs`
siblings, and `prompt`'s is `pub(super) mod tests` so `gate`'s can use its
fakes. Ten integration files, split by surface:

| file | asserts |
|---|---|
| `agent_run.rs`, `sandbox_run.rs`, `auth.rs` | what an argv parses to and what policy it derives, over `Cli::parse` alone |
| `agent_session.rs` | what `--session` accepts, and what it refuses before any I/O happens |
| `cwd_policy.rs` | the working-directory guard — spawned, because it reads `getcwd` and `HOME`, and `set_current_dir` is process-global |
| `auth_store.rs` | the credential file end to end — spawned, because the chain reads real environment variables and `set_var` is `unsafe` under edition 2024 |
| `hash.rs` | `hash` and `--pin-sha256` asserted together, over the real binary's stdout |
| `audit_log.rs` | the real subscriber, driven over an in-memory sink |
| `audit_log_install.rs` | one test, and it must stay one: installing a `tracing` dispatcher is process-global |
| `name.rs` | that the binary's name is not one a POSIX shell resolves before searching `$PATH` — a security test, because such a name "does not fail, it succeeds", so a hand check of the sandbox looks like a working run |

[guide-module-layout.md](../guide-module-layout.md) is the authority on which of
those a new test belongs in.

## You should now be able to explain

- Why parsing and policy derivation live in `sandbx_cli` rather than in
  `main.rs`, and what that buys CI.
- Why `Grants` is one flattened struct rather than a copy per subcommand, and
  what the two-copy version would have drifted into.
- Why helper dispatch must run before `Cli::parse`, and why logging is
  initialised inside its closure rather than above it.
- Which error becomes which exit code, and why `auth` fails with 2 while
  everything else fails with 1.
- What the model is told before the first request, what is left out of that
  message, and why the flags are never named in it.
- Why the answer goes to stdout and everything about it goes to stderr, and
  what a consumer gains from that.
- What the wrap-up round sends, which gate judges it, and how its outcome is
  merged into the one turn a session stores.
- How a credential file's mode is checked, why it is read from a descriptor,
  and why a too-wide file is refused rather than fixed.
- Why `session.rs` has no `_` arm, and what a sixth content block would do to
  a transcript if it did.
- What `AgentRun::execute` settles before `drive` is reached, and why the
  credential is read after the policy and the terminal but before the session.
- Why `drive` takes its stream opener and its channels as arguments, and what
  that lets a unit test assert without a key.

## Next

Nothing further in this directory — the reference block ends here, and so does
the set. What comes after it is the numbered reading order closing
[guide-repo-map.md](../guide-repo-map.md), which walks every `guide-*.md` and
`decision-*.md` in [`context/`](../) in the order they make sense in. These
chapters were the on-ramp to exactly that list, and the test of whether they
worked is on the first file you open from it: a document that would have read as
a wall on day one should now read as a reference you are looking something up
in.
