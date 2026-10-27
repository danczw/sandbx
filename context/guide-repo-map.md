# Repo map

Virtual Cargo workspace, `members = ["crates/*"]`, resolver 3, edition 2024.

```
Cargo.toml          workspace manifest + lint table (unsafe_code = "forbid",
                    every member, sandbx-core included, no per-crate exemption;
                    dependencies are out of its reach, so no first-party unsafe
                    block and every raw syscall through a vetted wrapper)
clippy.toml         the disallowed-methods list
deny.toml           cargo-deny
.githooks/          pre-commit: fmt --check, clippy -D warnings, doc -D warnings;
                    commit-msg: Conventional Commits and a 72-character subject
.github/            CI and release workflows, their action pins, and dependabot
.github/scripts/    what a workflow calls but must be runnable without one
                    ◄── all three: guide-ci.md
docs/release-notes/ one file per tag, which the release gates on; TEMPLATE.md
SECURITY.md         the promise to users — the one doc that must never lag
```

## Crates

```
sandbx-core      (no internal deps)  ── sandboxing; the only crate allowed to spawn
    └──► sandbx-tools ──┬──► sandbx-approval ──┐
                        ├──────────────────────┘
                        ├──► sandbx-turn ───┐  turn loop
sandbx-compact ─────────┤                   │
sandbx-providers ───────┘                   │
         └──────────────────────────────────┼──► sandbx-cli   clap, the
sandbx-approval ────────────────────────────┤                 subcommand bodies,
sandbx-auth ────────────────────────────────┤                 the turn loop's
sandbx-core ────────────────────────────────┤                 caller
sandbx-grants ──────────────────────────────┤
sandbx-logging ─────────────────────────────┤
sandbx-prompt ──────────────────────────────┤
sandbx-provider ────────────────────────────┤
sandbx-session-bridge ──────────────────────┤
sandbx-session-error ───────────────────────┤
sandbx-session-id ──────────────────────────┤
sandbx-session-message ─────────────────────┤
sandbx-session-store ───────────────────────┤
sandbx-event ─────┬─────────────────────────┤
sandbx-text ──────┴─► sandbx-tui-transcript │
                       └──► sandbx-screen ──┤
sandbx-tui-input ───────────────────────────┘
```

`sandbx-logging` depends on `sandbx-core` for `AUDIT_TARGET` alone — the target
its filter admits. Drawn as a leaf for that reason: the edge carries one
constant, not a mechanism.

`sandbx-grants` is drawn as a leaf and is not one: it depends on `sandbx-core`,
`sandbx-auth` and `sandbx-session-paths`. The first two are leaves of the same
bus, so two crossings would say less than its table row does; the third would
need a node drawn first, for the reason below.

`sandbx-session-paths` is not drawn at all, the bus above being `sandbx-cli`'s
direct dependencies and this not being one of them. Its two parents are
`sandbx-grants` and `sandbx-session-bridge`, both drawn as leaves of that bus.

`sandbx-providers` is drawn as a leaf and has stopped being one: `sandbx-event`,
`sandbx-prompt` and `sandbx-provider` are its three internal edges — the
accumulator builds an `AgentEvent` per wire frame, `anthropic/body.rs`
serializes a `&Prompt`, and `stream_chat` returns an `EventStream` and builds
every `ProviderError` on it. `sandbx-provider` is drawn as a leaf and is not one
either, for the first of those reasons: the alias's `Item` names an
`AgentEvent`. None of the four arrows is drawn, every target already being a
leaf of the bus, and four more crossings would say less than the table rows do.
The edge that runs the other way is now a **dev** one: nothing in
`sandbx-turn`'s `src/` names this crate since #366 took the last two, so the
turn loop reaches no client code in a production build and `turn_loop.rs`'s
spawnability pin is the one reference left (#364, #365, #366).

| Crate | Owns | Internal deps |
|---|---|---|
| `sandbx-core` | sandboxing. **The only crate allowed to spawn a subprocess** | — |
| `sandbx-tools` | the seven built-ins, each confined by core | core |
| `sandbx-providers` | hand-rolled streaming API clients | event, prompt, provider |
| `sandbx-turn` | the turn loop | approval, compact, event, prompt, provider, tools (core and providers are *dev*-only) |
| `sandbx-cli` | arg parsing and the subcommand bodies | core, approval, auth, event, grants, logging, prompt, provider, providers, screen, session-bridge, session-error, session-id, session-message, session-store, text, tools, tui-input, turn |
| `sandbx-logging` | the one `tracing` subscriber, and the hold the screen takes | core |
| `sandbx-session-store` | the on-disk transcript: append-only JSONL under whatever root it is handed | session-error, session-id, session-message |
| `sandbx-screen` | the screen one turn is drawn on, and putting the terminal back | tui-transcript (pty-fixture is *dev*-only) |
| `sandbx-tui-input` | the keys that stop a turn, and what a hangup means | — (pty-fixture is *dev*-only) |
| `sandbx-tui-transcript` | what that screen shows: the event fold, and the layout it is drawn in | event, text |
| `sandbx-pty-fixture` | a pty pair for tests that drive a real terminal | — |
| `sandbx-helper` | the test-only binary the enforcement suite spawns, and that suite | core |
| `sandbx-session-message` | the five shapes a transcript line is made of | — |
| `sandbx-session-error` | why a session operation did not happen | — |
| `sandbx-session-id` | a session's name, and the one rule that makes it safe in a path | session-error |
| `sandbx-session-paths` | where transcripts live: `$XDG_STATE_HOME`, else `$HOME`, never the working directory | session-error |
| `sandbx-event` | the vocabulary a streamed turn is spoken in: one event per thing that arrived, and why it ended | — |
| `sandbx-prompt` | what a model is asked for, in no API's vocabulary: the request shapes, carrying no `Serialize` | — |
| `sandbx-provider` | the provider seam: the stream a client hands back, and the error it can fail with | event |
| `sandbx-text` | the one denylist of what model text may not carry to a terminal | — |
| `sandbx-approval` | what a gate is asked and what it is told; no policy | tools |
| `sandbx-auth` | the provider key: which source it comes from, and the file it is kept in | — |
| `sandbx-compact` | which prefix of a history may be withheld from a request, and the measurement that decides it | prompt |
| `sandbx-session-bridge` | the translation between the stored transcript shapes and the provider's request shapes | compact, prompt, session-error, session-id, session-message, session-paths, session-store |
| `sandbx-grants` | the `--allow-…` flags, and the policy they describe — including what a no-flag run derives and the working directories it refuses | auth, core, session-paths |

`sandbx-turn` depends on core only as a dev-dependency: its tests drive real
tools over a temp dir rather than mocking below the tool boundary.

`sandbx-session-store` depends on `sandbx-session-error`, `sandbx-session-id`
and `sandbx-session-message` — the three internal edges the diagram above does
not draw. `sandbx-session-bridge` and `sandbx-cli` each have an edge to all
three as well, and none of those is inherited through `sandbx-session-store`:
the bridge translates between the stored shapes and the provider's and names a
`SessionId` in `SessionChoice`, and the CLI is where a `SessionError` becomes
something else, where `CompletedTurn` appends a finished turn, and where a
`SessionId` is parsed off argv (#351, #360). `sandbx-session-id` is itself a
parent of `sandbx-session-error`, the id's own parser returning that type.

`sandbx-session-bridge` is the only crate reaching all seven of
`sandbx-compact`, `sandbx-prompt`, `sandbx-session-error`,
`sandbx-session-id`, `sandbx-session-message`, `sandbx-session-paths` and
`sandbx-session-store`, which is what being the seam costs: the two
vocabularies it maps between are declared in crates that do not depend on each
other, by the choice `sandbx-session-message`'s `//!` records. Still seven and
not eight: #364 narrowed the client edge to the request shapes rather than
adding one, so the crate now reaches no client code at all. Its edge to
`sandbx-session-store` is no longer the wide one it was: #360 and #361 took
`SessionId` and `sessions_directory` out of the crate the edge used to reach,
and #362 renamed what was left, so `Session` and `SessionStore` are now that
crate's whole surface. The diagram above draws none of those seven, only the
edge on to `sandbx-cli` — so note in particular that `sandbx-compact` is drawn
into the `sandbx-turn` bundle alone and has had two dependents since #351.

`sandbx-screen` depends on `sandbx-tui-transcript` and on nothing else of
sandbx's, and `sandbx-tui-input` on nothing at all: the event and text edges the
diagram used to draw to the drawing side land one step earlier, on the crate that
folds the events. Both are leaves, so no client code reaches the drawing side at
all — until #365 the event edge was `sandbx-providers`', and reqwest, rustls and
hyper came with it. `sandbx-cli` reaches `Transcript` through `sandbx-screen`'s
re-export and not an edge of its own — every entry point `sandbx-screen` has
takes or returns one — which is why `deny.toml` names one parent there and not
two (#352, #353).

`sandbx-pty-fixture` is in no crate's build, which is why it is absent from the
diagram above; its own `//!` says why it is a crate and not a module (#344).

`sandbx-helper` is absent from it for the same reason and a different one: nothing
depends on it, and it depends on `sandbx-core` only to re-export its dispatch. It
is a crate so that `CARGO_BIN_EXE_sandbx-helper` resolves for the tests that spawn
it, which cargo sets only for a bin of the same package (#328 decision 5, #347).

`sandbx-cli` is the turn loop's only caller outside its own tests. It reaches
`sandbx-provider`, `sandbx-prompt`, `sandbx-providers` and `sandbx-event`
directly rather than through `sandbx-turn`, which re-exports none of the four:
`agent-run` builds the client, which is `sandbx-providers`', and the first user
turn, which is `sandbx-prompt`'s; it names the closure's own
`Result<EventStream, ProviderError>`; and its renderer is a second fold of the
events the loop hands back.

## `sandbx-core`

```
src/lib.rs           re-exports; Linux-only, refused at compile time
   policy.rs         re-exports
      policy/sandbox.rs Axis, Grants, SandboxPolicy     ◄── the table
      policy/vetted.rs  VettedPath, ObjectId — a grant and the object it names
   fs_guard.rs       in-process path and object enforcement (6 of 7 tools)
   command.rs        re-exports; dispatch is the host-side helper entry
      run.rs         SandboxedCommand, the audit pipe, the kill chain
      dispatch.rs    HELPER_FLAG, HELPER_INNER_FLAG, with_helper_dispatch — the
                     entry into helper mode
   helper_args.rs    the argv seam: encode/decode, --ro/--rw/--rx each with a
                     <path> <dev>:<ino> pair, --allow-network, --allow-network-port,
                     --allow-unix-sockets, --allow-dns-name, --env,
                     --dns-over-tcp, --pin-sha256
   resolver.rs       RESOLVER_FILES, bound_by_resolver — the three files a
                     bounded resolver replaces, rendered with no nameserver
                     in the loop
   concealment.rs    conceal_process_state — the one step aimed at sandbx's own
                     process rather than a sandboxed child's
   digest.rs         Sha256Digest; open_verified and fd_path, the pinned exec
   audit.rs          AuditEvent, AUDIT_TARGET
   degradation.rs    the helper's channel to the parent, and its wire format
   spawn.rs          spawn::command — the one Command::new; env_clear, then
                     the allowlist and the policy's own constants
   error.rs          re-exports
      sandbox.rs     SandboxError — every refusal and failure, and its label
      refusal.rs     HelperRefusal — the closed set the channel admits, and
                     SandboxError::decided_by, the one place the two are mapped
                     and every variant's label spelled
   helper/
      mod.rs         re-exports exit_code, BLOCKED_SYSCALLS, both stages and
                     AUDIT_STDIN_FLAG
      exec.rs        the two stages — exec_sandboxed, then exec_inner as the init;
                     apply() sequences all three mechanisms; exit_code
      hardening.rs   namespaces, capsets, rlimits, pdeathsig, ppid_from_stat
      resolver.rs    bound_resolution — the ordered mount sequence that installs
                     what src/resolver.rs rendered, in stage 1 because stage 2
                     has no namespace to put it in
      seccomp.rs     re-exports BLOCKED_SYSCALLS and deny_dangerous_syscalls
         filter.rs   compiled_filter, clone3_filter, x32_gate,
                     deny_dangerous_syscalls — how it reaches the kernel
         rules.rs    BLOCKED_SYSCALLS, blocked_syscalls — what is denied
         tests/      unit tests: denylist, sockets, namespaces, arch; plus the
                     eval interpreter they are all read through
      ruleset/
         mod.rs      re-exports what `apply` and the tests reach
         requested.rs
                     Requested { handled, rules, net }, RequestedNet —
                     requested, requested_at
         compat.rs   handled_access, handled_net_access, kernel_probe,
                     negotiated_abi_from, negotiated_abi, enforcement_verdict
         opened.rs   open_grant, reads_back — the path opened is the one granted
         rights.rs   rights_for, fs_rules, net_rules
         tests/      unit tests: compat, grants, net, opened, rules
tests/               audit, capability_coverage, command (what an argv encodes
                     and parses; the half that spawns the helper is
                     sandbx-helper's), context_docs, denylist, fs_guard,
                     helper_args, policy — none gated: everything needing a
                     kernel went with the binary (#347)
```

Public surface: `AuditEvent`, `AUDIT_TARGET`, `SandboxedCommand`, `HELPER_FLAG`,
`HELPER_INNER_FLAG`, `with_helper_dispatch`, `SandboxError`, `Access`,
`HelperRefusal`, `FsGuard`, `ReadableWalk`, `BLOCKED_SYSCALLS`, `exit_code`,
`HelperArgs`, `Axis`, `Grants`, `NetworkPolicy`, `SandboxPolicy`, `VettedPath`,
`ObjectId`, `DNS_NAME_LIMIT`, `NAMESERVER_PORT`, `RESOLVER_FILES`,
`bound_by_resolver`, `Sha256Digest`, `DigestParseError`, `conceal_process_state`.

`Access` is the guard's two root sets, not `Axis`: `Axis::ReadExecute` has no
in-process meaning, and a refusal carries an `Access` so it can name the grant it
lacked rather than implying none was given.

One per-call-site `#[allow(clippy::disallowed_methods)]` for `Command::new` in
`src/`, in `spawn::command` — that site, not the whole crate; test files that
spawn the built binary carry their own. The lint *is* the backstop: a
CI grep for `Command::new` would be a second one, but a lint that names the call
site beats a grep that runs after it. Not `cargo build`, which compiles a stray
`Command::new` without complaint: `disallowed_methods` is `deny` in the
workspace lint table, so `cargo clippy` refuses it — in `.githooks/pre-commit`
and CI's Clippy step.

## `sandbx-helper`

```
src/main.rs          16 lines: with_helper_dispatch, and a failure message for a
                     run that is not helper mode. Every mechanism it dispatches
                     into is sandbx-core's helper/ tree
tests/               audit_channel, audit_outcome (how a real run ends), command
                     (the half that spawns the binary), concealment, enforcement,
                     enforcement_network, enforcement_resolver,
                     enforcement_syscalls
tests/support/       mod.rs — vetted, runtime_paths, allow_probe, run, run_pinned,
                     shared by the four enforcement targets; plus 10 [[bin]] probes,
                     required-features = ["sandbox-integration"] on every one but
                     concealment_probe, which needs no Landlock ABI
```

No public surface and no `public-api.txt`: a crate with no lib target has
nothing importable, and `.github/scripts/public-api.sh` skips it on that test
rather than by a list. A crate that *lost* its lib target while keeping a
baseline is an error there, and a lib target whose baseline was never committed
is an error in `ci.yml`, so the skip cannot go quiet in either direction (#402).

## `sandbx-logging`

```
src/lib.rs           subscriber, init — the one subscriber and its global
                     install; Audit, the writer behind it; hold and Held, the
                     buffer the screen takes            ◄── guide-logging.md
tests/               audit_log (what the filter admits over a closure writer),
                     audit_log_held (the held path end to end, re-execing to
                     read fd 2), audit_log_install (one test, by necessity)
```

Three test binaries and not one: `init` installs a process-global subscriber, so
a second test in the same binary would race whatever the first installed.
`audit_log_install.rs` holds exactly one test for that reason and its `//!` says
so.

## `sandbx-tools`

```
src/lib.rs        re-exports, and the crate-private ones the tool modules reach
   builtin.rs     BuiltinTool (closed enum), ALL: [Self; 7], ToolOutput,
                  RiskLevel; ToolSpec, crate-private so a tool's declaration is
                  not a public shape
   shared.rs      parse, read_file, read_capped, listing, guard_error, failed —
                  what more than one tool needs
   context.rs     ExecutionContext, DEFAULT_TIMEOUT — policy is PRIVATE (#56)
   limits.rs      ToolLimits
   error.rs       ToolError: Denied | BadInput | Failed | TimedOut
   tools/         bash, edit, find, grep, ls, read, write — each with its SPEC
tests/            per-tool (find and grep share search), plus registry, limits,
                  scan_limits, spawn
```

## `sandbx-providers`

```
src/lib.rs        re-exports; ensure_crypto_provider_installed
   sse.rs         SSE framing
   anthropic.rs   the vendor boundary: re-exports AnthropicClient
      client.rs   AnthropicClient — the request, and the base-URL and
                  transport rules that keep the key off the network in cleartext
      body.rs     Serialize for the Messages body, built from a &Prompt
      wire/       accumulate.rs, payload.rs + unit tests
tests/            anthropic_client, crypto_provider, error (Transport alone,
                  which is the one variant needing a crypto provider),
                  live_anthropic (needs `live-anthropic-tests`)
```

The tree is the boundary for every vendor *rule*, and for every wire string
sandbx writes or matches on — the ones it carries verbatim cross as opaque data
(`sandbx-event`'s `StopReason::Other`, this crate's `ApiError::kind`). The rules
are compiler-enforced: `Body` is `pub(super)` in a private `mod body` and no
neutral type derives `Serialize`, so the request shapes cannot be posted to any
API by accident — which since #364 rests on the orphan rule rather than on this
crate's own discipline, the shapes being `sandbx-prompt`'s and `serde` not being
among its dependencies; the wire payloads are `pub(super)` bar the two error
envelopes at `pub(crate)`; and `stop_reason` is a private free function, so no
`StopReason` comes from a wire string outside `anthropic/` (#59) — which the
enum leaving for `sandbx-event` did not weaken, the string table having stayed.
The vendor *name* is the one row nothing *contains* — no lint, no containment
test, no CI grep — and one sibling of `anthropic.rs` carries it: `lib.rs`
re-exports `AnthropicClient`. The key and its variable's name are
`sandbx-auth`'s, in its `key.rs`. A grep says which other files name it in doc
comments only. Per-rule account in
[decision-provider-seam.md](decision-provider-seam.md).

## `sandbx-provider`

```
src/lib.rs        EventStream (boxed FusedStream) — the provider seam;
                  ProviderError — why a call produced no usable stream
tests/            error (every variant but Transport)
```

The seam, and the whole of it: there is no provider trait and no provider enum,
so a client is anything whose `stream_chat` returns an `EventStream`. The two
items are one crate because neither is nameable without the other: the alias's
`Item` is a `Result<AgentEvent, ProviderError>`.

Not a light crate: `Transport` carries a `reqwest::Error` as a public field, so
reqwest and its HTTP stack travel with the seam. Not the TLS half — this crate
names no reqwest feature, which is what keeps rustls and `ring` with the one
crate that opens connections, and its manifest says why that matters. That line
between the two halves is what the turn loop gained: naming the seam here rather
than through `sandbx-providers` costs it reqwest and hyper and sheds rustls,
`ring`, the four `rustls-*` crates, `tokio-rustls`, `hyper-rustls`, `h2` and
`secrecy` — so no production build of `sandbx-turn` links TLS or can name the
type the API key is kept in. Whether the field should be boxed, which would shed
the rest, is a code change and so a separate question from the move; it is a box
on #335. Per-rule account in
[decision-provider-seam.md](decision-provider-seam.md).

## `sandbx-event`

```
src/lib.rs        AgentEvent, StopReason — one event per thing a streamed turn
                  produced, and why it ended
```

Public surface: those two enums and nothing else. One dependency, `serde_json`,
and it is `ToolCallRequested::input` alone — a call's arguments are whatever the
model sent. Nothing here derives `Serialize` or `Deserialize` and nothing here
parses, which is what lets every layer above speak the vocabulary without any of
them reaching a client: until #365 these two lived beside the clients, and
`sandbx-tui-transcript` reached reqwest, rustls and hyper to match on an enum,
carrying the chain on to `sandbx-screen` behind it. The crate's `//!` has why it
is a crate and not a module, and the half of the #59 seam that travels with the
types.

## `sandbx-prompt`

```
src/lib.rs        Prompt, RequestMessage, Role, ContentBlock, ToolDefinition,
                  ToolChoice, Thinking — what a model is asked for, as data
```

Public surface: those seven types and `ContentBlock::is_thinking`. One
dependency, `serde_json`, and it is the two opaque fields alone —
`ToolUse::input` and `ToolDefinition::schema`, each replayed or forwarded
verbatim. **`serde` is not a dependency**, and that absence is the mechanism
rather than a tidiness: with the types declared here, the orphan rule leaves this
the only crate in which an `impl Serialize for Prompt` could be written, so an
adapter has to declare a local wrapper and spell every field out. Until #364 the
same property rested on `anthropic/body.rs` being `pub(super)` within one crate.
`PartialEq` and not `Serialize` is also what a test wants to compare. The
cross-crate account is in
[decision-provider-seam.md](decision-provider-seam.md).

## `sandbx-text`

```
src/lib.rs        invisible — the one denylist of what model text may not carry
                  to a terminal, read by both the cli's line sink and the
                  transcript's cell
```

Public surface: `invisible`, and nothing else. Zero dependencies, workspace or
external, so both sinks can reach it without either reaching the other: a
character added to one copy and not another re-opens the hole in whichever was
missed, and the drift would be a terminal-injection difference between two
surfaces users read as the same. What they share is the hazard — each sink keeps
its own replacement, there being no one answer to what belongs in a cell versus
a line. The crate's `//!` has why neither `sandbx-core` nor the drawing crate is
the home (#363).

## `sandbx-approval`

```
src/lib.rs        CallGate, ToolCall, ApprovalDecision, Settled, Outcome — what
                  a gate is asked, the three answers it may give, one of which
                  ends the turn, and the five outcomes it is told a call reached
```

The shapes only: no policy, no channel to ask on, and nothing that decides.
`sandbx-turn` asks through them, the three production implementors are
`sandbx-cli`'s, and both of those edges are why `deny.toml` names two wrappers
(#355). Neither runs the other way: `CallGate` is foreign in `sandbx-cli` and
the gate types local there, which the orphan rule permits, so this crate needs
no edge to either of its parents and neither can drag it along by moving: #357
renamed the loop's crate without touching anything here. Depends on
`sandbx-tools` for the `BuiltinTool` a call names and the `ToolError` an outcome
carries.

## `sandbx-compact`

```
src/lib.rs    over_budget, plan_cut, Compaction, PromptUsage — which prefix of
              a history may be withheld from a request, and the measurement it
              is decided on
   compact_tests.rs  the cut-point algebra
```

Pure and total over `RequestMessage`, reaching nothing in the loop that calls
it. `PromptUsage` is declared here and not beside `Turn::observed`, where it
reads as belonging: the turn depends on compaction and not the reverse, so this
is the side of the edge it can sit on (#345). `sandbx-turn` re-exports both
types, which #356 did so that `cli/src/session.rs` could keep naming the
re-export until #351 moved it. That move has landed, and took an edge of its own
rather than the re-export, so the two parents in `deny.toml`'s block here are
`sandbx-session-bridge` and `sandbx-turn` — #357 re-pointed the second rather
than adding a third. The re-export has no *first-party* consumer left outside
`sandbx-turn`'s own `tests/turn_compaction.rs` — `grep PromptUsage
crates/sandbx-cli/` is empty and `Compaction` was never named there at all. It
is not therefore dead: `Turn::observed` and `TurnOutcome::usage` are public
fields typed `Option<sandbx_compact::PromptUsage>`, so the re-export is still
how a consumer outside this workspace names them, which is what #356 claimed for
it. `sandbx-prompt` is its one dependency, for `RequestMessage`, `Role` and
`ContentBlock` — #364 narrowed that from the whole client crate, so nothing here
reaches reqwest, rustls or hyper any more.

## `sandbx-turn`

```
src/lib.rs    re-exports: TurnError, Turn, TurnLimits, TurnOutcome,
                          TurnStop, PromptUsage, Compaction, run_turn
   run.rs         run_turn — generic over a stream-opening closure
   accumulate.rs  one round's message, rebuilt from deltas
   tools.rs       what is offered, the gate, and the one spawn_blocking site
   error.rs       TurnError
tests/       turn_loop, turn_compaction, audit_trail,
             support/mod.rs — the Script double and the request builders
```

`Compaction` and `PromptUsage` are `sandbx-compact`'s, re-exported here: the
loop is what asks for a cut, not what plans one (#356).

## `sandbx-session-message`

```
src/lib.rs        Message, Role, Content, Usage, CompletedTurn — the five
                  shapes a transcript line is made of, and the three tests
                  that pin them against the wire
```

The stored types are declared here rather than imported from
`sandbx-prompt`: a transcript is a file format, and one that moved whenever a
request type moved would not be. The translation lives in
`sandbx-session-bridge`, where a new content block is a compile error rather
than a block quietly missing from a transcript. Depends on no sandbx crate,
which is what lets the format outlive a change to either side of it (#359).

## `sandbx-session-id`

```
src/lib.rs        SessionId — 1–32 of [0-9a-z], an allowlist because an id
                  becomes a path component; from_clock and clock_millis
tests/            identifier — the refusal list, and a text round trip
```

The alphabet is an allowlist and not a search for `..` because a denylist's
first omission is a traversal, and `--session` takes its value straight off
argv. `clock_millis` is `pub` for `sandbx-session-store`'s header write.
Depends on `sandbx-session-error` alone, which is why that crate names no
`SessionId` — the edge back would be a cycle (#360).

## `sandbx-session-store`

```
src/lib.rs     re-exports SessionStore and Session
   session.rs  SessionStore, Session; which bit refuses and which reports
   record.rs   the three line kinds, and the fold that replays them
   shape.rs    which orders of messages a request may carry, as predicates
   vet.rs      the modes, O_NOFOLLOW, and reading one off a descriptor
tests/         permissions, recovery, transcript
```

Three internal dependencies, `sandbx-session-error`, `sandbx-session-id` and
`sandbx-session-message`, whose sections say why the stored shapes are their
own and not the provider's, why the id is a crate of its own since #360, and
why the error names no `SessionId`. See
[decision-on-disk-state.md](decision-on-disk-state.md) for the roots, the mode
rule and the line format.

## `sandbx-session-error`

```
src/lib.rs        SessionError — seventeen variants, Display, and a source that
                  answers for the two that wrap a foreign error
```

No `From` impls, by design: every wrapped failure is paired with the path and
operation it came from, which a blanket conversion would discard, and
`sandbx-cli` is what decides per call site what a session failure becomes.
`NotFound` carries an id's spelling and not a `SessionId`, because every
fallible path in the session tree returns this type — the id's own included — so
an edge to `sandbx-session-id`, which declares it, would be a cycle (#346,
#358, #360).

## `sandbx-session-paths`

```
src/lib.rs        sessions_directory — $XDG_STATE_HOME, else $HOME, never the
                  working directory
```

Both roots are required to be absolute, and the refusal stands where a third
root would have gone: a transcript under the working directory would sit inside
the tree a run can grant a tool write over, and the history resumed from it is
what the model is told it said. The lookup is injected rather than read off the
process because `set_var` is an `unsafe fn` under edition 2024 and the
workspace forbids `unsafe_code` in test binaries too, so a test cannot drive a
real environment; `sandbx-auth`'s `config_file` resolves its root the same way.

Depends on `sandbx-session-error` alone. A crate of its own so that
`sandbx-grants`, which reaches this one function to refuse a grant covering the
directory, no longer takes the whole session crate to get it (#361).

## `sandbx-session-bridge`

```
src/lib.rs        SessionChoice and open — which session a run opens, and what
                  it says on stderr about one it did; request_history,
                  stored_messages, request_usage, stored_usage — the four
                  translations; Merged and merge_user_runs — a run of user
                  messages collapsed into the one the API takes, and the index
                  space that collapse moves
```

The property is about the two block translations and not the file.
`request_block` and `stored_block` destructure by field name with no `_` arm, so
a fourth `Content` variant and a sixth `ContentBlock` variant are each a compile
error, in whichever direction the vocabulary grew, rather than a block missing
from a transcript. `merge_user_runs` does have a `_` arm — it matches a
`last_mut()` option, where a catch-all costs nothing — and the two role matches
are over unit variants, so they destructure nothing. Free functions and not
`From` impls: both vocabularies are foreign to this crate, which is the whole
reason it exists. `decision-on-disk-state.md` has the two index spaces and why
`Merged` carries both; `decision-thinking-replay.md` has the one block kind that
is deliberately dropped on the way to storage.

## `sandbx-tui-transcript`

```
src/lib.rs          re-exports: Transcript, draw, Hint
   transcript.rs    AgentEvent folded into entries, and the control bytes a cell
                    may not hold — no terminal behind it, so it is unit-tested
   view.rs          the layout: the transcript tail-aligned over a status bar
```

Public surface: `Transcript`, `draw` and `Hint`. The two files are one crate
because the fold has to strip what the layout draws — `view::GUTTER_MARK` is the
claim that sandbx wrote a row, and `transcript::forgeable` replaces it and its
confusables in entry text. Two crates would make that a cycle on one constant.
`Kind`, `Entry` and `Transcript`'s three readers stay crate-private for the same
reason: the layout is the only caller, and it is inside (#353).

## `sandbx-screen`

```
src/lib.rs          Screen — raw mode and the alternate screen, put back on
                    drop; Measured, the window read off the drawn descriptor;
                    and Transcript re-exported, every entry point taking one
```

One file, because `Measured` has no reader outside it: `Screen`'s field is
private and nothing public names the type, so the whole of #269's measurement
stays `pub(crate)` (#352). `clippy.toml` bans ratatui's `restore`, `run` and all
four `init` forms, and `terminal::size` and `CrosstermBackend::new` with them —
which is what leaves `Screen::enter` and `Measured::new` the only ways in.

## `sandbx-tui-input`

```
src/lib.rs          Keys — the reader thread, the watch for a terminal that went
                    away, and the press a turn awaits; nothing here draws, and
                    nothing here knows of a policy or a provider
```

One file, for `sandbx-screen`'s reason read over different items: `Seen`, the
private `Source` trait and its `Crossterm` implementor have no reader outside
the key reader, so the whole of #264's two-thread mechanism stays `pub(crate)`
and only `Keys` and `Stopped` leave (#354).

## `sandbx-auth`

```
src/lib.rs        re-exports Auth, AuthError, and the three names a caller
                  reaches: ENV_VAR, api_key, config_file
   key.rs         Auth — which source the provider key comes from: the
                  environment, then a file, and the login/logout/status over it
   store.rs       the credential file itself — its TOML shape, and the 0600/0700
                  modes it is refused and written under
   error.rs       AuthError — what stops `auth`, or a key resolution under
                  `agent-run`
```

No workspace dependency, so the crate that owns the credential file reaches
nothing that could widen what it writes. `sandbx-cli` holds the `Command::Auth`
variant, the `sandbx` binary the end-to-end tests spawn, and `AgentError`'s
`From<AuthError>`; `ENV_VAR` is also what `agent-run` refuses to `--allow-env`
and `config_file` what a path grant is refused for. See
[decision-credentials.md](decision-credentials.md) for the source order and that
refusal, and [decision-on-disk-state.md](decision-on-disk-state.md) for the mode
rule this crate shares with `sandbx-session-store`.

## `sandbx-cli`

```
src/lib.rs      mod lines and re-exports; no code
   invocation.rs
                Cli, Command — the clap surface and nothing else
   sandbox.rs
   hash.rs      Hash — the one subcommand that confines nothing
   agent.rs     re-exports AgentRun and Tui, and what the siblings reach
      run.rs    AgentRun — the turn loop's caller
      gate.rs   which tools --allow-tool approved, the refusal the rest get,
                and the one line per call the operator reads
      prompt.rs --approve call: the question put on /dev/tty, the three answers
                it takes, the verdict that ends the run when it can no longer be
                asked, and Operator, which carries the per-call line back to the
                same device
      orientation.rs
                the approved tools and the roots the model is told about before
                the first request
      render.rs the answer on stdout, everything about it on stderr
      wrapup.rs the second turn a round limit earns, which may call no tool,
                and the two outcomes merged into the one a session stores
      tui.rs    Tui — the same turn drawn on a screen, the keypress that ends
                one, and the gate that draws its verdicts instead of printing
                them                                 ◄── guide-tui.md
   error.rs     re-exports the three, and is the list of them
   error/agent.rs
                AgentError — twelve ways a turn does not finish
   error/run.rs
                SandboxRunError — Policy, Sandbox
   error/hash.rs
                HashError — a path and an io::Error, no variants
src/main.rs     helper dispatch, the tokio runtime, exit codes
tests/          agent_run, agent_session, auth, auth_store, cwd_policy, hash,
                name, sandbox_run, usage
```

Lib `sandbx_cli`, bin `sandbx`. Five subcommands: `sandbox-run`, `agent-run`,
`tui`, `hash` and `auth`. `tui` is `agent-run`'s flags, policy and session
drawn on a screen rather than streamed to stdout, so the two share `gate.rs`,
`orientation.rs` and `sandbx-session-bridge`, and differ only in where a turn
is reported. `hash` and `auth` run no sandbox — `hash` reads one file, so a
digest can be taken before there is a policy to take it under, and `auth` touches
only the credential file. `auth` is the one subcommand whose body is not here:
`invocation.rs` holds the variant and `sandbx-auth` everything under it.

`Grants` and `PolicyError` are `sandbx-grants`', re-exported here so
`sandbx_cli::Grants` and `sandbx_cli::PolicyError` stay spellable: the flags are
flattened into `SandboxRun` and `AgentRun`, and `AgentError` and
`SandboxRunError` each carry a `Policy` variant (#350).

## `sandbx-grants`

```
src/lib.rs      re-exports Grants and PolicyError — and holds what a no-flag run
                grants, why a path flag replaces that default rather than adding
                to it, and why deriving one is fallible
   flags.rs     Grants — the --allow-… flags, flattened into every subcommand
                that confines something, and the policy they derive
   root.rs      where a no-flag run may root its default policy, and what a
                path flag is vetted against, including the refusal of a grant
                reaching a path sandbx owns (unit-testable without a
                sandbox-capable kernel); vetted_root's /// is why it refuses
                rather than narrowing, and root::tests' //! the mutation check
   error.rs     PolicyError, and the one ADVICE every derived-default refusal
                appends
```

`Grants` exists so the axis loop, the one widening it applies — a write grant
confers read — and the working-directory default are written once. Two copies
would drift, and the drift would be a policy difference between subcommands that
users reasonably read as the same flags, which is why this is a crate rather
than a module of `sandbx-cli`: `deny.toml` names one parent, and nothing else
can grow a second definition of what a flag grants.

Depends on `sandbx-core` for `SandboxPolicy`, `Axis` and `VettedPath`, and on
`sandbx-auth` and `sandbx-session-paths` for the two paths sandbx owns — the
credential file and the session directory — which a derived root and a path
flag are both refused for reaching. Each of those two edges is one function
wide, so nothing here can reach the store that writes a transcript (#361).

## Reading order

If the repo is new to you, `cargo doc --open` first: each crate's `//!` says
what that crate owns and what it refuses, which is the vocabulary the order
below assumes. The order itself reads as reference rather than as a wall.

1. `guide-repo-map.md` — this file: which crate owns what, and what depends on
   what
2. `SECURITY.md` — what is claimed
3. `guide-sandboxing.md` — how it is enforced
4. `decision-policy.md` — where policy becomes kernel state, why there is one
   table, the one bound that is not path-keyed, why a grant is pinned to the
   object the harness vetted, and what happens when a grant covers a path sandbx
   owns
5. `decision-port-allowlist.md` — why a TCP port list costs UDP, what bounding
   egress to a host rather than a port would cost, and why a name allowlist is a
   hosts file and not a responder
6. `guide-process-lifetime.md` — why nothing sandbx starts outlives the call
   that started it
7. `guide-logging.md`, `decision-helper-audit-channel.md` — how a decision is
   recorded, how one made inside the helper gets out, and why a grant names a
   path and one flag names bytes instead
8. `decision-audit-records-access.md` — why a record names the access obtained
   and not the policy's decision
9. `guide-tools.md`, `guide-turn-loop.md` — the layers above
10. `decision-bounding-tool-work.md` — why a bound on a tool's input and a bound
    on its output are different propositions
11. `decision-provider-seam.md` — why there is no provider trait, and where the
    vendor's vocabulary stops
12. `decision-approval-gate.md` — what sits between the model and a tool, and
    how much it claims
13. `decision-credentials.md` — where a key comes from, why a sandboxed tool is
    handed none, and the one name that is refused
14. `decision-on-disk-state.md` — what sandbx writes outside the working
    directory, and who may read it
15. `decision-round-limit-answer.md` — why a turn out of rounds is asked once
    more, and what that costs
16. `decision-thinking-replay.md` — why a reasoning block is replayed inside a
    turn and nowhere else
17. `guide-tui.md` — what the screen draws, and what interrupting a turn loses
18. `guide-testing.md` — what a test has to assert, where it lives, and how long
    its name may be
19. `guide-ci.md` — what runs before a push, and what runs after
20. `guide-release-notes.md` — which half of a release body is written by hand,
    and which GitHub generates
21. `decision-google-style.md` — which style guide the code follows, and where
    it departs from it

`guide-` describes a subsystem as it currently is; `decision-` records why a
choice was made, and stays useful after the code moves.

One home per fact. A comment that has grown into an essay means this directory
needs a paragraph and the code needs a one-line pointer, and nothing measures a
doc's length — so the bound here is placement, not size: a fact lives in one doc,
and a second mention is a pointer to it. The rule above is how a duplicate is
resolved once one exists.
