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
context/onboarding/ the read-through for a new engineer, with its own index
                    ◄── the on-ramp to the reading order at the end of this file
SECURITY.md         the promise to users — the one doc that must never lag
```

## Crates

```
sandbx-core      (no internal deps)  ── sandboxing; the only crate allowed to spawn
    └──► sandbx-tools ──┬──► sandbx-approval ──┐
                        ├──────────────────────┘
                        ├──► sandbx-agent ──┐  turn loop
sandbx-providers ───────┘                   │
         └──────────────────────────────────┼──► sandbx-cli   clap, policy
sandbx-approval ────────────────────────────┤                 derivation, the
sandbx-core ────────────────────────────────┤                 turn loop's caller
sandbx-logging ─────────────────────────────┤
sandbx-session ─────────────────────────────┤
sandbx-session-message ─────────────────────┤
sandbx-text ────┬───────────────────────────┤
                └──► sandbx-tui ────────────┘
```

`sandbx-logging` depends on `sandbx-core` for `AUDIT_TARGET` alone — the target
its filter admits. Drawn as a leaf for that reason: the edge carries one
constant, not a mechanism.

| Crate | Owns | Internal deps |
|---|---|---|
| `sandbx-core` | sandboxing. **The only crate allowed to spawn a subprocess** | — |
| `sandbx-tools` | the seven built-ins, each confined by core | core |
| `sandbx-providers` | hand-rolled streaming API clients | — |
| `sandbx-agent` | the turn loop | approval, tools, providers (core is *dev*-only) |
| `sandbx-cli` | arg parsing, policy derivation, the subcommand bodies | approval, core, agent, logging, providers, session, session-message, text, tools, tui |
| `sandbx-logging` | the one `tracing` subscriber, and the hold the screen takes | core |
| `sandbx-session` | the on-disk transcript: an id, a root, and append-only JSONL | session-message |
| `sandbx-tui` | the screen one turn is drawn on, the keys that stop it | providers, text (pty-fixture is *dev*-only) |
| `sandbx-pty-fixture` | a pty pair for tests that drive a real terminal | — |
| `sandbx-helper` | the test-only binary the enforcement suite spawns, and that suite | core |
| `sandbx-session-message` | the five shapes a transcript line is made of | — |
| `sandbx-text` | the one denylist of what model text may not carry to a terminal | — |
| `sandbx-approval` | what a gate is asked and what it is told; no policy | tools |

`sandbx-agent` depends on core only as a dev-dependency: its tests drive real
tools over a temp dir rather than mocking below the tool boundary.

`sandbx-session` depends on `sandbx-session-message` — the one internal edge the
diagram above does not draw, both crates having a direct edge to `sandbx-cli` of
their own. The CLI's is not inherited: it translates between those shapes and
the provider's, which is why `deny.toml` names both parents.

`sandbx-pty-fixture` is in no crate's build, which is why it is absent from the
diagram above; its own `//!` says why it is a crate and not a module (#344).

`sandbx-helper` is absent from it for the same reason and a different one: nothing
depends on it, and it depends on `sandbx-core` only to re-export its dispatch. It
is a crate so that `CARGO_BIN_EXE_sandbx-helper` resolves for the tests that spawn
it, which cargo sets only for a bin of the same package (#328 decision 5, #347).

`sandbx-cli` is the turn loop's only caller outside its own tests. It reaches
`sandbx-providers` directly rather than through `sandbx-agent`, which re-exports
none of it: `agent-run` builds the client and the first user turn itself, and
renders the events the loop hands back.

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
baseline is an error there, so the skip cannot go quiet.

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
src/lib.rs        EventStream (boxed FusedStream) — the provider seam
   prompt.rs      Prompt, RequestMessage, ContentBlock, ToolDefinition,
                  ToolChoice, Thinking — data, with no Serialize
   event.rs       AgentEvent, StopReason
   error.rs
   sse.rs         SSE framing
   anthropic.rs   the vendor boundary: re-exports AnthropicClient
      client.rs   AnthropicClient — the request, and the base-URL and
                  transport rules that keep the key off the network in cleartext
      body.rs     Serialize for the Messages body, built from a &Prompt
      wire/       accumulate.rs, payload.rs + unit tests
tests/            anthropic_client, crypto_provider, error,
                  live_anthropic (needs `live-anthropic-tests`)
```

The tree is the boundary for every vendor *rule*, and for every wire string
sandbx writes or matches on — the ones it carries verbatim cross as opaque data
(`StopReason::Other`, `ApiError::kind`). The rules are compiler-enforced: `Body`
is `pub(super)` in a private `mod body` and no neutral type derives `Serialize`,
so the top-level types cannot be posted to any API by accident; the wire
payloads are `pub(super)` bar the two error envelopes at `pub(crate)`;
and `stop_reason` is a private free function, so no `StopReason` comes from a
wire string outside `anthropic/` (#59). The vendor *name* is the one row
nothing *contains* — no lint, no containment test, no CI grep — and one
sibling of `anthropic.rs` carries it: `lib.rs` re-exports `AnthropicClient`.
The key and its variable's name are the CLI's, in `auth/key.rs`. Four more files
name it in doc comments only. Per-rule account in
[decision-provider-seam.md](decision-provider-seam.md).

## `sandbx-text`

```
src/lib.rs        invisible — the one denylist of what model text may not carry
                  to a terminal, read by both the cli's line sink and the tui's
```

Public surface: `invisible`, and nothing else. Zero dependencies, workspace or
external, so both sinks can reach it without either reaching the other: a
character added to one copy and not another re-opens the hole in whichever was
missed, and the drift would be a terminal-injection difference between two
surfaces users read as the same. What they share is the hazard — each sink keeps
its own replacement, there being no one answer to what belongs in a cell versus
a line. The crate's `//!` has why neither `sandbx-core` nor `sandbx-tui` is the
home (#363).

## `sandbx-approval`

```
src/lib.rs        CallGate, ToolCall, ApprovalDecision, Settled, Outcome — what
                  a gate is asked, the three answers it may give, one of which
                  ends the turn, and the five outcomes it is told a call reached
```

The shapes only: no policy, no channel to ask on, and nothing that decides.
`sandbx-agent` asks through them and the three production implementors live in
`sandbx-cli`, which is why both crates name it in `deny.toml` (#355). The trait
is foreign in `sandbx-cli` and the gate types are local there, so the
implementors need no edge back. Depends on `sandbx-tools` for the `BuiltinTool`
a call names and the `ToolError` an outcome carries.

## `sandbx-agent`

```
src/lib.rs    re-exports: TurnError, Turn, TurnLimits, TurnOutcome,
                          TurnStop, PromptUsage, Compaction, run_turn
   turn.rs    re-exports run_turn and the four types that drive it
      run.rs         run_turn — generic over a stream-opening closure
      accumulate.rs  one round's message, rebuilt from deltas
      tools.rs       what is offered, the gate, and the one spawn_blocking site
   compact.rs   which prefix of a history may be withheld, and PromptUsage —
                the measurement it is decided on, declared on this side of the
                edge because the turn depends on compaction and not the reverse
   compact_tests.rs  the cut-point algebra
   error.rs   TurnError
tests/       turn_loop, turn_compaction, audit_trail,
             support/mod.rs — the Script double and the request builders
```

## `sandbx-session-message`

```
src/lib.rs        Message, Role, Content, Usage, CompletedTurn — the five
                  shapes a transcript line is made of, and the three tests
                  that pin them against the wire
```

The stored types are declared here rather than imported from
`sandbx-providers`: a transcript is a file format, and one that moved whenever a
provider type moved would not be. The translation lives in `sandbx-cli`, where a
new content block is a compile error rather than a block quietly missing from a
transcript. Depends on no sandbx crate, which is what lets the format outlive a
change to either side of it (#359).

## `sandbx-session`

```
src/lib.rs        re-exports
   id.rs          SessionId — 1–32 of [0-9a-z], an allowlist because an id
                  becomes a path component
   paths.rs       sessions_directory — $XDG_STATE_HOME, else $HOME, never the
                  working directory
   store.rs       re-exports SessionStore and Session
      session.rs  SessionStore, Session; which bit refuses and which reports
      record.rs   the three line kinds, and the fold that replays them
      shape.rs    which orders of messages a request may carry, as predicates
      vet.rs      the modes, O_NOFOLLOW, and reading one off a descriptor
   error.rs       SessionError
tests/            identifier, permissions, recovery, transcript
```

One internal dependency, `sandbx-session-message`, whose section above says why
those shapes are its own and not the provider's. See
[decision-on-disk-state.md](decision-on-disk-state.md) for the roots, the mode
rule and the line format.

## `sandbx-tui`

```
src/lib.rs          re-exports; nothing here knows of a policy or a provider
   transcript.rs    AgentEvent folded into entries, and the control bytes a cell
                    may not hold — no terminal behind it, so it is unit-tested
   view.rs          the layout: the transcript tail-aligned over a status bar
   screen.rs        Screen — raw mode and the alternate screen, put back on drop
   input.rs         Keys — the reader thread, and the press a turn awaits
```

## `sandbx-cli`

```
src/lib.rs      mod lines and re-exports; no code
   invocation.rs
                Cli, Command — the clap surface and nothing else
   grants.rs    re-exports Grants
   grants/flags.rs
                Grants — the --allow-… flags, flattened into every subcommand
                that confines something, and the policy they derive
   grants/root.rs
                where a no-flag run may root its default policy, and what a
                path flag is vetted against, including the refusal of a grant
                reaching a path sandbx owns (unit-testable without a
                sandbox-capable kernel)
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
   auth.rs      re-exports Auth and the three names the crate reaches
   auth/key.rs  Auth — which source the provider key comes from: the
                environment, then a file, and the login/logout/status over it
   auth/store.rs
                the credential file itself — its TOML shape, and the 0600/0700
                modes it is refused and written under
   session.rs   --session: which session to open, and the translation to and from
                the stored shapes
   error.rs     re-exports the five, and is the list of them
   error/agent.rs
                AgentError — twelve ways a turn does not finish
   error/run.rs
                SandboxRunError — Policy, Sandbox
   error/policy.rs
                PolicyError, and the one ADVICE every derived-default refusal
                appends
   error/hash.rs
                HashError — a path and an io::Error, no variants
   error/auth.rs
                AuthError — what stops `auth`, or a key resolution under `agent-run`
src/main.rs     helper dispatch, the tokio runtime, exit codes
tests/          agent_run, agent_session, auth, auth_store, cwd_policy, hash,
                name, sandbox_run, usage
```

Lib `sandbx_cli`, bin `sandbx`. Five subcommands: `sandbox-run`, `agent-run`,
`tui`, `hash` and `auth`. `tui` is `agent-run`'s flags, policy and session
drawn on a screen rather than streamed to stdout, so the two share `gate.rs`,
`orientation.rs` and `session.rs` and differ only in where a turn is reported.
`hash` and `auth` run no sandbox — `hash` reads one file, so a
digest can be taken before there is a policy to take it under, and `auth` touches
only the credential file.

`Grants` exists so the axis loop, the one widening it applies — a write grant
confers read — and the working-directory default are written once. Two copies
would drift, and the drift would be a policy difference between subcommands that
users reasonably read as the same flags.

## Reading order

Two passes, if the repo is new to you. `context/onboarding/` is the first: a
numbered read-through that builds the vocabulary this order assumes, from what
sandbx is to why the order of `apply` is load-bearing, followed by a per-crate
reference block read when you land in a crate rather than in order. It carries
its own index, and no entry here per chapter. The order below is the second
pass, and reads as reference rather than as a wall once the first is done.

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
6. `decision-default-policy.md` — what a no-flag run grants, and the directories
   it refuses instead
7. `guide-process-lifetime.md` — why nothing sandbx starts outlives the call
   that started it
8. `guide-logging.md`, `decision-helper-audit-channel.md` — how a decision is
   recorded, how one made inside the helper gets out, and why a grant names a
   path and one flag names bytes instead
9. `decision-audit-records-access.md` — why a record names the access obtained
   and not the policy's decision
10. `guide-tools.md`, `guide-turn-loop.md` — the layers above
11. `decision-bounding-tool-work.md` — why a bound on a tool's input and a bound
    on its output are different propositions
12. `decision-provider-seam.md` — why there is no provider trait, and where the
    vendor's vocabulary stops
13. `decision-approval-gate.md` — what sits between the model and a tool, and how
    much it claims
14. `decision-credentials.md` — where a key comes from, why a sandboxed tool is
    handed none, and the one name that is refused
15. `decision-on-disk-state.md` — what sandbx writes outside the working
    directory, and who may read it
16. `decision-round-limit-answer.md` — why a turn out of rounds is asked once
    more, and what that costs
17. `decision-thinking-replay.md` — why a reasoning block is replayed inside a
    turn and nowhere else
18. `guide-tui.md` — what the screen draws, and what interrupting a turn loses
19. `guide-testing.md` — what a test has to assert, where it lives, and how long
    its name may be
20. `guide-ci.md` — what runs before a push, and what runs after
21. `guide-release-notes.md` — which half of a release body is written by hand,
    and which GitHub generates
22. `decision-google-style.md` — which style guide the code follows, and where it
    departs from it

`guide-` describes a subsystem as it currently is; `decision-` records why a
choice was made, and stays useful after the code moves.

One home per fact. A comment that has grown into an essay means this directory
needs a paragraph and the code needs a one-line pointer, and nothing measures a
doc's length — so the bound here is placement, not size: a fact lives in one doc,
and a second mention is a pointer to it. The rule above is how a duplicate is
resolved once one exists.
