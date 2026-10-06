# Repo map

Virtual Cargo workspace, `members = ["crates/*"]`, resolver 3, edition 2024.

```
Cargo.toml          workspace manifest + lint table (unsafe_code = "forbid",
                    workspace-wide with no per-crate exemption, sandbx-core
                    included; zero unsafe anywhere)
clippy.toml         the disallowed-methods list
deny.toml           cargo-deny
.githooks/          pre-commit: fmt --check, clippy -D warnings; commit-msg:
                    Conventional Commits and a 72-character subject
.github/            CI and release workflows, their action pins, and dependabot
.github/scripts/    what a workflow calls but must be runnable without one
docs/release-notes/ one file per tag, which the release gates on; TEMPLATE.md
SECURITY.md         the promise to users — the one doc that must never lag
```

## Crates

```
sandbx-core      (no internal deps)  ── sandboxing; the only crate allowed to spawn
    └──► sandbx-tools ──┐
                        ├──► sandbx-agent ──┐  turn loop
sandbx-providers ───────┘                   │
         └──────────────────────────────────┼──► sandbx-cli   clap, policy
sandbx-core ────────────────────────────────┤                 derivation, the
sandbx-session ─────────────────────────────┘                 turn loop's caller
sandbx-tui       placeholder
```

| Crate | Owns | Internal deps |
|---|---|---|
| `sandbx-core` | sandboxing. **The only crate allowed to spawn a subprocess** | — |
| `sandbx-tools` | the seven built-ins, each confined by core | core |
| `sandbx-providers` | hand-rolled streaming API clients | — |
| `sandbx-agent` | the turn loop | tools, providers (core is *dev*-only) |
| `sandbx-cli` | arg parsing, policy derivation, the subcommand bodies | core, agent, providers, session, tools |
| `sandbx-session` | the on-disk transcript: an id, a root, and append-only JSONL | — |
| `sandbx-tui` | placeholder (#133) | — |

`sandbx-agent` depends on core only as a dev-dependency: its tests drive real
tools over a temp dir rather than mocking below the tool boundary.

`sandbx-cli` is the turn loop's only caller outside its own tests. It reaches
`sandbx-providers` directly rather than through `sandbx-agent`, which re-exports
none of it: `agent-run` builds the client and the first user turn itself, and
renders the events the loop hands back.

It also owns the tokio runtime, because the flavour is the binary's choice and
`sandbx-agent` deliberately does not make it — see `guide-turn-loop.md`.

## `sandbx-core`

```
src/lib.rs           re-exports; Linux-only, refused at compile time
   policy.rs         Axis, Grants, SandboxPolicy        ◄── the table
   fs_guard.rs       in-process path enforcement (6 of 7 tools)
   command.rs        SandboxedCommand, the audit pipe, the kill chain
      dispatch.rs    HELPER_FLAG, HELPER_INNER_FLAG, HelperDispatch — the entry
                     into helper mode
   helper_args.rs    the argv seam: encode/decode, --ro/--rw/--rx,
                     --allow-network-port, --env, --dns-over-tcp, --pin-sha256
   digest.rs         Sha256Digest; open_verified and fd_path, the pinned exec
   audit.rs          AuditEvent, AUDIT_TARGET
   degradation.rs    the helper's channel to the parent, and its wire format
   spawn.rs          spawn::command — the one Command::new; env_clear, then
                     the allowlist and the policy's own constants
   error.rs
   bin/sandbx-helper.rs
   helper/
      mod.rs         the two stages — exec_sandboxed, then exec_inner as PID 1;
                     apply() sequences all three mechanisms; exit_code
      hardening.rs   namespaces, capsets, rlimits, pdeathsig, ppid_from_stat
      seccomp.rs     compiled_filter, clone3_filter, x32_gate,
                     deny_dangerous_syscalls — how it reaches the kernel
         rules.rs    BLOCKED_SYSCALLS (28), blocked_syscalls — what is denied
         tests/      unit tests: denylist, sockets, namespaces, arch; plus the
                     eval interpreter they are all read through
      ruleset/
         mod.rs      Requested { handled, rules, net }, RequestedNet —
                     requested, requested_at
         compat.rs   handled_access, handled_net_access, kernel_probe,
                     negotiated_abi_from, negotiated_abi, enforcement_verdict
         rights.rs   rights_for, fs_rules, net_rules
         tests/      unit tests: compat, grants, net, rules
tests/               audit, audit_channel, audit_outcome (6, how a real run
                     ends), capability_coverage, command, denylist,
                     enforcement (39 real-kernel tests, paths and grants),
                     enforcement_syscalls (8, calls Landlock cannot express),
                     enforcement_network (6, the TCP ports it can),
                     fs_guard, helper_args, policy
tests/support/       mod.rs — runtime_paths, allow_probe, run, run_pinned,
                     shared by the three enforcement targets; plus 6 [[bin]] probes,
                     required-features = ["sandbox-integration"]
```

Public surface: `AuditEvent`, `AUDIT_TARGET`, `SandboxedCommand`, `HELPER_FLAG`,
`HELPER_INNER_FLAG`, `HelperDispatch`, `dispatch_helper_mode`,
`with_helper_dispatch`, `SandboxError`, `Access`, `FsGuard`, `ReadableWalk`,
`BLOCKED_SYSCALLS`, `exit_code`, `HelperArgs`, `Axis`, `Grants`,
`NetworkPolicy`, `SandboxPolicy`, `Sha256Digest`, `DigestParseError`.

`Access` is the guard's two root sets, not `Axis`: `Axis::ReadExecute` has no
in-process meaning, and a refusal carries an `Access` so it can name the grant it
lacked rather than implying none was given.

One per-call-site `#[allow(clippy::disallowed_methods)]` for `Command::new`, in
`spawn::command` — that site, not the whole crate. The lint *is* the backstop: a
CI grep for `Command::new` would be a second one, but a lint that fails the build
at the call site beats a grep that fails after it.

## `sandbx-tools`

```
src/lib.rs        BuiltinTool (closed enum), ALL: [Self; 7], ToolSpec, ToolOutput,
                  RiskLevel
   context.rs     ExecutionContext — policy is PRIVATE (#56)
   limits.rs      ToolLimits
   error.rs       ToolError: Denied | BadInput | Failed | TimedOut
   tools/         bash, edit, find, grep, ls, read, write — each with its SPEC
tests/            per-tool (find and grep share search), plus registry, limits,
                  scan_limits, spawn
```

Public surface: `ExecutionContext`, `DEFAULT_TIMEOUT`, `ToolError`, `ToolLimits`,
`ToolOutput`, `BuiltinTool`, `RiskLevel`.

## `sandbx-providers`

```
src/lib.rs        EventStream (boxed FusedStream) — the provider seam
   anthropic.rs   AnthropicClient
   credentials.rs resolve_api_key, anthropic_api_key, SecretString
   error.rs       ProviderError
   event.rs       AgentEvent, StopReason
   request.rs     MessagesRequest
   sse.rs         SSE framing
   mock.rs        MockProvider — behind the `mock` feature
   wire/          accumulate.rs, payload.rs + unit tests
tests/            anthropic_client, credentials, crypto_provider, error,
                  mock_provider (needs `mock`),
                  live_anthropic (needs `live-anthropic-tests`),
                  request_serialization
```

No vendor SDK, and no trait or enum over the backends: the seam is the
`EventStream` return type, which every client's `stream_chat` hands back. #90
deleted the one-variant `Provider` enum that used to sit in front of it.

## `sandbx-agent`

```
src/lib.rs    re-exports: TurnError, Turn, TurnLimits, TurnOutcome,
                          PromptUsage, Compaction, ToolCall, ApprovalDecision,
                          run_turn
   turn.rs    run_turn — generic over a stream-opening closure
      accumulate.rs  one round's message, rebuilt from deltas
      tools.rs       what is offered, the gate, and the one spawn_blocking site
   approval.rs  what a gate is asked, and the two answers it may give
   compact.rs   which prefix of a history may be withheld
      tests.rs       the cut-point algebra
   error.rs   TurnError (6 variants)
tests/       turn_loop (22), turn_compaction (23),
             support/mod.rs — the Script double and the request builders
```

## `sandbx-session`

```
src/lib.rs        re-exports
   id.rs          SessionId — 1–32 of [0-9a-z], an allowlist because an id
                  becomes a path component
   paths.rs       sessions_directory — $XDG_STATE_HOME, else $HOME, never the
                  working directory
   message.rs     Message, Role, Content, Usage, CompletedTurn — the stored
                  shapes, declared rather than imported
   store.rs       SessionStore, Session; which bit refuses and which reports
      record.rs   the three line kinds, and the fold that replays them
      vet.rs      the modes, O_NOFOLLOW, and reading one off a descriptor
   error.rs       SessionError
tests/            identifier, permissions, recovery, transcript
```

No internal dependency, and the stored types are its own rather than
`sandbx-providers`': a transcript is a file format, and one that moved whenever a
provider type moved would not be. The translation lives in `sandbx-cli`, where a
new content block is a compile error rather than a block quietly missing from a
transcript. See [decision-on-disk-state.md](decision-on-disk-state.md) for the
roots, the mode rule and the line format.

## `sandbx-cli`

```
src/lib.rs      Cli, Command — the clap surface and nothing else
   grants.rs    Grants — the --allow-… flags, flattened into both subcommands,
                the policy they derive, and the working-directory default a
                no-flag run gets (unit-testable without a sandbox-capable
                kernel)
   sandbox.rs   SandboxRun
   hash.rs      Hash — the one subcommand that confines nothing
   agent.rs     AgentRun — the turn loop's caller, and the gate it answers with
      render.rs the answer on stdout, everything about it on stderr
   auth.rs      Auth — which source the provider key comes from: the
                environment, then a file, and the login/logout/status over it
   auth/store.rs
                the credential file itself — its TOML shape, and the 0600/0700
                modes it is refused and written under
   session.rs   --session: which session to open, and the translation to and from
                the stored shapes
   error.rs     AgentError, SandboxRunError, PolicyError, HashError
   error/auth.rs
                AuthError — what stops `auth`, or a key resolution under `agent-run`
   logging.rs   the one subscriber
src/main.rs     helper dispatch, the tokio runtime, exit codes
tests/          agent_run, agent_session, audit_log, audit_log_install, auth,
                auth_store, cwd_policy, hash, name, sandbox_run
```

Lib `sandbx_cli`, bin `sandbx`. Four subcommands: `sandbox-run`, `agent-run`,
`hash` and `auth`. The last two run no sandbox — `hash` reads one file, so a
digest can be taken before there is a policy to take it under, and `auth` touches
only the credential file.

`Grants` exists so the axis loop, the one widening it applies — a write grant
confers read — and the working-directory default are written once. Two copies
would drift, and the drift would be a policy difference between two subcommands
that users reasonably read as the same flags.

## Reading order

1. `SECURITY.md` — what is claimed
2. `guide-sandboxing.md` — how it is enforced
3. `decision-enforcement-seam.md` — where policy becomes kernel state
4. `decision-axis-table.md` — why there is one table
5. `decision-environment-allowlist.md` — the one bound that is not path-keyed
6. `decision-port-allowlist.md` — why a TCP port list costs UDP
7. `decision-default-policy.md` — what a no-flag run grants, and the directories
   it refuses instead
8. `decision-pinned-entry-point.md` — why a grant names a path and one flag names
   bytes instead
9. `guide-logging.md`, `decision-helper-audit-channel.md` — how a decision is
   recorded, and how one made inside the helper gets out
10. `guide-tools.md`, `guide-turn-loop.md` — the layers above
11. `decision-provider-seam.md` — why there is no provider trait, and what is still
    vendor-shaped
12. `decision-approval-gate.md` — what sits between the model and a tool, and how
    much it claims
13. `decision-credentials.md` — where a key comes from, and what a sandboxed tool
    is not given
14. `decision-on-disk-state.md` — what sandbx writes outside the working
    directory, and who may read it

`guide-` describes a subsystem as it currently is; `decision-` records why a
choice was made, and stays useful after the code moves.
