# Repo map

Virtual Cargo workspace, `members = ["crates/*"]`, resolver 3, edition 2024.

```
Cargo.toml          workspace manifest + lint table (unsafe_code = "forbid",
                    workspace-wide with no per-crate exemption — the one planned
                    for sandbx-core was never needed; zero unsafe anywhere)
clippy.toml         the disallowed-methods list
deny.toml           cargo-deny
.githooks/          pre-commit: fmt --check, clippy -D warnings, subject length
.github/            CI and release workflows, their action pins, and dependabot
SECURITY.md         the promise to users — the one doc that must never lag
```

## Crates

```
sandbx-core      (no internal deps)  ── sandboxing; the only crate allowed to spawn
    └──► sandbx-tools ──┐
                        ├──► sandbx-agent ──┐  turn loop
sandbx-providers ───────┘                   │
         └──────────────────────────────────┼──► sandbx-cli   clap, policy
sandbx-core ────────────────────────────────┘                 derivation, the
sandbx-session   placeholder                                  turn loop's caller
sandbx-tui       placeholder
```

| Crate | Owns | Internal deps |
|---|---|---|
| `sandbx-core` | sandboxing. **The only crate allowed to spawn a subprocess** | — |
| `sandbx-tools` | the seven built-ins, each confined by core | core |
| `sandbx-providers` | hand-rolled streaming API clients | — |
| `sandbx-agent` | the turn loop | tools, providers (core is *dev*-only) |
| `sandbx-cli` | arg parsing, policy derivation, the subcommand bodies | core, agent, providers, tools |
| `sandbx-session` | placeholder — nothing implemented | — |
| `sandbx-tui` | placeholder — nothing implemented | — |

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
      dispatch.rs    HELPER_FLAG, HelperDispatch — the entry into helper mode
   helper_args.rs    the argv seam: encode/decode, --ro/--rw/--rx, --env
   audit.rs          AuditEvent, AUDIT_TARGET
   spawn.rs          spawn::command — the one Command::new; env_clear + allowlist
   error.rs
   bin/sandbx-helper.rs
   helper/
      mod.rs         apply() — sequences all three mechanisms; exit_code
      hardening.rs   namespaces, capsets, rlimits, pdeathsig, ppid_from_stat
      seccomp.rs     BLOCKED_SYSCALLS (28), blocked_syscalls, compiled_filter
         tests.rs    the denylist, the program, and the eval interpreter
      ruleset/
         mod.rs      Requested { handled, rules } — requested, requested_at
         compat.rs   handled_access, kernel_probe, negotiated_abi_from,
                     negotiated_abi, enforcement_verdict
         rights.rs   rights_for, fs_rules
         tests/      unit tests: compat, grants, rules
tests/               audit, capability_coverage, command, denylist,
                     enforcement (31 real-kernel tests, paths and grants),
                     enforcement_syscalls (8, calls Landlock cannot express),
                     fs_guard, helper_args, policy
tests/support/       mod.rs — runtime_paths, allow_probe, run, shared by the two
                     enforcement targets; plus 5 [[bin]] probes,
                     required-features = ["sandbox-integration"]
```

Public surface: `AuditEvent`, `AUDIT_TARGET`, `SandboxedCommand`,
`HelperDispatch`, `SandboxError`, `Access`, `FsGuard`, `ReadableWalk`,
`BLOCKED_SYSCALLS`, `exit_code`, `HelperArgs`, `Axis`, `Grants`,
`SandboxPolicy`.

`Access` is the guard's two root sets, not `Axis`: `Axis::ReadExecute` has no
in-process meaning, and a refusal carries an `Access` so it can name the grant it
lacked rather than implying none was given.

Four per-call-site `#[allow(clippy::disallowed_methods)]` for `Command::new` —
the four sites that spawn, not the whole crate. The lint *is* the backstop: a CI
grep for `Command::new` was planned as a second one and never added, because a
lint that fails the build at the call site beats a grep that fails after it.

## `sandbx-tools`

```
src/lib.rs        BuiltinTool (closed enum), ALL: [Self; 7], ToolSpec, ToolOutput
   context.rs     ExecutionContext — policy is PRIVATE (#56)
   limits.rs      ToolLimits
   error.rs       ToolError: Denied | BadInput | Failed | TimedOut
   tools/         bash, edit, find, grep, ls, read, write — each with its SPEC
tests/            per-tool, plus registry, limits, scan_limits, spawn
```

Public surface: `ExecutionContext`, `ToolError`, `ToolLimits`, `ToolOutput`,
`BuiltinTool`.

## `sandbx-providers`

```
src/lib.rs        EventStream (boxed FusedStream) — the provider seam
   anthropic.rs   AnthropicClient
   credentials.rs resolve_api_key, SecretString
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
                          PromptUsage, Compaction, run_turn
   turn.rs    run_turn — generic over a stream-opening closure
      accumulate.rs  one round's message, rebuilt from deltas
      tools.rs       what is offered, and the one spawn_blocking site
 compact.rs   which prefix of a history may be withheld
      tests.rs       the cut-point algebra
   error.rs   TurnError (6 variants)
tests/       turn_loop (16), turn_compaction (23),
             support/mod.rs — the Script double and the request builders
```

## `sandbx-cli`

```
src/lib.rs      Cli, Command — the clap surface and nothing else
   grants.rs    Grants — the --allow-… flags, flattened into both subcommands,
                and the policy they derive (unit-testable without a
                sandbox-capable kernel)
   sandbox.rs   SandboxRun
   agent.rs     AgentRun — the turn loop's caller
   error.rs     AgentError
   logging.rs   the one subscriber
src/main.rs     helper dispatch, the tokio runtime, exit codes
tests/          agent_run, audit_log, audit_log_install, name, sandbox_run
```

Lib `sandbx_cli`, bin `sandbx`. Two subcommands: `sandbox-run` and `agent-run`.

`Grants` exists so the axis loop and the one widening it applies — a write grant
confers read — are written once. Two copies would drift, and the drift would be a
policy difference between two subcommands that users reasonably read as the same
flags.

## Reading order

1. `SECURITY.md` — what is claimed
2. `guide-sandboxing.md` — how it is enforced
3. `decision-enforcement-seam.md` — where policy becomes kernel state
4. `decision-axis-table.md` — why there is one table
5. `decision-environment-allowlist.md` — the one bound that is not path-keyed
6. `guide-logging.md`, `decision-helper-audit-channel.md` — how a decision is
   recorded, and how one made inside the helper gets out
7. `guide-tools.md`, `guide-turn-loop.md` — the layers above
8. `decision-provider-seam.md` — why there is no provider trait, and what is still
   vendor-shaped
9. `decision-credentials.md` — where a key comes from, and what a sandboxed tool
   is not given

`guide-` describes a subsystem as it currently is; `decision-` records why a
choice was made, and stays useful after the code moves.
