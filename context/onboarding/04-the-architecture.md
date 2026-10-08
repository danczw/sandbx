# The architecture

The spine. Every later chapter zooms into one box drawn here, and opens by
saying which one — so when a chapter says "this is the gate", this is the page
that says where the gate sits.

One system, drawn three times: as **processes**, as **one request's path**, and
as a set of named **boundaries**. The three views describe the same code and
disagree about nothing; they answer different questions, and most confusion
about sandbx comes from trying to answer a process question with a data-flow
picture or the reverse.

## View 1 — three processes

A tool that only reads and writes files never leaves the harness process. A tool
that runs a program costs three processes, and the reason there are three rather
than two is a kernel detail worth getting straight early.

```
sandbx                                              ← unconfined
  │  parses argv, derives the policy, asks the model,
  │  decides, records
  │
  ├─► FsGuard                                       ← in-process enforcement
  │      6 of the 7 built-in tools never go further
  │
  └─► spawn::command  ──exec──►  /proc/self/exe --sandbx-core-exec
         │
         ├─ stage 1: helper supervisor               ← unconfined
         │    unshare(NEWUSER | NEWPID [| NEWNET])
         │    uid/gid map, drop capability sets,
         │    RLIMIT_CORE = 0, no_new_privs,
         │    the resolver bind mount
         │    └─exec─► /proc/self/exe --sandbx-core-exec-inner
         │
         └─ stage 2: helper inner, PID 1             ← confined by apply()
              pdeathsig, confirm the supervisor,
              apply(), then execve the command
```

| # | process | job |
|---|---|---|
| 0 | `sandbx` | spawns stage 1; when a timeout is set, in its own process group, polls the deadline and `killpg`s |
| 1 | helper supervisor | the namespaces, the mappings, the capability drops — everything that has to happen in a process that still needs to spawn one |
| 2 | helper inner | PID 1 of the new namespace. Arms `pdeathsig`, confirms its parent, applies seccomp and Landlock, becomes the command |

**Why stage 1 exists at all:** `unshare(CLONE_NEWPID)` places a process's
*children* in the new PID namespace, not the process itself. So the only way to
get a process that *is* PID 1 is to unshare in a parent and then create a child.
Stage 2 is a second `exec` of the same binary rather than a `fork`, because a
`fork` here would need `unsafe` — and the workspace sets
`unsafe_code = "forbid"` with no per-crate exemption.

**What is unconfined, and said out loud:** stages 0 and 1 both run with no
Landlock ruleset and no seccomp filter. For the supervisor that is structural —
it has to be able to spawn the stage that installs them —
and [`SECURITY.md`](../../SECURITY.md) carries it as an explicit *non-claim*
rather than leaving it to be discovered. The harness process is the same: a
vulnerability in sandbx's own code is not contained by sandbx.

- **Worth questioning:** the harness is the one process in this picture that
  parses untrusted input — the model's output, and file contents arriving as
  tool results — and it is the one process with no boundary at all. The
  non-claim is honest about it, and every decision record in `context/` reasons
  about confining *the command*; none asks whether the harness could confine
  itself. By the time `ExecutionContext::new` is called the harness's own needs
  are fully known: its session directory, its credential file, egress to the
  provider, the granted roots, and execute on `/proc/self/exe`. That is a
  writable Landlock policy, and Landlock is exactly the mechanism for
  self-restriction. What makes it hard is worth stating with the idea: the
  ruleset is irreversible, so anything needing a path discovered *later* —
  a resumed session's root, a grant widened mid-run — would have to move ahead
  of it or stop being possible. Neither happens in a single-shot run today,
  which is what makes now the cheap moment to ask.

Nothing sandbx starts outlives the call that started it (#28), by two
independent paths: the group kill from process 0, and `pdeathsig` on stage 2
plus the kernel's own teardown of a PID namespace whose PID 1 died. Two paths
because a command may call `setsid` and leave the process group, and `pdeathsig`
does not care about group membership.
[guide-process-lifetime.md](../guide-process-lifetime.md) has the kill chain,
and the one ordering rule inside it.

## View 2 — one request, end to end

`sandbx agent-run --allow-read /srv -- "what is in /srv?"`, traced once.

### Startup, in an order that is load-bearing

[`cli/src/main.rs`](../../crates/sandbx-cli/src/main.rs) does three things
before the subcommand runs, and the comments there say why each must be where it
is:

```rust
sandbx_core::with_helper_dispatch(std::env::args_os(), || {
```

That wrapper is first because *this same binary* is the helper. A process
re-exec'd with `--sandbx-core-exec` must restrict itself and become the target
command, never fall through into argument parsing. Logging is initialised
*inside* the closure, because in helper mode this process becomes the sandboxed
command and a subscriber above would write into that command's stderr.

The third is `conceal_process_state`, and it is the one step here that is itself
a boundary rather than a precondition for one. It clears this process's dumpable
flag, which reparents `/proc/<pid>/` to root and makes `environ`, `mem`, `maps`
and `fd/` fail a same-uid reader's access check — so a tool granted `/proc`
cannot read the provider key out of the harness's own environment. Its position
is pinned from both sides: inside the closure so the flag is sandbx's own and
not a sandboxed command's, and *after* parsing so a refusal exits with the
subcommand's code, with nothing spawned yet either way. A same-thread-group read
of `fd/` and `exe` stays exempt, which is why `digest` and the helper re-exec
still work.

Then [`AgentRun::execute`](../../crates/sandbx-cli/src/agent.rs) runs a sequence
where every step's position is justified in a comment. Read it once as a list:

| step | before what, and why |
|---|---|
| refuse an empty prompt | before the client — the API answers a 400 to what was knowable locally |
| `self.policy()?` | before the credential, so a refused policy never reads the key |
| `orientation::system_prompt(&policy, …)` | read off the *same* policy value: a second derivation re-reads `getcwd`, and a cwd that moved would name the model a root the sandbox did not grant |
| `ExecutionContext::new(policy)` | the policy moves in here and becomes private |
| `self.terminal()?` | before the credential and the session — a run with no channel to ask on is refused, so neither is opened for a turn that will not happen |
| `AnthropicClient::new(api_key()?)` | before the session, so a missing key leaves no header-only transcript nothing deletes |
| `session::open(…)` | last of the setup |

This is worth reading closely because it is the house style in miniature: the
order is the security property, and each line carries the counterexample that
fixes it in place. You will meet the same pattern inside `apply`, inside the
`pdeathsig` pair, and inside the default-policy guard.

### The round

`run_turn` then loops. [guide-turn-loop.md](../guide-turn-loop.md) is the
authority; the shape is:

```
┌─ round (max_rounds = 8) ────────────────────────────────────┐
│  request = history[cut..] ++ produced                       │
│  open(request)                     ◄── per-round timeout    │
│  consume stream ──► flush text before ToolUse, keep Usage   │
│  no ToolUse blocks?  ──► return TurnOutcome                 │
│  answer_calls (sequential)                                  │
│    resolve ─► offered? ─► approve ─► spawn_blocking         │
│    and each one, however it ended ─► settled                │
└─ loop ──────────────────────────────────────────────────────┘
```

Two things in that diagram are decisions rather than mechanics.

- **Re-entry is decided by the presence of `ToolUse` blocks, not by the stop
  reason the provider sent.** The blocks are what have to be answered; trusting
  the label would mean trusting the provider to describe its own output
  correctly. The stop reason is *reported* to the caller and nothing branches
  on it.
- **`approve` is asked before `spawn_blocking`, never racing it.** A blocking
  task cannot be cancelled (#26) — dropping the `JoinHandle` leaves it running
  to completion — so a gate consulted concurrently would be answering "denied"
  about a `write` that had already landed.

### Where a tool call actually reaches the filesystem

This is the fork in the road, and the single most important thing to carry out
of this chapter:

```
tool call
   │
   ├── read, write, edit, ls, grep, find  ──► FsGuard  ──► O_NOFOLLOW handle
   │        (6 of 7)                              in-process; Landlock never sees it
   │
   └── bash                               ──► SandboxedCommand ──► the three processes above
                (1 of 7)                              Landlock + seccomp + namespaces
```

For six of the seven built-ins, `FsGuard` **is** the enforcement. There is no
kernel boundary under them, because they never spawn anything for a kernel
boundary to apply to. A reader who has absorbed "sandbx uses Landlock" and
stopped there has the wrong model of the majority of what an agent does.

Everything else follows from the same run: a decision is recorded through
`tracing` under `AUDIT_TARGET`, one made *inside* the helper is relayed back
over the helper's own channel, and the finished turn is appended to a session
transcript as JSONL.

## View 3 — the boundaries, named

Six places where one part of the system refuses to trust, or refuses to know
about, another. Each is a deliberate shape in Rust, and the shape is the
enforcement — this is the view that explains why the code looks the way it does.

| boundary | where | the shape | what it buys |
|---|---|---|---|
| the vendor boundary | [`providers/src/anthropic.rs`](../../crates/sandbx-providers/src/anthropic.rs) and below | the body serializer is private to `anthropic/`; `Prompt` and friends have no `Serialize` | the top-level types cannot be posted to any API by accident, and every vendor rule and wire string sits at or below one file (#59) |
| the provider seam | [`providers/src/lib.rs`](../../crates/sandbx-providers/src/lib.rs) | `EventStream`, a boxed `FusedStream`; `run_turn` is generic over `AsyncFnMut(Prompt) -> Result<EventStream, …>` | no provider trait, no `dyn`, and no test double in anyone's public API |
| the tool boundary | [`tools/src/lib.rs`](../../crates/sandbx-tools/src/lib.rs) | `BuiltinTool`, a closed enum with `ALL: [Self; 7]`; `ToolSpec` crate-private | a new tool is a compile error everywhere it must be handled, not a registration that can be forgotten |
| the gate | [`agent/src/approval.rs`](../../crates/sandbx-agent/src/approval.rs) | `CallGate`, two methods, `run_turn`'s mandatory fifth parameter | there is no `run_turn_unchecked` — a caller cannot acquire a gate-less loop by omitting an argument |
| the policy's ownership | [`tools/src/context.rs`](../../crates/sandbx-tools/src/context.rs) | `ExecutionContext` holds the `SandboxPolicy` in a **private** field (#56) | a tool spends the policy through the context rather than being lent it to re-interpret |
| the two enforcement seams | [`core/src/fs_guard.rs`](../../crates/sandbx-core/src/fs_guard.rs) and [`core/src/helper_args.rs`](../../crates/sandbx-core/src/helper_args.rs) | handles rather than paths; an argv encoding where neither side trusts the other | the point where policy stops being data — [decision-enforcement-seam.md](../decision-enforcement-seam.md) |

The recurring trick is worth naming once: **a closed enum with an exhaustive
match is a compile-time gate.** `BuiltinTool` means a seventh tool cannot be
added without visiting every site that decides something about tools;
`HelperDispatch` has two variants and no success arm, so there is no value
representing "helper mode ran fine and we may now continue"; `TurnStop` is
matched exhaustively in `AgentRun::drive`, so a fourth way for a turn to end
cannot quietly reach the code that reports a clean one. None of those is
cleverness for its own sake — each one converts a runtime "did we remember?"
into a build failure.

## The CLI architecture

[`sandbx-cli`](../../crates/sandbx-cli/) is a library plus a binary: lib
`sandbx_cli`, bin `sandbx`. The split is not cosmetic, and the module doc says
what it is for:

> Parsing and policy derivation live here, not in `main.rs`, so a unit test can
> answer what a flag grants on a machine with no sandbox-capable kernel.

That is the whole reason. CI runs on hosts that cannot necessarily install a
Landlock ruleset; "what does `--allow-write /srv` grant" is a question about a
pure function over argv, and keeping it in the library half means it is answered
by a unit test rather than by a spawned binary.

So `main.rs` holds only what needs a real process:

- **helper dispatch**, which must precede parsing;
- **the tokio runtime** — `new_current_thread().enable_all()`. Current-thread
  because `spawn_blocking` is all the loop asks of the scheduler; `enable_all`
  rather than `enable_time` because the per-round timeout needs the timer *and*
  the provider's connector needs the IO driver. The flavour stays the binary's
  choice, which is why the agent crate asks for `rt` and never
  `rt-multi-thread`;
- **exit codes**, including the detail that `auth` fails with 2 rather than 1
  because `auth status` already spends 1 on "no key anywhere".

The five subcommands are one `Command` enum, and `Grants` — the `--allow-…`
flags — is flattened into each one that confines something, so no two
subcommands can disagree about what a flag means. `tui` is not a sixth thing:
it takes `agent-run`'s flags, derives the same policy, shares `gate.rs`,
`orientation.rs` and `session.rs`, and differs only in where a turn is reported.

## Where each box's detail lives

Every box above has one chapter that zooms into it and one `context/` doc that
owns it. The doc is the authority; the chapter is the on-ramp written to be read
before it.

| box | chapter | owned by |
|---|---|---|
| the three processes, the kill chain | [07](07-kernel-primer.md), [08](08-the-two-stage-helper.md) | [guide-process-lifetime.md](../guide-process-lifetime.md) |
| `apply`, Landlock, seccomp, the mount sequence | [08](08-the-two-stage-helper.md), [09](09-landlock.md), [10](10-seccomp.md) | [guide-sandboxing.md](../guide-sandboxing.md) |
| the two enforcement seams | [11](11-the-two-seams.md) | [decision-enforcement-seam.md](../decision-enforcement-seam.md) |
| what a grant confers on which axis | [12](12-a-flag-to-a-kernel-rule.md) | [decision-axis-table.md](../decision-axis-table.md) |
| what a no-flag run derives, and what it refuses | [12](12-a-flag-to-a-kernel-rule.md) | [decision-default-policy.md](../decision-default-policy.md) |
| the round loop, compaction, the three traps | [02](02-what-a-harness-is.md), [13](13-turn-loop-and-gate.md) | [guide-turn-loop.md](../guide-turn-loop.md) |
| the gate, and how much it claims | [13](13-turn-loop-and-gate.md) | [decision-approval-gate.md](../decision-approval-gate.md) |
| the provider seam and the vendor boundary | [02](02-what-a-harness-is.md) | [decision-provider-seam.md](../decision-provider-seam.md) |
| the seven tools and what bounds them | [15](15-tools-and-the-screen.md) | [guide-tools.md](../guide-tools.md), [decision-bounding-tool-work.md](../decision-bounding-tool-work.md) |
| what is recorded, and how the helper's half gets out | [14](14-audit-sessions-credentials.md) | [guide-logging.md](../guide-logging.md), [decision-helper-audit-channel.md](../decision-helper-audit-channel.md) |
| the transcript on disk | [14](14-audit-sessions-credentials.md) | [decision-on-disk-state.md](../decision-on-disk-state.md) |
| the screen, and what interrupting loses | [15](15-tools-and-the-screen.md) | [guide-tui.md](../guide-tui.md) |
| which crate owns what | [05](05-seven-crates.md) | [guide-repo-map.md](../guide-repo-map.md) |
| what is claimed, and what is not | [06](06-claims-and-non-claims.md), [17](17-gaps-and-open-questions.md) | [`SECURITY.md`](../../SECURITY.md) |

## You should now be able to explain

- Why there are three processes rather than two, in terms of what
  `unshare(CLONE_NEWPID)` does and does not place.
- Which processes in that picture are unconfined, and why one of them has to be.
- Why `with_helper_dispatch` is the first thing `main` does, and what would
  break if logging were initialised above it.
- Why the policy is derived before the API key is read.
- Which six tools never reach Landlock, and what enforces them instead.
- What `CallGate` being a mandatory parameter rather than an `Option` buys.
- Why "a closed enum plus an exhaustive match" keeps appearing, and name two
  places it does.
- Why parsing and policy derivation live in the library half rather than in
  `main.rs`.

## Next

[05 — seven crates](05-seven-crates.md), the static view under this runtime one,
and then the rest in the order on the [index](README.md). If you have only one
more sitting, spend it on the boundary: [06](06-claims-and-non-claims.md) for
what is claimed, then [11](11-the-two-seams.md) for where it is enforced.
