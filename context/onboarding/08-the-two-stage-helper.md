# The helper is this same binary, run again with a flag

This chapter is the arrow in **View 1 — three processes** of
[04 — the architecture](04-the-architecture.md), the one labelled
`spawn::command ──exec──► /proc/self/exe --sandbx-core-exec`, and the two boxes
hanging under it. That diagram is the map and this chapter does not redraw it;
read it first, then come here for what each line of it actually does and why the
lines cannot be reordered.

[07 — the kernel primer](07-kernel-primer.md) is the prerequisite. Everything
below assumes you know what `unshare(CLONE_NEWPID)` places, why a capability
bounding set is dropped before the effective set, and what a parent death signal
is cleared by. The code is almost all in
[`helper/mod.rs`](../../crates/sandbx-core/src/helper/mod.rs),
[`helper/hardening.rs`](../../crates/sandbx-core/src/helper/hardening.rs) and
[`command/dispatch.rs`](../../crates/sandbx-core/src/command/dispatch.rs), and
`helper/mod.rs` says in its own module doc that it is over the module budget
([guide-module-layout.md](../guide-module-layout.md)) deliberately, because it
is one ordered syscall sequence and splitting an order across files is how an
order gets broken.

## Why the helper is this binary, and why it is reached by inode

There is no separate helper executable to install, find or keep in step. The
command sandbx builds re-runs **itself**:
[`command.rs`](../../crates/sandbx-core/src/command.rs) has a `self_exe` that
returns the literal path `/proc/self/exe`, having first `read_link`ed it only to
check that procfs answers at all. The path handed to `execve` is the magic link,
not what it resolved to.

Three things follow, and the third is the security property.

- **Nothing is looked up.** No `PATH` search, no install prefix, no
  configuration naming a helper. There is no name for an attacker to win a race
  on, because there is no name.
- **The two stages are one image, so they cannot disagree.** The policy decoder
  in stage 2 is the encoder's own counterpart from the same build, not a
  separately versioned program that might parse `--rx` differently.
- **A rename over the binary cannot redirect the next spawn.** This is the
  reason the doc on `SandboxedCommand` gives, and
  [decision-default-policy.md](../decision-default-policy.md) states it as a
  rule under "the enforcer is reached by inode" (#149). `/proc/self/exe` names
  the *inode of the running image*, so replacing the file at the installed path
  — a package upgrade, or an attacker with write access to it — does not change
  what the re-exec reaches. The running image is also protected from in-place
  overwrite by the kernel's own `ETXTBSY`.

There is one subtlety in handing `execve` a self-referential path. The
resolution happens in the *child* that `Command::spawn` forked, so "self" there
is the child — and pre-exec, the child's image is the one it inherited, which is
this binary. The comment on `exec_sandboxed` names exactly that: it is
"`/proc/self/exe` unresolved, which the forked child reads as the image it
inherited rather than as a second lookup."

The cost is a shape constraint on every `main` in the workspace, which is what
the next two sections are about.

- **The one documented exception** is `SandboxedCommand::helper()`, which points
  the helper at a path instead. It is for tests, whose harness `main` has no
  dispatch of its own and so cannot be its own helper; they point it at the
  standalone
  [`sandbx-helper`](../../crates/sandbx-core/src/bin/sandbx-helper.rs) binary. A
  path is not an inode, and [`SECURITY.md`](../../SECURITY.md) names that as a
  limit rather than leaving it implied.

## Two flags, and the argv they sit at the front of

Helper mode is argv, and only argv. Two constants in `command/dispatch.rs`:

| flag | means | who writes it |
|---|---|---|
| `HELPER_FLAG` — `--sandbx-core-exec` | be stage 1: make the namespaces, spawn stage 2 | the harness, in `command_line()` |
| `HELPER_INNER_FLAG` — `--sandbx-core-exec-inner` | be stage 2: confine this process, become the command | stage 1, in `start_inner_stage` |

The flag must be `argv[1]`. `dispatch_helper_mode` splits argv after the
program's own name and matches on the first element only, so a
`--sandbx-core-exec` appearing anywhere else is an ordinary argument — including
inside the command the sandbox is being asked to run.

Three things ride alongside the flags, in a fixed order, and each is outside the
policy grammar on purpose:

- **`AUDIT_STDIN_FLAG` — `--sandbx-audit-stdin`.** Says "your stdin is the audit
  channel". Opt-in rather than implied by `HELPER_FLAG`, because without it a
  hand-invoked helper would write records into whatever fd 0 happens to be: a
  terminal is writable, so the records would surface as the command's own
  output, and a read-only pipe gives `EBADF`. Stage 1 passes it down to stage 2.
  [decision-helper-audit-channel.md](../decision-helper-audit-channel.md) is the
  record.
- **The supervisor's pid**, a bare number, positional, and the *first* token
  stage 2 reads — before the audit flag, and before the policy. Two reasons in
  the comment on `exec_inner`: the policy grammar and its round-trip stay
  untouched, and a caller reaching `exec_inner` directly cannot smuggle a
  supervisor pid in through the policy. It is a liveness token and explicitly
  not an authorization token.
- **The policy itself**, after a `--`, in the wire encoding owned by
  [`helper_args.rs`](../../crates/sandbx-core/src/helper_args.rs). Stage 1
  decodes it for its own use and then passes the original tokens **verbatim** to
  stage 2 — "a re-encode would be a second chance for the policy to drift on its
  way to the stage that enforces it".
  [decision-enforcement-seam.md](../decision-enforcement-seam.md) has the table,
  and the line worth carrying away: on this seam, which side is trusted —
  neither.

## `HelperDispatch` has no success variant

`main` cannot know whether it is the harness or the helper until it has looked
at argv, and the consequence of getting that wrong is unbounded: a process
started as the helper that falls through into ordinary argument parsing is a
command that runs with no sandbox. So the type that reports the answer is built
so that "carry on as normal" cannot be spelled by accident.

```rust
/// What [`dispatch_helper_mode`] decided. Two outcomes, not three: becoming the command
/// never returns, so there is no success variant to ignore by accident.
#[derive(Debug)]
#[must_use = "a helper run that failed must not fall through to running the command"]
pub enum HelperDispatch {
    /// Not a helper invocation: an ordinary run, argv too short to carry a flag included.
    NotHelperMode,

    /// Helper mode ran and failed; no unrestricted execution occurred. ...
    Failed(SandboxError),
}
```

Two variants for three imaginable outcomes. The missing one is success, and it
is missing because it is unreachable: both entry points return
`Result<Infallible, SandboxError>`, so the only way out of a helper run that
worked is the `execve` that replaces the process image. The match that
dispatches has no success arm to write:

```rust
match flag.as_str() {
    HELPER_FLAG => match crate::helper::exec_sandboxed(helper_args) {
        Err(error) => HelperDispatch::Failed(error),
    },
    HELPER_INNER_FLAG => match crate::helper::exec_inner(helper_args) {
        Err(error) => HelperDispatch::Failed(error),
    },
    _ => HelperDispatch::NotHelperMode,
}
```

Those inner `match`es have one arm each and are exhaustive, which is a thing
`Infallible` buys and a comment cannot: the compiler agrees there is no `Ok`.

`with_helper_dispatch` then owns the half a hand-written `main` gets wrong. It
takes the ordinary main as a closure, so for any binary that uses it the
ordinary path *cannot* run before dispatch; `Failed` prints with
`HELPER_FAILURE_PREFIX` and returns `ExitCode::FAILURE`, because "printing the
error but returning zero falls through to the ordinary path, which is a command
that runs unrestricted". Its own doc admits the residual: *it cannot enforce
being called first*. The CLI pays that by initialising logging **inside** the
closure — a subscriber installed above would write sandbx's records into the
sandboxed command's stderr.

### A Rust aside: `#[must_use]` on a closed enum, and what it does not do

`#[must_use]` on a *type* makes the compiler warn whenever a value of that type
is produced in statement position and dropped. The lint is `unused_must_use`, it
is warn-by-default, and CI runs
`cargo clippy --workspace --all-targets -- -D warnings`
([guide-ci.md](../guide-ci.md)), which turns it into a failed build. So
`dispatch_helper_mode(args);` on a line of its own does not compile here.

Be precise about the limit, because it is the interesting part: `must_use` is
about *using* the value, not about using it correctly. `let _ = dispatch(…);`
silences it, and so does any expression that consumes the value and ignores what
it said. The lint catches forgetting. What makes forgetting *harmless* is the
shape of the type, and the two obvious alternatives both lose it.

- **A `bool` would not do it.** `must_use` on the call site is available, but
  neither state has a name, so a polarity typo — `if !is_helper` — compiles and
  reads fine, and a reviewer has nothing to check it against. It cannot carry
  the error either, so the failure path has to be a second return value or a
  side channel, and the thing that must not be forgotten moves away from the
  thing that reports it.
- **A two-arm `Result` would not do it either**, and for a sharper reason: a
  `Result` *has* a success arm, and Rust's whole idiom for satisfying `must_use`
  on one is to discard that arm. `?`, `.ok()`, `unwrap_or_default()`,
  `if let Err(e) =` — every one of them is ordinary, reviewable code that
  silently continues on the `Ok` path. Worse, `Ok(())` would name the state
  this design says cannot exist. A type with a success variant invites a
  caller to write the fall-through that the no-success-variant type makes
  unrepresentable.

This is the pattern 04 calls out as the recurring trick — a closed enum plus an
exhaustive match as a compile-time gate — with `Infallible` doing the work that
makes the enum closed around the *dangerous* state rather than merely around a
list of cases.

## Stage 1: everything that must happen in a process that still has to spawn one

`exec_sandboxed` is stage 1. Its job description is in the negative: it does the
things that *cannot* be done in the process that becomes the command. It
installs no Landlock ruleset and no seccomp filter — it has to be able to spawn
the stage that installs them — and `SECURITY.md` carries that as a non-claim.

Read `start_inner_stage` and the `prepare_supervisor` it calls with the question
"why here?" and every step answers:

| step | why not earlier, why not later |
|---|---|
| `HelperArgs::decode` | stage 1 needs the policy to know which namespaces to unshare; the argv it passes down is the original, not a re-encode |
| `resolver::files` | **before** the unshare: a policy that denies IP egress lands in an empty network namespace, where a DNS lookup resolves nothing |
| `isolate` | the single `unshare` — user and pid always, net when the policy grants no network, mount when there are resolver files to bind. One call, so there is no window holding some of the isolation and not the rest |
| `resolver::bound_resolution` | **after** the unshare, which made the mount namespace, and **before** the capability drops, which take away the `CAP_SYS_ADMIN` the mounts need |
| `harden_process_state` | **after** the unshare: a fresh user namespace grants the full capability set within it, so dropping earlier would be undone |
| `set_no_new_privs` | here as well as in stage 2, so every `exec` this design performs is covered |
| `report` the degradations | **before** the spawn, so stage 1's records reach the channel ahead of anything stage 2 says |
| spawn stage 2 | last: this is the process that becomes PID 1 |

Then `wait`, then `relay`. `relay` is worth a second look because it is the
reason an operator sees a faithful status: a command killed by a signal is
re-raised at this process rather than translated to `128 + signal`, so the
status the harness reads is genuinely *signalled* and `sandbx-cli` and the
`bash` tool can branch on it. The comment names the cases where re-raising
cannot work — Rust's runtime sets `SIGPIPE` to `SIG_IGN` and handles
`SIGSEGV`/`SIGBUS` to report stack overflow — and falls back to the numbered
form, which is how a shell encodes the same fact anyway.

One structural point about the whole stage: `start_inner_stage` is one region so
that exactly one site reports a stage-1 refusal (#160). Stage 2 does not exist
anywhere inside it, so at most one refusal can reach the channel; after the
spawn the stage deliberately reports nothing, because stage 2 may have reported
its own more specific refusal and the last record on the channel wins.

## Stage 2: PID 1, and the last process before the command

`exec_inner` runs in the first child of stage 1, which by construction is PID 1
of the new PID namespace. Its own doc notes a second property that falls out of
being a fresh `exec`: the process is single-threaded, so there is no
`fork`/`exec` window and no async-signal-safety constraint — which is how the
whole design stays inside `unsafe_code = "forbid"`.

In order:

- **Split the supervisor pid, then the audit flag.** In the order stage 1 wrote
  them. A missing supervisor pid is the one refusal that cannot be reported,
  there being no channel yet.
- **`claim_audit_channel`.** Early, so everything after it is reportable, and
  before `apply`, so no filter `apply` installs can be the thing that refuses
  the `dup` or the open of `/dev/null`. It duplicates fd 0 with
  `F_DUPFD_CLOEXEC` and puts `/dev/null` in the stdin slot, so the command
  inherits a null stdin and the duplicate vanishes on a successful `exec`. Both
  halves are the point: a command holding the write end could forge records, or
  hold the channel open and leave the parent waiting on an EOF that never comes.
- **`restrict_and_exec`**: decode, arm, confirm, check the environment, `apply`,
  open the pin, `exec`.

The environment check is the one place the two stages are allowed to differ, and
it is a check rather than a re-narrowing. `spawn::command` is the crate's only
`Command` builder and narrows by construction, so clearing again would answer
with silence. What it catches is a caller who reached the inner stage directly
and therefore arrives with a full environment: that run is **refused**, not
quietly narrowed. It is an error and not an `assert!`, because
`dispatch_helper_mode` is exhaustive and a panic leaves through neither of its
arms.

The pin is opened *after* `apply`, which looks backwards until you read the
reason: opening first would hash a file no grant covers and report a digest
mismatch where the honest answer is a denied read. Then `exec` — through
`/proc/self/fd/N` when there is a pin, so the kernel opens the very inode that
was hashed, with `arg0` set back to the requested program name unconditionally,
so a matching pin changes nothing the command can observe about `$0`.

- **Worth questioning:** `HELPER_INNER_FLAG` is `pub`, and its own doc says it
  is public "only so a test can invoke the inner stage directly; elsewhere it
  runs a command without the namespaces confining it". That is an accurate
  warning attached to the thing it warns about. Walk the direct path and the gap
  is concrete: `bind_lifetime_to_supervisor` arms against the invoking shell,
  `confirm_supervisor` passes for anyone who passes their own pid, an `env -i`
  invocation passes the environment check, and `apply` then installs a real
  Landlock ruleset and a real seccomp filter — around a process in the host's
  network namespace. A policy that denies network relies on the empty namespace
  rather than on the filter, so that part of it simply is not there. None of
  this is a privilege escalation, and it contradicts no claim: `SECURITY.md`
  scopes every claim to a command run through `SandboxedCommand`, and anyone
  able to choose sandbx's argv could run the command directly instead. The
  objection is about the public surface. `decision-enforcement-seam.md` is the
  record to argue with — it reasons about the argv seam on the premise that
  *neither side is trusted* and that the helper can only ever narrow, and a
  stage reachable on its own narrows less than the two stages together while
  still succeeding, which is the one outcome `HelperDispatch`'s shape cannot
  catch. `#[doc(hidden)]`, or a test-only export, would keep the test's access
  without putting the half-stage in the public API.

## Arm, then confirm

Two calls, in `restrict_and_exec`, adjacent:

```rust
bind_lifetime_to_supervisor()?;
confirm_supervisor(supervisor)?;
```

[guide-process-lifetime.md](../guide-process-lifetime.md#arm-then-confirm) owns
the kill chain these two sit in. The on-ramp is why the order is the security
property.

`bind_lifetime_to_supervisor` sets `PR_SET_PDEATHSIG` to `SIGKILL`. It is first
because the window in which the supervisor could die unnoticed should be as
short as the kernel allows — and because arming has no retroactive effect: if
the supervisor is *already* gone, there is no future death to report and the
signal never fires. A process in that state is PID 1 of a namespace nobody is
watching, holding a command nothing will reap.

`confirm_supervisor` closes that window by establishing that the supervisor is
still this process's parent. Reversing the pair opens it again, and not by a
rounding error: between a check that passed and an arming that had not happened
yet, a supervisor death is caught by neither. Arm first and every instant is
covered by one of the two — "a death before the check is caught by the check, a
death after it by the armed signal."

`getppid()` is no help here, and this is the detail most people have to be told.
Stage 2 is PID 1 of a PID namespace whose parent lives *outside* it, so the
kernel has no number in this namespace to report and returns 0. `/proc` is still
the host's procfs — remounting it would need `mount(2)`, which the filter denies
— so the parent is readable in host numbering from `/proc/self/stat`, which is
the numbering stage 1 passed down.

Parsing that line is its own small trap, and `ppid_from_stat` is the whole of
it:

```rust
fn ppid_from_stat(stat: &str) -> Option<&str> {
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(1))
}
```

Field 4 is the parent pid, but field 2 is the executable name, unquoted and free
to contain spaces and parentheses of its own — the kernel escapes control
characters there and not those. So counting from the left is unsound and
counting from the last `)` is *exact*, not merely safer: every field after the
name is numeric and so contains no `)`. Two more decisions in those two lines.
The function returns a `&str` rather than a parsed integer, because
`confirm_supervisor` compares it against the token from the command line and
parsing both sides would let `0123` match `123`. And an unrecognised line yields
`None`, which becomes a refusal rather than a guess.

Pid reuse cannot produce a false pass, which is the question to ask of any
pid-based check: the comparison is against the kernel's live parent link, and an
orphan is reparented to init or a subreaper — neither of which can be the pid of
a supervisor that just spawned this process.

## `apply`'s order, step by step

[guide-sandboxing.md](../guide-sandboxing.md#apply-sequence) is the authority on
this sequence and draws it in full. What follows is the same order with one
question against each step: what breaks if it moves?

| step | what moving it costs |
|---|---|
| `set_no_new_privs` | nothing later can install a seccomp filter: unprivileged installation needs this bit, and this process holds no capabilities at all, stage 1 having dropped them |
| `deny_dangerous_syscalls` | the syscalls that could undo the rest — `mount_setattr`, namespace creation, the `clone3` refusal — stay available while the Landlock ruleset is being built |
| `requested(policy)` | the ABI negotiation would be in scope beside the rules; keeping it inside means the handled set and the rules cannot come from different ABIs |
| `handle_access` for fs, then for net | Landlock requires the whole handled set *before* `create`, and an axis left unhandled is unrestricted everywhere rather than denied |
| `create` | there is no ruleset to add a rule to |
| `open_grant` + `add_rule`, per grant | a rule needs a descriptor, and `create` must already have happened — Landlock splits the two calls across it |
| the port rules | same split; under `HardRequirement` a port right the ruleset does not handle is an error rather than a right the kernel quietly drops |
| `restrict_self` | nothing is enforced at all; this is the call that makes the ruleset this thread's |
| `enforcement_verdict` | a partially enforced ruleset passes for a whole one |

Two properties hold the sequence together. Everything in it is **irreversible**,
so no step can be a trial run and nothing can be relaxed later for the command's
benefit. And everything in it is **inherited across `exec`**, which is the
reason a process may confine itself and only then become a program it does not
trust — the restrictions stick to the command rather than to this process.

The reason `apply` is one long function rather than four, stated in the module
doc, is that the order *is* the security property. A sequence split across
modules is a sequence that can be called in the wrong order from a new site; a
sequence in one function with a comment per step carries its own
counterexamples. That is the same justification the startup order in
[04](04-the-architecture.md#view-2--one-request-end-to-end) runs on.

## You should now be able to explain

- Why the helper is this binary rather than a separate executable, what reaching
  it through `/proc/self/exe` closes, and why handing `execve` a
  self-referential path resolves to the right image.
- What is in helper argv, in what order, and why the supervisor pid and the
  audit flag are outside the policy grammar.
- Why `HelperDispatch` has two variants rather than three, and what `Infallible`
  proves that a comment could not.
- What `#[must_use]` on a type actually enforces, how it can be silenced, and
  why a `bool` or a `Result` in the same position would be weaker.
- Which steps have to happen in stage 1 because it still has to spawn a process,
  and which two of them are pinned between the `unshare` and the capability
  drops.
- Why stage 2 claims the audit channel before `apply` and opens the pin after
  it.
- Why arming the parent death signal before confirming the supervisor is the
  only order that has no window, and why `getppid()` cannot do the confirming.
- Why `/proc/self/stat` is parsed from its last `)` and compared as a string.
- At least three steps of `apply` whose position is load-bearing, and what
  moving each one costs.

## Next

[09 — Landlock](09-landlock.md), and then [10 — seccomp](10-seccomp.md): the two
steps of `apply` that got a sentence each here and deserve a chapter each.
