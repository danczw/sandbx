# The environment allowlist

Why a sandboxed command starts with an empty environment, and why the clearing
happens in the one factory every `Command` in the crate is built by rather than at
each of the four spawn sites — with the inner stage checking what it inherited as
well, so the clearing is falsifiable. The mechanism is in `guide-sandboxing.md`;
this is what the choices were between.

## What #98 actually was

Not a policy that defaulted open — an axis that did not exist. A workspace-wide
grep for `env_clear`, `env_remove`, `.env(` and `.envs(` returned zero hits, so
every variable the harness held crossed `fork`/`exec` verbatim:

```
$ FAKE_SECRET=leaked-abc123 sandbx sandbox-run --allow-read /usr -- /usr/bin/env | grep FAKE
FAKE_SECRET=leaked-abc123
```

Latent at the time — no shipped subcommand put a credential in the harness's
environment — but `anthropic_api_key()` reads `ANTHROPIC_API_KEY` out of the
process environment, so it was already real for a library consumer embedding
`sandbx-core` beside its own secrets, and would have become live for the CLI the
day the agent loop got a subcommand. It also blocked
[#41](https://github.com/danczw/sandbx/issues/41): credential *injection* cannot
be designed on top of an environment that is already shared in full.

## Allowlist, not denylist

A denylist of secret-looking names (`*_KEY`, `*_TOKEN`, `*_SECRET`) is wrong on
arrival and gets worse: it is a guess about naming, and it silently stops covering
the harness the first time a variable is added that does not match the pattern. An
allowlist's failure mode is the opposite and is the safe one — a variable nobody
named is dropped, and the symptom is a command that cannot find something rather
than a secret that escaped.

So `env_clear()` then re-add, rather than removing known-bad names.

## Names on the wire, values from the live environment

The policy carries `Vec<String>` of **names**. Values are read with
`std::env::var_os` at the moment the `Command` is built. One variable is set from
a constant instead; *One variable sandbx sets itself* has it.

Two reasons, and the first is the hard one. The policy crosses into the helper as
argv, and argv is not private: the sandboxed command reads its own
`/proc/self/cmdline`. A value on the wire would therefore be handed to exactly the
process the allowlist exists to keep it from. (This is also why the CLI flag is
`--allow-env NAME` and not `NAME=VALUE` — the latter is #41's problem, and solving
it this way would solve it wrongly.)

Second, a name is a stable thing to audit; a value is not. The audit record counts
the allowlist (`env=7`) rather than listing it, on the same basis: a name is not a
secret, but a value routinely is, and a record that spelled out names would invite
the next change to print values beside them.

A consequence worth stating: a name the harness does not hold contributes
*nothing*, rather than an empty string. Absent and empty are different to a
program that checks.

## Narrow by construction, at one site

Four `Command`s are built on the spawn path — `output()`, `run_with_deadline()`,
the supervisor's re-exec into stage 2, and stage 2's `.exec()` into the real
program. None of them calls `Command::new`: all four go through `spawn::command`,
which clears and re-adds as it builds, so a narrowed environment is a property of
every `Command` in the crate rather than a step each site remembers.

Three alternatives were on the table, and the first two were tried and discarded.

**Clear once at the top, check at the inner stages.** Rejected **for stage 1**,
because the helper is a public entry point: any binary calling
`with_helper_dispatch` becomes a helper when handed `HELPER_FLAG`, and the
enforcement suite invokes the helper binary directly with nothing above it to have
cleared anything. A check there turns a supported invocation into a refusal, where
filtering makes it correct instead.

**Call `restrict` at each of the four sites.** What actually shipped first (#101),
and the problem was not correctness but that every one of the four calls was
unfalsifiable. The sites mask each other: any single clear could be deleted and a
later one covered for it, leaving the command's `environ` byte-identical with no
test able to tell. Four hand-written obligations, each individually unobservable,
and a fifth spawn site added later would have inherited the harness's whole
environment rather than nothing — failing *open*.

**One factory.** `spawn::command` is the only `Command::new` in the workspace, and
the only `#[allow(clippy::disallowed_methods)]` for it. Two properties fall out
that no amount of per-site discipline gave:

- There is one line to delete, and deleting it fails 24 enforcement tests. The
  invariant is now pinned, not merely upheld.
- A new spawn site cannot forget. `clippy.toml` bans `Command::new` workspace-wide
  under `-D warnings`, so the only way to build one is the way that narrows —
  checked by adding a bare `Command::new` elsewhere and watching the lint refuse
  to compile it. The fail-open hole above is closed structurally rather than by
  remembering.

Keeping the first three sites, rather than narrowing only at the final `exec`, is
not ceremony either. A helper process lives for milliseconds, but
`/proc/<pid>/environ` is readable for all of them, and the point is that the secret
is never anywhere it does not need to be.

## Stage 2 checks as well, and refuses

Stage 2 does one more thing: before applying anything it looks at the environment
it *inherited* and refuses if the policy permits no variable of that name. The factory is
what the command relies on; this is what says whether the stage above actually went
through it. Narrowing again instead would answer the same question with silence.

So stage 2 depends on an earlier stage having run, and the asymmetry with stage 1
is a deliberate trade rather than a derivation from reachability. Stage 2 is **not**
reachable only through stage 1: `HELPER_INNER_FLAG` is `pub` and dispatched from
argv, exactly as the enforcement suite invokes it. The honest statement is that
direct inner invocation is a test-only entry point the project is willing to see
refused, where direct stage-1 invocation is a supported one a library consumer has.
So stage 1 sanitises and stage 2 refuses.

A refusal through `SandboxError` and not an `assert!`, for the reason
`dispatch_helper_mode` is exhaustive: a helper run must end by either running the
command or reporting why not, and a panic is neither — it would report a broken
harness invariant as a crash on the command's own stderr.

## `default()` passes nothing

Default-deny, matching every other axis, and matching `allow_system_executables`
as a *shape*: the library ships the strict thing and the CLI opts into the
convenience.

The trap this creates is worth naming, because it is the same one
`allow_system_executables` has, and it is sharper than it first looks. With an
empty allowlist there is no `PATH`, and a bare program name then resolves against
whichever default the lookup falls back to. There are two, and they disagree:

| Spawned by | Fallback when `PATH` is unset |
|---|---|
| `execvp` (a direct `sandbox-run -- tool`) | the C library's — `confstr(_CS_PATH)`, i.e. `/bin:/usr/bin` on glibc |
| a shell (`sandbox-run -- sh -c …`, the `bash` tool) | the shell's own compiled-in default — dash and bash both add `/usr/local/bin` and the `sbin` directories |

So it does not fail cleanly, and it does not fail consistently either:
`sandbox-run -- cat file` works, `~/.cargo/bin/tool` is not found by any route,
and `/usr/local/bin/tool` depends on whether a shell was in the way. The symptom
is `No such file or directory` with nothing to connect it to the environment. A
flat failure would at least be honest.

`SandboxRun::policy()` therefore calls `allow_standard_env()` next to
`allow_system_executables()`, and the two sit together with one rationale: both
grant what a command needs merely to *begin*, and withholding either makes the
sandbox look broken rather than strict.

`STANDARD_ENV_NAMES` is seven exact names (`PATH`, `HOME`, `TERM`, `LANG`,
`LC_ALL`, `LC_CTYPE`, `TZ`) rather than a prefix glob for `LC_*`. A glob would need
a second grammar on the helper wire, and matching logic on both sides of it, for
one convenience; a caller wanting another `LC_` variable names it.

## Skip at the gate, refuse at the seam

`allow_env` **drops** a name containing `=` or a NUL. `decode` **refuses** one.

Not an inconsistency. A caller composing a policy is in the position
`allow_system_executables` is in when a path does not exist on this system:
dropping is the conservative answer, and it is what keeps `encode`/`decode`
round-tripping — nothing `encode` can emit is something `decode` rejects. But an
argv *containing* such a name cannot have come from `encode`, so the seam is
looking at a protocol it does not speak, and this file's rule is that every decode
failure is a refusal rather than a guess.

## One variable sandbx sets itself

`--dns-over-tcp` puts `RES_OPTIONS=use-vc` in the command (why:
`decision-port-allowlist.md`). A *value*, on the axis that carries only names —
so the rule it lives under is narrow: only a compile-time constant may be
imposed, never anything read from the harness. The argv argument above does not
apply to a constant, because a value the sandboxed command can already read in
the binary it is about to exec is not a disclosure. `DNS_OVER_TCP_ENV` is the
whole table, and the policy crosses the seam carrying a valueless
`--dns-over-tcp` rather than the pair, so the wire still names no value and
`decision-enforcement-seam.md` stays true as written.

Two accessors keep the two halves from disagreeing. `imposed_env()` is what
`spawn::command` applies, *after* the allowlist, so a name reached both ways
arrives with the policy's value. `permits_env()` is the union of allowlist and
imposed table, and is the single predicate both `spawn::command` and stage 2's
inherited-environment check consult — because stage 2 refuses, a variable the
factory imposes and the check did not know about would kill every hinted run.
That is the one coupling here that is load-bearing rather than tidy.

Where the two names collide the library resolves it and the CLI refuses it,
which is *skip at the gate, refuse at the seam* in its other direction.
`allow_env("RES_OPTIONS")` on a hinted policy is quietly overridden, keeping the
builder total. But `--dns-over-tcp --allow-env RES_OPTIONS` is two flags
disagreeing about one variable, and honouring both would drop the operator's
value in silence — so `PolicyError::ImposedVariable`, the same answer
`variable_name` gives `NAME=VALUE`. The refusal matches against `imposed_env`
rather than the literal name, so the CLI never spells `RES_OPTIONS` and a second
imposed variable inherits the check.

## The mutation check

The same check `decision-axis-table.md` does for a table change, since
`STANDARD_ENV_NAMES` is a table of a kind:

```
drop "PATH" from STANDARD_ENV_NAMES
   ──► standard_env_carries_path                      fails   ◄── pins the name itself
       standard_env_is_the_documented_startup_set     fails   ◄── pins the whole set, in order
       the_startup_environment_is_granted_anyway      passes  ◄── derives its expectation
       audit line                                     env=6
       sandbox-run -- cat /etc/hostname               still starts   ◄── the surprise
       sandbox-run --allow-exec $dir -- mytool        ENOENT
```

Two things came out of running it. The CLI test passes because it compares
`policy()` against `allow_standard_env()` rather than against seven literal names —
derived from the same source, so it moves with the mutation. That is the trap
`decision-enforcement-seam.md` names about derived expectations, and it is why
`standard_env_is_the_documented_startup_set` compares the whole set *in order*
against spelled-out names: that one is the assertion doing the work, and it is what
keeps the CLI's `--help` text naming those seven from drifting into a lie.

And `cat` still ran with no `PATH` at all, which is how the C library's fallback
came to be documented above rather than guessed at. The mutation's honest symptom
is the second command: a program outside `/bin:/usr/bin` is not found. So `PATH` is
load-bearing, but not in the all-or-nothing way the first draft of this file
claimed.

The gap the tests close that the compiler cannot: the environment is deliberately
not an `Axis` row (see `decision-axis-table.md`), so no exhaustive `match` forces a
new spawn site to narrow. The clippy ban covers most of that — a site that does not
go through `spawn::command` does not compile — but a lint is not a proof that the
factory narrows anything. What supplies that is `tests/enforcement.rs` running
`/usr/bin/env` through the real helper and asserting on its stdout — the issue's own
reproducer, inverted. It goes through the suite's `support::run` helper, which spawns the
helper *without* clearing anything first, so what it pins is the sandbox doing it on
its own.

Stage 2's refusal needs a test of its own, because every path that reaches it
honestly reaches it already narrowed, where the check is trivially satisfied:
`the_inner_stage_refuses_an_unnarrowed_environment` invokes the
inner stage directly, naming the test harness as the supervisor so the liveness
check passes, and plants a variable with `Command::env`. Without it the check would
be as deletable-with-a-green-suite as the lines it exists to pin.
