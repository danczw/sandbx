# The environment allowlist

Why a sandboxed command starts with an empty environment, and why clearing it is
repeated at four spawn sites rather than checked at one — with the inner stage
checking as well, so the repetition is falsifiable. The mechanism is in
`guide-sandboxing.md`; this is what the choices were between.

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
`std::env::var_os` at the moment the `Command` is built.

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

## Filter at every stage, not just the last

Four `Command`s are built on the spawn path — `output()`, `run_with_deadline()`,
the supervisor's re-exec into stage 2, and stage 2's `.exec()` into the real
program. All four call `env::restrict`.

The alternative was to clear once at the top and have the inner stages *check* that
their environment already matched. Rejected **for stage 1**, because the helper is
a public entry point: any binary calling `with_helper_dispatch` becomes a helper
when handed `HELPER_FLAG`, and the enforcement suite invokes the helper binary
directly with nothing above it to have cleared anything. An assertion there turns
a direct invocation into a refusal; applying the filter makes it correct instead.
`restrict` is idempotent — after the first clear the environment already *is* the
allowlist — so the repetition costs nothing.

Stage 2 is the exception, and both halves are kept there: it **checks** its own
inherited environment and refuses, *and then* filters what it passes on. The filter
is what the command actually relies on; the check is what makes the stage-1 clear
falsifiable. Without it the two stages mask each other — either `restrict` call
could be deleted and the other would cover for it, leaving the command's `environ`
byte-identical and no test able to tell.

So stage 2 *does* now depend on an earlier stage having run, and the asymmetry with
the paragraph above is a deliberate trade rather than a derivation from
reachability. Stage 2 is **not** reachable only through stage 1: `HELPER_INNER_FLAG`
is `pub` and dispatched from argv, exactly as the enforcement suite invokes it. The
honest statement is that direct inner invocation is a test-only entry point the
project is willing to see refused, where direct stage-1 invocation is a supported
one a library consumer has, so stage 1 sanitises and stage 2 refuses.

A refusal through `SandboxError` and not an `assert!`, for the reason
`dispatch_helper_mode` is exhaustive: a helper run must end by either running the
command or reporting why not, and a panic is neither — it would report a broken
harness invariant as a crash on the command's own stderr.

What that buys is bounded, and worth stating plainly. Only the stage-1 clear is
pinned by it. The two `command.rs` sites are upstream of a stage that re-narrows,
and stage 2's own `.exec()` hands over an environment stage 1 already narrowed, so
all three remain deletable with a green suite. Collapsing the four sites into a
single `Command` factory — one place carrying the `clippy::disallowed_methods`
allow, narrowing by construction — would subsume the whole class and is the real
fix; this is the cheap part of it.

The first three are not ceremony either. A helper process lives for milliseconds,
but `/proc/<pid>/environ` is readable for all of them, and the whole point is that
the secret is never anywhere it does not need to be.

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
not an `Axis` row (see `decision-axis-table.md`), so no exhaustive `match` forces
a new spawn site to call `env::restrict`. What stands in for that is
`tests/enforcement.rs` running `/usr/bin/env` through the real helper and
asserting on its stdout — the issue's own reproducer, inverted. It goes through
the suite's `run()` helper, which spawns the helper *without* clearing anything
first, so what it pins is the helper stages doing it on their own.

Stage 2's refusal needs a test of its own, because every path that reaches it
honestly reaches it already narrowed, where the check is trivially satisfied:
`the_inner_stage_refuses_an_environment_an_earlier_stage_did_not_narrow` invokes the
inner stage directly, naming the test harness as the supervisor so the liveness
check passes, and plants a variable with `Command::env`. Without it the check would
be as deletable-with-a-green-suite as the lines it exists to pin.
