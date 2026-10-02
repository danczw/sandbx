# The environment allowlist

Why a sandboxed command starts with an empty environment, and why clearing it is
repeated at four spawn sites instead of asserted at one. The mechanism is in
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

The alternative was to clear once at the top and have the inner stages *assert*
their environment already matched. Rejected because the helper is a public entry
point: any binary calling `with_helper_dispatch` becomes a helper when handed
`HELPER_FLAG`, and the enforcement suite invokes the helper binary directly with
nothing above it to have cleared anything. An assertion there turns a direct invocation into a refusal; applying
the filter makes it correct instead. `restrict` is idempotent — after the first
clear the environment already *is* the allowlist — so the repetition costs
nothing, and nothing in a later stage depends on an earlier one having run.

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
the C library's fallback search path — `/bin:/usr/bin` on glibc, from
`confstr(_CS_PATH)`. So it does not fail cleanly: `sandbox-run -- cat file` works,
and `sandbox-run -- some-tool` installed in `/usr/local/bin` or `~/.cargo/bin`
comes back as `No such file or directory` with nothing to connect that to the
environment. A flat failure would at least be honest.

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
