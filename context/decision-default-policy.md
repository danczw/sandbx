# The working-directory default policy

Why a no-flag `sandbx sandbox-run` grants read and write on the directory it was
run from, why a path flag *replaces* that rather than adding to it, and why four
working directories are refused instead. The mechanism is thirty lines of
`crates/sandbx-cli/src/grants.rs`; this is what the choices were between.

## What it is for

Every grant was typed by hand, which made the common case — work on the project I
am standing in — a wall of flags:

```sh
sandbx sandbox-run --allow-read /home/me/proj --allow-write /home/me/proj -- grep -rn TODO .
```

Box 1 of [#109](https://github.com/danczw/sandbx/issues/109) makes that the
default. Exec and env were already unconditional (`allow_system_executables`,
`allow_standard_env`), so what was left was the filesystem axes and the guards
that make a *default-reachable write grant* safe to ship.

What it does **not** reach is a toolchain installed under `$HOME`. `cargo test` is
the example everyone reaches for and it is the wrong one: with rustup, `cargo` is
`~/.cargo/bin/cargo` and needs `--allow-exec` plus read on `~/.cargo/registry` and
`~/.rustup`, none of which a working-directory grant covers. The default removes
the flags for the *directory*, not for the build. Examples in the README use
commands from the system paths for that reason.

It lives in `Grants`, which both subcommands flatten, so `sandbox-run` and
`agent-run` cannot disagree about it. It lives in the CLI and nowhere lower:
`SandboxPolicy::default()` still grants nothing, so an embedder constructing a
policy inherits no convenience it did not ask for. Same shape as
`allow_standard_env` in `decision-environment-allowlist.md` — the library ships
the strict thing, the CLI opts in.

## A path flag suppresses it

Any of `--allow-read`, `--allow-write`, `--allow-exec` present ⇒ no default. None
⇒ derive. `--allow-env`, `--allow-network` and `--allow-unix-sockets` name no path
and change nothing. The predicate runs over `Axis::ALL`, so a fourth path flag
joins the rule rather than being forgotten into a default that widens it.

The alternative was an unconditional default plus a `--no-default-policy` opt-out,
and what decides it is the failure mode rather than the ergonomics. Under that
shape, `sandbx agent-run --allow-read /srv` — a deliberately tight hand-written
policy — *silently gains write over the whole working tree*. An explicit statement
of intent would be widened without saying so.

Suppression's failure mode is the mirror and is the safe one: the operator gets
less than expected and hears about it immediately, as a permission denial naming
the path the grant lacked. Narrow and loud beats wide and silent. It also adds no
flag, and going the other way later stays available — unconditional-plus-opt-out
is a strict widening of this, so nothing here forecloses it.

## The refusals, and the shape of the predicate

A derived write grant is reachable by accident in a way a typed one is not, so
`vetted_root` refuses outright rather than deriving a narrower root:

| Refuse when | Test |
|---|---|
| cwd is the filesystem root | `cwd.parent().is_none()` |
| cwd is `$HOME`, or *holds* it | `homes.iter().any(\|h\| h.starts_with(cwd))` |
| cwd is where homes live, or holds it | `holds_home_directories(cwd)`, below |
| no usable `$HOME`, and cwd is shaped like a home | `looks_like_a_home(cwd)`, below |
| cwd overlaps a path already granted execute | `granted.iter().any(\|p\| p.starts_with(cwd) \|\| cwd.starts_with(p))` |
| the running `sandbx` is inside cwd | `exe.starts_with(cwd)` |

One `starts_with` covers both `$HOME` cases: it is true of equal paths, so "cwd is
`$HOME`" and "cwd is `/home`" fall out of the same test, and it is
whole-component, so `/home/u/project-tools` is not inside `/home/u/project`. The
root rule stays alongside it because it subsumes the root only when `HOME` is set.

Only the `$HOME` arm reads the environment, and it is there to *name* a directory
the arm below it already covers by location. That ordering is deliberate: it was
the other way round once, and the inversion was a hole — see below.

Every arm is a refusal and not a narrower default, because both fallbacks are
worse. Falling back to the system paths alone makes an ordinary command fail for a
reason the message would not explain; granting the directory anyway is the thing
being refused. So each refusal instead names the two flags to type, behind one
`const` so two refusals cannot advise differently.

### No depth rule

Not refusing direct children of `/`. Depth is not sensitivity: `/srv`, `/opt`,
`/workspace`, `/app` and `/data` are ordinary project roots, and in a container
`/app` *is* the working directory — refusing it would kill the default where
sandbx is most likely to be deployed. Meanwhile `~/.ssh` is three levels down and
far worse. Enumerating the genuinely dangerous children (`/etc`, `/root`, `/proc`)
starts a denylist whose first omission is silent, which is the shape
`decision-environment-allowlist.md` already rejected for variable names.

### No subdirectory-of-`$HOME` rule

`~/code/project` is the entire use case. What the guard is for is the no-flag run
that happens *by accident*, and that is standing in `$HOME` itself.

### Where homes live is refused by location, not by `$HOME`

`HOME_PARENTS` — `/home`, `/Users`, `/var/home`, `/root` — is refused whatever the
environment says, and only the *child* reading (`/home/other`) is gated on there
being no usable `$HOME`.

It was the other way round for two drafts, and both were holes. The first gated
the whole rule on `homes.is_empty()`, so `cd /home && env -u HOME sandbx
sandbox-run -- true` derived read and write over every user's home. The second
fixed that and was still wrong, because `homes.is_empty()` asks whether `HOME` was
*set*, not whether it named anything useful. `HOME=`, `HOME=relative/path`,
`HOME=/nonexistent` and — the ordinary case — a service account's
`HOME=/var/lib/svc` all leave `homes` non-empty holding a path no cwd under
`/home` can match, which disabled the exact arm and skipped the fallback at once.
All four were reproduced deriving `readable=1 writable=1` over `/home`.

What that showed is that `$HOME` was carrying a decision it cannot carry. Nothing
about the variable makes a root at `/home` narrower — it is write over every
user's home however `HOME` is spelled — so the location rule stands on its own and
`$HOME` only adds the one directory a location cannot name: `~/code` is fine,
`~` is not. `current_root` also now keeps only an absolute `HOME`, since set but
useless is the unset case.

This is a list of names, which the depth-rule section above rejects for exactly
that reason, and the distinction is worth stating because it is thin. The depth
rule would have been guessing at which directories are *sensitive*; this names the
one place on a Unix system whose entire purpose is to hold other people's trees,
and the cost of an omission is that one layout degrades to no protection rather
than that the mechanism has a hole. Over-refusing stays the right direction: `/var`
is refused because `/var/home` is in the list, and `/root/work` in the degraded
case, and `--allow-read`/`--allow-write` lift both.

An unusable `HOME` still *derives* — refusing outright would break the container
case the default exists for, `HOME` unset and cwd `/app`. That is the one
constraint here a plausible edit would quietly reverse, which is why it is the
sentence on `vetted_root`'s `///` as well as a line in this file.

### The system binaries are refused from both directions

`allow_system_executables` grants read and execute on `/usr`, `/bin`, `/lib`,
`/lib64` to every run. A derived root overlapping one of those would add write
beside that execute — the pair `Axis::grants` exists to keep apart — so
`vetted_root` refuses it, reading the paths off the policy it is deriving rather
than restating them.

The test is `starts_with` both ways round. One way was tried and is not a control:
on any merged-`/usr` host `getcwd` resolves `/bin` to `/usr/bin`, which *holds* no
granted path and so passed, handing a no-flag run write over every system binary.
Landlock rights cover a subtree, so containment in either direction is the same
collision.

The cost is `/usr/src/app`, the stock `WORKDIR` in the official Node images, which
now needs its two flags. That is a real ergonomic loss on a deployment this
feature is for, and it is the trade this file keeps making: the operator gets less
than expected and hears about it immediately, by name, with the flags to type.

### Both spellings of `$HOME`

The wrapper pushes raw `$HOME` *and* its canonical form. Fedora Silverblue ships
`/home -> /var/home`, so `getcwd` says `/var/home/u` where `$HOME` says
`/home/u`; comparing one form is a bypass of the other. `HOME` unset falls out as
an empty slice with no second code path.

## The enforcer arm

`exe.starts_with(cwd)` resolves the open question the issue left: refuse.

The escape is live, not theoretical. `SandboxedCommand::command_line()` resolves
`current_exe()` on **every** spawn, so between two tool calls in one turn an agent
can rename a replacement over `target/debug/sandbx` and the next spawn execs it,
choosing its own confinement. (`ETXTBSY` blocks overwriting in place; rename-over
is what `cargo build` does.) Nothing asks the operator first, and it happens inside
a single turn.

A carve-out — grant the tree except the binary — is **not expressible**.
`SandboxPolicy` is grants-only, matching is prefix-only, and Landlock composes
rules by union with no subtraction. It would be a new mechanism in core and in both
enforcement layers, for one case.

It is also consistent with the home arm, which is likewise defeated by typing
`--allow-write ~`. The guard governs what sandbx *derives*; what an operator asks
for in so many words stays theirs.

Cost is bounded: the arm only fires for a locally-built binary, so an installed
`/usr/local/bin/sandbx` never sees it. It does mean sandbx's own developers get the
refusal in their own repo, one `--allow-write .` from working.

`std::env::current_exe()` directly, rather than promoting core's `pub(crate)`
wrapper, which would drag `SandboxError` into this crate's error mapping for no
gain. A failure to resolve it is a refusal, since core's own call would fail at the
first spawn anyway — but the *canonicalization* of it falls back to the unresolved
path, so a failure there cannot turn into a missing guard.

The arm is load-bearing only because the helper is reached by *path*.
[#149](https://github.com/danczw/sandbx/issues/149) would have core re-exec
through `/proc/self/exe`, a link to the inode, which a rename-over cannot
redirect — and the arm becomes a convenience worth reconsidering.

### The execute axis is not touched

The default grants read and write and no execute, and
`the_default_root_is_not_executable` pins that by asserting the execute axis is
byte-identical to `allow_system_executables`'s. The overlap arm above is what makes
that assertion mean something: the one way a derived root could have been executable
anyway was by sitting under a granted system path, and such a root is now refused.

### What it does not reach

Write on a project tree is write on whatever runs in that tree next:
`.git/hooks/*`, `.git/config`, `.cargo/config.toml`, `Makefile`, `package.json`
scripts, `rust-toolchain`. Those execute *outside* the sandbox the next time the
operator builds or commits, and no guard can fix it — it is what accepting the
default means. It is a non-claim in `SECURITY.md` rather than a refusal here.

The asymmetry with the enforcer arm is deliberate and worth stating, because
otherwise that arm reads as theatre next to `.git/hooks`. The enforcer case fires
unattended, inside one turn, through sandbx's own next spawn, and one path
comparison detects it. "Any file the operator might later execute" is unbounded,
undetectable, and enumerating candidates would be a denylist whose first omission
is silent.

## Canonicalizing the working directory

`getcwd` already returns a resolved path, so `canonicalize` is there for the other
thing it proves: that the directory is still openable. `PathFd::new` in the helper
requires that, and `FsGuard::canonical_roots` *drops* a root it cannot resolve
rather than refusing. The two layers disagree, and the safe reading of the
disagreement is that an unopenable working directory must fail here, loudly,
rather than become a grant one layer silently omits.

## `policy()` became fallible

Deriving a policy can now refuse, so `Grants::policy()` returns
`Result<SandboxPolicy, PolicyError>` and the error threads out through both
subcommands. `AgentRun` derives the policy *before* building the client, so a
refusal costs no round trip and never reads the key.

`PolicyError` lives in the CLI, not in core: deriving a policy is the CLI's own
step, and `SandboxError` must not grow a variant core never produces. `sandbox-run`
got its own two-variant `SandboxRunError` for the same reason folding everything
into one `CliError` was rejected — that would make `AgentError`'s provider and
turn variants look reachable from `sandbox-run`.

Every variant ends in one shared `ADVICE` const, so two refusals cannot name
different flags — except `EnforcerUnknown`, which exists only to *not* carry it.
That is the one case where the advice would be false: a path flag does skip
`current_root()`, but `command_line()` calls `current_exe()` again on every spawn,
so the run fails a step later with an unrelated message. An error whose suggestion
cannot work is worse than one with no suggestion.

## The seam

`vetted_root(cwd, homes, exe)` is pure, with all three inputs injected as values;
`current_root()` is the thin wrapper that reads them off the process. Same split as
`resolve_api_key(env_var, lookup)` / `anthropic_api_key()` in
`crates/sandbx-providers/src/credentials.rs`, with values rather than a closure
since nothing is called twice.

Both are private, and the tests for them are inline. Making the seam public so
`tests/sandbox_run.rs` could drive the refusals is the trade
`guide-module-layout.md` forbids — widening the API to suit a test. What the
integration suite gets instead is the end-to-end refusals in `tests/cwd_policy.rs`,
which spawn the built binary: the guard reads `getcwd` and `HOME` off the real
process, and `set_current_dir` is process-global, so under parallel tests one case
would decide another's verdict.

## The mutation check

The same check `decision-axis-table.md` does for a table change. Six mutations,
run rather than reasoned about:

```
default becomes unconditional (drop the paths_given guard)
   ──► a_path_flag_replaces_the_working_directory      fails   ◄── the rule itself
       each_allow_flag_widens_only_its_own_axis        fails
       allow_flags_repeat_to_grant_several_paths       fails
       a_path_flag_runs_from_the_home_directory        fails   ◄── the guard now fires on an explicit policy
       the_default_matches_what_sandbox_run_derives    passes  ◄── derives its expectation

default removed entirely
   ──► the_working_directory_is_readable_and_writable  fails
       an_env_flag_keeps_the_working_directory         fails
       refuses_to_run_from_the_filesystem_root         fails
       refuses_to_run_from_the_home_directory          fails

enforcer arm deleted
   ──► the_binary_inside_the_root_is_refused           fails
       a_refusal_names_the_flags_to_type_instead       fails

home arm narrowed from starts_with to equality
   ──► a_directory_holding_home_is_refused             fails
       a_refusal_names_the_flags_to_type_instead       fails

holds_home_directories arm deleted
   ──► the_home_parents_are_refused_with_no_home_set       fails
       the_home_parents_are_refused_when_home_is_elsewhere fails
       a_refusal_names_the_flags_to_type_instead           fails
       refuses_to_run_from_home_whatever_home_names        fails
       an_unset_home_still_derives_a_root                  passes  ◄── /app is not a home parent
       a_named_home_leaves_a_neighbour_alone               passes

that arm re-gated on homes.is_empty() (the draft-2 hole)
   ──► the_home_parents_are_refused_when_home_is_elsewhere fails   ◄── $HOME=/var/lib/svc
       refuses_to_run_from_home_whatever_home_names        fails
       the_home_parents_are_refused_with_no_home_set       passes  ◄── the gate is satisfied

the child reading deleted
   ──► an_unset_home_refuses_a_child_of_one                fails
       the_home_parents_are_refused_with_no_home_set       passes

overlap arm deleted, or tested one way round
   ──► a_directory_overlapping_the_system_binaries_is_refused  fails
       refuses_to_run_from_the_system_binaries                 fails
       a_directory_named_like_a_system_one_is_a_valid_root     passes
```

The home arms are three tests rather than one loop because the gating is what went
wrong twice: a single looping test could not tell "the location rule is gone" from
"it is back behind `homes.is_empty()`" from "it no longer sees `/home/other`", and
the middle one is the reproduced bug.

Deleting the overlap arm and testing it one way round fail the same two tests,
which is the signal being asked for: the loop covers each granted path *and* a
directory under it, so a one-way test is detected as the absence it is.

That loop reads `granted()` rather than naming paths, because
`allow_system_executables` skips a path the host lacks — `/lib64` is absent on
arm64, which failed a hardcoded list on CI's aarch64 leg while passing x86_64.

Two things the first mutation shows. Dropping the guard breaks tests in two
suites that never mention the default — `each_allow_flag_widens_only_its_own_axis`
and `allow_flags_repeat_to_grant_several_paths` both assert on the whole policy, so
suppression is pinned by tests older than it. And
`the_default_matches_what_sandbox_run_derives` passes, because both sides of the
comparison mutate together: that is the derived-expectation trap
`decision-enforcement-seam.md` names, and it is why it is a cross-subcommand
consistency test and not the one pinning what the default *is*.

The gap the tests do not close: `current_root()`'s own lookups — the two spellings
of `$HOME`, the `is_absolute` filter, the `canonicalize` fallbacks — are read off
the live process and have no unit test, by construction. `tests/cwd_policy.rs`
covers what it can by setting `HOME` on the spawned binary, which is how the
empty-and-relative cases are pinned; the Silverblue double-push is argued above and
tested only through `vetted_root`, which receives both forms as values. Note what
this means for the filter: it is the arm that does *not* depend on it —
`holds_home_directories` — carrying the security weight, and that is the reason to
prefer it.
