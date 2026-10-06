# The working-directory default policy

Why a no-flag `sandbx sandbox-run` grants read and write on the directory it was
run from, why a path flag *replaces* that rather than adding to it, and why some
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
⇒ derive. `--allow-env`, `--allow-network`, `--allow-unix-sockets` and
`--dns-over-tcp` name no path and change nothing. The predicate runs over `Axis::ALL`, so a fourth path flag
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
`~` is not.

The same conflation then survived one layer in, on the *child* reading, which is
the one arm `$HOME` legitimately gates — and it survived because `homes` was still
answering two questions with one list. `homes.is_empty()` was reading as "no usable
`$HOME`" off a list whose actual job is "paths a cwd is compared against", so any
absolute path kept in it for comparison also silenced the stand-in. `HOME=/nonexistent`
with cwd `/home/other` derived read and write over a neighbour's tree (#154), and so
did `HOME=/dev/null` and the `HOME=/` Docker hands a UID with no passwd entry — the
first names nothing, the other two resolve to something that is not a home, and all
three matched no cwd while satisfying the gate.

So the two signals are two fields. `Homes { paths, usable }`: `paths` holds every
absolute spelling of `$HOME` worth comparing a cwd against, and `usable` says
whether it resolved to a directory below the filesystem root. An unresolvable
`$HOME` is still compared — `cd /srv/people` with `HOME=/srv/people/alice`
unprovisioned is refused for *holding* a home, which a filter that dropped the path
would have lost — and it never satisfies the stand-in gate. A fourth tightening of
the one list would have kept failing in one direction or the other.

What this costs, visibly: a cwd shaped like a home under `HOME_PARENTS` is now
refused where an unusable `$HOME` previously derived. `HOME=/home/app` not yet
provisioned and cwd `/home/builder` is the shape, and the refusal is the point —
the two are indistinguishable without a home to compare — but it is a new refusal,
and the flags lift it.

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

Non-goal: a home root `HOME_PARENTS` does not list. With no usable `$HOME`, a site
that keeps homes at `/srv/people` or behind autofs gets neither the child refusal
nor the parent one, because both recognise a home by location and that location is
not one they know — `$HOME` is the whole of the cover there, and an unusable one
leaves none. Consulting `/etc/passwd` was considered and does not fix it: the
layouts that need it are the LDAP and autofs ones `/etc/passwd` cannot see either,
so it would move the omission rather than close it, at the cost of parsing a file
inside the guard. This is the degradation the paragraph above accepts, and
`--allow-read`/`--allow-write` are the answer for such a site either way.

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

`named_homes` keeps raw `$HOME` *and* its canonical form when they differ. Fedora
Silverblue ships `/home -> /var/home`, so `getcwd` says `/var/home/u` where `$HOME`
says `/home/u`; comparing one form is a bypass of the other. `HOME` unset falls out
as an empty `paths` with no second code path.

## The enforcer is reached by inode

The open question the issue left — whether a derived root may hold the running
`sandbx` — is settled by not needing an answer. `command_line()` hands the kernel
`/proc/self/exe`, a magic link to the image this process is running
([#149](https://github.com/danczw/sandbx/issues/149)).

What a path guard had to stop was live rather than theoretical. Resolved by path
on **every** spawn, the helper could be swapped between two tool calls in one
turn: rename a replacement over `target/debug/sandbx` and the next spawn execs
it, choosing its own confinement, with nothing asking the operator first.
(`ETXTBSY` blocks overwriting in place; rename-over is what `cargo build` does.)
A link to the inode cannot be redirected, so the replacement lands and the
running process execs what it was always going to exec.

`exe.starts_with(cwd)` is therefore gone, with `PolicyError::EnforcerInside` and
`EnforcerUnknown`. Any replacement for it would be comparing a name nothing is
reached by. A carve-out — grant the tree except the binary — would not have
helped either: `SandboxPolicy` is grants-only, matching is prefix-only, and
Landlock composes rules by union with no subtraction.

What that widens is worth naming rather than filing under "bounded cost". A
`/usr`-rooted prefix is still refused, by the overlap arm and not by this one:
`/usr/local/bin` holds `/usr`, which every command may already execute. The arm
was the only thing refusing a *user-level* prefix, so a no-flag run from
`~/.cargo/bin`, `~/.local/bin` or `/opt/x/bin` now derives read and write over
the directory holding the installed binary. It also stopped refusing sandbx's own
developers a no-flag run in their own repo, which is what made it the one arm
that fired in ordinary use.

The residue is the *next* invocation of `sandbx`: a write grant over the binary
replaces what runs then, by a human or a script. No guard reaches that, it is the
same property as `.git/hooks/*` in a granted tree, and it stays a non-claim in
`SECURITY.md`.

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

Nothing in that list is refused, and nothing can be: it waits for a human action,
and enumerating the candidates would be a denylist whose first omission is silent.

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

Every variant about the working directory ends in one shared `ADVICE` const, so
two refusals cannot name different flags. `ImposedVariable` is the one that does
not: it is about neither a path nor the working directory, and path-flag advice
on it would answer a question nobody asked.

## The seam

`vetted_root(cwd, homes, granted)` is pure, with all three inputs injected as values,
and `named_homes(home) -> Homes` takes the one variable the same way; `current_root()`
is the thin wrapper that reads both off the process. Same split as
`resolve_api_key(env_var, lookup)` / `anthropic_api_key()` in
`crates/sandbx-providers/src/credentials.rs`, with values rather than a closure
since nothing is called twice.

All three are private, and the tests for them are inline. Making the seam public so
`tests/sandbox_run.rs` could drive the refusals is the trade
`guide-module-layout.md` forbids — widening the API to suit a test. What the
integration suite gets instead is the end-to-end refusals in `tests/cwd_policy.rs`,
which spawn the built binary: the guard reads `getcwd` and `HOME` off the real
process, and `set_current_dir` is process-global, so under parallel tests one case
would decide another's verdict.

## The mutation check

The same check `decision-axis-table.md` does for a table change. Each mutation run
rather than reasoned about:

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
       an_unresolvable_home_refuses_a_child_of_one         fails
       a_home_that_is_no_directory_refuses_a_child_of_one  fails
       a_refusal_names_the_flags_to_type_instead           fails
       the_home_parents_are_refused_with_no_home_set       passes

that gate re-read off the path list, !usable ──► paths.is_empty() (the #154 hole)
   ──► an_unresolvable_home_refuses_a_child_of_one         fails
       a_home_that_is_no_directory_refuses_a_child_of_one  fails
       an_unset_home_refuses_a_child_of_one                passes  ◄── the gate is satisfied
       refuses_to_run_from_home_whatever_home_names        passes  ◄── /home is a home parent

usable stops asking for a directory below / (HOME=/dev/null, HOME=/)
   ──► a_home_that_is_no_directory_refuses_a_child_of_one  fails
       an_unresolvable_home_refuses_a_child_of_one         passes  ◄── it never resolved

the written form dropped when $HOME does not resolve
   ──► an_unresolvable_home_is_still_compared              fails
       an_unresolvable_home_refuses_a_child_of_one         passes  ◄── the other field

the Silverblue second spelling dropped
   ──► a_symlinked_home_names_both_forms                   fails

an unusable $HOME refused outright instead of deriving
   ──► an_unresolvable_home_still_runs_from_a_project      fails
       refuses_to_run_from_home_whatever_home_names        fails   ◄── the wrong refusal
       an_unset_home_still_runs_from_a_project             passes  ◄── nothing to refuse on

overlap arm deleted, or tested one way round
   ──► a_directory_overlapping_the_system_binaries_is_refused  fails
       refuses_to_run_from_the_system_binaries                 fails
       a_directory_named_like_a_system_one_is_a_valid_root     passes
```

The home arms are five tests rather than one loop because the gating is what went
wrong three times: a single looping test could not tell "the location rule is gone"
from "it is back behind the path list" from "it no longer sees `/home/other`" from
"`/home/other` is seen but an unusable `$HOME` satisfies the gate", and the last is
#154 in both its spellings — a `$HOME` that resolves to nothing, and one that
resolves to something that is not a home.

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

The gap the tests do not close, narrowed by #154: the derivation is now
`named_homes`, which takes `$HOME` as a value and is unit-tested over every shape —
unset, empty, relative, unresolvable, resolving to a non-directory, resolving to
`/`, resolving to a real home, and symlinked, that last against a `tempfile`
symlink rather than argued from a Silverblue host. All that is left reading the
live process is `current_root()`'s two lookups themselves, `getcwd` and
`var_os("HOME")`; `tests/cwd_policy.rs` covers what it can of them by setting
`HOME` on the spawned binary. Note what the history means: it is the arm that
depends on `$HOME` not at all — `holds_home_directories` — that never had any of
the three holes, and that is the reason to prefer it.
