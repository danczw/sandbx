# What the harness does when a grant covers something it owns

Three issues asked one question. `--allow-write` over the session root lets one
turn choose what the next turn is told it said (#173). `--allow-read ~/.config`
hands a tool the credential file and the provider key in it (#184). `--allow-read
/proc` reaches `/proc/<harness-pid>/environ`, so an operator who *exported* the
key handed it over without naming it to `--allow-env` at all (#192). In each the
operator granted a tree, and the tree held something that is sandbx's rather than
the project's.

The question is not which paths are sensitive. It is what a harness may do about
a grant it was handed. `decision-tool-credentials.md` left it open on purpose,
having established the rule it has to be answered under; this is where it is
answered, and the answer is two mechanisms rather than one. The two on-disk roots
are refused. The procfs route is closed by sandbx hiding its own process instead,
because refusing `/proc` would cost `sandbox-run` a legitimate use for a hazard
that is not about a path at all.

## Subtraction was never available

The shape that looks right first — grant the tree, carve out the file — does not
exist. Landlock composes rules by union and has no exclusion form, so a ruleset
cannot say "everything under `$HOME` except one path"; adding the narrower rule
adds access rather than removing it. `decision-default-policy.md` records the
same finding where it rejected a carve-out for the running binary, and
`SandboxPolicy` is grants-only for the same reason: there is no subtracting type
to put a carve-out on.

Nor can the grant be decomposed into the siblings of the owned path. A tree is
not a fixed set — `~/.config` gains a directory the day after the run — so a
decomposed grant is narrower than what was typed in a way that drifts, and the
operator who typed `--allow-read ~/.config` would get a policy nobody wrote.

What is left is to refuse, or to take the owned thing out of reach by some route
other than the policy. Both are used here, one each.

## Both subcommands, because a refusal is all it may be

`decision-tool-credentials.md` fixes the rule: **the two subcommands may differ
by a refusal, never by a policy**, and the test of a refusal is that it is
decidable from argv. `agent-run` can refuse `--allow-env ANTHROPIC_API_KEY`
one-sidedly because the name is matched against a constant.

A path refusal is not like that. Whether `--allow-read ~` reaches the session
directory is answered by deriving both paths and comparing them, and a comparison
one subcommand acts on and the other ignores is two policies from one set of
flags. So this refusal applies to both subcommands or to neither — and it applies
to both, which keeps `the_policy_matches_what_sandbox_run_derives` green by
construction rather than by exemption: neither subcommand derives a policy at
all.

That is also why it lives in `Grants::policy`, which the same document rejected
as a home for the credential check. The rejection was about *attribution*:
`Grants` does not know which subcommand is asking, so it cannot refuse for one of
them. A rule that holds for both needs no attribution, and `Grants` is the one
place argv becomes a `SandboxPolicy` — flattened into both run subcommands, so
they cannot drift apart.

The operator keeps an escape that is not a flag: `sandbox-run` under a different
`$HOME`, or `XDG_STATE_HOME` pointed elsewhere, moves what sandbx owns and the
refusal moves with it. That is the honest form of an override — it says where the
state went, instead of leaving sandbx holding state inside a tree it just handed
away.

## Either direction, and both spellings

A Landlock right covers a subtree, so containment has to be tested both ways
round. A grant *above* the session directory hands over every transcript; a grant
naming one transcript inside it hands over that history, which is the file whose
contents become what the model is told it said. `reaches_owned` therefore runs
`starts_with` in both directions, on components rather than bytes, so a directory
merely spelled like an owned one — `~/.config/sandbx-notes` — still derives.

Grants are taken verbatim: nothing canonicalizes them, and nothing requires them
to be absolute. A purely lexical comparison would therefore miss `--allow-read .`
from `$HOME`, and miss the host where `/home` links to `/var/home` — Fedora
Silverblue — where one spelling would be refused and the other would not.
`resolved` closes both by canonicalizing the deepest ancestor that exists and
re-joining what is left, applied to each side of the comparison. The deepest
*existing* ancestor and not the whole path, because `canonicalize` needs every
component to exist and a credential nobody has stored yet does not.

A relative grant is joined to the working directory before any of that, which is
what the helper opens it against too. Resolving it ancestor by ancestor is not
enough on its own: the walk bottoms out at the empty path, so a relative grant
whose *first* component does not exist yet — `--allow-write sandbx` from
`~/.local/state`, with no transcript saved — would stay relative and match no
absolute owned path. That is the one spelling in which existence could still have
decided the verdict, and it is the spelling `--session` creates during the very
run the policy was derived for.

A working directory that cannot be read refuses the relative grant rather than
standing in as nothing, which would leave it matching no owned path (#203). An
absolute grant needs no working directory and is not refused for one. That
narrows what `current_root`'s placement rested on: an invocation that typed its
own flags still never depends on `HOME`, but it depends on `getcwd` for a
relative one, and the refusal says to write the grant absolute rather than
advising the path flags it was already given.

Joining the cwd is therefore a step of its own — `absolute`, which the flag route
calls and the derived route does not, over a `resolved` that is total. The cwd
arrives as an argument rather than off the process: a direction that fails only
on a deleted directory is one no test can pin.

## It does not ask whether anything is stored there

The refusal fires on a host with no transcript and no key, exactly as #41's
refusal fires with the variable unset. Three reasons, and the first is the one
that would bite:

An existence-sensitive refusal is a race. `agent-run --session` creates the
transcript during the run the policy was derived for, so a check against the
filesystem would answer "nothing there" and then put something there. The same
run would be refused on its second invocation and not its first.

The second is testability, the reason `decision-tool-credentials.md` gives for
the by-name refusal: a verdict keyed on what is on disk this minute is a verdict
no test can pin without building the state it is testing for. The third is that
the same argv then gets the same answer on every host, so an operator reporting a
refusal reports something anybody can reproduce.

## There is no exact-path hatch

`--allow-read ~/.config/sandbx/credentials.toml` is refused, not honoured as the
narrowest possible form of the request. Naming the file *is* the request the
refusal exists for: the hazard is a tool reading the key, and a flag that names
the key's file is the shortest way to that. A hatch at the exact path would also
be a hatch for an injected flag in any wrapper script that builds an argv, with
the one spelling that reads most like deliberate care.

## The derived default is the same hazard by another route

A no-flag run from inside the session directory derives read and write over the
working directory, and the working directory is the history. The issue did not
name that route, and the existing path refusals could not see it: every one of
them sits inside `if !self.paths_given()`, which is also why an explicit path
flag bypassed all of them before this. So `vetted_root` gains the same arm as the
per-grant loop, and one rule covers both — the refusal is about what a grant
reaches, not about how the grant was spelled.

One rule, two messages, and they are different errors on purpose. The derived
route refused nothing the operator typed, so it reads like its neighbours —
"refusing to derive a policy from …" — and ends on the shared advice to pass the
path flags. The flag route cannot end there: advising `--allow-read PATH` to an
operator whose `--allow-read` was just refused says nothing, so it says what to
change about the path instead.

## #192 is a different mechanism, not more of this

An exported key is not on a path sandbx owns. It is in sandbx's own memory and
`environ`, which procfs publishes to every process running as the same uid; the
harness is not sandboxed, and `/proc` is the host's.

Refusing `/proc` as a path was available and is disqualified twice over. It would
be a refusal by name, which `SECURITY.md` declines for `/etc`, `/var`, `/proc`
and `/sys` on the grounds that depth is not sensitivity and a list of dangerous
directories has a silent first omission. And it would break `sandbox-run`: a
command reading `/proc/self/status` is ordinary, the operator chose it, and the
key it would be protected from is one the operator exported for sandbx to spend.

So sandbx conceals its own process instead. `conceal_process_state` clears
`PR_SET_DUMPABLE` at startup, which makes the kernel reparent `/proc/<pid>/` to
root; `environ`, `mem`, `maps` and `fd/` then fail `__ptrace_may_access` for a
same-uid reader. No policy changes, both subcommands behave identically, and
`sandbox-run --allow-read /proc` keeps working for everything except sandbx's own
entry.

It costs the two things the flag was protecting: no core dump of the harness, and
no same-uid debugger attach to it, so `gdb -p` and `strace -p` against a running
sandbx are refused. A failure to set it is a refusal rather than a degradation,
unlike the capability bounding set — there the bit cannot be spent on any host,
here the key is exposed on the host where the call failed.

The call sits just after `Cli::parse`, which is what lets the refusal exit with
the subcommand's own failure code: `auth status` spends 1 on "no key anywhere",
so a refusal there has to be 2 or a script reads it as an absence. Parsing argv
exposes nothing, and nothing has been spawned yet either way — what the flag has
to precede is the first sandboxed command, not the first line of `main`.

The flag is set on the harness and nowhere else. The helper does not set it, and
`helper/hardening.rs` says why: the kernel resets dumpable on every `execve` of
an ordinary binary, so it would cover only the helper's pre-exec window. That
same reset is what keeps the sandboxed command unaffected, which is correct — its
`environ` holds only what `--allow-env` named.

What this does not close: every *other* same-uid process's `environ` is still
reachable through a `/proc` grant, `/proc/<harness-pid>/cmdline` stays readable,
and the helper's own entry is not concealed, which is what the audit channel's
`/proc/<helper-pid>/fd/0` exposure rides on. "Do not grant `/proc`" stays.

## What it costs

`--allow-read ~` and `--allow-read /` are now refused on every host, with no key
stored and no session saved, because both roots derive under `$HOME`. Those two
flags are the ones an operator reaches for when a command needs more than the
project tree, so this is the change most likely to be met as a regression. The
message names the grant, the owned path inside it, and what sandbx keeps there;
the answer is to grant the trees the command needs.

Nothing else narrows. A grant over a project tree, a scratch directory, `/usr`,
`/tmp` or `/etc` derives exactly what it did before, and no subcommand gained a
policy difference.

## What was rejected

**A warning instead of a refusal.** Printing "this hands over your key" and
continuing is the fail-open shape `decision-credentials.md` and
`decision-tool-credentials.md` both reject. The operator who granted the tree by
mistake is the one who will not read the line.

**Stripping the owned path out of the grant.** Silently narrowing derives a
different policy from the same flags, which is the divergence
`the_policy_matches_what_sandbox_run_derives` exists to catch, and the symptom is
a tool failing on a path the operator was told it could read.

**Refusing on `agent-run` only.** The hazard is worst there, but the route is not
decidable from argv, so a one-sided answer would be a policy difference and the
rule forbids it.

**An `--allow-owned-paths` override.** A flag that unlocks the one grant the
refusal exists for would be typed by exactly the operator the refusal is for, and
read as a permission rather than a hazard. Moving `$HOME` or `XDG_STATE_HOME`
already moves what sandbx owns, which is the same power stated honestly.

## The mutation check

Delete the `reaches_owned` check from the per-grant loop in `Grants::policy`:

```
delete the if in the per-grant loop
   ──► a_grant_reaching_an_owned_path_is_refused_on_both   fails
       naming_the_credential_file_itself_is_refused        fails
       a_grant_above_an_owned_root_is_refused              passes  ◄── tests the helper
       a_grant_inside_an_owned_root_is_refused             passes  ◄── tests the helper
       a_root_inside_an_owned_path_is_refused              passes  ◄── the other arm
       the_policy_matches_what_sandbox_run_derives         passes  ◄── no divergence to see
```

The unit tests over `reaches_owned` keep passing, because the helper still
answers correctly — what was deleted is the one call that acts on its answer. The
two spawned cases in `cwd_policy.rs` are the only ones that fail, which is why
they exist, and `cargo test` stops at the first failing binary so they have to be
run with `--test cwd_policy` to be seen.

Delete the arm in `vetted_root` instead and `a_root_inside_an_owned_path_is_refused`
is the only failure: the two routes are covered separately on purpose.
