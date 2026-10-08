# What sandbx is

The whole system from outside, before any of it is taken apart.
[04 — the architecture](04-the-architecture.md) draws the boxes this chapter
only names; read this one first, because the boxes make much more sense once
you know what the thing is trying to be.

## One sentence, then the thesis

sandbx is a command-line harness that asks an AI model a question, lets it use
tools to answer, and runs every one of those tools inside a boundary the kernel
holds.

The second half is the whole project. Most agent harnesses treat confinement as
somebody else's job: run the agent in a container, or ask a human before each
command. sandbx puts the boundary *inside* the harness, derived per run from the
flags you typed, so that the thing deciding what a tool may touch and the thing
running the tool are the same program. The design record for that seam opens
with the sentence worth memorising:

> Where policy stops being data and becomes something the kernel holds.
>
> — [decision-enforcement-seam.md](../decision-enforcement-seam.md)

"Data" is a `SandboxPolicy` — a Rust value, a set of granted paths and axes,
which anything in the process could in principle ignore. "Something the kernel
holds" is a Landlock ruleset, a seccomp filter and a set of namespaces, applied
to a process that then cannot take them off. The interesting engineering in this
repo is almost all about that conversion: getting it right, getting it to fail
closed when it cannot be done, and proving afterwards that it happened.

**Worth questioning:** the thesis buys per-run, per-path precision at the cost
of being Linux-only and refusing to run at all where the kernel will not
cooperate. A container-based harness runs anywhere a container runs. Nothing in
`context/` argues that trade explicitly — the decision records argue the
*shape* of the boundary, not the choice to own one — so it is worth asking
whether the portability cost has ever been priced, and what sandbx would look
like on a host where it is currently a refusal.

## Five subcommands

The binary is `sandbx`; the library half is `sandbx_cli`. The clap surface is
one enum in [`cli/src/lib.rs`](../../crates/sandbx-cli/src/lib.rs) — see
`Command` — and its doc comments are the long `--help` text, which makes them
worth reading before the code.

| subcommand | what it does | confines something |
|---|---|---|
| `sandbox-run` | runs one command under the boundary and reports what it did | yes |
| `agent-run` | asks the model one question and streams the answer, with every tool call bounded by the same policy | yes |
| `tui` | the same turn drawn on a screen you can watch and stop | yes |
| `hash` | prints a file's SHA-256 in the form `--pin-sha256` takes | no |
| `auth` | stores, removes or checks the provider API key | no |

Two things to notice about that table.

- **`tui` is not a second agent.** It takes `agent-run`'s flags, derives the
  same policy, and differs only in where a turn is reported. They share the
  gate, the orientation message and the session handling, which is why
  `guide-repo-map.md` describes the pair as one subcommand drawn two ways.
- **The two that confine nothing are deliberate, not unfinished.** `hash` has
  to read a file before there is a policy to read it under — the digest is an
  *input* to the policy. `auth` touches only the credential file. Neither can be
  put behind the sandbox without a circularity, and `SECURITY.md` is explicit
  that the sandbox does not confine sandbx itself.

## The default policy, and why it is the interesting part

Everything is denied unless a flag grants it. What a no-flag `sandbox-run` gets
anyway, from [`core/src/policy.rs`](../../crates/sandbx-core/src/policy.rs):

```rust
const SYSTEM_EXECUTABLE_PATHS: [&str; 4] = ["/usr", "/bin", "/lib", "/lib64"];

const STANDARD_ENV_NAMES: [&str; 7] = ["PATH", "HOME", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ"];
```

`allow_system_executables` folds the first list through `allow_read_execute`,
and `allow_standard_env` folds the second through `allow_env`. On top of those
the CLI adds, *only when no path flag was given*, read and write on the working
directory.

Three consequences that catch everybody once:

- **A path flag replaces the working-directory default rather than adding to
  it.** `--allow-read /srv` is read on `/srv` and nothing else. The alternative
  — an unconditional default plus an opt-out — was rejected because a
  deliberately tight hand-written policy would then silently gain write over
  the whole working tree.
  [decision-default-policy.md](../decision-default-policy.md) states the rule
  as "narrow and loud beats wide and silent".
- **Grants do not widen each other.** Read does not confer execute, and write
  confers neither. `allow_read_execute` is the single exception, and it exists
  because a program needs execute on the binary *and* read on the libraries its
  loader pulls in. This is why `cargo test` under `sandbox-run` needs seven
  flags: the working directory needs write for `target/` **and** execute for
  the test binary it just built.
- **Some working directories are refused rather than granted.** Standing at the
  filesystem root, in `$HOME`, in a directory that holds home directories, or
  anywhere overlapping the system binaries, a no-flag run is refused with a
  message naming the two flags to type instead. The guard governs what sandbx
  *derives* and never what you ask for — the refusal lifts the moment you say
  what you mean.

### Under `agent-run`, that default is the blast radius

The same `Grants` struct is flattened into every subcommand that confines
something, so `sandbox-run` and `agent-run` cannot disagree about what a flag
means. The derived default comes along with it: with no path flag, the model may
rewrite anything under the directory you ran it from. The CLI help says so in as
many words.

- **Worth questioning:** whether the *default* should be shared as well as the
  flags. `decision-default-policy.md` gives one reason for sharing — "it lives
  in `Grants`, which both subcommands flatten, so `sandbox-run` and `agent-run`
  cannot disagree about it" — and that argument is about the *flags*, which
  genuinely must not drift. It does not obviously extend to the default, where
  the two subcommands differ in the thing that matters: under `sandbox-run` a
  human chose the command, and under `agent-run` a model did, possibly at the
  direction of text it read out of a file. A read-only derived default for
  `agent-run`, with write arriving only on an explicit `--allow-write .`, would
  keep one `Grants` and still make the asymmetry explicit. The record's own
  closing argument applies in this direction too: narrow and loud beats wide and
  silent.

## What the kernel has to provide

sandbx runs on Linux and nowhere else; `core/src/lib.rs` refuses a non-Linux
target at compile time rather than building something that cannot enforce
anything. At runtime it needs unprivileged user namespaces, and a Landlock ABI
at or above a floor. That floor has one home — `BASELINE_ABI` — and every prose
copy of it is named in a test, `every_prose_copy_of_the_floor_is_current`, which
fails if a bump leaves one behind; [`SECURITY.md`](../../SECURITY.md) and
[guide-sandboxing.md](../guide-sandboxing.md) are two of them. This chapter does
not restate the figure, because the test's own comment says that every added
copy is another way for a trim to break the build — which is the kind of
discipline worth noticing on day one.

What matters more than the number is why there is a floor at all, and the reason
is in a comment on `BASELINE_ABI` in
[`ruleset/compat.rs`](../../crates/sandbx-core/src/helper/ruleset/compat.rs):

> A floor rather than a preference: Landlock leaves any access type *not* in the
> handled set unrestricted everywhere, so pinning a lower ABI leaves whole
> categories unguarded.

So an old kernel is not a weaker sandbox, it is an unguarded category. The
ruleset is requested as a `HardRequirement`, negotiation walks *down* from the
newest ABI to the floor looking for the newest the kernel takes in full, and
below the floor the run is refused. Nothing falls back to running unconfined —
that is what "fails closed" means here, and it is a claim you can check rather
than a slogan.

## Run it

Five commands, from the project [`README.md`](../../README.md). Run them in a
checkout of some project, not in `$HOME` — the fourth and fifth are the ones
that teach the most.

```sh
sandbx sandbox-run -- grep -rn TODO .                        # works
sandbx sandbox-run -- cat /etc/shadow                        # permission denied
sandbx sandbox-run --allow-read /srv -- cat /srv/notes.txt   # works
sandbx sandbox-run --allow-read /srv -- cat /etc/shadow      # permission denied
sandbx sandbox-run -- curl https://example.com               # no network at all
```

The third and fourth are the same flag with two outcomes, which is the default
policy's replacement rule from above. The fifth fails before it resolves
anything: with no network grant the command runs in an empty network namespace,
so there is no interface to send on rather than a rule that denies sending.

Then the one worth doing deliberately:

```console
$ cd ~ && sandbx sandbox-run -- true
sandbx: refusing to derive a policy from your home directory /home/you — pass --allow-read PATH and --allow-write PATH for the tree the command needs
```

Every refusal in this family names the flags to type instead, behind one shared
constant so that two refusals cannot advise differently.

## Exit codes mean something

`agent-run` and `tui` use the status to say how a turn ended, which a script can
branch on. From [`cli/src/agent.rs`](../../crates/sandbx-cli/src/agent.rs):

| code | meaning |
|---|---|
| 0 | the turn ended on an answer |
| 1 | a failure, named on stderr |
| 2 | `INCOMPLETE` — a bound the operator chose cut the turn short |
| 3 | `NO_CONSENT` — the operator could no longer be asked |

Three rather than two is the point: a run that stopped because nobody could
approve a tool call is neither a failure nor a bound being hit, and a caller has
to be able to tell the three apart (#218). `auth` uses 2 for a failure instead
of 1, because `auth status` already spends 1 on "no key anywhere" and a script
must not read a refused credential file as an absent one.

## Where it is

Pre-alpha: one question, the tools to answer it, and a resumable conversation.
No live session and no interrupt — `tui` can stop a turn, but a tool already
running finishes, because sandbx cannot cancel a blocking call mid-flight (#26).
The version is in the workspace `Cargo.toml`, and what shipped in which release
is on the releases page rather than in a file here.

## You should now be able to explain

- What "policy stops being data and becomes something the kernel holds" means
  concretely, and which two things sit on either side of that conversion.
- Which of the five subcommands confine something, and why the two that do not
  cannot be made to.
- What a no-flag run grants, and why typing one path flag takes the working
  directory away.
- Why read does not confer execute, and the one grant that confers both.
- Why an old kernel is a refusal rather than a weaker sandbox.
- What exit code 3 means and why it is not 1 or 2.

## Next

[02 — what a harness is](02-what-a-harness-is.md), which backs up one step: the
loop this product is built around, and why a model that can only emit tokens
needs a program willing to act on them. Then [03](03-the-landscape.md) for the
other projects that answered the same questions differently, and
[04 — the architecture](04-the-architecture.md), which takes the system above
and draws it three times: as processes, as one request's path end to end, and as
a set of named boundaries.
