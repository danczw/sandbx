# Seven crates, and only one of them may spawn

[04 — the architecture](04-the-architecture.md) draws the system three times,
and all three drawings are about run time: processes that exist, a request that
moves, boundaries that hold. This chapter is the floor plan underneath them. It
attaches most directly to 04's **View 3 — the boundaries, named**, whose table
has a *where* column naming a crate per boundary; what follows is that column
read as a graph, plus the manifest machinery that makes the graph binding rather
than advisory.

[guide-repo-map.md](../guide-repo-map.md) is the authority for the module trees
inside each crate. This chapter is about the seven boxes and the arrows between
them.

## The graph

Seven crates under `members = ["crates/*"]`, and every internal edge is a path
dependency. Read `──►` as "may name the types of":

```
sandbx-cli        ──►  agent  tui  session  providers  tools  core
sandbx-agent      ──►  providers  tools        (core: dev-dependency only)
sandbx-tui        ──►  providers
sandbx-tools      ──►  core
sandbx-core       ──►  —
sandbx-providers  ──►  —
sandbx-session    ──►  —
```

Four things about that shape are worth more than the picture.

- **Three crates have no internal dependency at all,** and each of the three
  owns exactly one thing that lives outside the process: `sandbx-core` owns the
  kernel, `sandbx-providers` owns the wire, `sandbx-session` owns the disk. None
  of the three can name another's types, which is why a stored transcript is not
  a `Prompt` and a `SandboxPolicy` is not a request body. The module doc on
  [`session/src/lib.rs`](../../crates/sandbx-session/src/lib.rs) says the
  consequence out loud — the stored shapes are declared there rather than
  imported, because a file format that moved whenever a provider type moved
  would not be a file format.
- **`sandbx-cli` is the only crate that depends on all the others, and the only
  one that ships a binary.** Everything converges there because that is where
  argv becomes a policy and a policy becomes a run. 04's *The CLI architecture*
  section covers the lib-plus-bin split.
- **`sandbx-tui` reaches `sandbx-providers` for the vocabulary, not the
  transport.** The only names it borrows are `AgentEvent` and `StopReason` — see
  [`transcript.rs`](../../crates/sandbx-tui/src/transcript.rs). No client, no
  credential, no policy. The screen folds events it is handed; it never opens a
  stream.
- **Nothing points up.** There is no cycle, and no crate reaches sideways into a
  peer at its own level. `sandbx-tools` cannot see `sandbx-agent`, so a tool
  cannot ask the loop for another round; `sandbx-agent` cannot see
  `sandbx-session`, so the loop cannot write to the transcript — the CLI does
  that after a turn ends.

## Who owns what

| crate | owns | the name you meet first |
|---|---|---|
| `sandbx-core` | sandboxing: the policy type, the in-process guard, the helper, the one spawn site | `SandboxPolicy`, `SandboxedCommand`, `FsGuard` |
| `sandbx-tools` | the seven built-ins, each confined by core | `BuiltinTool`, `ExecutionContext` |
| `sandbx-providers` | hand-rolled streaming clients against an LLM API | `EventStream`, `Prompt` |
| `sandbx-agent` | the turn loop, and the gate a caller must supply | `run_turn`, `CallGate` |
| `sandbx-session` | the on-disk transcript: an id, a root, append-only JSONL | `SessionStore` |
| `sandbx-tui` | the screen one turn is drawn on, and the keys that stop it | `Screen`, `Transcript` |
| `sandbx-cli` | parsing, policy derivation, the five subcommand bodies | `Cli`, `Command`, `Grants` |

The crate set is also the label set. GitHub carries exactly one `crate:*` label
per crate — `crate:core`, `crate:tools`, and so on — each with a description
naming what that crate owns, so a triage label and this table answer the same
question.

## A Rust aside: the workspace is not a crate

If every Cargo project you have built had one `Cargo.toml` with a `[package]`
table in it, five things here will read as unfamiliar. None of them is exotic;
all five are load-bearing.

**It is a *virtual* workspace.** The root [`Cargo.toml`](../../Cargo.toml) has a
`[workspace]` table and **no** `[package]` table. There is no crate at the root
— no `src/`, nothing to build there. What the root holds is the member list, the
shared metadata, and the lint table. Two practical consequences: with no
`default-members` key, a cargo command run at the root applies to every member,
so `cargo test` there is the whole workspace; and because there is no root
package, cargo has no package `edition` from which to infer a dependency
resolver. That is why `resolver` is written out explicitly — omit it in a
virtual workspace and cargo falls back to the oldest resolver and warns.

**`[workspace.package]` is inheritance, not defaulting.** The version, edition,
license, repository, MSRV and `publish` flag are declared once at the root, and
each member *asks* for them field by field:

```toml
version.workspace = true
edition.workspace = true
rust-version.workspace = true
```

A field a member does not spell out is not inherited. The CI `msrv` job depends
on this: it reads `rust_version` out of `cargo metadata`, which reports the
**inherited** value, so a `[workspace.package]` entry that no member asks for is
inert and reads back as `null`. [guide-ci.md](../guide-ci.md) explains why that
job errors on `null` instead of quietly testing on stable.

**`[workspace.lints]` is a lint table every crate opts into by hand.** The root
declares the levels:

```toml
# `sandbx-core` opts in too: the one site that spawns carries its own `#[allow]`,
# which is narrower than exempting the crate.
[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"

[workspace.lints.clippy]
# Method list: clippy.toml.
disallowed_methods = "deny"
```

and every one of the seven members carries the two lines that take them:

```toml
[lints]
workspace = true
```

`forbid` is the level above `deny` and the distinction matters here: a `deny`
can be overridden by an `#[allow]` further in, and a `forbid` cannot — writing
`#[allow(unsafe_code)]` under a `forbid` is itself a compile error. That is what
makes the "zero `unsafe` anywhere" property in
[`SECURITY.md`](../../SECURITY.md) checkable rather than aspirational, and it is
why 04 can say a `fork` in the helper was not an option: the thing that would
have made it legal does not exist.

- **Worth questioning:** the opt-in is per crate and cargo offers no way to
  require it. An eighth crate that omits `[lints] workspace = true` gets none of
  the three — no forbidden `unsafe`, no mandatory docs, no `Command::new` ban —
  and nothing in the build or in CI would say so. All seven opt in today, so
  `SECURITY.md`'s "`unsafe` is forbidden workspace-wide" is true as written; no
  `decision-*.md` records the choice, because there is nothing to choose between
  — the gap is cargo's. What makes it worth raising anyway is that the repo
  already owns the mechanism that would pin it:
  [`context_docs.rs`](../../crates/sandbx-core/tests/context_docs.rs) is a Rust
  test that walks the repo root and asserts a property of files outside its own
  crate. A test that read every `crates/*/Cargo.toml` and asserted the opt-in
  would cost about as much as the walk it would borrow. Chapter
  [16](16-how-the-repo-is-maintained.md) is where that family of test lives.

**`resolver = "3"`.** Resolver 3 is MSRV-aware: given a choice of versions it
*prefers* one compatible with the stated `rust-version`. That is a convenience
locally and a hazard in CI, because an unlocked resolve can quietly route around
a lockfile that is broken at the floor — which is exactly why the `msrv` job
passes `--locked`. Resolver 3 also unifies features per *package* across a
dependency graph, and `sandbx-providers` has a comment in its manifest
explaining what that cost: a self dev-dependency enabling its own `mock` feature
would have turned the feature on in the single rlib every consumer links, so the
mock provider is reached through a `[[test]]` target with
`required-features = ["mock"]` instead.

**`edition = "2024"`.** The edition is declared once and inherited by all seven,
so there is no mixed-edition reading to do. One concrete thing it buys in this
tree: let-chains — `if cond && let Some(x) = opt` — which are edition-2024-only
and stable only from the toolchain version the manifest names. The helper uses
them, and the root manifest's comment on `rust-version` records that the
let-chain in `helper/` is one of the two things holding the floor where it is.
When you read a condition in
[`helper/mod.rs`](../../crates/sandbx-core/src/helper/mod.rs) whose lines begin
`&& let`, that is the feature, not a typo.

**`publish = false`.** No crate here goes to crates.io; the shipped artifact is
the `sandbx` binary from a release tag. The flag also changes what a manifest is
allowed to omit — a published crate's path dependency still needs a `version`
key for the registry copy, and these do not, so every internal edge is the bare
`{ path = "../sandbx-core" }` form you saw above. That interacts with one more
file. [`deny.toml`](../../deny.toml) sets `wildcards = "deny"`, and a path
dependency with no version *is* a wildcard by construction, so the same file
sets `allow-wildcard-paths = true` — the root manifest's comment on `publish`
names this as a reason the flag is there at all.

## Only `sandbx-core` may spawn, and the compiler says so

The claim is in the first sentence of
[`core/src/lib.rs`](../../crates/sandbx-core/src/lib.rs):

```rust
//! Sandboxed execution for sandbx, and the only place any crate's `src/` may spawn a
//! subprocess (`spawn::command`, per the `Command::new` ban in `clippy.toml`). Two
//! default-deny layers (see [`SandboxPolicy`]): [`FsGuard`] checks paths in-process, for
//! Rust tools that never spawn and so are never seen by the kernel; Landlock, seccomp and
//! namespaces restrict children, applied by a re-exec'd helper to itself so sandbx is not.
```

The reason is the one thing Landlock and seccomp cannot do. A process's
environment crosses `fork`/`exec` before either mechanism has any say, and
neither can express "not this variable" — seccomp compares register values and
cannot follow a pointer, and Landlock is about paths. So the only way to
withhold a variable from a child is to never put it there, which means the
narrowing has to happen at construction time, in whatever builds the `Command`.
One builder can be made to narrow. Five hand-written clears cannot be made to,
and [decision-environment-allowlist.md](../decision-environment-allowlist.md)
records what happened when there were four: each of the four was individually
unfalsifiable, because the sites masked one another — delete any single clear
and a later one covered for it, leaving the command's `environ` byte-identical
and no test able to tell. Worse, a fifth spawn site added later would have
inherited the harness's whole environment, which fails *open*.

That is the invariant. The method list that holds it is the whole of
[`clippy.toml`](../../clippy.toml):

```toml
# A direct spawn bypasses every Landlock/seccomp restriction sandbx applies, and
# the one exempt factory, `sandbx-core::spawn::command`, narrows the environment as
# it builds the `Command`; see `context/decision-environment-allowlist.md`.
disallowed-methods = [
    { path = "std::process::Command::new", reason = "spawn via sandbx_core::SandboxedCommand so Landlock/seccomp restrictions are applied" },
    # Inert until something enables tokio's "process" feature: the path resolves
    # nowhere, which clippy warns about unless `allow-invalid` silences it — and
    # that flag also silences a typo in this line, hence it is scoped to this entry.
    { path = "tokio::process::Command::new", reason = "spawn via sandbx_core::SandboxedCommand so Landlock/seccomp restrictions are applied", allow-invalid = true },
]
```

Both halves of the pair are needed, and they are in two files: the lint *level*
is in the workspace manifest, because that is where cargo's lint table lives,
and the *method list* is here, because that is where clippy reads its own
configuration from. Note the second entry and its comment —
`tokio::process::Command::new` resolves to nothing today, since no crate here
enables tokio's `process` feature, and a path that resolves nowhere is itself a
clippy warning unless `allow-invalid` silences it. The flag is scoped to that
one entry rather than set file-wide, because file-wide it would also silence a
typo in the first entry, which is the one currently doing all the work.

Three mechanisms hold the invariant, and they are different in kind.

- **The lint, so a new spawn site does not compile.** `deny` plus the list
  above means the only way to build a `Command` anywhere in the workspace is the
  way that narrows. `decision-environment-allowlist.md` records that this was
  checked rather than assumed — a bare `Command::new` was added elsewhere and
  the lint refused to compile it.

- **Visibility, so nothing outside the crate can reach the exemption.** The
  module is declared `mod spawn;` — private — and the factory is
  `pub(crate) fn command`. It appears in none of `core/src/lib.rs`'s
  `pub use` lines. So the monopoly is not only "other crates should not call
  `Command::new`"; it is that the sanctioned alternative is unreachable from
  outside `sandbx-core`. What the other crates get is `SandboxedCommand`, and
  the two places that build one are
  [`tools/src/context.rs`](../../crates/sandbx-tools/src/context.rs) and
  [`cli/src/sandbox.rs`](../../crates/sandbx-cli/src/sandbox.rs).

- **A test, because the lint says nothing about behaviour.** A lint can prove
  that every `Command` came from the factory. It cannot prove the factory
  narrows anything. That half is pinned by `sandbx-core`'s enforcement suite,
  which runs a real command and reads its environment back.
  `decision-environment-allowlist.md` records the gain in those terms: where
  there were four hand-written obligations none of which could be falsified,
  there is now one line to delete, and deleting it fails 24 enforcement tests.

And then the part that must not be overstated.
[`SECURITY.md`](../../SECURITY.md) carries this as an explicit non-claim: the
boundary is enforced by convention plus tooling, not by a capability system —
`unsafe` is forbidden workspace-wide and spawning outside `sandbx-core` is a
clippy error, *but a determined contributor can add raw syscalls*. The ban stops
a forgetful spawn, which is the realistic failure. It is not a sandbox around
the codebase.

## The most instructive line in the workspace

Here is the whole of the exemption, from
[`spawn.rs`](../../crates/sandbx-core/src/spawn.rs):

```rust
pub(crate) fn command(program: impl AsRef<OsStr>, policy: &SandboxPolicy) -> std::process::Command {
    // The only `Command::new` in any crate's `src/`; tests that spawn the binary carry
    // their own allow. See `clippy.toml`.
    #[allow(clippy::disallowed_methods)]
    let mut command = std::process::Command::new(program);
```

An `#[allow]` attribute in Rust applies to the item it is attached to and
everything inside it. Attached to a `let` statement, as here, its scope is that
one statement. The same attribute could have been written four other ways, each
one line shorter to type:

| where the `#[allow]` could go | what it would then permit |
|---|---|
| `[workspace.lints]`, dropping the lint | every `Command::new` in all seven crates |
| `#![allow(…)]` at the top of `core/src/lib.rs` | every `Command::new` in `sandbx-core` |
| on `mod spawn;` | every `Command::new` in `spawn.rs` |
| on `fn command` | every `Command::new` in this function |
| on the `let` | this one call, and nothing else |

The last is the one that shipped, and the root manifest's own comment explains
the choice: "`sandbx-core` opts in too: the one site that spawns carries its own
`#[allow]`, which is narrower than exempting the crate." That is the house
thinking in a single line, and it generalises past clippy:

- **An exemption is scoped to the thing exempted, not to the file that holds
  it.** Each wider placement above would still describe the code accurately
  today and would still pass CI. What they would give up is the property that a
  *second* spawn site added to `spawn.rs` tomorrow fails to compile. The narrow
  form keeps the ban's edge pointed at the next change rather than at the
  current one.
- **The exemption is where the invariant is documented.** The two comment lines
  beside it are the only place in the tree that states "this is the only
  `Command::new` in any crate's `src/`" next to the line that makes it true. A
  grep for `disallowed_methods` across the tree turns up a handful of allows
  under `crates/*/tests/`, which are separate crates driving the built binary,
  and exactly one under any `src/`. That ratio is checkable in one command,
  which is the point.
- **The lint is the backstop, not the record.** `guide-repo-map.md` makes the
  comparison explicitly: a CI grep for `Command::new` would be a second
  backstop, but a lint that fails the build *at the call site* beats a grep that
  fails after it. The feedback arrives where the mistake is.

Read 04's View 3 again after this. The closed enum with an exhaustive match, the
private field on `ExecutionContext`, the gate as a mandatory parameter and this
`#[allow]` are four spellings of one move: take a rule a human would otherwise
have to remember, and give it to the compiler at the narrowest scope that still
covers it.

## Why `sandbx-core` is a *dev*-dependency of `sandbx-agent`

[`agent/Cargo.toml`](../../crates/sandbx-agent/Cargo.toml) lists
`sandbx-providers` and `sandbx-tools` under `[dependencies]`, and
`sandbx-core` under `[dev-dependencies]`. For a reader new to the distinction: a
dev-dependency is linked only when cargo builds that crate's tests, examples and
benchmarks. It is *not* available to `src/`. Naming `sandbx_core::` in
`turn.rs` would simply fail to resolve.

The stated reason is about the tests. `guide-repo-map.md` puts it in one line —
the agent's tests "drive real tools over a temp dir rather than mocking below
the tool boundary." The loop's own test double is a scripted provider, not a
scripted tool: `run_turn` is generic over a closure that opens a stream, so the
*provider* side is faked with no network and no API key, while the tool side
runs the genuine `BuiltinTool` against a `tempfile` directory. To build the
`ExecutionContext` those real tools need, a test has to construct a
`SandboxPolicy` and a `VettedPath`, and both are `sandbx-core` types — hence the
manifest edge, used by
[`tests/support/mod.rs`](../../crates/sandbx-agent/tests/support/mod.rs) and the
three test targets beside it.

The consequence is the more interesting half, and you can check it in one grep:
**`sandbx_core` appears nowhere in `sandbx-agent/src/`.** Not once. The loop
takes an `&ExecutionContext` from `sandbx-tools` and hands it to
`BuiltinTool::execute`; it never sees a policy, cannot read one, and could not
name the type if it wanted to. Combine that with the private field on
`ExecutionContext` — the boundary 04 lists as "the policy's ownership" (#56) —
and the arrangement is doubly closed:

- the field is private, so even a crate that *can* name `SandboxPolicy` cannot
  pull one out of a context and re-interpret it;
- and `sandbx-agent` cannot name `SandboxPolicy` at all, so the question does
  not arise in the one crate that decides which tool calls happen.

A plain `[dependencies]` edge would have cost nothing at run time and would have
dissolved that second property silently. The dev-only placement is what keeps
the turn loop structurally unable to have an opinion about policy — which is
the same shape as the `#[allow]` above, applied to a manifest instead of a
statement.

## You should now be able to explain

- Which three crates have no internal dependency, and the one external thing
  each of them owns.
- What a virtual workspace is, and two things that follow from there being no
  package at the root.
- How a crate opts into `[workspace.lints]`, and why `forbid` is not just a
  louder `deny`.
- What `resolver = "3"` changes about version selection, and why the `msrv` job
  therefore runs `--locked`.
- Why withholding an environment variable cannot be done with Landlock or
  seccomp, and what that forces about where a `Command` is built.
- The three mechanisms that hold the spawn monopoly, which of them says nothing
  about behaviour, and the non-claim `SECURITY.md` attaches to all of them.
- Why the `#[allow(clippy::disallowed_methods)]` sits on a `let` rather than on
  the function, the module, or the crate.
- What a dev-dependency does not give `src/`, and what that buys where
  `sandbx-agent` is concerned.

## Next

[06 — claims and non-claims](06-claims-and-non-claims.md), which turns from how
the code is arranged to what the arrangement promises. The chapter that picks up
*this* one's other half is much later:
[16](16-how-the-repo-is-maintained.md) is the same instinct applied to prose
instead of code, and the Rust tests that hold documentation to it.

This chapter draws the graph; it does not go inside any of its boxes. Each
crate's own module tree, type by type, is [18](18-crate-core.md) through
[24](24-crate-cli.md) — reference chapters, read when you land in a crate rather
than in sequence from here.
