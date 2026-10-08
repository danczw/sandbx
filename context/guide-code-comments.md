# Code comments

Keep the knowledge next to the code. Write none where none is needed.

A comment earns its line by carrying a fact the code cannot: a kernel quirk, an
ordering requirement, where an ABI number came from. Everything else is cost,
paid on every read — so the default is nothing, and for most public items the one
mandatory `///` is the whole budget. But cut words, keep facts: a pass that
deletes a quirk, an ordering requirement or a "this does not imply that" has
failed, however much shorter it made the file.

## Budget

| Thing | Budget |
|---|---|
| public item (`///`) | one line; `missing_docs = "warn"` makes it mandatory |
| + a constraint a plausible edit would break | one more sentence, two if the mechanism needs naming |
| public enum variant or public field | one clause, and only because `missing_docs` fires on these too |
| private field, getter, `From`, `Default` | nothing, unless the name is genuinely ambiguous — then one clause |
| test function | one line, and only when it states what the name cannot |
| inline `//` | one or two lines, where the *why* is not derivable from the line |
| module `//!` | five lines: what the module owns, and the one thing a reader must know before editing it |

Over budget is a rewrite, not a deletion: find the sentence doing the work and
keep that one. Where there is no such sentence the comment goes whole — the
common case, not the exception.

## Zero is the budget

Over budget at one line, because the line says what the reader already had:

- **A restated name.** `/// Read a file.` on `BuiltinTool::Read`; `/// Decode the
  argv.` on `HelperArgs::decode`. Names are the documentation.
- **A type the signature names.** `/// Returns a SecretString, or a
  ProviderError on failure.` on `anthropic_api_key`.
- **Narration.** A `//` restating the line under it — `// Open the transcript,
  then check its mode.` above the open and the check — or the branch beside it:
  `// If no port is allowed, deny the axis.` above `if ports.is_empty()`.
- **A banner.** `// ---- helpers ----`, `// === seccomp ===`. Sections are what
  modules are for.
- **An echo of the `//!`** three lines above it.
- **A getter's `///`.** `/// Returns the guard.` on `guard()`.

Then cut:

- **History.** "which produced #49", "was first proposed as", "used to be",
  "added in the commit that split the helper". `git log` and the issue tracker
  hold this and stay accurate. An issue number is allowed when the reader needs
  it to find the work; the issue carries its own status, so the comment does not.
- **Rejected alternatives**, unless the rejection is a trap someone will
  re-propose next month. Then one sentence: what fails, not the argument.
- **Rhetoric and emphasis.** `**The table.**`, "deliberately", "irreducible
  residue", "which is worse than a flat failure would be". A doc comment is a
  reference entry.
- **Prose already in `context/*.md` or `SECURITY.md`** — but leave the one-line
  claim in the code and point: `` // Landlock has no path-scoped unix socket
  right before ABI V9; see `context/guide-sandboxing.md`. ``
- **Planned work.** File an issue (see `CLAUDE.md`).

## Keep

- Why a sequence cannot be reordered.
- Why a syscall, flag, or apparent redundancy is required.
- Where a magic constant or ABI number comes from.
- An asymmetry the type system does not enforce (`ReadExecute` confers read;
  nothing confers execute).
- A workaround and the condition that would let it go.

Compress these to the load-bearing clause; do not delete them to hit a number.
Expect `sandbx-core/src/helper/` to shrink by rewording rather than by deleting,
and prefer one terse sentence to none on any enforcement path.

Out of scope, because they are not commentary: the doc comments clap renders into
`--help` and the ones schemars turns into a tool's JSON-schema `description`.
Leave them, and exclude them when reading a crate's density.

The exemption follows the item, not the file. Schemars' derives are confined to
`sandbx-tools/src/tools/*.rs`, so a path excludes them exactly; clap's are on
eight modules — `sandbx-cli/src/` `lib.rs`, `grants.rs`, `agent.rs`, `auth.rs`,
`sandbox.rs`, `hash.rs`, `agent/prompt.rs`, `agent/tui.rs` — interleaved with code
no exemption reaches, so a path cannot. Only `lib.rs` is excluded below, which
leaves 195 rendered lines of `sandbx-cli` counted as commentary (measured at
`2fc597f`; recount when the flag surface moves). Subtract them from both terms
before reading that crate against the threshold.

## Before and after

```rust
/// Grant unix-domain sockets.
///
/// **All of them**, not a chosen one. The denial is a seccomp rule on
/// `socket(AF_UNIX, …)`, and seccomp compares register values: the path
/// passed to `connect` lives behind a pointer it cannot follow. Landlock
/// gained a path-scoped right for this in ABI V9 (Linux 7.1), and a
/// per-socket grant can be added once that is available in practice.
///
/// So this opens every pathname socket the filesystem policy can reach —
/// an ssh-agent, a docker socket, the session bus. Grant it deliberately,
/// and keep the filesystem policy narrow, because that is what still bounds
/// which sockets exist to be dialled.
```

```rust
/// Grant every unix-domain socket the filesystem policy can reach.
///
/// All or nothing: the denial is a seccomp rule on `socket(AF_UNIX, …)`, and
/// seccomp cannot follow the pointer to `connect`'s path. Per-socket grants
/// need Landlock ABI V9 (Linux 7.1). The filesystem policy is what bounds
/// which sockets exist to be dialled.
```

Four facts in, four facts out, a third of the lines.

## Verifying a pass

Under 15% comment lines (`///`, `//!`, `//`) as a share of **every line of every
`.rs` file in the crate, test code included**, read per crate. A smell test, not a
quota:

```sh
find crates/<crate> -name '*.rs' \
  -not -path '*/sandbx-cli/src/lib.rs' -not -path '*/sandbx-tools/src/tools/*' \
  -not -path '*/sandbx-core/src/helper/*' \
  -exec cat {} + | awk '
  { t++ } /^[[:space:]]*(\/\/\/|\/\/!|\/\/([^\/!]|$))/ { c++ }
  END { printf "%d/%d  %.1f%%\n", c, t, 100 * c / t }'
```

The `-not` clauses are the rendered docs and the by-nature exemption below, out of
scope rather than under budget — and for clap they reach only `lib.rs`, so
`sandbx-cli`'s figure needs the correction above. Every exemption leaves the
numerator *and* the denominator:
`sandbx-core/src/helper/` is a third of that crate's lines at twice the target, so
counting its lines while exempting its comments puts 15% out of reach for the crate
however hard the rest of it is cut.

The denominator sits in the same sentence as the threshold because the two drift
apart otherwise, and a ratio whose denominator is undefined cannot be read against
a threshold at all. "Non-test" would mean three incompatible things: whole files;
whole files minus inline `mod tests` blocks; or that minus `foo/tests.rs`,
`foo/tests/` and `crates/*/tests/` too. The middle one is not available —
`guide-module-layout.md` moves tests out of a file as they grow, so stripping
inline blocks while keeping sibling files measures two crates by two rules
depending on where their tests sit today. Excluding test code makes a crate's ratio
*worse* in every case, a test block being mostly code carrying one `///` per test,
so the denominator was never what held a crate inside the budget.

### The floor

One mandatory `///` per public item, field and variant over the file's
non-comment lines. A crate that is mostly public API has a high floor with *no*
explanation left in it, and a short file a higher one still. Exempt by nature:
`sandbx-core/src/helper/`, enforcement rationale end to end, and any file whose
comments *are* the content, such as a syscall denylist's group labels. Count the
floor for the file in front of you before chasing the target; below it, a pass is
deleting facts.

### Checks

A comment-only change leaves the code byte-identical:

```sh
git diff -U0 -- '*.rs' | grep -E '^[+-]' | grep -vE '^(\+\+\+|---)' \
  | sed 's/^[+-][[:space:]]*//' | grep -vE '^(///|//!|//|$)'
```

That must print nothing. Then `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, and
`RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
--document-private-items` — trimming a referenced item breaks an intra-doc link,
and CI gates those.

For a crate whose docs are rendered somewhere, diff the rendering too: capture
`--help` before and after. A doc comment on a clap type reaches `--help` even
when `about` is set, because clap derives `long_about` from it unless given
`long_about = None`.
