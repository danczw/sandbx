# The gates

Two halves of one set of checks: `.githooks/` runs before a commit exists,
`.github/workflows/` runs after a push. They are deliberately not independent —
`pre-commit` and `ci.yml`'s `Format`, `Clippy` and `Doc` steps run byte-identical
commands, so a red CI run is a hook someone skipped rather than a check only CI
knows about. Identical in the command, not in the envelope: CI spells the doc
step's variable in an `env:` block and the hook inlines it.

## The local half

Wired by one line, which is why there is no hook-manager dependency:

```sh
git config core.hooksPath .githooks
```

One more line is worth setting in the same breath, so `git blame` skips the
mechanical sweeps listed in `.git-blame-ignore-revs` and names the commit that
last changed the code. GitHub applies that file on its own; locally it is opt-in,
once per clone:

```sh
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

`pre-commit` is `cargo +nightly-2026-09-11 fmt --all -- --check`, then
`cargo clippy --workspace --all-targets -- -D warnings`, then the `Doc` step
under `RUSTDOCFLAGS: -D warnings`. Not the test suite: a hook that takes minutes
is a hook people pass `--no-verify` to, and the three together are seconds on a
warm target dir. The doc build earns its place by being the only one of them that
reads a doc comment at all — a broken intra-doc link passes fmt and clippy, so
without it the first thing to notice is CI after the push.

### fmt is the one gate whose exit code is not enough

Three of `rustfmt.toml`'s four options are nightly-only (#334), and rustfmt skips
an option it cannot set with a `Warning:` on stderr and exit 0 — on stable, or on
a name with a typo in it. So both halves capture the output and fail on
`Warning:`, which is the rule below about a glob that matches nothing, applied to
a gate rather than to a loop. The toolchain is named on the command line in both,
so a `+toolchain` that goes missing fails rather than falling through: `rustfmt`
is deliberately not a component of `ci.yml`'s stable step.

In `ci.yml` the nightly installs *before* stable, and the two cannot be swapped:
`dtolnay/rust-toolchain` makes what it installs the default, so with nightly last
every plain `cargo` in the job runs on it and `cargo clippy` fails outright
(#441). Stable installs last and is therefore the default, and only the one
`+nightly` fmt command leaves it.

`commit-msg` checks the **subject only**; the body is free-form. Eight types
(`feat fix docs refactor test chore build ci`), the scope and the breaking-change
`!` both optional, and a 72-character ceiling. `Merge`, `Revert`, `fixup!`,
`squash!` and `amend!` subjects are exempt, because the rebase they are made for
rewrites them.

Two things fall out of that pattern that are easy to trip over:

- **A scope is optional, so a change spanning crates takes none.** `docs: …` is
  valid. Inventing a scope to look consistent is worse than omitting it.
- **The scope charset is `[a-z0-9._/-]+`, so a comma is not a scope.**
  `docs(providers,session):` is refused; drop to no scope.

## The remote half

| job | what it proves |
|---|---|
| `test` | fmt, clippy, the default-feature suite, and rustdoc |
| `sandbox (x86_64)`, `sandbox (aarch64)` | the enforcement suite on a real kernel, gnu then the published musl triple |
| `msrv` | the suite still builds at the floor the manifest states |
| `notes` | the manifest's version has a notes file, and every `v*.md` is within budget |
| `api-diff` | every crate with a public surface has a committed baseline, and every widening of it has a line there |
| `audit` | cargo-deny — advisories, licences, and which workspace crate may depend on which — the allowlist read back against the real graph, both release-channel tables, and zizmor over the workflows |

`permissions: contents: read` replaces the repo default and
`persist-credentials: false` drops the clone's token, so a compromised action
cannot push or publish. The scheduled run is weekly on Monday because an advisory
appears without a code change.

**Branch protection pins job names.** `sandbox (${{ matrix.arch }})` is spelled
out in a `name:` for that reason: renaming a job blocks every merge on a status
that will never report.

### A test-only feature gates a target, not a self dev-dependency

`[dev-dependencies]` naming the crate itself with `features = ["x"]` is the
obvious way to cover a gated item with a plain `cargo test`, and the wrong one.
Resolver 3 unifies features per package, and that edge is active under
`--all-targets`, so `x` is on in the one rlib every consumer links: production
code naming the gated item passes clippy and the suite, and fails first in the
release build. Gate the target instead — `required-features`, or a whole-file
`#![cfg(feature = ..)]` as `sandbox-integration`'s tests are — and name the
feature in the CI command that runs it.

### Ordering: `cargo metadata` before any toolchain step

`msrv` cannot install its toolchain until it knows which one, and `notes` cannot
find its file until it knows the version. Both therefore read the manifest with
whatever cargo the runner image ships, before `dtolnay/rust-toolchain` runs at
all. Two traps in that read:

- `rust_version` from `cargo metadata` is the **inherited** value. A
  `[workspace.package]` entry no member inherits is inert and reads as `null`,
  so the job errors rather than silently testing on stable.
- The default shell is `bash -e` without `pipefail`, so piping cargo into `jq`
  takes `jq`'s exit status. Hence two statements, not one pipeline.

`--locked` is the whole point of `msrv`: resolver 3 *prefers* MSRV-compatible
versions, so an unlocked run resolves around a broken lockfile and passes.

### A glob that matches nothing must fail

`notes` counts the files it checked and errors on zero. A loop over
`docs/release-notes/v*.md` that found no file would otherwise exit 0, and a
green gate that checked nothing is worse than a red one. Any check that iterates
needs the same guard.

### A vacuous `[[bans.deny]]` block is the same shape of hole

`cargo deny` reads a block's `name` as a package to look for, so a name matching
nothing is vacuous rather than wrong: the block bans a package that does not
exist, the crate the typo meant becomes unbanned, and every edge into it goes
unchecked. It is not silent — each listed parent gets a `warning[unused-wrapper]`
— but it is **non-fatal**, so the run ends `bans ok`, exit 0. On this repo that
is one warning beside five ambient `warning[duplicate]` lines, which is the
practical point: the signal exists and is indistinguishable from the noise a
passing run already prints. Measured on #415 and reproduced against a second
block, which is why it is not a suspicion about the tool.

`deny-wrappers.py` reads the allowlist back against `cargo metadata` and fails on
three things cargo-deny only warns about or ignores: a `sandbx-*` name that
resolves to no package, a crate something depends on having no block at all, and
an array that is not exactly the real parent set — an extra parent being
`warning[unused-wrapper]` again, which passes while overstating who may depend on
the crate. It runs before `cargo-deny-action` for the reason the release-channel
check does, and its `--self-test` runs first, against scratch workspaces, so a
checker that has stopped checking fails rather than passing the real file by
default. Every check a `deny.toml` can reach is mutation-tested: disable it and a
named case fails, and the harness asserts the set of survivors, so a check that
becomes untestable fails the run rather than passing quietly. Exactly two
survive, both unreachable from any config and both saying so in their comments —
the zero-comparison guard and the empty-package-set guard. They assert against a
future edit to the keying or the graph read, not against a file.

**It also refuses three keys that make cargo-deny's own enforcement vacuous**,
each the same hole as a typo'd name wearing different clothes, and all three
measured on 0.20.2 rather than assumed:

| key | what cargo-deny does |
|---|---|
| `version = "=9.9.9"` | matches no crate; `bans ok`, exit 0 |
| `crate = "sandbx-a@9.9.9"` | the same, through the PackageSpec |
| `[graph] exclude-dev`, `[graph] exclude` | drops those edges from the graph it walks, turning real parents into `warning[unused-wrapper]` |

A version pin is refused even when it currently resolves, because every
workspace crate shares one inherited version and a pin that matches today goes
vacuous at the next release with nothing to say so. `crate =` on its own is
cargo-deny's accepted synonym for `name =` and is simply read — refusing a legal
spelling would fail CI over a correct file, which is what pressures people into
editing the file instead of the gate.

Refusing the `[graph]` keys is what **keeps cargo-deny load-bearing rather than
replaced**. Without them its `wrappers` enforcement can be emptied while it
exits 0, leaving this script as the only real check on workspace edges; with
them the two are defence in depth. That matters most for `sandbx-core`, whose
entry rests entirely on a dev edge. cargo-deny remains the sole authority for
advisories, licences and third-party bans.

Python, where its three neighbours are `/bin/sh`, because it has to read TOML and
`/bin/sh` has no parser for it. The first version approximated one in awk and a
review found five ways to break it — a comment inside a multi-line array
injecting a phantom parent, a trailing comment after `name`, a `name` key in any
later table being absorbed, an indented closing bracket swallowing the next
table, and key order inside a block mattering when TOML says it does not.
`tomllib` is standard library from 3.11 and removes the class rather than
patching it. All five are self-test cases, beside a sixth for the plain
multi-line array that awk did handle, so a rewrite back into shell cannot
reintroduce any of them quietly.

The general shape, and the third instance of it in this file: **a gate that
cannot distinguish "nothing to check" from "checked and clean" is not a gate.**
`notes` counts its files, `api-diff` guards a crate that lost its lib target, and
this reads its own input back against the graph it describes.

### The baseline is the diff, not the log

`pub(crate)` is invisible to `cargo-public-api`, so widening one to `pub` reads as
an *added* item. That is the whole mechanism. The added line lands in
`crates/<crate>/public-api.txt`, inside the PR's own diff where a reviewer is
already looking, rather than in a job log somebody has to open on purpose. So the
job does not judge the widening, even though it is a required check: it goes red only
when the baseline no longer matches the surface. What it forbids is a widening with
no line recording it, and the fix is always to commit that line.

It forbids that only for a widening the surface can *see*. An item whose parent
module is private is absent from the baseline at any visibility, so turning it
`pub` moves no line and the gate stays green — which is why `unreachable_pub` is
a workspace lint (`Cargo.toml`). The two split the class between them: the
baseline records a widening that reaches the surface, the lint rejects one that
does not reach it, and neither sees the other's half. Read the paragraph above
alone and you will credit this job with a guarantee it only half holds.

Being required, its name is pinned like the others above — renaming the job silently
drops the gate until the ruleset is updated to match.

Three things to get right:

- **Regenerate with the pinned nightly, never plain `nightly`.** rustdoc JSON is
  nightly-only and its format version changes without notice, so a different
  nightly rewrites every baseline for no change in API.
  `.github/scripts/public-api.sh` sets `RUSTUP_TOOLCHAIN` itself for that reason.
  The date is written four times — in the script's default, in `ci.yml`'s toolchain
  step for this job, and in the fmt command in `ci.yml` and `.githooks/pre-commit`
  — because `dtolnay/rust-toolchain` cannot read it out of the script. A mismatch
  is loud rather than silent: the script checks the toolchain is installed and says
  which one is missing, and `cargo +nightly-…` fails outright when it is not.
- **The nightly is for rustdoc JSON and rustfmt, and nothing else.** Every build
  and test stays on stable, as does every other job, and the manifest's
  `rust-version` is untouched. rustfmt shares this pin rather than taking its own
  so that one date moves at a time (#334).
- **A crate with no lib target is skipped, and a lib target and a committed
  baseline are guarded as a pair.** There is no importable surface to diff, and
  `cargo public-api` errors rather than printing an empty list — which, with the
  output redirected into the baseline, would truncate it to zero bytes before the
  script aborted. The lib-target list comes from `cargo metadata`, read into a
  variable first because `/bin/sh` has no `pipefail`, and a crate with no lib
  target that still has a committed baseline is an **error**: otherwise one that
  lost its lib target would lose its gate while `git diff --exit-code` stayed
  clean. The other two directions are errors in `ci.yml` rather than in the
  script, not because the index is out of the script's reach but because the
  script exists partly to create that file on a first run, so erroring there
  would fire on the workflow it serves. A lib target whose baseline was never
  added is invisible to `git diff` and so was ungated entirely; a baseline whose
  crate is gone is regenerated by nothing and diffs against nothing, the script
  keying on manifests rather than on baselines (#402).
  `sandbx-helper` is the only crate skipped today (#347). The script therefore
  needs `jq`, which it checks for alongside the toolchain.

### `RUSTDOCFLAGS`, not a `[lints.rustdoc]` table

Not a cargo limitation — `[lints.rustdoc]` does work, verified on cargo 1.95:
`private_intra_doc_links = "deny"` there fails the build exactly as
`RUSTDOCFLAGS: -D warnings` does. The reason is coverage. A lints table
enumerates lints by name and has to be kept current; `-D warnings` denies the
whole class, including lints a future toolchain adds.

The Doc step also passes `--all-features`, unlike Clippy: a binary behind
`required-features` — the enforcement suite's probes — is documented there or
nowhere.

## Publication: the two questions a tag answers

`release.yml` asks `release-channel.sh` two things, and neither answer may be a
default — a mis-marked release cannot be un-pushed, which is why both are decided
in a script with a table in `--self-test` rather than inline in the workflow.

**Which channel.** Only an exact 1.0-or-later version is a `release`; everything
else is a `prerelease`. This implements the support policy in `SECURITY.md`.

**Whether it takes GitHub's "latest" link.** Highest semver wins: a tag takes the
link only if no published non-draft release carries a higher version. A
pre-release never takes it. The rule exists because the REST API defaults
`make_latest` to `true`, so omitting the flag lets *publication* order decide —
post-1.0, a `v1.5.1` backport tagged after `v2.0.0` would demote `v2.0.0`.
`gh release create` is therefore always passed an explicit `--latest=true|false`.

The rejected alternative is worth naming because it reads as the simpler one:
"only the newest `MAJOR.MINOR` line may be latest" still needs the set of
published releases to know which line is newest, so it buys no simplicity, and it
re-promotes an older patch of the current line — `v1.5.1` published while
`v1.5.3` exists would take the link back.

**A published tag the comparison cannot parse is an error, not a skip.** Every
unrecognised shape classifies `prerelease`, so skipping one would read as
"nothing higher is published" and hand the link away — the exact demotion this
rule exists to stop. A tag therefore has to be `M.m.p` with optional pre-release
and build parts to be skipped as a non-competitor; anything else fails the step,
which is recoverable, where a wrong `latest` is not. Version fields are capped at
nine digits for the same reason: a wider one reaches `[ -gt ]`, which reports a
parse error rather than an order, and `if` reads that as "not higher".

### Why the query is in the workflow and the comparison is not

`guide-repo-map.md` requires everything in `.github/scripts/` to run without a
workflow, and this decision needs the published set, which only an API call
supplies. So `release-channel.sh --latest <tag>` reads candidate tags on
**stdin**: the script makes no network call, stays runnable by hand, and the
self-test feeds it synthetic sets. The `gh api` call lives in the `notes` job,
which is the only one with a checkout — `publish` deliberately has none, so that
`contents: write` is confined to a job holding no source.

Two traps in that step, both of which have bitten:

- **The handoff is validated, not defaulted.** An empty `$CHANNEL` or `$LATEST`
  means the job-output wiring broke; the step errors. Defaulting either would be
  right for every pre-1.0 tag and would hide the break until 1.0.
- **`gh api` gets its own statement, not a pipe into the script.** The default
  shell has no `pipefail`, so a pipeline reports the script's status and a failed
  API call reads as an empty release set — which answers `true`. The empty set is
  tested for separately, because a call that succeeds and matches nothing lands
  in the same place by a route no exit status reports.

The version compare is hand-rolled and field-wise rather than `sort -V`, which is
GNU-only; the scripts are `#!/bin/sh` and the self-test runs under `dash`.

### One release run at a time

Reading the published set makes the decision a snapshot, and two `v*` tags pushed
close together would each take theirs before either published — so the later
publisher wins and can demote the higher version. `release.yml` therefore groups
on `github.workflow` **alone**. `ci.yml` groups on workflow-plus-ref and cancels,
which is the opposite of what a release wants on both keys: the collision here is
between two different tags, so a per-ref group would not see it, and a half-done
publish must not be cancelled.

The cost is that `cancel-in-progress: false` queues at most one run per group — a
third tag pushed while one is publishing and one is queued cancels the queued run,
which then has to be re-run by hand. That is the trade taken deliberately: a
cancelled run is visible and repeatable, and a tag that took the "latest" link
wrongly cannot be un-pushed.

## Pinned actions, and what updates them

Every action is pinned to a SHA with a `# vX.Y.Z` comment beside it. Dependabot
rewrites **both**, so nothing may follow that comment on the line — a version it
cannot match is left stale.

`dtolnay/rust-toolchain` is pinned from `v1`, not `stable`: the `stable` branch
is regenerated as master plus one commit, so a SHA taken from it is reachable
from no ref and never bumps again.

zizmor runs through `pipx run zizmor==1.30.1` rather than its own action, because
an action would add a third-party action to the surface that step audits. The
version is pinned by hand since dependabot does not track it.

### The dependabot policy

Weekly on Monday — one batch at the start of the week rather than a trickle
through it — with a seven-day `cooldown`, on the basis that a compromised
release is usually yanked within days. `default-days` is the only cooldown key
the `github-actions` ecosystem reads; the `semver-*-days` ones are inert.

Minor and patch updates are **grouped into one PR**; majors are deliberately
left ungrouped, so each arrives alone and gets read. `directory: /` is required
for this ecosystem, which finds `.github/workflows` from there. Dependabot
commits through the API, so `.githooks/commit-msg` never sees them — the
`ci` prefix is what keeps a squash merge's subject conventional.
