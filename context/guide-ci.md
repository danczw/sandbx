# The gates

Two halves of one set of checks: `.githooks/` runs before a commit exists,
`.github/workflows/` runs after a push. They are deliberately not independent —
`pre-commit` and `ci.yml`'s first two steps are byte-identical, so a red CI run
is a hook someone skipped rather than a check only CI knows about.

## The local half

Wired by one line, which is why there is no hook-manager dependency:

```sh
git config core.hooksPath .githooks
```

`pre-commit` is `cargo fmt --all -- --check` then
`cargo clippy --workspace --all-targets -- -D warnings`. Not the test suite: a
hook that takes minutes is a hook people pass `--no-verify` to.

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
| `notes` | every release-notes file is within budget, and the manifest's version has one |
| `audit` | cargo-deny, the release-channel table, and zizmor over the workflows |

`permissions: contents: read` replaces the repo default and
`persist-credentials: false` drops the clone's token, so a compromised action
cannot push or publish. The scheduled run is weekly on Monday because an advisory
appears without a code change.

**Branch protection pins job names.** `sandbox (${{ matrix.arch }})` is spelled
out in a `name:` for that reason: renaming a job blocks every merge on a status
that will never report.

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

### `RUSTDOCFLAGS`, not a `[lints.rustdoc]` table

Not a cargo limitation — `[lints.rustdoc]` does work, verified on cargo 1.95:
`private_intra_doc_links = "deny"` there fails the build exactly as
`RUSTDOCFLAGS: -D warnings` does. The reason is coverage. A lints table
enumerates lints by name and has to be kept current; `-D warnings` denies the
whole class, including lints a future toolchain adds.

The Doc step also passes `--all-features`, unlike Clippy: a feature-gated item's
intra-doc links are checked there or nowhere.

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
