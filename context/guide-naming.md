# Naming

A name is read far more often than it is written, and it is read inside a line
that already carries a module path, a receiver and arguments. Length is the cost
it imposes on every one of those lines.

## Budget

| Thing | Budget |
|---|---|
| `fn`, `struct`, `enum`, `trait`, type alias, `const`, `static`, `mod` | 32 characters |
| enum variant, struct field | 32 characters |
| test function | 50 characters |

The ceilings are headroom, not a target. The tree sits near 10 characters for
items and around 40 for tests; a name that needs the whole budget is usually a
name describing two things.

Tests get a longer budget because the name is what a failure prints: `cargo test`
shows it without the `///`, so what the test asserts has to be legible from the
failure line alone. That is a reason for a sentence, not for an
essay: `cargo test` prints the name, and past about fifty characters it stops
being scannable in a list of four hundred.

## Shortening

The context a name sits in is not part of the name. In order of how much they
usually buy:

- **The file, module and crate.** In `wire/tests/usage.rs`,
  `message_start_and_message_delta_combine_into_one_usage_event` is
  `start_and_delta_combine_into_one_usage_event`. In
  `wire/tests/tool_use.rs`, a `tool_call` is a `call`.
- **Leading articles**, when the subject is unambiguous without them:
  `the_cut_lands_on_…` → `cut_lands_on_…`.
- **`rather_than` / `and_not` → `not`.** `a_future_version_is_refused_not_guessed`.
- **`does_not` → `never`**, for a property that holds always rather than in the
  one case under test: `compaction_never_shortens_the_transcript`.
- **`is_reported_as X` → `reports_X`.**

What not to trade away:

- **The asymmetry under test.** `open_read_refuses_a_path_outside_every_root`
  keeps `every`; dropping it describes a weaker check than the one that runs.
- **The distinguishing clause**, when a sibling test is one word away.
  `grep_does_not_follow_a_symlink_out_of_the_root` and
  `grep_does_not_follow_a_file_symlink_out_of_root` cover a directory symlink and
  a file symlink; the file/directory distinction *is* the test.
- **Abbreviation.** `msg`, `def`, `cfg` in a name that is only over budget by
  three characters. Cut a word instead.

## Measuring

```sh
grep -rhoE '^\s*(pub(\([^)]*\))?\s+)?(async\s+)?fn\s+\w+' --include='*.rs' crates \
  | sed 's/.*fn //' | awk '{ if (length($0) > 50) print length($0), $0 }' | sort -rn
```

Swap `fn` for `struct`, `enum` or `const` and the threshold for 32 to read the
item budget. A hit is a rewrite, not an abbreviation.

Renaming a test can break a prose reference: `context/*.md` cites test names as
the evidence for a claim, `decision-default-policy.md`'s mutation index being a
claim-to-test-name map outright. Grep `context/` for the old name before
considering the rename done.
