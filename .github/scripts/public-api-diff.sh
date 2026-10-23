#!/bin/sh
# Prints what a branch adds to or removes from each workspace library's public API,
# against a base revision. Report only: a widening is not an error, but #328 requires
# every one to be justified in the PR, and it has to be visible to be justified.
#
# Usage: public-api-diff.sh <base-rev>
# Needs cargo-public-api and the nightly below; neither is used for anything else.

set -eu

base="${1:?usage: public-api-diff.sh <base-rev>}"
# Pinned with cargo-public-api 0.52.0, which reads this nightly's rustdoc JSON format.
# Bump the two together: a newer format is refused, not misread.
toolchain="${PUBLIC_API_TOOLCHAIN:-nightly-2026-10-20}"

root="$(git rev-parse --show-toplevel)"
cd "$root"
work="$(mktemp -d)"
# The worktree goes before the directory holding it, or git keeps a stale entry.
trap 'git worktree remove --force "$work/base" 2>/dev/null || true; rm -rf "$work"' EXIT
git worktree add --detach --quiet "$work/base" "$base"

# One target dir for both sides, so the dependencies build once.
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}/public-api"
export CARGO_TARGET_DIR

# Libraries only: a binary has no public API. Two statements, not a pipeline, so a
# failed `cargo metadata` stops the script instead of reading as an empty list.
libraries() {
  metadata="$(cd "$1" && cargo metadata --format-version 1 --no-deps)" || return 1
  printf '%s' "$metadata" | jq -r '
    .packages[] | select(any(.targets[]; .kind | index("lib"))) | .name'
}
crates="$(libraries "$root")"
base_crates="$(libraries "$work/base")"
in_base=" $(echo $base_crates) "

# A loop over nothing exits 0, and a green report that compared nothing is worse
# than a red one.
[ -n "$crates" ] || { echo "public-api-diff: no library crate found" >&2; exit 1; }

# `-ss` drops blanket and auto-trait impls, which repeat for every type and would
# bury the one line that matters.
api() {
  (cd "$1" && cargo "+$toolchain" public-api -ss -p "$2")
}

changed=0
for crate in $crates; do
  # A crate new on this branch has no base listing; everything in it is new. Any
  # other failure on the base side stops the script rather than reading as "all new".
  case "$in_base" in
    *" $crate "*) api "$work/base" "$crate" > "$work/$crate.base" ;;
    *) : > "$work/$crate.base" ;;
  esac
  api "$root" "$crate" > "$work/$crate.head"
  if ! cmp -s "$work/$crate.base" "$work/$crate.head"; then
    changed=$((changed + 1))
    echo "### \`$crate\`"
    echo
    echo '```diff'
    diff -U0 "$work/$crate.base" "$work/$crate.head" | grep -E '^[+-][^+-]' || true
    echo '```'
    echo
  fi
done

if [ "$changed" -eq 0 ]; then
  echo "No public API changed in: $(echo $crates)"
fi
