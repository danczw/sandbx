#!/bin/sh
# Fails when a workspace crate that another one depends on has no `[[bans.deny]]`
# entry in deny.toml. cargo-deny enforces the entries it has and is silent about a
# crate it has none for, so without this a new crate is open to every dependent.

set -eu

cd "$(git rev-parse --show-toplevel)"

# Two statements, not a pipeline, so a failed `cargo metadata` stops the script
# instead of reading as "nothing depends on anything".
metadata="$(cargo metadata --format-version 1 --no-deps)"
depended="$(printf '%s' "$metadata" | jq -r '
  [.packages[].dependencies[] | select(.path != null) | .name] | unique | .[]')"

# A loop over nothing exits 0, and a green gate that checked nothing is worse than a
# red one.
[ -n "$depended" ] || { echo "check-crate-bans: no workspace dependency found" >&2; exit 1; }

checked=0
missing=0
for crate in $depended; do
  checked=$((checked + 1))
  if ! grep -qx "crate = \"$crate\"" deny.toml; then
    echo "::error::$crate is a dependency of another workspace crate and has no [[bans.deny]] entry in deny.toml"
    missing=$((missing + 1))
  fi
done

echo "checked $checked"
[ "$missing" -eq 0 ]
