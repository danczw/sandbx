#!/bin/sh
# Regenerates the committed public-API baseline for every workspace crate.
#
# The baseline is what makes a widening reviewable. `pub(crate)` is invisible to
# cargo-public-api, so turning one `pub` lands here as an added line — in the PR's
# own diff, which a reviewer reads, rather than in a CI log nobody opens.
# `ci.yml`'s `api-diff` job runs this and fails when the result differs from what
# is committed, so a widening cannot merge without the line that records it.
#
# Run it after any change to a crate's public surface and commit the result.

set -eu

# cargo-public-api builds rustdoc JSON, which stable rustdoc refuses: the
# `-Z` it needs is nightly-only. Pinned rather than plain `nightly` so the
# baseline is reproducible — an unpinned nightly emits a new JSON format version
# the day it lands and rewrites every file here for no API change. 0.52.x accepts
# nightly-2025-11-22 or later.
nightly="${NIGHTLY:-nightly-2026-09-11}"
version=0.52.0

cd "$(dirname "$0")/../.."

command -v cargo-public-api >/dev/null 2>&1 || {
    echo "::error::cargo-public-api missing: cargo install cargo-public-api --locked --version $version"
    exit 1
}

rustup run "$nightly" rustc --version >/dev/null 2>&1 || {
    echo "::error::$nightly missing: rustup toolchain install $nightly"
    exit 1
}

for manifest in crates/*/Cargo.toml; do
    crate=$(basename "$(dirname "$manifest")")
    echo "  $crate"
    # `--simplified` omits blanket impls (`impl<T> Any for T`), which every type
    # has and none of which anyone chose. Auto-trait and derived impls stay in: a
    # type becoming `Send`, or gaining `Clone`, is a real change to the surface.
    RUSTUP_TOOLCHAIN="$nightly" cargo public-api -p "$crate" --simplified \
        > "crates/$crate/public-api.txt"
done
