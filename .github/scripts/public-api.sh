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

command -v jq >/dev/null 2>&1 || {
    echo "::error::jq missing: it is how the lib-target list below is read"
    exit 1
}

# A crate with no lib target has no surface to diff, and `cargo public-api` errors
# rather than printing an empty list — arriving *after* the redirect below has truncated
# the baseline to zero bytes, so the failure names this script and not the crate.
# `sandbx-helper` is bin-only by design (#328 decision 5), hence the skip.
#
# Two statements and not one pipeline, for the reason `guide-ci.md` gives for the `msrv`
# job: `/bin/sh` has no `pipefail`, so a failed `cargo metadata` would take jq's exit
# status and leave the lists below empty, reading as every crate having lost its lib.
metadata=$(cargo metadata --format-version 1 --no-deps)
# Two lists, because the loop keys on the *directory* name — that is what gives the
# baseline its path — while `cargo public-api -p` keys on the *package* name. A directory
# whose name is not its package's is a crate this script cannot address, which is a
# different fault from having no lib and is not a legitimate skip.
packages=$(printf '%s' "$metadata" | jq -r '.packages[].name' | sort -u)
# Every library kind, not `lib` alone: a `crate-type` of `rlib` or `cdylib` is still a
# surface, and keying on `lib` would skip it with no baseline and no complaint.
libs=$(printf '%s' "$metadata" | jq -r '
    .packages[]
    | select(any(.targets[].kind[]; . == "lib" or . == "rlib" or . == "dylib"
        or . == "cdylib" or . == "staticlib" or . == "proc-macro"))
    | .name' | sort -u)

for manifest in crates/*/Cargo.toml; do
    crate=$(basename "$(dirname "$manifest")")

    if ! printf '%s\n' "$packages" | grep -qx "$crate"; then
        echo "::error::crates/$crate is not a package name cargo knows."
        echo "::error::This script addresses crates by directory name, so the two must match."
        exit 1
    fi

    if ! printf '%s\n' "$libs" | grep -qx "$crate"; then
        # Skipping a bin-only crate is right. Skipping one that *lost* its lib target is
        # how this gate would go quiet while `git diff --exit-code` stayed clean, the
        # stale baseline still sitting in the tree — so that case is an error.
        #
        # The mirror — a lib target whose baseline was never added — is `ci.yml`'s,
        # not this script's, and not because the index is out of reach here: erroring
        # on it would fire on the run that creates the file, which is why someone
        # adding a crate runs this at all. This guard reads the tree the script just
        # wrote; that one reads what the author staged (#402).
        if [ -f "crates/$crate/public-api.txt" ]; then
            echo "::error::$crate has no lib target, but crates/$crate/public-api.txt exists."
            echo "::error::Either it lost its lib target, or that baseline should be deleted."
            exit 1
        fi
        echo "  $crate (no lib target)"
        continue
    fi

    echo "  $crate"
    # `--simplified` omits blanket impls (`impl<T> Any for T`), which every type
    # has and none of which anyone chose. Auto-trait and derived impls stay in: a
    # type becoming `Send`, or gaining `Clone`, is a real change to the surface.
    RUSTUP_TOOLCHAIN="$nightly" cargo public-api -p "$crate" --simplified \
        > "crates/$crate/public-api.txt"
done
