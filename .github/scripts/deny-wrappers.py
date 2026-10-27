#!/usr/bin/env python3
"""Checks `deny.toml`'s workspace dependency allowlist against the real graph (#329).

`cargo deny check bans` cannot do this. It reads a `[[bans.deny]]` block's `name` as a
package to look for, so a name matching nothing is vacuous rather than wrong: the block
bans a package that does not exist, the crate the typo meant becomes unbanned, and every
edge into it goes unchecked. `cargo deny` says `warning[unused-wrapper]` for each listed
parent and then `bans ok`, exit 0 — non-fatal, so a green gate over the boundary #329
exists to hold. Measured on #415 against `sandbx-turn` and reproduced against
`sandbx-approval`, so it is the tool's behaviour and not a suspicion about it.

Two weaker holes close with it, both non-fatal to `cargo deny` the same way: a crate
something depends on having no block at all ("omission reads as permission", which
`deny.toml`'s own header calls unexpressed), and a `wrappers` array naming a parent with
no edge, which is `warning[unused-wrapper]` and passes while overstating who may depend
on the crate.

Python rather than `/bin/sh` like its three neighbours, for one reason: this has to read
TOML, and `/bin/sh` has no parser for it. An awk approximation was written first and a
review found six ways to break it — a comment inside a multi-line array injecting a
phantom parent, a trailing comment after `name`, a `name` key in any later table being
absorbed, an indented closing bracket swallowing the next table, and key order inside a
block being significant when TOML says it is not. `tomllib` has been in the standard
library since 3.11 and removes that whole class rather than patching it; the runner this
job uses already has Python, since the zizmor step is `pipx`.

`--self-test` runs the checks against scratch workspaces instead of this repo, one
fixture per case, and asserts both the exit status and which error fired.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import tomllib

# Only `sandbx-*` blocks are checked. A third-party ban is a legitimate entry for a
# package deliberately absent from the graph, so asserting it resolves — or that it
# carries a `wrappers` array — would fail exactly the bans that are doing their job.
PREFIX = "sandbx-"


def read_graph(root: pathlib.Path) -> tuple[set[str], dict[str, set[str]]]:
    """The workspace's package names, and `child -> {parents}` over internal edges.

    `--no-deps` needs no registry and no lockfile resolution, so the runner image's
    cargo is enough and no toolchain step precedes this in CI (`guide-ci.md`). Dev and
    build edges count: `wrappers` reads the whole graph, so a dev-dependency is a parent
    too — which `sandbx-core`'s own entry relies on.
    """
    done = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        capture_output=True,
        text=True,
        cwd=root,
        check=True,
    )
    meta = json.loads(done.stdout)
    packages = {p["name"] for p in meta["packages"]}
    if not packages:
        raise RuntimeError("cargo metadata reported no workspace packages")

    edges: dict[str, set[str]] = {}
    for package in meta["packages"]:
        for dep in package.get("dependencies", []):
            if dep["name"] in packages:
                edges.setdefault(dep["name"], set()).add(package["name"])
    return packages, edges


def read_blocks(path: pathlib.Path) -> list[dict]:
    """`[[bans.deny]]` as tomllib gives it, so key order and comments cannot matter."""
    with path.open("rb") as handle:
        return tomllib.load(handle).get("bans", {}).get("deny", [])


def check(root: pathlib.Path, out) -> int:
    """Checks the workspace at `root`. Writes `::error::` lines to `out`.

    Returns the number of `sandbx-*` blocks compared, or -1 on any failure, so the
    summary can report what was actually compared rather than how many blocks exist.
    """
    packages, edges = read_graph(root)
    blocks = read_blocks(root / "deny.toml")
    failed = False

    def error(*lines: str) -> None:
        nonlocal failed
        failed = True
        for line in lines:
            print(f"::error::{line}", file=out)

    named = []
    for index, block in enumerate(blocks):
        name = block.get("name")
        if not isinstance(name, str) or not name:
            error(
                f"deny.toml's [[bans.deny]] block #{index + 1} has no name.",
                "This check addresses blocks by name, so an unnamed block is unchecked.",
            )
            continue
        named.append((name, block.get("wrappers")))

    # 1. Every `sandbx-*` block names a real package. The hole this script exists for.
    for name, _ in named:
        if name.startswith(PREFIX) and name not in packages:
            error(
                f"deny.toml bans '{name}', which is not a workspace package.",
                f"A block naming nothing is vacuous: '{name}' is unbanned and its edges",
                "unchecked, while 'cargo deny check bans' still exits 0.",
            )

    # 2. Every crate something depends on has a block. Omission reads as permission,
    #    which is why the crates nothing depends on are the only legitimate absences.
    declared_names = {name for name, _ in named}
    for crate in sorted(edges):
        if crate not in declared_names:
            parents = " ".join(sorted(edges[crate]))
            error(
                f"'{crate}' is depended on by {parents} but has no deny.toml block.",
                "Nothing then constrains who may depend on it.",
            )

    # 3. Each array is exactly the real parent set, and present. A missing parent is
    #    `error[banned]`, which cargo-deny catches; an extra one is only
    #    `warning[unused-wrapper]`, which it does not, and which overstates who may
    #    depend on the crate. An absent array bans the crate outright — cargo-deny does
    #    reject that, but with a message about the crate rather than about this file.
    compared = 0
    for name, wrappers in named:
        if not name.startswith(PREFIX) or name not in packages:
            continue
        compared += 1
        want = edges.get(name, set())
        if wrappers is None or wrappers == []:
            error(
                f"'{name}' has a deny.toml block with no wrappers, which bans it",
                f"outright rather than permitting nothing. Its real parents are:"
                f" {' '.join(sorted(want)) or '(none, so the block should be absent)'}",
            )
            continue
        got = set(wrappers)
        if got != want:
            error(
                f"'{name}' lists the wrong parents in deny.toml.",
                f"  graph:     {' '.join(sorted(want)) or '(none)'}",
                f"  deny.toml: {' '.join(sorted(got)) or '(none)'}",
            )

    return -1 if failed else compared


FIXTURE_CRATES = ("a", "b", "c")


def write_fixture(root: pathlib.Path, deny: str) -> None:
    """`b` depends on `a`; `c` dev-depends on `a`, so the dev-edge arm is covered."""
    root.mkdir(parents=True)
    (root / "Cargo.toml").write_text(
        '[workspace]\nresolver = "3"\nmembers = ["a", "b", "c"]\n'
    )
    for crate in FIXTURE_CRATES:
        (root / crate / "src").mkdir(parents=True)
        (root / crate / "src" / "lib.rs").write_text("")
        (root / crate / "Cargo.toml").write_text(
            f'[package]\nname = "sandbx-{crate}"\nversion = "0.0.0"\n'
            'edition = "2024"\npublish = false\n'
        )
    with (root / "b" / "Cargo.toml").open("a") as handle:
        handle.write('\n[dependencies]\nsandbx-a = { path = "../a" }\n')
    with (root / "c" / "Cargo.toml").open("a") as handle:
        handle.write('\n[dev-dependencies]\nsandbx-a = { path = "../a" }\n')
    (root / "deny.toml").write_text(deny)


# name, expected ok/fail, a string the output must contain, the deny.toml body.
# A fresh directory per case: leaked state between cases is how a scratch harness
# reports a verdict about the wrong fixture.
CASES: list[tuple[str, bool, str, str]] = [
    # Nothing depends on b or c, so their absence is correct.
    ("clean", True, "", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]
"""),
    # The hole. `cargo deny check bans` exits 0 on this file.
    ("typo", False, "is not a workspace package", """
[[bans.deny]]
name = "sandbx-a-nope"
wrappers = ["sandbx-b", "sandbx-c"]
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]
"""),
    # `sandbx-a` is depended on and has no block, and nothing else here can fail: the
    # third-party ban is skipped by prefix, so check 1 and check 3 both have nothing to
    # say. A fixture that also tripped check 3 would leave check 2's membership test
    # unexercised while still exiting 1 on the other check's message.
    ("missing_block_only", False, "has no deny.toml block", """
[[bans.deny]]
name = "openssl"
"""),
    ("extra_parent", False, "lists the wrong parents", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c", "sandbx-nobody"]
"""),
    # Drops the normal parent, keeping the dev one.
    ("missing_normal_parent", False, "lists the wrong parents", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-c"]
"""),
    # Drops the dev parent, keeping the normal one. Independent of the case above and
    # not a reworded copy: a graph read that skipped dev edges would pass this one while
    # still failing that one, and dev is the arm `sandbx-core`'s entry needs.
    ("missing_dev_parent", False, "lists the wrong parents", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b"]
"""),
    # Carries a correct block alongside the unnamed one, so checks 2 and 3 both pass and
    # only the unnamed-block guard can fail this.
    ("unnamed_block", False, "has no name", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]
[[bans.deny]]
wrappers = ["sandbx-b"]
"""),
    # An array with no parents bans the crate outright. cargo-deny rejects it too, but
    # naming the crate rather than this file, so the summary must not say "match".
    ("empty_wrappers", False, "bans it", """
[[bans.deny]]
name = "sandbx-a"
wrappers = []
"""),
    ("absent_wrappers", False, "no wrappers", """
[[bans.deny]]
name = "sandbx-a"
"""),
    # A third-party ban names a package deliberately absent from the graph, and carries
    # no wrappers. Both are legitimate, so the prefix skip must spare it.
    ("third_party_ban_spared", True, "", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]
[[bans.deny]]
name = "openssl"
"""),
    # The five shapes the awk parser got wrong, kept as cases so a future rewrite back
    # into shell cannot reintroduce them quietly.
    ("multiline_array", True, "", """
[[bans.deny]]
name = "sandbx-a"
# A comment between the name and the array, as every real block has.
wrappers = [
    "sandbx-b",
    "sandbx-c",
]
"""),
    ("comment_inside_array", True, "", """
[[bans.deny]]
name = "sandbx-a"
wrappers = [
    # The "b" edge is direct, and this comment has quotes in it.
    "sandbx-b",
    "sandbx-c",
]
"""),
    ("trailing_comment_after_name", True, "", """
[[bans.deny]]
name = "sandbx-a" # why this crate is constrained
wrappers = ["sandbx-b", "sandbx-c"]
"""),
    ("name_key_in_a_later_table", True, "", """
[[bans.deny]]
name = "sandbx-a"
wrappers = ["sandbx-b", "sandbx-c"]

[[bans.skip]]
name = "sandbx-b"
"""),
    ("indented_closing_bracket", True, "", """
[[bans.deny]]
name = "sandbx-a"
wrappers = [
    "sandbx-b",
    "sandbx-c",
  ]

[sources]
unknown-registry = "deny"
"""),
    ("wrappers_before_name", True, "", """
[[bans.deny]]
wrappers = ["sandbx-b", "sandbx-c"]
name = "sandbx-a"
"""),
]


def self_test() -> int:
    import io

    root = pathlib.Path(tempfile.mkdtemp())
    failures = 0
    try:
        for name, want_ok, want_text, body in CASES:
            directory = root / name
            write_fixture(directory, body.lstrip("\n"))
            buffer = io.StringIO()
            try:
                compared = check(directory, buffer)
            except Exception as exc:  # a crash is a failure, not a verdict
                print(f"::error::self-test '{name}': raised {exc!r}")
                failures += 1
                continue
            output = buffer.getvalue()
            got_ok = compared >= 0

            if got_ok != want_ok:
                print(f"::error::self-test '{name}': "
                      f"{'passed' if got_ok else 'failed'}, want "
                      f"{'pass' if want_ok else 'fail'}")
                print("\n".join("  " + line for line in output.splitlines()))
                failures += 1
                continue
            if want_text and want_text not in output:
                print(f"::error::self-test '{name}': output lacks {want_text!r}")
                print("\n".join("  " + line for line in output.splitlines()))
                failures += 1
                continue
            print(f"  ok  {name}")
    finally:
        shutil.rmtree(root, ignore_errors=True)

    if failures:
        return 1
    print(f"self-test: {len(CASES)} cases pass")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if argv:
        # Not a fall-through to the real check: a mistyped flag would then pass the step
        # while the self-test that guards this checker never ran.
        print(f"::error::unknown argument: {' '.join(argv)}", file=sys.stderr)
        print("::error::usage: deny-wrappers.py [--self-test]", file=sys.stderr)
        return 2

    root = pathlib.Path(__file__).resolve().parents[2]
    compared = check(root, sys.stdout)
    if compared < 0:
        return 1
    print(f"deny.toml: {compared} {PREFIX}* blocks match the graph")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
