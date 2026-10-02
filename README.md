# sandbx

[![CI](https://github.com/danczw/sandbx/actions/workflows/ci.yml/badge.svg)](https://github.com/danczw/sandbx/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

A security-first AI coding agent harness, written in Rust.

Most agent harnesses delegate isolation to an external container. sandbx treats
sandboxed tool execution as part of the harness itself: every command an agent
runs goes through a Landlock + seccomp boundary, and the sandbox fails closed
rather than degrading to unrestricted execution.

> **Pre-alpha.** The turn loop exists, but nothing is wired to a UI yet: there is
> no way to talk to an agent from the command line, and no approval prompt before a
> tool runs. What works today is the sandbox beneath it, the tools that run inside
> it, and a library-level loop over them. Enforced today on Linux 6.10+ with
> unprivileged user namespaces: filesystem (Landlock), network (empty netns),
> dangerous syscalls (seccomp), process lifetime (PID namespace). Kernels that
> cannot enforce are refused, never run unrestricted. Do not assume a version
> sandboxes anything until it says so.

## Try the sandbox

The agent is not built, but the boundary it will run behind is, and `sandbx`
exposes it directly so you can check the enforcement by hand:

```sh
sandbx sandbox-run --allow-read /srv -- cat /srv/notes.txt   # works
sandbx sandbox-run --allow-read /srv -- cat /etc/shadow      # permission denied
sandbx sandbox-run -- curl https://example.com               # no network at all
```

Everything is denied unless a flag grants it. The one exception is read access
to the system binaries and libraries a command needs in order to start — with
nothing readable, not even `/bin/true` reaches `main`.

Each run also records the policy it was about to run under, on stderr:

```console
$ sandbx sandbox-run --allow-read /srv -- /bin/true
2026-10-02T09:11:52.287465Z  INFO sandbx::audit: decision="spawned" program="/bin/true" readable=1 writable=0 executable=4 network=false unix_sockets=false
```

Read `spawned` as the intent to spawn, not its success: the record is written
before the helper execs, so it appears for a command that then fails to start, and
a run killed by `--timeout` gets no closing record. What the record is for is the
policy — what the command was granted — and that is settled before it runs.

It is metadata only, never a command's output, and it never touches stdout: the
command's own stdout is forwarded untouched, so piping it is unaffected. To keep
only the record, `2>&1 >/dev/null | grep sandbx::audit`. Note that `2>/dev/null`
discards the sandboxed command's own stderr along with the record — including the
permission denials the examples above are there to show.

| flag | grants |
|------|--------|
| `--allow-read PATH`  | read access to `PATH`. Repeatable |
| `--allow-write PATH` | write access to `PATH`. Repeatable |
| `--allow-exec PATH`  | run programs under `PATH` (grants read too). Repeatable |
| `--allow-network`    | a network namespace with an interface. IP egress only |
| `--allow-unix-sockets` | unix-domain sockets. *All* of them, not a chosen path |
| `--timeout SECONDS`  | kill the command, and every process it spawned, if it runs longer. Unset means no limit |

## Install

Prebuilt Linux binaries are attached to each
[release](https://github.com/danczw/sandbx/releases); each archive ships with a
`.sha256` beside it. They are statically linked (musl), so there is no minimum
glibc and no runtime dependency beyond a Linux 6.10+ kernel with unprivileged
user namespaces enabled. Or build from source:

```sh
cargo install --git https://github.com/danczw/sandbx sandbx-cli
```

## Development

```sh
cargo test --workspace                                 # default suite
cargo test --workspace --features sandbox-integration  # needs Linux kernel ≥ 6.10
cargo test -p sandbx-providers \
  --features live-anthropic-tests                      # needs a paid ANTHROPIC_API_KEY
cargo clippy --workspace --all-targets -- -D warnings
git config core.hooksPath .githooks                    # fmt + clippy on commit
```

`unsafe` is forbidden in every crate, including `sandbx-core`, and spawning a
subprocess outside `sandbx-core` is a clippy error — the sandbox boundary is
enforced by the build, not by convention alone. Even the PID namespace needs no
exemption: `unshare` leaves the caller behind and places its *children* in the
new namespace, so re-execing the helper once more is enough and there is no
`fork` to make safe.

## License

MIT
