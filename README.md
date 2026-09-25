# echo

[![CI](https://github.com/danczw/echo/actions/workflows/ci.yml/badge.svg)](https://github.com/danczw/echo/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

A security-first AI coding agent harness, written in Rust.

Most agent harnesses delegate isolation to an external container. echo treats
sandboxed tool execution as part of the harness itself: every command an agent
runs goes through a Landlock + seccomp boundary, and the sandbox fails closed
rather than degrading to unrestricted execution.

> **Pre-alpha.** There is no agent yet — only the sandbox beneath it and the
> tools that will run inside it. Enforced today on Linux 6.10+: filesystem
> (Landlock), network (empty netns), dangerous syscalls (seccomp). Kernels that
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

| flag | grants |
|------|--------|
| `--allow-read PATH`  | read access to `PATH`. Repeatable |
| `--allow-write PATH` | write access to `PATH`. Repeatable |
| `--allow-network`    | a network namespace with an interface |

## Install

Prebuilt Linux binaries are attached to each
[release](https://github.com/danczw/echo/releases); each archive ships with a
`.sha256` beside it. They are statically linked (musl), so there is no minimum
glibc and no runtime dependency beyond a Linux 6.10+ kernel. Or build from
source:

```sh
cargo install --git https://github.com/danczw/echo echo-cli
```

## Development

```sh
cargo test --workspace                                 # default suite
cargo test --workspace --features sandbox-integration  # needs Linux kernel ≥ 6.10
cargo clippy --workspace --all-targets -- -D warnings
git config core.hooksPath .githooks                    # fmt + clippy on commit
```

`unsafe` is forbidden in every crate, including `echo-sandbox`, and spawning a
subprocess outside `echo-sandbox` is a clippy error — the sandbox boundary is
enforced by the build, not by convention alone.

## License

MIT
