# sandbx

[![CI](https://github.com/danczw/sandbx/actions/workflows/ci.yml/badge.svg)](https://github.com/danczw/sandbx/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

A security-first AI coding agent harness, written in Rust.

Most agent harnesses delegate isolation to an external container. sandbx treats
sandboxed tool execution as part of the harness itself: every command an agent
runs goes through a Landlock + seccomp boundary, and the sandbox fails closed
rather than degrading to unrestricted execution.

> **Pre-alpha.** You can ask an agent one question from the command line and
> watch it use tools to answer. What is missing above that is the interactive
> surface — no session, no history, no interrupt — and, more importantly, any
> approval prompt: every tool call the model asks for runs, so the grants you pass
> are the whole of what a prompt injection can reach. Enforced today on Linux 6.10+ with
> unprivileged user namespaces: filesystem (Landlock), network (empty netns),
> dangerous syscalls (seccomp), process lifetime (PID namespace). Kernels that
> cannot enforce are refused, never run unrestricted. Do not assume a version
> sandboxes anything until it says so.

## Try the sandbox

`sandbx` exposes the boundary directly, so you can check the enforcement by hand
before trusting an agent to it:

```sh
sandbx sandbox-run --allow-read /srv -- cat /srv/notes.txt   # works
sandbx sandbox-run --allow-read /srv -- cat /etc/shadow      # permission denied
sandbx sandbox-run -- curl https://example.com               # no network at all
```

Everything is denied unless a flag grants it. The one exception is what a command
needs in order to start: read access to the system binaries and libraries — with
nothing readable, not even `/bin/true` reaches `main` — and the handful of
environment variables below.

The environment is cleared too. A sandboxed command does not inherit the one
`sandbx` was launched with, so a secret in your shell does not reach it; name a
variable with `--allow-env` to pass it through. Granted anyway, for the same
reason as the system binaries: `PATH`, `HOME`, `TERM`, `LANG`, `LC_ALL`,
`LC_CTYPE` and `TZ`. `PATH` matters most: without it a bare program name is looked
up only in the C library's fallback (`/bin:/usr/bin`), so `cat` would still start
but anything installed elsewhere would not be found.

Each run also records the policy it was about to run under, on stderr:

```console
$ sandbx sandbox-run --allow-read /srv -- /bin/true
2026-10-02T09:11:52.287465Z  INFO sandbx::audit: decision="spawned" program="/bin/true" readable=1 writable=0 executable=4 network=false unix_sockets=false env=7
```

Read `spawned` as the intent to spawn, not its success: the record is written
before the helper execs, so it appears for a command that then fails to start, and
a run killed by `--timeout` gets no closing record. What the record is for is the
policy — what the command was granted — and that is settled before it runs.

`env=7` is a count, not a list: a variable's *name* is not a secret, but its value
routinely is, and a record that spelled out the names would invite the next change
to print values beside them. It counts the allowlist, not what crossed — a name
nothing in `sandbx`'s own environment matches passes nothing, so on a host with no
`TZ` set the command above sees fewer than seven. Like `readable`, it records what
was granted.

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
| `--allow-env NAME`   | let the command inherit `NAME`, with the value `sandbx` itself holds. There is no way to set one from here. Repeatable |
| `--timeout SECONDS`  | kill the command, and every process it spawned, if it runs longer. Unset means no limit |

## Try the agent

`agent-run` asks one question and lets the model use tools to answer it. The same
grants apply, and they are the only thing bounding what the agent reaches:

```sh
export ANTHROPIC_API_KEY=sk-ant-…

sandbx agent-run \
  --allow-read  ./src \
  --allow-write ./src \
  -- "find the TODO comments under src and list them"
```

The answer streams on stdout; which tool is running goes to stderr, so piping
stdout gives you the answer alone. All seven tools are offered — `read`, `write`,
`edit`, `ls`, `grep`, `find` and `bash` — and each runs through the same boundary,
so a path you did not grant comes back to the model as a refusal for it to work
around rather than a crash.

| flag | |
|------|--|
| `--model NAME`    | which model to ask. Default `claude-sonnet-5` |
| `--max-tokens N`  | cap what the model may produce in one turn. Default 4096 |
| `--system TEXT`   | a system prompt. Unset sends none |

It is single-shot on purpose: one question, one answer, then the process ends.
There is no session to resume and no way to interrupt a turn mid-flight.

Exit `0` means the model finished its answer. Exit `2` means `--max-tokens` cut
it off mid-sentence — what reached stdout is real but incomplete, which is worth
distinguishing if a script is reading it. Anything else failed before or during
the turn, with the reason on stderr.

> **Nothing asks you before a tool call runs.** The model chooses the calls and
> they execute, which means a prompt injection in a file the agent reads can reach
> anything the grants allow. The sandbox is the control, not the asking — so grant
> the narrowest tree that lets the task finish, and read
> [SECURITY.md](SECURITY.md) before pointing it at anything you care about.
>
> `ANTHROPIC_API_KEY` is read by the harness, and no tool sees it unless you name
> it to `--allow-env` — which hands over the value in full. That is the one flag
> to think twice about here.

## Install

Prebuilt Linux binaries are attached to each
[release](https://github.com/danczw/sandbx/releases); each archive ships with a
`.sha256` beside it. They are statically linked (musl), so there is no minimum
glibc and no runtime dependency beyond a Linux 6.10+ kernel with unprivileged
user namespaces enabled. Or build from source:

```sh
cargo install --git https://github.com/danczw/sandbx sandbx-cli
```

The `sandbx-cli` argument is required — this is a virtual workspace, so the bare
form errors.

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
