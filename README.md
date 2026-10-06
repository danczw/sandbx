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
> per-call approval prompt: a tool is approved for the whole run or not at all, so
> the grants you pass are the whole of what a prompt injection reaches once it has
> a tool. Enforced today on Linux 6.10+ with
> unprivileged user namespaces: filesystem (Landlock), network (empty netns, or
> a TCP port allowlist),
> dangerous syscalls (seccomp), process lifetime (PID namespace). Kernels that
> cannot enforce are refused, never run unrestricted. Do not assume a version
> sandboxes anything until it says so.

## Try the sandbox

`sandbx` exposes the boundary directly, so you can check the enforcement by hand
before trusting an agent to it:

```sh
sandbx sandbox-run -- grep -rn TODO .                        # works: the project you are in
sandbx sandbox-run -- cat /etc/shadow                        # permission denied
sandbx sandbox-run --allow-read /srv -- cat /srv/notes.txt   # works
sandbx sandbox-run --allow-read /srv -- cat /etc/shadow      # permission denied
sandbx sandbox-run -- curl https://example.com               # no network at all
```

Everything is denied unless a flag grants it. Three things are granted without
one. Two are what a command needs in order to start: read access to the system
binaries and libraries — with nothing readable, not even `/bin/true` reaches
`main` — and the handful of environment variables below. The third is the
working directory.

### The default policy

With no path flag, `sandbx` grants read *and write* on the directory you ran it
from, so working on the project you are standing in needs no flags at all. Giving
any path flag — `--allow-read`, `--allow-write` or `--allow-exec` — replaces that
default rather than adding to it, so `--allow-read /srv` is read on `/srv` and
nothing else. That direction is deliberate: a policy narrower than you expected
announces itself as a permission denial naming the path, while a wider one says
nothing at all.

It grants the *directory*, not your toolchain. A compiler or package manager
installed under your home — rustup's `~/.cargo/bin`, nvm, pyenv — is outside the
default, so `sandbx sandbox-run -- cargo test` fails with a permission denial
until you add `--allow-exec ~/.cargo/bin` and read access to what it needs
(`~/.cargo/registry`, `~/.rustup`). What works with no flags is a command from
the system paths, which is why the examples above use `grep` and `cat`.

Some working directories are refused rather than granted, because the tree would
be far wider than you meant, would hold what every command already runs, or would
hold the enforcer itself:

```console
$ cd ~ && sandbx sandbox-run -- true
sandbx: refusing to derive a policy from your home directory /home/you — pass --allow-read PATH and --allow-write PATH for the tree the command needs
```

The rest are the filesystem root; where home directories live (`/home`, `/Users`,
`/var/home`, `/root`, or anything holding one); anything overlapping the system
binaries, since `sandbx` already grants execute there and write beside it would
let a command rewrite `/usr/bin/git`; and any directory holding the running
`sandbx`, where a write grant replaces the thing doing the enforcing. Each refusal
names the flags to type instead, and passing them lifts it: the guard governs what
`sandbx` derives, never what you ask for.

With no usable `HOME` — a systemd unit, cron, `docker exec`, or a `HOME` that is
empty or points nowhere — `sandbx` cannot tell one person's home directory from
another's, so it also refuses any direct child of those locations. That is wider
than the rule it stands in for, which is the right direction for a guess.

Read [SECURITY.md](SECURITY.md) before relying on this: a write grant over a
project tree also covers `.git/hooks`, `Makefile` and `.cargo/config.toml`, which
run outside the sandbox the next time you build or commit.

### Pinning the program

An `--allow-exec` grant names a path, so it runs whatever is at that path when the
command starts — not the binary you were looking at when you typed the flag. Where
the command can also write the tree it runs from, which is the usual build-then-run
pair, it can choose its own binary. `--pin-sha256` closes that by naming the bytes:

```console
$ sandbx sandbox-run --allow-exec /tmp/demo \
    --pin-sha256 "$(sandbx hash /tmp/demo/tool)" -- /tmp/demo/tool
```

`sandbx hash PATH` prints a digest in the form the flag takes and confines nothing;
it reads one file, as `sha256sum` does. If the bytes differ the run is refused
before anything executes, with both digests on stderr. The flag grants nothing, so
it neither widens a policy nor replaces the working-directory default, and it needs
an absolute program path.

It covers the one program you named and nothing that program then spawns itself. A
pinned `/usr/bin/python3` is still arbitrary code.

The environment is cleared too. A sandboxed command does not inherit the one
`sandbx` was launched with, so a secret in your shell does not reach it; name a
variable with `--allow-env` to pass it through. Granted anyway, for the same
reason as the system binaries: `PATH`, `HOME`, `TERM`, `LANG`, `LC_ALL`,
`LC_CTYPE` and `TZ`. `PATH` matters most: without it a bare program name is looked
up only in the C library's fallback (`/bin:/usr/bin`), so `cat` would still start
but anything installed elsewhere would not be found.

One variable `sandbx` sets rather than passes on: `--dns-over-tcp` puts
`RES_OPTIONS=use-vc` in the command. That is a constant, not something read from
your shell, and it is the only exception.

Each run also records the policy it ran under and how it ended, on stderr:

```console
$ sandbx sandbox-run --allow-read /srv -- /bin/true
2026-10-05T20:37:54.124622Z  INFO sandbx::audit: decision="spawned" program="/bin/true" readable=1 writable=0 executable=4 network="denied" network_ports=0 unix_sockets=false env=7 dns_over_tcp=false
2026-10-05T20:37:54.130729Z  INFO sandbx::audit: decision="exited" program="/bin/true" code=0
```

Two records, and `program` ties them together. Read `spawned` as the intent to
spawn, not its success: it is written before the helper execs, so it appears for a
command that then fails to start. What it is for is the policy — what the command
was granted — and that is settled before it runs.

The second record says how the run ended, and every run gets exactly one.
`exited` carries the code `sandbx` itself exits with, a signal as 128 + n, so a
command the sandbox killed does not read as a success. A run with no status of its
own is `failed` with a reason you can filter on: `reason="timeout"` for a
`--timeout` kill, `reason="exec_failed"` for a program that could not be executed
at all, `reason="pin_mismatch"` for a program that is not the bytes it was pinned
to, `reason="landlock"` or `reason="seccomp"` for a sandbox the kernel would not
accept. Each of those would otherwise look like a command that ran and exited
1, the stage that refused having exited in the command's place.

`env=7` is a count, not a list: a variable's *name* is not a secret, but its value
routinely is, and a record that spelled out the names would invite the next change
to print values beside them. It counts the allowlist, not what crossed — a name
nothing in `sandbx`'s own environment matches passes nothing, so on a host with no
`TZ` set the command above sees fewer than seven. Like `readable`, it records what
was granted. The one variable `sandbx` sets itself has its own field,
`dns_over_tcp`, rather than being counted here as a name you passed.

It is metadata only, never a command's output, and it never touches stdout: the
command's own stdout is forwarded untouched, so piping it is unaffected. Both
records are written before any of the command's own output, which `sandbx`
forwards once the run is over. To keep
only the record, `2>&1 >/dev/null | grep sandbx::audit`. Note that `2>/dev/null`
discards the sandboxed command's own stderr along with the record — including the
permission denials the examples above are there to show.

| flag | grants |
|------|--------|
| *(no path flag)*     | read and write on the working directory. Any path flag below replaces this |
| `--allow-read PATH`  | read access to `PATH`. Repeatable |
| `--allow-write PATH` | write access to `PATH`. Repeatable |
| `--allow-exec PATH`  | run programs under `PATH` (grants read too). Repeatable |
| `--pin-sha256 HEX`   | refuse the run unless the program named after `--` hashes to `HEX`. Grants nothing, needs an absolute path, once per run |
| `--allow-network`    | IP egress on any TCP port, with UDP and raw sockets. Shares the host's network namespace |
| `--allow-network PORT` | IP connect and bind on `PORT` alone — on every host, since the kernel matches the port and not the destination. Denies UDP and raw sockets with it, so names resolve only over TCP (see `--dns-over-tcp`), and shares the host's network namespace. Repeatable |
| `--allow-unix-sockets` | unix-domain sockets. *All* of them, not a chosen path |
| `--allow-env NAME`   | let the command inherit `NAME`, with the value `sandbx` itself holds. No flag sets a value, bar the one below. Repeatable |
| `--dns-over-tcp`     | ask glibc's stub resolver to use TCP, by setting `RES_OPTIONS=use-vc`. Allowlists no port of its own |
| `--timeout SECONDS`  | kill the command, and every process it spawned, if it runs longer. Unset means no limit |

Resolving a name needs `--allow-read /etc` under *any* network policy, bare
`--allow-network` included: `resolv.conf` and `nsswitch.conf` are not granted by
anything else. Under a port allowlist it also needs TCP 53 and the resolver on
TCP, which together are one line:

```console
$ sandbx sandbox-run --dns-over-tcp \
    --allow-network 53 --allow-network 443 --allow-read /etc \
    -- curl -sSI https://example.com
```

Two things that line does not say. `--allow-read` is a path flag, so it
*replaces* the working-directory default — name the tree the command works on as
well, or it loses the read and write it had. And where `resolv.conf` is a symlink
out of `/etc`, which is the systemd-resolved default on most distributions, read
the link target too: `--allow-read /run/systemd/resolve`.

`--dns-over-tcp` is a request to the resolver inside the command, not something
`sandbx` enforces: a command that ignores `RES_OPTIONS` is unaffected, and musl
has no equivalent — a statically linked musl binary starts on UDP and falls back
to TCP only on a truncated reply, so this route does not open it.

## Try the agent

`agent-run` asks one question and lets the model use tools to answer it. The same
grants apply, and they are the only thing bounding what the agent reaches:

```sh
export ANTHROPIC_API_KEY=sk-ant-…

sandbx agent-run -- "find the TODO comments under src and list them"
```

That grants the directory you ran it from, which is also the whole of what a
prompt injection in a file the agent reads can reach. Name a narrower tree when
the question needs less than the project:

```sh
sandbx agent-run \
  --allow-read  ./src \
  --allow-write ./src \
  -- "find the TODO comments under src and list them"
```

Both of those answer by reading. Changing a file takes a second decision, because
only the four read-only tools are approved by default:

```sh
sandbx agent-run \
  --allow-write ./src \
  --allow-tool  edit \
  -- "add a doc comment to every public fn under src"
```

The answer streams on stdout; the approved set, and then which tool the gate ran
and which it refused, goes to stderr — so piping stdout gives you the answer
alone. Read that first line: it is what makes a misplaced `--` obvious, since
`--allow-tool -- write the file` is the bare flag plus a prompt. All seven are
offered to the model — `read`, `write`, `edit`, `ls`, `grep`, `find` and `bash` —
and each one the gate approves still runs through the same boundary. A path you
did not grant is refused there instead, which comes back to the model as a failed
result for it to work around rather than a crash — and reaches stderr not at all.

| flag | |
|------|--|
| `--allow-tool [TOOL]` | approve a tool that does more than read. Repeatable; bare approves all seven |
| `--model NAME`    | which model to ask. Default `claude-sonnet-5` |
| `--max-tokens N`  | cap what the model may produce in one turn. Default 4096 |
| `--system TEXT`   | a system prompt. Unset sends none |

It is single-shot on purpose: one question, one answer, then the process ends.
There is no session to resume and no way to interrupt a turn mid-flight.

Exit `0` means the model finished its answer. Exit `2` means `--max-tokens` cut
it off mid-sentence — what reached stdout is real but incomplete, which is worth
distinguishing if a script is reading it. Anything else failed before or during
the turn, with the reason on stderr.

> **Nothing asks you before an approved tool call runs.** `--allow-tool` is a
> decision per tool per run, not per call: approve `bash` and the model runs every
> command it chooses to, which means a prompt injection in a file the agent reads
> reaches anything the grants allow. The sandbox is the control, not the asking —
> so approve the fewest tools the task needs, grant the narrowest tree that lets it
> finish, and read [SECURITY.md](SECURITY.md) before pointing it at anything you
> care about.
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
