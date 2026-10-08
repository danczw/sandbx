# sandbx

[![CI](https://github.com/danczw/sandbx/actions/workflows/ci.yml/badge.svg)](https://github.com/danczw/sandbx/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

A security-first AI coding agent harness, written in Rust. Isolation is part of
the harness, not an external container: every command an agent runs goes through
a Landlock + seccomp boundary that fails closed. Claims and non-claims:
[SECURITY.md](SECURITY.md).

> **Pre-alpha.** One question, tools to answer it, a resumable conversation. No
> live session, no interrupt.
>
> Requires Linux 6.10+ with unprivileged user namespaces. Enforced: filesystem
> (Landlock), network (empty netns, or a TCP port allowlist), dangerous syscalls
> (seccomp), process lifetime (PID namespace).

## Try the sandbox

```sh
sandbx sandbox-run -- grep -rn TODO .                        # works: the project you are in
sandbx sandbox-run -- cat /etc/shadow                        # permission denied
sandbx sandbox-run --allow-read /srv -- cat /srv/notes.txt   # works
sandbx sandbox-run --allow-read /srv -- cat /etc/shadow      # permission denied
sandbx sandbox-run -- curl https://example.com               # no network at all
```

### The default policy

Everything is denied unless a flag grants it. Granted without one:

- **read on system binaries and libraries** (`/usr`, `/bin`, `/lib`, `/lib64`);
- **seven environment variables** — see [The environment](#the-environment);
- **read *and write* on the working directory**.

Any path flag — `--allow-read`, `--allow-write`, `--allow-exec` — *replaces* the
working-directory default rather than adding to it: `--allow-read /srv` is read
on `/srv` and nothing else.

That default grants the *directory*, not your toolchain (rustup's
`~/.cargo/bin`, nvm, pyenv live under your home). So `grep` and `cat` need no
flags and `cargo test` needs seven:

```sh
sandbx sandbox-run \
  --allow-exec ~/.cargo/bin --allow-exec ~/.rustup \
  --allow-read ~/.cargo/registry \
  --allow-write . --allow-exec . \
  --allow-write /dev/null --allow-write /tmp \
  -- cargo test --offline
```

- `~/.cargo/bin` the shims, `~/.rustup` the toolchain, `~/.cargo/registry` the
  vendored sources — `--offline` still reads them, and without it cargo reports
  `no matching package named serde_json found`.
- the working directory needs write for `target/` **and** execute for the test
  binary: write does not imply execute.
- `/tmp` for the linker's temporary files.
- `/dev/null` is the trap, and it needs *write*. A build script redirecting a
  child's stdio opens it `O_RDWR`, so `--allow-read /dev` is not enough and you
  get a `PermissionDenied` from inside `build.rs` instead.
- `--offline` because the network is denied; resolving dependencies instead needs
  `--allow-network 443 --allow-read /etc`, which widens what a `build.rs` reaches.

Some working directories are refused rather than granted:

```console
$ cd ~ && sandbx sandbox-run -- true
sandbx: refusing to derive a policy from your home directory /home/you — pass --allow-read PATH and --allow-write PATH for the tree the command needs
```

Refused as a derived root: the filesystem root, `$HOME`, where home directories
live, anything overlapping the system binaries. Every refusal names the flags to
type instead, and the guard governs what `sandbx` derives, never what you ask for
([context/decision-default-policy.md](context/decision-default-policy.md)).

One refusal does govern what you ask for, and no flag lifts it: a granted path
may not reach sandbx's own state — the session store, and the credential file
`auth login` writes. Hence `--allow-read ~` and `--allow-read /` are refused on
both run subcommands.

Read [SECURITY.md](SECURITY.md) first: a write grant over a project tree also
covers `.git/hooks`, `Makefile` and `.cargo/config.toml`, which run outside the
sandbox the next time you build or commit.

### Pinning the program

`--allow-exec` names a path, so it runs whatever is there when the command
starts — paired with write on the same tree, the command can choose its own
binary. `--pin-sha256` names the bytes instead:

```console
$ sandbx sandbox-run --allow-exec /tmp/demo \
    --pin-sha256 "$(sandbx hash /tmp/demo/tool)" -- /tmp/demo/tool
```

- `sandbx hash PATH` prints a digest in the form the flag takes. A mismatch
  refuses the run before anything executes, with both digests on stderr.
- Grants nothing; the program path must be absolute.
- Covers the one program named, not what it spawns: a pinned `/usr/bin/python3`
  is still arbitrary code.
- Refused rather than run unchecked: a `#!` script (pin the interpreter, pass
  the script as an argument), and a program you may execute but not read.

### The environment

The environment is cleared, so a secret in the launching shell does not reach
the command. `--allow-env NAME` passes one through with the value `sandbx` holds;
`--dns-over-tcp` is the one flag that *sets* a value (`RES_OPTIONS=use-vc`).

Granted anyway: `PATH`, `HOME`, `TERM`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`.
Without `PATH`, a bare program name is looked up only in the C library's
fallback (`/bin:/usr/bin`).

### The audit trail

Each run records the policy it ran under and how it ended, on stderr:

```console
$ sandbx sandbox-run --allow-read /srv -- /bin/true
2026-10-08T14:01:45.619054Z  INFO sandbx::audit: decision="spawned" program="/bin/true" readable=1 writable=0 executable=4 network="denied" network_ports=0 unix_sockets=false env=7 dns_over_tcp=false dns_names=0 pinned=false
2026-10-08T14:01:45.627489Z  INFO sandbx::audit: decision="exited" program="/bin/true" code=0
```

Two records per run, tied by `program`: one `spawned`, then exactly one of
`exited` or `failed`. Under `sandbx tui` they arrive on stderr too, held back
until the screen is given up so they follow the turn rather than interleave with
it. Four fields do not read the way they look:

| field | reads |
|---|---|
| `decision="spawned"` | the *intent* to spawn, written before the helper execs — so it appears for a command that then fails to start — carrying the settled policy |
| `decision="absent"` | a path naming nothing inside a root you granted — no `reason=`. Outside your roots it is a `denied` like any other, so the trail never says which outside paths exist |
| `env=` | how many names were *granted*, not how many crossed: a name `sandbx`'s own environment lacks passes nothing |
| `pinned=` | whether a digest had to match before the exec. A matching pin reads as unpinned; a mismatch is already the `reason="pin_mismatch"` record |

A `failed` record carries in `reason=` what refused the run or cut it short —
`timeout` for a `--timeout` kill, `unsupported` for a kernel that cannot enforce,
`landlock` or `seccomp` for one that would not take the ruleset or the filter,
`pin_mismatch` for bytes that are not what was pinned. Read it: each would
otherwise look like a command that ran and exited 1. The set is exhaustive, from
`SandboxError::label`; every record kind, the `degraded` of a best-effort
hardening step included, is in
[context/guide-logging.md](context/guide-logging.md).

Metadata only, never a command's output, and never on stdout, which is forwarded
untouched. For the record alone, `2>&1 >/dev/null | grep sandbx::audit`; a plain
`2>/dev/null` discards the command's own stderr too, permission denials included.

### `sandbox-run` flags

| flag | grants |
|------|--------|
| *(no path flag)*     | read and write on the working directory. Any path flag below replaces this |
| `--allow-read PATH`  | read `PATH`. Repeatable |
| `--allow-write PATH` | write `PATH`. Repeatable |
| `--allow-exec PATH`  | run programs under `PATH` (grants read too). Repeatable |
| `--pin-sha256 HEX`   | refuse the run unless the program named after `--` hashes to `HEX`. Grants nothing, absolute path, once per run |
| `--allow-network`    | IP egress on any TCP port, plus UDP and raw sockets. Shares the host's netns |
| `--allow-network PORT` | IP connect and bind on `PORT` alone, on every host — the kernel matches the port, not the destination. Denies UDP and raw sockets, so names resolve only over TCP. Shares the host's netns. Repeatable |
| `--allow-unix-sockets` | unix-domain sockets. *All* of them, not a chosen path |
| `--allow-env NAME`   | inherit `NAME`, with the value `sandbx` itself holds. Repeatable |
| `--allow-dns NAME`   | let `NAME` resolve and nothing else. Grants no path and no port. Repeatable |
| `--dns-over-tcp`     | ask glibc's stub resolver to use TCP, via `RES_OPTIONS=use-vc`. Allowlists no port. Not with `--allow-dns` |
| `--timeout SECONDS`  | kill the command, and every process it spawned, past that. Unset: no limit |

### Resolving a name

Two routes. Name the hosts the command may resolve, which grants nothing else:

```console
$ sandbx sandbox-run --allow-dns example.com --allow-network 443 \
    --allow-read /etc/ssl/certs -- curl -sSI https://example.com
```

- **It grants no path**, so resolution needs no `--allow-read /etc` — the one
  flag that makes a policy *smaller*. TLS still needs the CA bundle, and that
  read grant is a path flag like any other: it replaces the working-directory
  default. A name you did not list fails at once rather than after a timeout —
  `Could not resolve host`, exit 6.
- **Where `resolv.conf` is a symlink out of `/etc`** — the systemd-resolved
  default — that file gets no read rule and the command gets `EACCES` there.
- **It needs a host where an unprivileged user namespace may mount**, so
  `kernel.apparmor_restrict_unprivileged_userns=1` (Ubuntu's default since 24.04)
  refuses the run rather than leave every name resolving. Narrow fix: an AppArmor
  profile for the `sandbx` binary carrying `userns,`.
- **What it bounds, and the shapes it refuses**, in
  [SECURITY.md](SECURITY.md#what---allow-dns-bounds).

Or leave every name resolvable, over TCP, which is what a port allowlist leaves
room for:

```console
$ sandbx sandbox-run --dns-over-tcp \
    --allow-network 53 --allow-network 443 --allow-read /etc \
    -- curl -sSI https://example.com
```

- `--allow-read` is a path flag, so that line replaces the working-directory
  default: name the command's own tree too, or it loses the read and write it had.
- Where `resolv.conf` is a symlink out of `/etc` — the systemd-resolved default
  — read the target too: `--allow-read /run/systemd/resolve`.
- `--dns-over-tcp` is a request to the resolver inside the command, not something
  `sandbx` enforces, and musl has no equivalent — so this route does not open a
  static musl binary, where `--allow-dns` works on both libcs.

## Authenticate

`agent-run` needs an Anthropic API key. The environment comes first:

```sh
export ANTHROPIC_API_KEY=sk-ant-…
```

Or store it once, and export nothing:

```sh
read -rs KEY && printf %s "$KEY" | sandbx auth login
sandbx auth status   # says which source answered, never prints the key
sandbx auth logout
```

- `auth login` reads stdin and will not prompt, so the key reaches neither your
  terminal, your shell's history nor argv.
- It writes `$XDG_CONFIG_HOME/sandbx/credentials.toml` (or `~/.config/…`) at
  `0600` in a directory at `0700`, and later refuses to read it if anyone but
  you can reach either, naming the `chmod` that fixes it.
- `auth status` exits 0 on a key found, 1 on none, 2 on one refused.
- Exporting the variable wins over the stored key.

The stored key is plaintext; what protects it, and what still reaches it, is in
[SECURITY.md](SECURITY.md).

## Try the agent

`agent-run` asks one question and lets the model use tools to answer it. The same
grants apply, and they are the only thing bounding what the agent reaches:

```sh
sandbx agent-run -- "find the TODO comments under src and list them"
```

That grants the directory you ran it from — also the whole of what a prompt
injection in a file the agent reads can reach. Name a narrower tree, and it
answers by reading that tree alone:

```sh
sandbx agent-run --allow-read ./src -- "find the TODO comments under src"
```

Changing a file takes a second decision — only the four read-only tools are
approved by default:

```sh
sandbx agent-run \
  --allow-write ./src \
  --allow-tool  edit \
  -- "add a doc comment to every public fn under src"
```

All seven tools are offered to the model — `read`, `write`, `edit`, `ls`,
`grep`, `find`, `bash` — and each one the gate approves still runs through the
same boundary. A path you did not grant is refused there: the model sees a failed
result to work around, and the trail gets one `denied` record per refusal.

The answer streams on stdout; the approved set, then one line per call, goes to
stderr. Read that first stderr line — it is what makes a misplaced `--` obvious,
since `--allow-tool -- write the file` is the bare flag plus a prompt.

```console
sandbx: write /work/notes.md — ran
sandbx: write /etc/hosts — refused by the policy: outside every writable root
sandbx: bash — refused: the `bash` tool is not approved for this run: …
```

To decide each call yourself, `--approve call` asks on your terminal before every
write and every command — `y` for this call, `n` to refuse it, `a` for every call
to that tool for the rest of the run. Read-only calls are not asked about,
`--allow-tool` must still have approved the tool at all, and a run with no
terminal refuses to start rather than falling back to the per-run answer. The
per-call lines move to the terminal with the question, so `2> run.log` cannot
leave you answering one call blind.

| flag | |
|------|--|
| `--allow-tool [TOOL]` | approve a tool that does more than read. Repeatable; bare approves all seven |
| `--approve WHEN`  | `run` (default) takes the answer from `--allow-tool` alone; `call` asks on your terminal per write and per command |
| `--model NAME`    | which model to ask. Default `claude-sonnet-5` |
| `--max-tokens N`  | cap what the model may produce in one turn. Default 4096 |
| `--max-rounds N`  | cap how many rounds of tool calls one turn may spend. Default 8, plus the wrap-up round below |
| `--no-wrap-up`    | do not spend one more request answering a turn that hit `--max-rounds` |
| `--session [ID]`  | save the conversation; bare starts one and prints its id, an id resumes it |
| `--system TEXT`   | a system prompt, sent after whatever lines name the run's approved tools and roots |
| `--show-thinking` | print a summary of the model's reasoning on stderr as it arrives. Stored nowhere, and a 400 on models before Claude 4.6 |

One question, one answer, then the process ends. `sandbx tui` takes the same
flags and draws that turn on a screen instead of streaming it, where ctrl-c or
escape ends it mid-flight — storing nothing of that turn and leaving a running
tool call to finish unseen. It needs a terminal on stdout, so it refuses a piped
run, and it refuses `--approve call`, whose question wants the terminal the
screen has taken ([context/guide-tui.md](context/guide-tui.md)):

```sh
sandbx tui --allow-tool bash -- "what is in this directory?"
```

`--session` carries a conversation across runs:

```bash
sandbx agent-run --session -- 'remember the number 41'
# sandbx: session 1z8k3p7q started; resume it with --session 1z8k3p7q
sandbx agent-run --session 1z8k3p7q -- 'what number did I ask you to remember?'
```

A session is a plaintext JSONL transcript under `$XDG_STATE_HOME/sandbx/sessions`
(or `~/.local/state/sandbx/sessions`), `0600` in a `0700` directory, holding
whatever a tool read into the conversation. Nothing expires or redacts it, and
resuming one another user can write is refused — [SECURITY.md](SECURITY.md).

| `agent-run` and `tui` exit | means |
|---|---|
| `0` | the model finished its answer |
| `2` | a bound cut the turn short, named on stderr — `--max-tokens` or `--max-rounds`. Out of rounds, one more request answers the turn with no tool, so stdout usually holds a summary a blank line below what arrived before the cap; `--no-wrap-up` skips it, leaving nothing at all if the model opened with a tool call ([context/decision-round-limit-answer.md](context/decision-round-limit-answer.md)). Under `tui` it also means you interrupted the turn, and there no wrap-up round is sent |
| `3` | `--approve call` lost the terminal it asks on, so the turn ended there: that call and the ones behind it were refused and no further request was sent. What the turn did before is on stdout and in `--session` |
| anything else | it failed before or during the turn, with the reason on stderr |

> **By default nothing asks you before an approved tool call runs.**
> `--allow-tool` is per tool per run, not per call: approve `bash` and the model
> runs every command it chooses. `--approve call` needs a terminal, so an
> unattended run cannot have it. Either way the sandbox is the control, not the
> asking: approve the fewest tools, grant the narrowest tree, and read
> [SECURITY.md](SECURITY.md) first.
>
> `--allow-env ANTHROPIC_API_KEY` is refused here: sandbx makes the provider call
> itself. Every other variable you name is passed in full, so that is the flag to
> think twice about.

## Install

Prebuilt Linux binaries are attached to each
[release](https://github.com/danczw/sandbx/releases), each with a `.sha256`
beside it. Statically linked (musl): no minimum glibc, no runtime dependency
beyond a Linux 6.10+ kernel with unprivileged user namespaces. Or build from
source:

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

`unsafe` is forbidden in every crate and spawning a subprocess outside
`sandbx-core` is a clippy error, so the boundary is enforced by the build.

- `context/guide-repo-map.md` — which crate owns what, and what depends on what.
- `context/guide-ci.md` — what the hooks run before a commit, and CI after a push.
- `context/guide-module-layout.md` — a module's budget, and where its tests live.
- the `context/guide-*.md` beside them, how each subsystem works; the
  `context/decision-*.md`, why it has that shape.

## License

MIT
