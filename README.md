# sandbx

[![CI](https://github.com/danczw/sandbx/actions/workflows/ci.yml/badge.svg)](https://github.com/danczw/sandbx/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

A security-first AI coding agent harness, written in Rust.

Most agent harnesses delegate isolation to an external container. sandbx makes it
part of the harness: every command an agent runs goes through a Landlock +
seccomp boundary that fails closed rather than degrading to unrestricted
execution. What it claims, and what it does not, is [SECURITY.md](SECURITY.md).

> **Pre-alpha.** One question from the command line, tools used to answer it, and
> a conversation you can save and resume. Missing: the interactive surface (no
> live session, no interrupt) and any per-call approval prompt — a tool is
> approved for the whole run or not at all, so the grants you pass are the whole
> of what a prompt injection reaches once it has a tool.
>
> Requires Linux 6.10+ with unprivileged user namespaces. Enforced today:
> filesystem (Landlock), network (empty netns, or a TCP port allowlist),
> dangerous syscalls (seccomp), process lifetime (PID namespace).

## Try the sandbox

Check the enforcement by hand before trusting an agent to it:

```sh
sandbx sandbox-run -- grep -rn TODO .                        # works: the project you are in
sandbx sandbox-run -- cat /etc/shadow                        # permission denied
sandbx sandbox-run --allow-read /srv -- cat /srv/notes.txt   # works
sandbx sandbox-run --allow-read /srv -- cat /etc/shadow      # permission denied
sandbx sandbox-run -- curl https://example.com               # no network at all
```

### The default policy

Everything is denied unless a flag grants it. Three things are granted without
one:

- **read on the system binaries and libraries** (`/usr`, `/bin`, `/lib`,
  `/lib64`) — with nothing readable, not even `/bin/true` reaches `main`;
- **seven environment variables** — see [The environment](#the-environment);
- **read *and write* on the working directory**, so working on the project you
  are standing in needs no flags at all.

Any path flag — `--allow-read`, `--allow-write`, `--allow-exec` — *replaces* the
working-directory default rather than adding to it, so `--allow-read /srv` is
read on `/srv` and nothing else.

That default grants the *directory*, not your toolchain: a compiler or package
manager under your home (rustup's `~/.cargo/bin`, nvm, pyenv) is outside it. So
`grep` and `cat` need no flags and `cargo test` needs five:

```sh
sandbx sandbox-run \
  --allow-exec ~/.cargo/bin --allow-exec ~/.rustup \
  --allow-write . --allow-exec . \
  --allow-read /dev --allow-write /tmp \
  -- cargo test --offline
```

- `~/.cargo/bin` is the shims, `~/.rustup` the toolchain they hand off to.
- the working directory needs write for `target/` **and** execute for the test
  binary it just built: write does not imply execute.
- `/tmp` is the linker's temporary files.
- `/dev` is the trap. cargo redirects a child's stdio to `/dev/null`, and without
  it you get `could not execute process .../rustc -vV (never executed):
  Permission denied` — which reads as a missing execute grant on a path you did
  grant.
- `--offline` because the network is denied. Resolving dependencies also needs
  `--allow-network 443 --allow-read /etc`, which widens what a `build.rs`
  reaches.

Some working directories are refused rather than granted:

```console
$ cd ~ && sandbx sandbox-run -- true
sandbx: refusing to derive a policy from your home directory /home/you — pass --allow-read PATH and --allow-write PATH for the tree the command needs
```

Refused as a derived root: the filesystem root; `$HOME`; where home directories
live (`/home`, `/Users`, `/var/home`, `/root`, or anything holding one); anything
overlapping the system binaries, which already have execute. With no usable
`HOME` — unset, empty or pointing nowhere, as under a systemd unit, cron or
`docker exec` — any *direct child* of those locations is refused too. Every
refusal names the flags to type instead, and `--allow-read PATH` with
`--allow-write PATH` lifts any of them: that guard governs what `sandbx` derives,
never what you ask for.

One refusal does govern what you ask for, and no flag lifts it: a path you grant
may not reach what sandbx keeps its own state under — the session store, and the
credential file `auth login` writes — whether or not anything is stored there
yet. `--allow-read ~` and `--allow-read /` are refused on both run subcommands
for that reason, and the message names the owned path the grant reached.

A directory holding the `sandbx` binary is *not* refused, so a no-flag run from
an install prefix such as `~/.local/bin` grants write there. The helper is
reached through `/proc/self/exe`, so a rename over the path cannot redirect the
next spawn — but replacing the binary reaches the next `sandbx` you start
yourself.

Read [SECURITY.md](SECURITY.md) before relying on any of this: a write grant over
a project tree also covers `.git/hooks`, `Makefile` and `.cargo/config.toml`,
which run outside the sandbox the next time you build or commit.

### Pinning the program

`--allow-exec` names a path, so it runs whatever is there when the command
starts — paired with write on the same tree, the command can choose its own
binary. `--pin-sha256` closes that by naming the bytes:

```console
$ sandbx sandbox-run --allow-exec /tmp/demo \
    --pin-sha256 "$(sandbx hash /tmp/demo/tool)" -- /tmp/demo/tool
```

- `sandbx hash PATH` prints a digest in the form the flag takes, and confines
  nothing. A mismatch refuses the run before anything executes, with both digests
  on stderr.
- The flag grants nothing — it neither widens a policy nor replaces the
  working-directory default — and the program path must be absolute.
- It covers the one program you named, not what that program spawns: a pinned
  `/usr/bin/python3` is still arbitrary code.
- Two images are refused rather than run unchecked: a `#!` script (pin the
  interpreter and pass the script as an argument) and a program you may execute
  but not read.

### The environment

The environment is cleared, so a secret in the shell `sandbx` was launched from
does not reach the command. `--allow-env NAME` passes one through, with the value
`sandbx` itself holds; `--dns-over-tcp` is the one flag that *sets* a value
(`RES_OPTIONS=use-vc`).

Granted anyway, for the same reason as the system binaries: `PATH`, `HOME`,
`TERM`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`. Without `PATH` a bare program name is
looked up only in the C library's fallback (`/bin:/usr/bin`).

### The audit trail

Each run records the policy it ran under and how it ended, on stderr:

```console
$ sandbx sandbox-run --allow-read /srv -- /bin/true
2026-10-05T20:37:54.124622Z  INFO sandbx::audit: decision="spawned" program="/bin/true" readable=1 writable=0 executable=4 network="denied" network_ports=0 unix_sockets=false env=7 dns_over_tcp=false pinned=false
2026-10-05T20:37:54.130729Z  INFO sandbx::audit: decision="exited" program="/bin/true" code=0
```

Two records per run, tied by `program`: one `spawned`, then exactly one of
`exited` or `failed`.

| field | reads |
|---|---|
| `decision="spawned"` | the *intent* to spawn, written before the helper execs — so it appears for a command that then fails to start — carrying the policy as settled |
| `decision="exited"` | with `code=`, the code `sandbx` itself exits with; a signal as 128 + n, so a command the sandbox killed does not read as a success |
| `decision="failed"` | with `reason=`, a run refused or cut short before it could exit on its own (table below) |
| `decision="degraded"` | a hardening step the kernel would not allow, reported and carried on (see [SECURITY.md](SECURITY.md) on the capability bounding set) |
| `decision="denied"` | a tool call refused by the in-process guard, with `tool=`, `subject=` and `reason=` |
| `decision="allowed"` | a tool call that went through, with `tool=` and `subject=`. Written *after* the access, so the trail answers what the agent saw rather than what the policy decided |
| `decision="absent"` | a path that names nothing inside a root you granted — no `reason=`, nothing having refused it. Outside your roots it is a `denied` like any other, so the trail does not say which of those paths exist |
| `env=` | how many names were *granted* — not which, and not how many crossed: a name `sandbx`'s own environment does not hold passes nothing, so with no `TZ` set the run above sees fewer than seven |
| `dns_over_tcp=` | its own field, not one of the counted names |
| `pinned=` | whether a digest had to match before the exec, and the only place the trail says the entry point was checked at all. A matching pin leaves the run looking unpinned; a mismatch is already the `reason="pin_mismatch"` record closing it |

Every `reason=` a `failed` record carries, exhaustively. Each of these would
otherwise look like a command that ran and exited 1, the stage that refused
having exited in the command's place:

| `reason` | the run was refused or cut short by |
|---|---|
| `timeout` | a `--timeout` kill |
| `spawn_failed` | a helper process that could not be started |
| `bad_helper_args` | a helper invocation it would not parse best-effort |
| `landlock` / `seccomp` | a kernel that would not accept the ruleset or the filter |
| `unsupported` | a kernel that cannot enforce: too old, Landlock off at boot, or a ruleset accepted and not enforced |
| `namespace_setup_failed` | a user, PID or network namespace that could not be created |
| `process_hardening` | capabilities, core dumps or the environment not in the state the command may be born into |
| `inner_stage_failed` | a helper stage that could not start the stage below it |
| `exec_failed` | a program that could not be executed at all |
| `pin_mismatch` | a program that is not the bytes it was pinned to |
| `pin_unreadable` | a program a pin could not be checked against |
| `pinned_script` | a `#!` script, which `--pin-sha256` cannot cover |

The trail is metadata only, never a command's output, and never on stdout, which
is forwarded untouched. To keep only the record,
`2>&1 >/dev/null | grep sandbx::audit`; a plain `2>/dev/null` discards the
command's own stderr with it, including the permission denials.

### `sandbox-run` flags

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
| `--allow-dns NAME`   | let `NAME` resolve, and nothing else. `sandbx` resolves it itself before the command starts and gives the command a hosts file holding those addresses and no nameserver at all. Grants no path — it needs no `--allow-read /etc` — and no port. Repeatable |
| `--dns-over-tcp`     | ask glibc's stub resolver to use TCP, by setting `RES_OPTIONS=use-vc`. Allowlists no port of its own. Not with `--allow-dns` |
| `--timeout SECONDS`  | kill the command, and every process it spawned, if it runs longer. Unset means no limit |

### Resolving a name

Two routes. Name the hosts the command may resolve, which grants nothing else:

```console
$ sandbx sandbox-run --allow-dns example.com --allow-network 443 \
    -- curl -sSI https://example.com
```

`sandbx` resolves `example.com` before the command starts and gives it a hosts
file holding that address, an `nsswitch.conf` whose `hosts` line reads `files`
alone so glibc has no DNS source, and a `resolv.conf` naming no nameserver. A
name you did not list does not resolve, at once rather than after a timeout.
The working-directory default survives: this is the one flag that makes a
policy *smaller*, needing no `--allow-read /etc`. Every `nsswitch.conf` line
that is not about a name is kept as the host had it, so an account that lives
in `systemd`, `sss` or LDAP still looks up inside the sandbox.

Where `resolv.conf` is a symlink out of `/etc` — the systemd-resolved default —
that one file gets no read rule, a bind following the link so a rule spelled
`/etc/resolv.conf` would name the target instead. The command gets `EACCES`
there rather than `sandbx`'s body, unless some other grant reaches the target.
The bound does not rest on that file either way: glibc is left no DNS source by
`nsswitch.conf`, and musl, which reads it and falls back to `127.0.0.1` when it
cannot, is left no allowlisted port to reach a nameserver on.

It bounds resolution, not connection: an IP literal reaches any allowlisted
port exactly as before. So the run is refused where a nameserver would still
answer for every name — alongside `--dns-over-tcp`, alongside bare
`--allow-network`, alongside `--allow-unix-sockets` (nscd answers over one, and
glibc asks it first), with 53 in the port list, or with no `--allow-network` at
all.

It needs a host where an unprivileged user namespace may mount. A kernel that
restricts them — `kernel.apparmor_restrict_unprivileged_userns=1`, Ubuntu's
default since 24.04 — denies `CAP_SYS_ADMIN` inside the namespace it just let
you create, so the run is refused rather than left resolving every name. The
way out that stays narrow is an AppArmor profile for the `sandbx` binary
carrying `userns,`, which restores the unshare for `sandbx` and nothing else.
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` also works and
is the worse of the two: it lifts the restriction for every program on the
host, not just this one.

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
  on most distributions — read the target too:
  `--allow-read /run/systemd/resolve`.
- `--dns-over-tcp` is a request to the resolver inside the command, not something
  `sandbx` enforces. A command that ignores `RES_OPTIONS` is unaffected, and musl
  has no equivalent: a static musl binary starts on UDP and falls back to TCP
  only on a truncated reply, so this route does not open it. `--allow-dns` works
  on both libcs, and for a static binary, because it replaces the files every
  resolver reads rather than asking one to behave differently.

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

`auth login` reads the key from stdin and will not prompt, so it reaches neither
your terminal, your shell's history nor argv. It writes
`$XDG_CONFIG_HOME/sandbx/credentials.toml` (or `~/.config/…`) with mode `0600` in
a directory at `0700`, and later refuses to read the file if anyone but you can
reach either, naming the `chmod` that fixes it rather than fixing it silently.
`auth status` exits 0 when it found a key, 1 when there is none and 2 when one
was refused, so a script can tell "log in" apart from "something is wrong".

Exporting the variable wins over the stored key, so you can override it for one
shell without logging out. The stored key is plaintext, and a path grant that
would reach it — `--allow-read ~/.config`, or the file's own path — is refused
rather than honoured; an exported one is kept out of a `/proc` grant by sandbx
concealing its own procfs entry. See [SECURITY.md](SECURITY.md).

## Try the agent

`agent-run` asks one question and lets the model use tools to answer it. The same
grants apply, and they are the only thing bounding what the agent reaches:

```sh
sandbx agent-run -- "find the TODO comments under src and list them"
```

That grants the directory you ran it from — also the whole of what a prompt
injection in a file the agent reads can reach. Name a narrower tree when the
question needs less:

```sh
sandbx agent-run \
  --allow-read  ./src \
  --allow-write ./src \
  -- "find the TODO comments under src and list them"
```

Both answer by reading. Changing a file takes a second decision, only the four
read-only tools being approved by default:

```sh
sandbx agent-run \
  --allow-write ./src \
  --allow-tool  edit \
  -- "add a doc comment to every public fn under src"
```

All seven tools are offered to the model — `read`, `write`, `edit`, `ls`, `grep`,
`find`, `bash` — and each one the gate approves still runs through the same
boundary. A path you did not grant is refused there instead, which reaches the
model as a failed result to work around rather than a crash, and the trail as one
record per refusal:

```console
2026-10-06T22:05:10.633436Z  INFO sandbx::audit: decision="denied" tool="write" subject="/tmp/outside-grant.txt" reason="outside every writable root"
```

The answer streams on stdout; the approved set, then which tool the gate ran and
which it refused, goes to stderr. Read that first stderr line — it is what makes
a misplaced `--` obvious, since `--allow-tool -- write the file` is the bare flag
plus a prompt.

Every run opens by telling the model which roots its tools can reach, and a run
that refuses a tool names the ones it approved too, so the turn is not spent
guessing at paths the sandbox refuses or at tools the gate does. A run that
approves all seven names none of them: there is nothing left to refuse.

| flag | |
|------|--|
| `--allow-tool [TOOL]` | approve a tool that does more than read. Repeatable; bare approves all seven |
| `--model NAME`    | which model to ask. Default `claude-sonnet-5` |
| `--max-tokens N`  | cap what the model may produce in one turn. Default 4096 |
| `--max-rounds N`  | cap how many rounds of tool calls one turn may spend. Default 8, plus the wrap-up round below |
| `--no-wrap-up`    | do not spend one more request answering a turn that hit `--max-rounds` |
| `--session [ID]`  | save the conversation; bare starts one and prints its id, an id resumes it |
| `--system TEXT`   | a system prompt, sent after whatever lines name the run's approved tools and roots |
| `--show-thinking` | print a summary of the model's reasoning on stderr as it arrives. Stored nowhere, and a 400 on models before Claude 4.6 |

Each run is one question and one answer, then the process ends; there is no way
to interrupt a turn mid-flight. `--session` carries a conversation across runs:

```bash
sandbx agent-run --session -- 'remember the number 41'
# sandbx: session 1z8k3p7q started; resume it with --session 1z8k3p7q
sandbx agent-run --session 1z8k3p7q -- 'what number did I ask you to remember?'
```

A session is a plaintext JSONL transcript under `$XDG_STATE_HOME/sandbx/sessions`
(or `~/.local/state/sandbx/sessions`), created `0600` in a `0700` directory, and
it holds whatever a tool read into the conversation. Resuming one another user
can write is refused; one they can only read resumes and says so on stderr. A
path grant reaching that directory is refused too, so no tool gets write over
the history it is part of.
Nothing expires or redacts it — see [SECURITY.md](SECURITY.md).

| `agent-run` exit | means |
|---|---|
| `0` | the model finished its answer |
| `2` | a bound cut the turn short, named on stderr — `--max-tokens` or `--max-rounds`. A turn out of rounds is asked once more, a round that may call no tool, so stdout usually holds a summary — one blank line below whatever arrived before the cap, if anything did. stderr says when that round failed instead, and `--no-wrap-up` skips it, leaving stdout with whatever the cap cut off — nothing at all if the model opened with a tool call |
| anything else | it failed before or during the turn, with the reason on stderr |

> **Nothing asks you before an approved tool call runs.** `--allow-tool` is a
> decision per tool per run, not per call: approve `bash` and the model runs every
> command it chooses. The sandbox is the control, not the asking — approve the
> fewest tools the task needs, grant the narrowest tree that lets it finish, and
> read [SECURITY.md](SECURITY.md) before pointing it at anything you care about.
>
> `--allow-env ANTHROPIC_API_KEY` is refused here: sandbx makes the provider call
> itself, so no tool call needs that value. Every other variable you name is still
> passed in full, so that is the flag to think twice about. The two paths sandbx
> keeps its own state under — the session store and the stored credential — are
> refused to a path flag, on this subcommand and on `sandbox-run` alike, so
> `--allow-read ~` and `--allow-read /` no longer derive a policy. Name the trees
> the command needs.

## Install

Prebuilt Linux binaries are attached to each
[release](https://github.com/danczw/sandbx/releases), each with a `.sha256`
beside it. They are statically linked (musl): no minimum glibc, no runtime
dependency beyond a Linux 6.10+ kernel with unprivileged user namespaces. Or
build from source:

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
`context/guide-repo-map.md` says which crate owns what; the `context/guide-*.md`
beside it, how each subsystem works.

## License

MIT
