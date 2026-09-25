# Security Policy

sandbx's entire purpose is to confine what an AI agent can do. A weakness in that
boundary is not a bug in a feature — it is a bug in the product. This document
says what the boundary currently claims, what is known to be wrong with it, and
how to tell us about something we missed.

## Reporting a vulnerability

**Use [private vulnerability reporting](https://github.com/danczw/sandbx/security/advisories/new).**
Please do not open a public issue for a sandbox escape.

You should get a first response within a week. This is a personal project with
no security team and no bug bounty; what you will get is an honest assessment,
credit if you want it, and a public advisory once a fix ships.

If a report turns out to describe something already listed under *Known
weaknesses*, we will say so and point you at the issue rather than treat it as
new.

## Supported versions

| version | supported |
|---------|-----------|
| latest pre-release | yes |
| anything older | no |

Pre-1.0, there are no backports. Fixes land on `main` and ship in the next
tagged pre-release. If you are running an alpha, run the newest one.

## What sandbx claims to enforce

On Linux 6.10 or newer, for a command run through `SandboxedCommand`:

| control | mechanism | covers |
|---------|-----------|--------|
| filesystem | Landlock, ABI 5 minimum | reads, writes, and execution by path, granted separately |
| network | empty network namespace | IP egress, abstract unix sockets |
| syscalls | seccomp-bpf | a denylist of dangerous calls |

Three properties matter as much as the list:

- **It fails closed.** A kernel that cannot enforce the baseline is refused. A
  ruleset the kernel only partly applies is treated as failure. sandbx does not
  degrade to unrestricted execution and then carry on.
- **It is default-deny.** A policy grants nothing until something is added.
- **Grants do not widen each other.** Read access does not confer the right
  to execute what it can see, and write access does not confer the right to
  run what it just wrote. Execute comes only from `allow_read_execute`.

## What sandbx does *not* claim

- **Non-Linux is unsupported**, and refused rather than silently unsandboxed.
- **The harness process itself is not sandboxed** — only the commands it runs.
  A vulnerability in sandbx's own code is not contained by sandbx.
- **A dependency is not contained.** Anything linked into the binary runs with
  the harness's privileges, not a tool's.
- **The boundary is enforced by convention plus tooling**, not by a capability
  system: `unsafe` is forbidden outside `sandbx-core` and spawning a process
  elsewhere is a clippy error, but a determined contributor can add raw syscalls.
- **Approval is not enforcement.** A tool call you approve runs. sandbx bounds
  what it can reach; it does not decide whether it should run.
- **Only wall-clock time is bounded.** A tool's command is killed if it outruns
  its limit (90 seconds by default), and `sandbox-run` takes an opt-in
  `--timeout`. Nothing else is capped: no CPU bound, no memory bound, and no
  limit on how many processes a command spawns. The sandbox governs *what* a
  command can reach, and now *how long* it may run, but not *how much* it can
  consume.
- **A running tool call cannot be interrupted.** Only its own deadline stops it;
  there is no way to cancel one from outside
  ([#26](https://github.com/danczw/sandbx/issues/26)).

## Known weaknesses

Open, and public on purpose — a sandbox that hides its gaps is worse than one
that names them.

| issue | severity | what |
|-------|----------|------|
| [#8](https://github.com/danczw/sandbx/issues/8) | high | With `--allow-network`, a command can `connect()` to a pathname AF_UNIX socket and reach a host daemon outside the cage. A network namespace isolates only *abstract* unix sockets. Reaching `$SSH_AUTH_SOCK` or the session bus is a full escape. Landlock's `ResolveUnix` would fix it but needs ABI V9 (Linux 6.15), which is not yet available in practice. |

Track them with the [`security` label](https://github.com/danczw/sandbx/labels/security).

**If you rely on `--allow-network` today, assume the filesystem boundary does
not hold** for anything reachable through a unix socket.

## Not vulnerabilities

These are documented behaviour, and reports of them will be closed as such:

- Network reachable after you passed `--allow-network`.
- A command reading or executing files under a path you granted with
  `--allow-read`, including system binaries granted by default so that commands
  can start at all.
- An agent running a tool call you approved.
- Refusal to run on a kernel older than 6.10, or on a non-Linux host. That is
  fail-closed behaviour working as intended.
