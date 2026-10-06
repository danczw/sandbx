# The pinned entry point

Why `--pin-sha256` names bytes rather than a path, covers one `execve` rather
than a run, and sits beside the policy rather than inside it. The claim it makes
and the limit it does not cross are in `SECURITY.md`; this is why it has that
shape.

## The gap

A filesystem grant names a path. `SandboxPolicy::allow_read_execute` already says
so — "a directory granted here can run anything that appears in it later" — so
`--allow-exec` is a standing permission to run whatever is at that path when the
command starts, not permission to run the binary the operator was looking at.

The shape that matters is build-then-run. `--allow-exec ./target/debug/mytool
--allow-write ./target` is the natural flag pair for "run the thing you just
built", and it is also the pair that lets the command choose its own binary: in an
agent session the second tool call can rewrite what the first one built. #146
reproduced it — `/tmp/demo/tool` was `/bin/true` when the policy was written and
`/bin/id` when it ran, and Landlock permitted both, because both are that path.

## Not an `Axis` row

`SandboxPolicy` is what a sandboxed process may do, and both enforcement layers
derive from `Axis::grants` (`context/decision-axis-table.md`). A digest derives
nothing there: it adds no Landlock right, no seccomp rule and no `FsGuard` root,
and a pin grants nothing — a pinned program with no `--allow-exec` still cannot
run. Made a row, it would have to answer what it confers, and the answer is
nothing.

So it is a field on `SandboxedCommand` and on `HelperArgs`, beside `program` and
`args`. That follows `exec_inner`'s precedent for the supervisor pid: a token
ahead of the policy, keeping the policy grammar and its round-trip untouched.
Untouched in fact: `Axis`, `Grants`, `SandboxPolicy::grant`, `paths`,
`granted_paths`, and `Grants::paths` in the CLI. The CLI's `pin()` is likewise
outside `paths_given()`, so a pin cannot suppress the working-directory default —
a flag that granted nothing must not narrow anything either.

## The descriptor, not the path

Hashing a path and then `execve`ing that path is TOCTOU, and the window is exactly
the one the feature exists to close. So `open_verified` opens the program once,
hashes *that handle*, and hands it back; the helper execs `/proc/self/fd/N` for it
and holds the handle across the call. `Sha256Digest::of_file` takes a `&mut File`
and never a path, which makes the honest route the only one the type permits.

Three things that makes true. Landlock dereferences the magic link, so the exec is
still checked against the program's real path and a pinned run needs no grant on
`/proc`. `O_CLOEXEC` on the handle is harmless: the kernel opens the image in
`do_open_execat` before `flush_old_files` runs. And the open happens *after*
`apply`, so the descriptor is provably one the policy authorizes — opening first
would hash a file no grant covers and report a mismatch where the honest answer is
a denied read.

Symlinks are followed, deliberately and against the first draft of #146's plan.
The proposition is "the bytes `execve` would run hash to this", and `execve`
follows them too; the swap is closed by holding the inode rather than by how it was
reached, so `O_NOFOLLOW` would refuse `/usr/bin/python3` and buy nothing.

`arg0` is restored unconditionally to the program as the caller named it, so a
matching pin changes nothing the command can observe. Without it `$0` would be the
procfs path, which `ps` and a multi-call binary both read.

## No path in the flag

The pin covers the one `execve` sandbx performs, so it applies to one binary — the
program after `--`, already in the argv. `--allow-exec PATH=<sha256>` would name
that path a second time, and attaching a digest to a repeatable path grant implies
it pins each of them. One flag taking exactly one value is the
`--allow-network-port` shape `context/decision-enforcement-seam.md` blesses: no
lookahead in `decode`, no new `=`-splitting parse family, and `--allow-env`'s "a
flag takes a name, never a pair" stays intact. It also removes the dead-pin case —
with no path to mismatch, a pin cannot silently fail to fire.

It does cost program resolution. sandbx opens the file, so sandbx and not libc's
`execvp` resolves the name, and a bare name would be resolved against the `PATH`
the *policy* imposes — hashing one file and execing another. A pin therefore
requires an absolute program. Resolving `PATH` in sandbx's own code would mean
reimplementing `execvp`'s search inside the security-critical path, for a flag
whose point is naming one exact binary. Unpinned runs keep today's behaviour.

Refused in two places on purpose: the CLI returns a `PolicyError` naming what to
write instead, because only there is the program in scope to put in the advice,
and the wire refuses it again as `BadHelperArgs`, because a hand-built argv does
not pass through the CLI.

## Not trust-on-first-use

TOFU needs somewhere to persist the record, which is #108's state directory, and
it pins whatever was on disk the first time — change detection, not authorization.
An explicit digest says what the operator decided. `sandbx hash PATH` exists so
that digest need not be produced by hand: a pin has to be taken before there is a
policy to take it under, which is why that one subcommand confines nothing.

## No warning mode

A mismatch refuses before anything executes. There is no `--pin-warn`, because the
bypass already exists and is omitting the digest. The refusal carries its own label
on the audit channel so the trail can tell it from a command that ran and exited 1;
the two digests reach the operator on stderr, the channel carrying an empty detail
as every other refusal does (`context/decision-helper-audit-channel.md`).
