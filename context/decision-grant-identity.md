# A grant names an object, not a name

A policy is judged in the harness and its rules are opened in the helper. #205
closed the symlink half of that seam: every grant crosses already resolved, and
`open_grant` reads each descriptor back through `/proc/self/fd` and refuses the
whole run when the link names something other than what it was told to open. A
link redirected in between reads back as its target, and the run refuses.

What that leaves open is substitution of one *real* directory for another at the
same name. A `rename(2)` over the vetted path — no symlink anywhere — leaves the
spelling identical, so the readback agrees and Landlock is handed rules over a
directory the harness never vetted. The window is between the resolve in the
harness and `PathFd::new` in the helper, and reaching it needs write access to
the granted path's parent.

#212 closes it by making the comparison about the object: the harness carries the
`(dev, ino)` it vetted across the seam, and the helper stats the descriptor and
refuses a mismatch. The decision this note records is not that — it is the
question #212 mainly exists to settle, which is **what the helper does with a
grant that arrives with no pin**. The answer is that it refuses, and that nothing
can hand it one.

## Refusing is the only answer, so the work is making it unreachable

Accepting an unpinned grant makes the inode comparison opt-in. SECURITY.md's
claim is default-deny *at the library level, which is the level that is a
boundary*; a guarantee that holds for the CLI and lapses for a library caller is
a claim the code no longer earns, and the caller who would most benefit from the
pin is exactly the one who would not know to ask for it. So the helper refuses.

That settles the helper and leaves the real cost on the other side. `SandboxPolicy`
is public, its builders are public, and `grant` is the one place a path enters a
policy — so a refusal reaches every library embedder and the system-executable
grants `allow_system_executables` adds for itself. A refusal at run time would be
the worst version of a correct decision: the embedder learns at the refused run
what a type could have told it at `cargo build`.

So the pin travels **inside** the grant rather than beside it. A vetted-path value
carries the resolved path and its `(dev, ino)` together, `grant` takes that
instead of a bare path, and there is no unpinned state for the helper to have a
policy about. The refusal still exists — `decode` refuses a wire grant with no
pin — but no construction path in the crate can reach it, so what an embedder
actually meets is a signature change. (#212 settles the type's name; this note
settles that there is one.)

## `grant` stays I/O-free

The invariant on `SandboxPolicy::grant` is not a performance note. `HelperArgs::decode`
builds a policy through `grant` too, inside the helper — the process a grant is
meant to be safe from — so resolving there would resolve against whatever the
links point at by then, and the comparison would be against the attacker's
answer. The same reasoning forbids stat'ing there.

Two producers, therefore, and the asymmetry between them is the whole design:

```
harness   vet(path)        resolve, then stat   ──►  path + (dev, ino)
helper    decode(argv)     no I/O at all        ──►  path + (dev, ino)
```

The helper's producer is crate-private and reads the pin off argv. That is not a
weaker source: argv is the harness's own, passed from stage 1 to stage 2 verbatim
and never re-encoded, and the path token has always been trusted on exactly that
basis. What the pin removes is the reliance on the *filesystem* agreeing between
the two processes, which is the only party the seam was ever exposed to.

## The pin is taken where the check is

`Grants::policy` resolves each grant and then asks `reaches_owned` whether it
covers something sandbx owns. The stat belongs there, beside that check, so the
pinned object is the object the operator's refusal was evaluated against. Pinning
anywhere earlier would pin something the check had not yet applied to; anywhere
later and the two could already disagree.

`allow_system_executables` pins at the site it already canonicalizes, which is
inside the library rather than in the CLI. That matters because it is the one
grant set a caller gets without going through `Grants::policy` at all, and
leaving it unpinned would reintroduce the unpinned case by the back door.

Between the vet and the encode is a window of its own, and it fails closed: a
rename there pins the object that was vetted, the helper opens the one that
replaced it, and the stat disagrees. Refusing is the right outcome and needs no
further mechanism.

After the rule is added there is no window at all. `PathBeneath` holds the
descriptor, so the kernel attaches the rule to that inode; a later rename moves
the name and not the rule.

## Three tokens per grant, not two

The wire form is a flag and a path, one pair per grant, in `Axis::ALL` order. The
pin is a third token on the same pair, and `decode`'s path arm refuses a pair
without it as `BadHelperArgs` — the same shape as the existing "path flag with no
path after it", and for the same reason: the decoder gates enforcement, so it
refuses anything it does not recognise rather than inferring.

`decision-enforcement-seam.md` requires a wire spelling to be one `decode`
accepts by construction. A third mandatory token keeps that property; an optional
one would not, because "is this token a pin or the next flag?" is a lookahead in
the decoder, which is the thing that file rejects.

The path token already crosses through `Path::display()` and is lossy for a
non-UTF-8 path. The pin neither fixes nor worsens that, and is not where it gets
fixed.

## The readback stays

The spelling comparison is not superseded. Three things it does that a stat does
not:

- It names both paths in the refusal. `(dev, ino)` cannot tell an operator what
  was substituted for what.
- It catches the mount cases — a `pivot_root`, an `MS_MOVE` over a granted root,
  a bind whose source is unlinked, which `read_link` reports by appending
  `" (deleted)"`. Those make every grant read back as something else.
- It is the cheap check, and it runs first.

The two answer different questions: the readback asks whether the name still
leads where it led, the stat asks whether the thing at the end of it is the same
thing.

## A rule the helper makes for itself is pinned later

`open_grant` runs in stage 2, inside whatever stage 1 unshared, so a mount made
there is a mount the comparison sees. Today that is harmless because
`hardening::isolate` unshares no `CLONE_NEWNS` and a pre-existing bind vets as
itself. It stops being harmless as soon as the helper mounts something of its
own, which is what #145 needs for `/etc/hosts`, `/etc/nsswitch.conf` and
`/etc/resolv.conf`.

The distinction to hold: an **operator** grant is vetted before the helper runs,
so its pin is taken in the harness and the stat in stage 2 must agree. A rule the
**helper** adds for itself is vetted after its own mount, so its pin is taken in
stage 2 and there is no cross-process window to close. Pinning both at the same
point refuses the helper's own resolver files — the mount moved the inode under a
name the harness had already pinned, which is indistinguishable from the attack
unless the two are kept apart.

This is also where the pin meets what can make a mount in stage 2 at all. The
helper's mounts rest on the capability drop rather than on `BLOCKED_SYSCALLS`,
and whether the newer mount API — `open_tree`, `move_mount`, `fsopen`, `fsmount`,
`mount_setattr` — belongs in the filter is #145's question, not this note's. It
is the same seam: a pin that has to survive mounts made in stage 2 is worth only
as much as the bound on what can make one.

## What it costs

**A breaking change to the policy builders.** `grant`, `allow_read`,
`allow_write` and `allow_read_execute` change signature, so every embedder
recompiles — `SandboxedCommand::new`, `FsGuard::new`, the guidance on
`ExecutionContext::new`, and the policy constructions in the tool and agent
tests. This is the cost that buys default-deny without a runtime refusal, and it
is paid once at a pre-1.0 version.

**A stat per grant, in the harness.** Beside a resolve that already walks every
ancestor, which is the expensive part.

**A property `guide-sandboxing.md` states, moving.** That file says the property
to keep is about spellings and not about mounts: a file bind-mounted over
`/etc/hosts` reads back `/etc/hosts`, measured, and is fine. Under the pin that
holds only for a bind that existed when the grant was vetted. One made between
the vet and the open now refuses — correctly, because that is the attack, but it
is a narrowing and not a clarification.

**Nothing an operator types changes.** No flag is added, no grant narrows, and a
run whose granted directories are the ones that were vetted behaves as it did.

## What was rejected

**Accepting an unpinned grant.** Covered above: it makes a stated guarantee
conditional on the caller asking for it, and SECURITY.md's claim is about the
library level precisely because that is the level that is a boundary.

**Refusing at run time, with the pin beside the grant.** Identical security,
worse failure. A `SandboxPolicy` field next to the paths can be left unset, so
the embedder's first signal is a refused run rather than a compile error, and
`allow_system_executables` would need its own arm to avoid refusing itself.

**Inheriting the harness's `O_PATH` descriptor through the exec.** The cleaner
close, and the one that re-resolves nothing helper-side at all: no pin to carry,
no third token, no comparison to get wrong. Receiving an inherited descriptor
needs `from_raw_fd` and passing one needs `pre_exec`, both `unsafe`, against the
workspace-wide `unsafe_code = "forbid"` that no crate overrides. Rejected on the
lint, not on the design, and it is the shape to return to if the lint ever gains
a carve-out.

**Treating the stat as equally blocked.** #212's own text reads as though the
lint prices both remedies out. It does not: `nix` is already a `sandbx-core`
dependency with the `fs` feature, so `fstat` over an `AsFd` is safe and in-tree,
and `fs::metadata` on `/proc/self/fd/<n>` is a second route with no new
dependency, resolving the magic link to the inode the descriptor holds rather
than by name. Only the descriptor-inheritance route is lint-blocked.

**Resolving in the helper instead.** The oldest rejected shape, recorded on
`grant` and restated here because the pin makes it tempting a second time: with a
stat available, "just canonicalize helper-side and compare" looks like it needs
no seam change. It resolves in the process the grant is meant to be safe from.
