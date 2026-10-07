# What a per-host egress allowlist would cost

`--allow-network 443` bounds egress to a port and not to a host. The only thing
that could bound it to a host is a userspace proxy, and this is what each piece
of one would be worth — which of them is a kernel refusal, which is a program's
cooperation, and which widens the boundary it is meant to narrow. What the port
allowlist does claim is `decision-port-allowlist.md`; what `SECURITY.md` may say
is the test applied throughout.

One piece survives it, and it is not the one the title is about: a resolver can
bound *which names resolve*, because sandbx can hold the whole route to a name.
Nothing here bounds where a command connects.

## No kernel mechanism sees a destination

Landlock's network rule is `NetPort::new(port, rights)` (`helper/mod.rs:420`)
and there is no address in that shape. seccomp compares register values, and the
`sockaddr` carrying the destination is behind a pointer the filter cannot follow
— at `connect`, at `sendto`, and at every syscall further down the chain, which
is why narrowing the check buys nothing (`decision-port-allowlist.md`, *What was
rejected*).

So a destination becomes a *value* in exactly one place: after a connection has
been terminated and re-originated by something that reads the address itself.
That is the proxy, and it is why this question cannot be answered with a smaller
mechanism.

The practical reading of the gap: a port allowlist stops a command reaching an
SSH port or a database. It does not stop one exfiltrating over HTTPS, which is
the threat the README puts first.

## Five pieces, and the tier each one lands in

The project keeps three tiers of verb and they are not interchangeable: a kernel
refusal is **enforcement**, a mechanism a program can simply ignore is
**cooperation**, and a mechanism that reads what it was not reading before is a
**widening** whatever else it buys.

| | |
|---|---|
| a listener the command can reach | neither — a transport, and granting it widens the sandbox |
| interception, so an unmodified command is proxied | cooperation |
| TLS termination, so the allowlist is about names | widening |
| credential substitution per destination | widening, following termination |
| a resolver answering for allowlisted names | enforcement, of resolution only |

**The listener has no free spelling.** `decision-tool-credentials.md`'s channel
table applies to this unchanged, because it is the same question asked for a
secret instead of a destination: loopback TCP means `--allow-network <port>`,
which drops `CLONE_NEWNET` (`helper/hardening.rs:240`) and puts the command in
the host's netns; a unix socket means `--allow-unix-sockets`, one boolean
covering every pathname socket the filesystem policy reaches (`policy.rs:92`);
stdin and stdout are spent on the command's own I/O. A proxy that bounds egress
by granting a network the command did not previously have refutes itself.

**Interception is cooperation, and sandbx ships the binary that defeats it.**
`decision-tool-credentials.md` has this in full: `HTTP_PROXY` binds only
programs that read it and only for HTTP; a transparent redirect needs `nftables`
rules inside a netns, which needs privileges sandbx does not hold; an
`LD_PRELOAD` shim on `connect` is stepped around by a static binary and by a
direct syscall, and the release artifacts are static musl. Whatever is built,
the claim is scoped to cooperating clients or it overstates.

**Termination widens the boundary it is meant to narrow**, the same way and for
the same reasons as for a credential, which is where
`decision-tool-credentials.md` settles it: the command trusts a CA sandbx
controls, so it can be man-in-the-middled for every destination and not only the
allowlisted ones, and the harness reads plaintext it previously could not.
Against a model choosing a tool call's arguments from untrusted text, that is
the wrong direction.

Credential substitution needs termination to read the request it substitutes
into, so it leaves with termination. #41 ends in a refusal rather than a
mechanism and `decision-tool-credentials.md` is where that was decided; nothing
here reopens it.

## SNI without termination reads a value the client chose

The tempting middle: read the `ClientHello`, match the server name, forward or
drop, and never hold a key. It avoids the widening, and it is still cooperation
— a weaker kind than `HTTP_PROXY`, because it looks like inspection.

The name in an SNI extension is composed by the client. A client that omits it,
that sends one name and requests another in the HTTP `Host` header, or that uses
Encrypted ClientHello, reaches the address it dialled regardless: the `connect`
named an address, the proxy matched a string, and the two were never required to
agree. Filtering on it bounds a cooperating client's *stated intent*, which is
not a destination control and must not be written as one.

## Why the resolver is the exception

A resolver is not egress enforcement and the claim must not imply it is — an IP
literal walks past it, and so does any address the command already holds. What
it can bound is resolution, and there it holds the whole route rather than part
of one.

Under a port allowlist seccomp already denies UDP and raw sockets, so
`getaddrinfo` can reach neither a UDP nameserver nor `AF_NETLINK`
(`helper/seccomp/rules.rs:182-190`). The one transport left is TCP, on a port
the operator names. If the proxy is what answers on it, a name outside the
allowlist has nowhere else to be asked — the enforcement is positional, the same
shape as the credential refusal, and it needs no interception and no termination
to be true.

It is also the only route to resolution for a statically linked musl binary.
`--dns-over-tcp` is a glibc resolver hint and musl has no equivalent
(`decision-port-allowlist.md`), so that gap closes here or nowhere.

## A refused name gets REFUSED

`REFUSED` (RCODE 5), and a refusal record on the sandbx side.

**`NXDOMAIN` would lie.** It asserts the name does not exist, which is a
statement about the world where the fact is a statement about policy. An
operator debugging reads "typo" where the truth is "this policy did not name
it", and a client caching the negative answer then fails for a reason that
outlives the lookup.

**Answering nothing is worse than either.** It is a client-side timeout, the
diagnostic #147 existed to remove — the confusing part there was that resolution
failed silently where the operator was watching the port.

`REFUSED` is the only code that means the server declines, which is exactly the
fact, and a stub resolver with no other nameserver to try stops there rather
than retrying the name.

The record reuses `AuditEvent::denied(tool, subject, reason)` (`audit.rs:100`)
with the proxy as the tool, so a refused name reads as `decision="denied"` like
every other refusal. Two things it must not do. It must not add a label to
`REPORTED_BY_HELPER` (`error.rs:290`): that set is closed around what crosses
the helper's audit channel, and this refusal is decided harness-side, where no
channel is involved. And it must not be the only signal — today
`AuditEvent::Denied` is emitted by `fs_guard.rs` alone, so a resolver refusal is
the first egress-shaped one, and the operator-facing failure has to be legible
without the trail.

## The claim, written first

The resolver's sentence:

> sandbx answers DNS for the sandboxed command itself and resolves only the
> names you allowlisted. A name you did not name is answered `REFUSED` and
> recorded as a refusal. This bounds which names resolve; it does not bound where
> the command connects — an address the command already holds, or obtains by any
> route other than this resolver, is reachable on any allowlisted port exactly as
> before.

The per-host sentence:

> sandbx bounds egress to the hosts you allowlisted — provided the program
> honours `HTTP_PROXY`, is not statically linked and does not `connect` directly;
> and provided you install the CA sandbx generates, after which sandbx reads
> every byte the tool sends.

The first writes plainly and names its own limit in the same breath. The second
cannot be written without the conditions that empty it. That is the whole
verdict: the resolver is a mechanism, per-host egress is not, and the test is
the one `decision-tool-credentials.md` applied to the same proxy from the other
side.

Neither sentence is in `SECURITY.md`'s *What sandbx claims to enforce* table,
and the first does not go there until a resolver makes it true. The non-claim
that table's counterpart already carries stays, and gains the verdict so the
next reader does not re-derive it.

## What must not happen in the meantime

**No host field may enter `SandboxPolicy` before something enforces it, and no
name allowlist either.** The type is read as the record of what was granted
(`policy.rs:87`), so a field nothing honours tells its next reader that a grant
is respected. This is the rule that kept #42 to per-port, and it is the same rule
`decision-tool-credentials.md` states for a credential placeholder, under the
same heading. An intermediate step, if one is wanted, is a separate opt-in type
the enforcement path rejects outright — not an unenforced field on the existing
one.

The resolver inherits it in the harder direction: the name allowlist is the
thing being enforced, so it may not be recorded until the resolver answers for
it.

## What was rejected

**SNI filtering as a destination control.** Covered above: a string the client
composed, matched against a policy, while the bytes go to the address it
dialled.

**`NXDOMAIN` for a name outside the allowlist.** A policy refusal dressed as a
fact about the world, cacheable as one.

**A host field recorded now and enforced later.** The trap the rule above exists
to close.

**`nftables` redirect inside a network namespace**, the one interception a
static binary cannot step around. It needs the netns back — which a port
allowlist gives up because a port rule inside an empty one has nothing to permit
— and privileges to write rules that sandbx does not hold and should not
acquire.

**Shipping the proxy with the claim scoped to cooperating clients.** Honest as a
sentence and wrong as a product: it is a new network-facing service with a new
trust boundary, and no crate depends on a server-side HTTP stack today, in a
project whose claim is that the boundaries are kernel ones. The resolver is the
part that earns that cost, and it earns it without the rest.

## What it costs

Nothing stops working, and nothing is claimed that was not claimed before. What
the decision buys is that the next reader of `--allow-network <port>` finds the
proxy already priced: four of its five pieces decided against, one carved out
with its claim written, and the `SECURITY.md` non-claim saying which is which
rather than recording an absence.

The honest summary is that per-host egress is not a mechanism sandbx can have,
and that the resolver, which was only ever a component of it, is.
