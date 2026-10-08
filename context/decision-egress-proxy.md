# What a per-host egress allowlist would cost

`--allow-network 443` bounds egress to a port and not to a host. The only thing
that could bound it to a host is a userspace proxy, and this is what each piece
of one would be worth — which of them is a kernel refusal, which is a program's
cooperation, and which widens the boundary it is meant to narrow. What the port
allowlist does claim is `decision-port-allowlist.md`; what `SECURITY.md` may say
is the test applied throughout.

One piece survives it, and it is not the one the title is about: a resolver can
bound *which names resolve*, because sandbx can hold the whole route to a name.
That piece is `--allow-dns NAME` (#145); the mechanism it ships with is not the
one this note first specified, and the paragraphs below say what moved and why.
Nothing here bounds where a command connects.

## No kernel mechanism sees a destination

Landlock's network rule is `NetPort::new(port, rights)` (`helper/mod.rs`'s `apply`)
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
| a resolver bounding which names resolve | enforcement, of resolution only |

**The listener has no free spelling.** `decision-tool-credentials.md`'s channel
table applies to this unchanged, because it is the same question asked for a
secret instead of a destination: loopback TCP means `--allow-network <port>`,
which drops `CLONE_NEWNET` (`helper/hardening.rs`'s `isolate`) and puts the
command in the host's netns; a unix socket means `--allow-unix-sockets`, one
boolean covering every pathname socket the filesystem policy reaches
(`SandboxPolicy::allow_unix_sockets`); stdin and stdout are spent on the
command's own I/O. A proxy that bounds egress by granting a network the command
did not previously have refutes itself.

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
(`helper/seccomp/rules.rs`'s `blocked_syscalls`, under `confine_to_tcp`). The
one transport left is TCP, on a port the operator names. Hold the only thing
that can answer there and a name outside the allowlist has nowhere else to be
asked: the enforcement is positional, the same shape as the credential refusal,
and it needs no interception and no termination to be true.

What this note first specified as holding that position was a DNS responder of
sandbx's own. That shape cannot be built unprivileged — the measurements are
under *What was rejected* — and #145 holds the position a different way, which
costs a mount namespace and no listener at all. Stage 1 resolves each
allowlisted name through `getaddrinfo` before it unshares, then binds its own
`hosts`, `nsswitch.conf` and `resolv.conf` over `/etc` in a mount namespace the
command inherits. `hosts: files` removes glibc's `dns` source, so an unlisted
name is not asked over any transport rather than asked and refused; the
nameserver-less `resolv.conf` is for musl, which ignores `nsswitch.conf`.

Only the `hosts` and `networks` lines of `nsswitch.conf` are sandbx's; the rest
of the host's file is copied through. A body of our own would have written
`passwd: files` over a host resolving its accounts through `systemd`, `sss` or
LDAP, and a command that cannot resolve its own uid is a broken sandbox, not a
bounded one. Two host shapes refuse instead of being bounded badly: no
`/etc/nsswitch.conf` at all, where glibc would keep its built-in `dns` source;
and a symlinked `/etc/hosts` or `/etc/nsswitch.conf`, where `mount(2)` resolves
the link, the bind lands on its target, and the link is left for a write grant
on `/etc` to replace.

Positional either way, and in one respect further ahead: the responder would
have answered whatever the command asked it during the run, where a rendered
file is fixed before the command starts.

It is also the only route to resolution for a statically linked musl binary.
`--dns-over-tcp` is a glibc resolver hint and musl has no equivalent
(`decision-port-allowlist.md`), so that gap closes here or nowhere. The files
close it: musl reads `/etc/hosts`, and a static binary reads it too.

One consequence worth stating in the other direction, because it is the only flag
that has it: `--allow-dns` makes `--allow-read /etc` unnecessary, and makes a grant
naming one of the files it replaces a refusal. Landlock binds a rule to the inode,
so by the time stage 2 opens those three paths they are sandbx's files, and the
read rules `ruleset::rights` adds for them reach nothing else. A grant naming one
of them is pinned to the host's file instead, which the bind has already replaced —
so `SandboxPolicy::grant_bound_by_resolver` refuses the pair, as
`GrantBoundByResolver` from `command_line` and as `PolicyError::DnsGrantsBoundFile`
at the flag. Which names those are is `resolver::bound_by_resolver`, and it takes
each entry both by its own name and by what that name resolves to: a systemd
`/etc/resolv.conf` is a symlink, `mount(2)` resolves its target, so the bind lands
on the stub and a grant spelling the stub directly is refused too. The resolving is
of the entries and never of the operator's path, which arrives resolved already.
Exact names and not the directory holding them: binding a file inside `/etc` leaves
`/etc`'s own inode alone, so `--allow-read /etc` beside the flag still works, and it
is what a command that needs the rest of the directory should pass — which is what
both refusals now say. The alternative route — `--dns-over-tcp --allow-network 53
--allow-read /etc` — grants the command the whole directory and leaves every name
resolvable.

## A name outside the allowlist is absent, not refused

There is no response code, because there is no responder. An unlisted name has
no line in the hosts file and glibc has no other source to try, so
`getaddrinfo` returns `EAI_NONAME` — "Name or service not known", at once and
with no timeout. `curl` prints `Could not resolve host` and exits 6.

That is as legible as the `REFUSED` this note specified, and it arrives by the
path every other resolution failure arrives by, which the `REFUSED` route could
not claim: a stub resolver reads an RCODE, a shell script reads the exit code.
**It is also indistinguishable from a typo**, which `REFUSED` was chosen to
avoid, and that is the cost. It is paid where the operator is: `sandbox.rs`'s
advice names `--allow-dns NAME` as the first of the two answers, and the
refusals catch the shapes where the flag is the wrong one before the run
starts. Four of them are decided on the policy itself
(`SandboxPolicy::unbounded_resolution`), so an embedder calling
`SandboxedCommand` meets them and not only an operator typing flags, and
`HelperArgs::decode` refuses an argv carrying one. `Grants::policy` keeps all
five for their messages; the one it owns alone is a name allowlist with no
egress at all, which bounds resolution to addresses nothing can reach and is
pointless rather than unenforceable.

The refusal that is not about IP at all is `--allow-unix-sockets`: glibc asks
nscd over `/var/run/nscd/socket` *before* it
reads `nsswitch.conf`, the rendered file cannot turn that off, and
`--allow-unix-sockets` is one boolean over every pathname socket.

What the trail records is a count on `Spawned`, `dns_names`, and no per-name
record at all. The responder would have had one query per name to report;
resolution ahead of the spawn has one event, and `Spawned` carries counts and
not values (`guide-logging.md`, *What is built*) — doubly so here, an internal
host name being infrastructure rather than a pointer to it.

Two things that have not changed. No label joins `HelperRefusal::ALL`: that set
is closed around what crosses the helper's audit channel, and nothing about the
allowlist is decided on it. And the operator-facing failure is legible without
the trail, which is what the advice above is for.

## The claim, written first

The resolver's sentence, as #145 made it true:

> sandbx resolves the names you allowlisted itself, before the command starts,
> and gives the command a hosts file holding those addresses and no nameserver
> at all. A name you did not list does not resolve. This bounds which names
> resolve; it does not bound where the command connects — an address the command
> already holds, or obtains by any route other than resolution, is reachable on
> any allowlisted port exactly as before.

It is the sentence this section wrote first, with the response code taken out
and the mechanism's own shape put in. Both halves of what the test asked for
survived the mechanism changing: it is plain, and its limit is in the same
breath.

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

The first sentence is now in `SECURITY.md`'s *What sandbx claims to enforce*
table, in the form that table's rows take. The per-host sentence is not, and the
non-claim beside it stays and carries the verdict so the next reader does not
re-derive it.

## No unenforced field, which is how the allowlist landed

**No host field may enter `SandboxPolicy` before something enforces it, and no
name allowlist either.** The type is read as the record of what was granted
(`policy.rs`), so a field nothing honours tells its next reader that a grant
is respected. This is the rule that kept #42 to per-port, and it is the same rule
`decision-tool-credentials.md` states for a credential placeholder, under the
same heading. An intermediate step, if one is wanted, is a separate opt-in type
the enforcement path rejects outright — not an unenforced field on the existing
one.

The name allowlist was held to it in the harder direction — the allowlist is the
thing being enforced — and discharged rather than waived: #145 landed
`dns_names`, the mounts that honour it and the enforcement tests in one commit.
The rule still stands for a *host* field, which nothing enforces and which the
five pieces above say nothing can.

## What was rejected

**SNI filtering as a destination control.** Covered above: a string the client
composed, matched against a policy, while the bytes go to the address it
dialled.

**A DNS responder of sandbx's own, answering over TCP.** The shape this note
specified, and unbuildable unprivileged. Three measurements, on an ordinary
desktop kernel with no sandbx in the way:

- a port allowlist sets `allows_network()`, so `isolate` keeps the host netns
  (`helper/hardening.rs`), and an unprivileged `bind(127.0.0.1:53)`
  there is `EPERM` — `net.ipv4.ip_unprivileged_port_start` is 1024;
- inside a netns sandbx owns, the same bind succeeds and the netns has no route
  out, so a name it resolves is unreachable and nothing is gained;
- no port above 1024 is reachable either: neither glibc's nor musl's
  `resolv.conf` can name a port, so a stub resolver cannot be pointed at a
  listener.

`REFUSED` goes with it, being a response code with nothing to send it. What
replaced the pair is in *Why the resolver is the exception*.

**`NXDOMAIN` for a name outside the allowlist.** A policy refusal dressed as a
fact about the world, cacheable as one. Decided when the responder was still the
mechanism; the file route makes an unlisted name absent instead, which is a
third answer and not this one.

**A per-name audit record.** The responder would have had a query to report per
name. Resolution before the spawn has one event and `Spawned` carries counts, so
the trail gains `dns_names` and no names — see *A name outside the allowlist is
absent, not refused*.

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

Nothing stops working: a run that passes no `--allow-dns` resolves exactly what
it resolved before, unshares no mount namespace, and reads the host's own `/etc`.
What the decision buys is that the next reader of `--allow-network <port>` finds
the proxy already priced: four of its five pieces decided against, the fifth
built, and the `SECURITY.md` non-claim saying which is which rather than
recording an absence.

The fifth cost what the listener would have cost, in a different currency: a
mount namespace, three bind mounts and a tmpfs, only for a run that asks for
them.

The honest summary is that per-host egress is not a mechanism sandbx can have,
and that the resolver, which was only ever a component of it, is.
