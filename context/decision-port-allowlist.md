# What a port allowlist has to deny, and what a per-host one would cost

`--allow-network 443` says egress reaches port 443 and nowhere else. Landlock's
network rules police TCP bind and connect and nothing else, so with UDP left open
that sentence is false: a command confined to one TCP port could still send
datagrams to any host on any port. The repo rule that `SECURITY.md` must never
overstate the sandbox then leaves two choices — weaken the claim, or deny the
transports that falsify it. The claim is the product. The transports go.

Three other things falsify it the same way, each by reaching a TCP port without
passing the hook Landlock's port rules hang off: a stream socket carrying a
protocol other than TCP, a stream socket in a family that tunnels IP, and TCP
Fast Open. Whenever a port list is in force, seccomp denies on `socket`:

```
type & 0xf != SOCK_STREAM, domain != AF_UNIX                           ◄── 15 rules
type & 0xf == SOCK_STREAM, domain not in {AF_UNIX, AF_INET, AF_INET6}  ◄──  1 rule
domain in {AF_INET, AF_INET6}, protocol not in {0, IPPROTO_TCP}        ◄──  2 rules
```

on `setsockopt`, because the family is not fixed at `socket` time:

```
level == SOL_TCP, optname == TCP_ULP                                   ◄──  1 rule
```

and on `sendto`, `sendmsg` and `sendmmsg`:

```
flags & MSG_FASTOPEN                                                   ◄──  3 rules
```

## What it costs

Named here rather than discovered later. `SECURITY.md` carries the effects next
to the claim they buy — resolution failing, `bind` refused on an unlisted port,
QUIC, HTTP/3, `ping`, kTLS, `TCP_ULP`, TCP Fast Open — and the denials only as
classes: UDP, raw sockets, another protocol, a family that tunnels IP. What it
does not carry is why any effect follows, and `AF_NETLINK` it does not name at
all. That one is the reason resolution fails, so it lives here or nowhere.
MPTCP, SCTP, AF_VSOCK, AF_BLUETOOTH and `espintcp` are named here alone too:

- **Name resolution fails.** `getaddrinfo` can reach neither a UDP resolver nor
  `AF_NETLINK`, which glibc opens as a `SOCK_RAW` socket, so it cannot enumerate
  interfaces either. This is the big one, and the usual way the allowlist first
  surprises someone: `--allow-network 443 -- curl https://example.com` fails at
  resolution, not at connect. `--dns-over-tcp` is the way out, and it does not
  reach every command: see *Resolving anyway, over TCP* below.
- **`bind` fails on every port the list does not name**, including `bind(port 0)`
  — the ephemeral port a program asks for when it wants a local listener, which
  an allowlist cannot express. `handled_net_access` hands Landlock `BindTcp`
  alongside `ConnectTcp`, so handling the axis at all denies both directions on
  an unlisted port. A test harness that stands up a local HTTP mock on
  `127.0.0.1:0` works under the default policy, whose empty netns leaves `bind`
  alone, and fails under `--allow-network <port>`. The narrower-looking flag is
  not narrower on this axis.
- QUIC and HTTP/3, which are UDP.
- `ping` and anything else over ICMP, which is a raw socket.
- MPTCP and SCTP, which are stream sockets the Landlock hooks do not police.
- AF_VSOCK and AF_BLUETOOTH streams, caught by the family allowlist below.
- TCP Fast Open, for any client that asks for it by flag.
- Every TCP upper-layer protocol, since the `TCP_ULP` denial is the option and
  not the ULP name — in practice in-process kTLS, which userspace TLS libraries
  do not use, and `espintcp`.

A bare `--allow-network` is unaffected by any of it.

## Resolving anyway, over TCP

DNS has a TCP transport, and TCP 53 is a port a Landlock rule can name. glibc's
stub resolver takes it when `RES_OPTIONS` contains `use-vc`, so the whole cliff
comes down to one environment variable:

```
--dns-over-tcp --allow-network 53 --allow-network 443 --allow-read /etc
```

`--allow-read /etc` is part of it, and is needed under *any* network policy: `/etc`
is not in `SYSTEM_EXECUTABLE_PATHS`, and nothing else grants `resolv.conf` or
`nsswitch.conf`. The flag is why it is one line and not an incantation nobody
finds.

Two sharp edges in that line, both outside what the flag can fix. `--allow-read`
is a path flag, so it suppresses the working-directory default — the recipe has
to name the command's own tree as well or take it away. And a Landlock rule
covers the resolved target, not the link: where `resolv.conf` points out of
`/etc`, as it does under systemd-resolved, the grant on `/etc` does not reach the
file. `--allow-read /run/systemd/resolve` is the rest of it there.

Two things it is not. It **grants no port**: the operator still writes
`--allow-network 53`, because a flag that opened a port of its own would put a
port on the audit trail that nobody named — the same defect as reporting a count
the policy does not hold. And it is a **hint, not enforcement**: the API spells it
`hint_dns_over_tcp` rather than `allow_`, because what happens next is the
resolver's choice. A command carrying its own resolver ignores `RES_OPTIONS`
entirely, and musl has no equivalent — it starts on UDP and falls back to TCP only
on a truncated reply, so a statically linked musl binary does not resolve by this
route at all. Enforcing it would mean a resolver answering for the sandboxed
command — the one piece *What a per-host egress allowlist would cost*, below,
finds claimable out of the proxy it prices, and the only route a static musl
binary has to a name (#145).

## The host network namespace is shared, not narrowed

`allows_network()` is true for `Ports`, so `hardening::isolate` drops
`CLONE_NEWNET` — a port rule inside an empty netns would have nothing to permit.
The consequence is worth stating plainly: a port allowlist puts the command in
the *host's* network namespace, where the default policy had it in an empty one.
So `--allow-network 8080` reaches a developer's own `127.0.0.1:8080`, and the
host's abstract unix socket namespace is no longer isolated either — only the
`socket(AF_UNIX)` denial stands between the command and it, which
`--allow-unix-sockets` lifts.

A port allowlist is therefore not uniformly narrower than `Denied`. It is
narrower on which remote ports are reachable and wider on what is local.

## Why not for `Denied` or `AnyPort`

The denial is gated on `NetworkPolicy::Ports` with an exhaustive match, so a
fourth state would not compile rather than inherit an answer.

`Denied` already runs in an empty network namespace, where a datagram has nowhere
to send — denying the socket adds no confinement, and would cost `AF_NETLINK`,
which glibc's `getaddrinfo` needs in the most-used configuration of all. A
regression for no gain.

`AnyPort` asked for unrestricted egress. Denying UDP there would make the sandbox
*narrower* than the flag says, which is the same kind of defect as overstating
it: either way the documentation and the mechanism disagree.

## Why the mask, and why all fifteen values

`__sys_socket` reads the socket type as `type & SOCK_TYPE_MASK`
(`include/linux/net.h`, `0xf`) and treats the bits above as
`SOCK_NONBLOCK`/`SOCK_CLOEXEC`. `SOCK_DGRAM | SOCK_CLOEXEC` is `0x8_0002` — the
spelling every modern library uses — so an `Eq` against `SOCK_DGRAM` matches none
of them while the kernel still hands back a datagram socket. `MaskedEq(0xf)` is
the comparison, not a tidier `Eq`.

And every value of that 4-bit field except `SOCK_STREAM`, rather than naming
`SOCK_DGRAM` and `SOCK_RAW`. An allowlist over four bits is fifteen cheap rules
and is total; a denylist of two constants is a guess about what the field can
mean. It also closes `SOCK_SEQPACKET`, `SOCK_RDM`, `SOCK_DCCP`, `SOCK_PACKET`
and whatever a later kernel assigns, with no further thought required.

`SOCK_RAW` is mostly unreachable anyway — it needs `CAP_NET_RAW`, which the
supervisor drops. It stays in the mask because the allowlist's integrity must not
rest on another subsystem having succeeded.

## Why the protocol rules exist at all

`SOCK_STREAM` is not TCP. `hook_socket_connect` asks for `CONNECT_TCP` only where
`sk_is_tcp` holds, which `include/net/sock.h` defines as `sk_type == SOCK_STREAM
&& sk_protocol == IPPROTO_TCP`, and returns 0 — *unrestricted* — for every other
socket. So `socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP)` was a stream socket no
port rule ever saw, and the type enumeration cannot catch it: `SOCK_STREAM` is
the type the allowlist is about and has to pass. MPTCP is the one that matters in
practice, being built into distribution kernels with no module to load.

Those two rules name `AF_INET` and `AF_INET6` instead of excluding `AF_UNIX` the
way the type rules do, because those two families are exactly `sk_is_inet` —
beyond them a protocol number means something else entirely. Protocol 0 passes
beside `IPPROTO_TCP`: it means the family's default for the type, which for a
stream socket is TCP.

## Why stream sockets are allowlisted by family

A protocol rule scoped to the IP families leaves a stream socket in some *other*
family untouched, and a family that tunnels IP dials its inner socket from inside
the kernel. `smc_connect` (`net/smc/af_smc.c`) calls
`kernel_connect(smc->clcsock, …)`, and `kernel_connect` goes straight to
`sock->ops->connect` without `security_socket_connect` — so no Landlock hook
runs and no port rule is consulted. `socket(AF_SMC, SOCK_STREAM, SMCPROTO_SMC)`
needs no privilege, autoloads `net-pf-43`, and reached any TCP port. AF_TIPC and
AF_IB are the same shape.

Hence one rule denying a stream socket in any family but `AF_UNIX`, `AF_INET` and
`AF_INET6`, rather than a denylist of the families known to tunnel — the same
argument as the type field, one layer up. It costs AF_VSOCK and AF_BLUETOOTH
streams under an allowlist, which is the right side of the trade: a vsock to the
hypervisor is egress the allowlist makes no promise about, and silently
permitting it is the failure mode, not refusing it.

### `socket` is not the only entrance

The family rule guards `socket`, and a socket's family does not stay fixed there.
`setsockopt(fd, SOL_TCP, TCP_ULP, "smc")` on an ordinary
`socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)` — exactly the shape the allowlist is
designed to permit — runs `smc_ulp_init`, which assigns
`file->private_data = smcsock`. `sock_from_file` reads that field, so a later
`connect` on the same descriptor dispatches to `smc_connect` and lands in the
`kernel_connect` path above; `sk_is_tcp` is false for the `PF_SMC` sock, so
Landlock's hook returns 0, meaning unrestricted. Nothing privileged is involved:
`__tcp_ulp_find_autoload`'s `CAP_NET_ADMIN` check gates the module *autoload*,
not the lookup of a ULP already resident, and `do_tcp_setsockopt`'s `TCP_ULP`
case has no check of its own. The denial is therefore a second rule on a second
syscall, not a wider version of the family rule.

Only the option can be named, not the ULP: `optval` is a pointer, which is the
same wall as a destination check. So `TCP_ULP` goes entirely, which is also the
fail-closed shape — a ULP added to the kernel tomorrow is denied without an edit.

The bypass is live from v6.14 on. Before it, `current_check_access_socket` gated
on `sock->type != SOCK_STREAM` rather than `sk_is_tcp`, so a converted socket
reached the `sa_family != skc_family` check and the connect failed with `-EINVAL`
of its own accord. `BASELINE_ABI` is V5, which Linux 6.10 reports, so sandbx does
run on kernels where this was already closed — the rule is unconditional
regardless, since the policy may not depend on which side of that boundary the
host is on.

## Why TCP Fast Open is denied

`tcp_sendmsg_locked` routes a send carrying `MSG_FASTOPEN` into
`tcp_sendmsg_fastopen`, which calls `__inet_stream_connect` directly
(`net/ipv4/tcp.c`). `security_socket_connect` is reached only from
`__sys_connect_file`, so the destination in `msg_name` is a port Landlock never
sees — and `net.ipv4.tcp_fastopen` has client mode enabled by default on
mainline and on every mainstream distribution. The connect happens *inside a
send*, which is why the rules live on `sendto`, `sendmsg` and `sendmmsg` and not
on `socket`.

Expressible, unlike a destination check, because `MSG_FASTOPEN` is a flag in a
register rather than anything behind a pointer. An ordinary send never sets it,
so the cost is confined to clients that opt in by flag.

The `TCP_FASTOPEN_CONNECT` sockopt is a different path and needs no rule: it
defers the handshake but still goes through the `connect` syscall, so
`security_socket_connect` runs on the address and the port rules apply.

## What was rejected

**Allowing UDP on port 53 only.** The obvious fix for the DNS cliff, and it is
not expressible. seccomp gates the `socket` call, where no port exists yet, and
`connect`'s `sockaddr` is behind a pointer the filter cannot follow. What is
expressible is TCP 53, which is what `--dns-over-tcp` is for.

**Setting `RES_OPTIONS=use-vc` whenever a port list is in force.** It would make
the common case work with no flag, and sandbx would be reaching into the
command's configuration without being asked — invisibly overriding a
`resolv.conf` option the operator may have set deliberately. Explicit, or not at
all.

**Narrowing the denial to `connect`/`sendto` rather than `socket`.** Same wall,
one syscall later: the destination is always behind a pointer.

**Installing a port list for `Denied` too, as belt and braces.** It would break
`bind` on loopback for every default-policy run, which programs do use for local
IPC, buys nothing over an already-empty netns, and would make the *default* path
depend on Landlock's net handling having succeeded.

## What a per-host egress allowlist would cost

`--allow-network 443` bounds egress to a port and not to a host. The only thing
that could bound it to a host is a userspace proxy, and this is what each piece
of one would be worth — which of them is a kernel refusal, which is a program's
cooperation, and which widens the boundary it is meant to narrow. What the port
allowlist does claim is everything above; what `SECURITY.md` may say is the test
applied throughout.

One piece survives it, and it is not the one the heading is about: a resolver can
bound *which names resolve*, because sandbx can hold the whole route to a name.
That piece is `--allow-dns NAME` (#145); the mechanism it ships with is not the
one this note first specified, and the paragraphs below say what moved and why.
Nothing here bounds where a command connects.

### No kernel mechanism sees a destination

Landlock's network rule is `NetPort::new(port, rights)` (`helper/mod.rs`'s `apply`)
and there is no address in that shape. seccomp compares register values, and the
`sockaddr` carrying the destination is behind a pointer the filter cannot follow
— at `connect`, at `sendto`, and at every syscall further down the chain, which
is why narrowing the check buys nothing (*What was rejected*, for the port
allowlist, above).

So a destination becomes a *value* in exactly one place: after a connection has
been terminated and re-originated by something that reads the address itself.
That is the proxy, and it is why this question cannot be answered with a smaller
mechanism.

The practical reading of the gap: a port allowlist stops a command reaching an
SSH port or a database. It does not stop one exfiltrating over HTTPS, which is
the threat the README puts first.

### Five pieces, and the tier each one lands in

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

**The listener has no free spelling.** `decision-credentials.md`'s channel
table applies to this unchanged, because it is the same question asked for a
secret instead of a destination: loopback TCP means `--allow-network <port>`,
which drops `CLONE_NEWNET` (`helper/hardening.rs`'s `isolate`) and puts the
command in the host's netns; a unix socket means `--allow-unix-sockets`, one
boolean covering every pathname socket the filesystem policy reaches
(`SandboxPolicy::allow_unix_sockets`); stdin and stdout are spent on the
command's own I/O. A proxy that bounds egress by granting a network the command
did not previously have refutes itself.

**Interception is cooperation, and sandbx ships the binary that defeats it.**
`decision-credentials.md` has this in full. Whatever is built, the claim is
scoped to cooperating clients or it overstates.

**Termination widens the boundary it is meant to narrow**, the same way and for
the same reasons as for a credential, which is where
`decision-credentials.md` settles it.

Credential substitution needs termination to read the request it substitutes
into, so it leaves with termination. #41 ends in a refusal rather than a
mechanism and `decision-credentials.md` is where that was decided; nothing
here reopens it.

### SNI without termination reads a value the client chose

The tempting middle: read the `ClientHello`, match the server name, forward or
drop, and never hold a key. It avoids the widening, and it is still cooperation
— a weaker kind than `HTTP_PROXY`, because it looks like inspection.

The name in an SNI extension is composed by the client. A client that omits it,
that sends one name and requests another in the HTTP `Host` header, or that uses
Encrypted ClientHello, reaches the address it dialled regardless: the `connect`
named an address, the proxy matched a string, and the two were never required to
agree. Filtering on it bounds a cooperating client's *stated intent*, which is
not a destination control and must not be written as one.

### Why the resolver is the exception

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
under *What was rejected for a host* — and #145 holds the position a different way, which
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
(*Resolving anyway, over TCP*, above), so that gap closes here or nowhere. The
files close it: musl reads `/etc/hosts`, and a static binary reads it too.

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

### A name outside the allowlist is absent, not refused

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

### The claim, written first

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
the one `decision-credentials.md` applied to the same proxy from the other
side.

The first sentence is now in `SECURITY.md`'s *What sandbx claims to enforce*
table, in the form that table's rows take. The per-host sentence is not, and the
non-claim beside it stays and carries the verdict so the next reader does not
re-derive it.

### No unenforced field, which is how the allowlist landed

**No host field may enter `SandboxPolicy` before something enforces it, and no
name allowlist either.** The type is read as the record of what was granted
(`policy/sandbox.rs`), so a field nothing honours tells its next reader that a grant
is respected. This is the rule that kept #42 to per-port, and it is the same rule
`decision-credentials.md` states for a credential placeholder, under the
same heading. An intermediate step, if one is wanted, is a separate opt-in type
the enforcement path rejects outright — not an unenforced field on the existing
one.

The name allowlist was held to it in the harder direction — the allowlist is the
thing being enforced — and discharged rather than waived: #145 landed
`dns_names`, the mounts that honour it and the enforcement tests in one commit.
The rule still stands for a *host* field, which nothing enforces and which the
five pieces above say nothing can.

### What was rejected for a host

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

### What declining it costs

Nothing stops working: a run that passes no `--allow-dns` resolves exactly what
it resolved before, unshares no mount namespace, and reads the host's own `/etc`.
What the decision buys is that the next reader of `--allow-network <port>` finds
the proxy already priced: four of its five pieces decided against, the fifth
built, and the `SECURITY.md` non-claim saying which is which rather than
recording an absence.
