# What a port allowlist has to deny besides other ports

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

Named here rather than discovered later, and repeated in `SECURITY.md` because
the cost belongs next to the claim it buys:

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
command — the one piece `decision-egress-proxy.md` finds claimable out of the
proxy it prices, and the only route a static musl binary has to a name (#145).

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
