# Why the port allowlist denies UDP

`--allow-network 443` says egress reaches port 443 and nowhere else. Landlock's
network rules police TCP bind and connect and nothing else, so with UDP left open
that sentence is false: a command confined to one TCP port could still send
datagrams to any host on any port. The repo rule that `SECURITY.md` must never
overstate the sandbox then leaves two choices — weaken the claim, or deny the
transports that falsify it. The claim is the product. The transports go.

So, whenever a port list is in force, seccomp denies on `socket`:

```
type & 0xf != SOCK_STREAM, domain != AF_UNIX        ◄── 15 rules
domain in {AF_INET, AF_INET6}, protocol not in {0, IPPROTO_TCP}   ◄── 2 rules
```

## What it costs

Named here rather than discovered later, and repeated in `SECURITY.md` because
the cost belongs next to the claim it buys:

- **Name resolution fails.** `getaddrinfo` can reach neither a UDP resolver nor
  `AF_NETLINK`, which is a `SOCK_DGRAM` socket, so it cannot enumerate
  interfaces either. This is the big one, and the usual way the allowlist first
  surprises someone: `--allow-network 443 -- curl https://example.com` fails at
  resolution, not at connect. Tracked as #147.
- QUIC and HTTP/3, which are UDP.
- `ping` and anything else over ICMP, which is a raw socket.
- MPTCP and SCTP, which are stream sockets the Landlock hooks do not police.

A bare `--allow-network` is unaffected by any of it.

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
way the type rules do, because those two families are exactly `sk_is_inet`. A
port allowlist makes no claim about a vsock or a Bluetooth stream, so it must not
quietly refuse one. Protocol 0 passes beside `IPPROTO_TCP`: it means the family's
default for the type, which for a stream socket is TCP.

## What was rejected

**Allowing UDP on port 53 only.** The obvious fix for the DNS cliff, and it is
not expressible. seccomp gates the `socket` call, where no port exists yet, and
`connect`'s `sockaddr` is behind a pointer the filter cannot follow. #147 holds
the options that are expressible.

**Narrowing the denial to `connect`/`sendto` rather than `socket`.** Same wall,
one syscall later: the destination is always behind a pointer.

**Installing a port list for `Denied` too, as belt and braces.** It would break
`bind` on loopback for every default-policy run, which programs do use for local
IPC, buys nothing over an already-empty netns, and would make the *default* path
depend on Landlock's net handling having succeeded.
