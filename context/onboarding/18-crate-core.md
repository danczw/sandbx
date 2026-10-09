# Most of `sandbx-core` is explained somewhere else

`sandbx-core` is the largest crate in the workspace — thirty-six source files —
and it is the whole left-hand column of
[04 — the architecture](04-the-architecture.md). Every box in 04's View 1 lives
here: `FsGuard`, `spawn::command`, both helper stages, the ruleset, the filter.
Both of View 3's enforcement seams are files in this crate. And it is the only
crate whose `src/` may build a `std::process::Command` at all, which
[05 — seven crates](05-seven-crates.md) takes apart in detail.

That makes it the crate chapters `07` through `14` are mostly *about*, so this
one is not a seventh account of Landlock. It is a map: which file owns which
job, and which chapter explains it. Where a mechanism already has a chapter you
get one sentence and a link, because a worse copy of [09](09-landlock.md) two
directories away is a liability rather than a convenience. Genuinely only here:
the crate's shape as a public surface, the policy types as types, `resolver.rs`,
`concealment.rs`, the refusal sets in `error.rs`, and where the tests live.

## Where to start: the module map

The table to come back to. If you landed in this crate from a stack trace, find
your file in the first column and read the chapter in the third.
[guide-repo-map.md](../guide-repo-map.md) has the same tree with the
*identifiers* per module and is the authority for those; what this adds is the
third column.

| module | owns | covered in |
|---|---|---|
| [`lib.rs`](../../crates/sandbx-core/src/lib.rs) | the Linux-only gate and the whole public surface | below |
| [`policy.rs`](../../crates/sandbx-core/src/policy.rs) | `Axis`, `Grants`, `NetworkPolicy`, `SandboxPolicy` — what a run may reach | below, and [12](12-a-flag-to-a-kernel-rule.md) for the trace |
| [`policy/vetted.rs`](../../crates/sandbx-core/src/policy/vetted.rs) | `VettedPath`, `ObjectId` — a granted path and the object it named | [09](09-landlock.md), [12](12-a-flag-to-a-kernel-rule.md) |
| [`fs_guard.rs`](../../crates/sandbx-core/src/fs_guard.rs) | seam 1: the in-process check six of the seven tools stop at | [11](11-the-two-seams.md) |
| [`helper_args.rs`](../../crates/sandbx-core/src/helper_args.rs) | seam 2: `HelperArgs::encode`/`decode`, the argv the helper is told | [11](11-the-two-seams.md), [12](12-a-flag-to-a-kernel-rule.md) |
| [`command.rs`](../../crates/sandbx-core/src/command.rs) | `SandboxedCommand`: the builder, the audit pipe, the deadline, the kill | [08](08-the-two-stage-helper.md), [14](14-audit-sessions-credentials.md) |
| [`command/dispatch.rs`](../../crates/sandbx-core/src/command/dispatch.rs) | the two flags and `HelperDispatch` — the entry into helper mode | [08](08-the-two-stage-helper.md) |
| [`helper/mod.rs`](../../crates/sandbx-core/src/helper/mod.rs) | the two stages, and `apply`'s ordered sequence | [08](08-the-two-stage-helper.md) |
| [`helper/hardening.rs`](../../crates/sandbx-core/src/helper/hardening.rs) | namespaces, capability sets, `RLIMIT_CORE`, `pdeathsig` | [07](07-kernel-primer.md), [08](08-the-two-stage-helper.md) |
| [`helper/resolver.rs`](../../crates/sandbx-core/src/helper/resolver.rs) | the ordered mount sequence that installs the rendered files | [07](07-kernel-primer.md) for bind mounts; below for what it installs |
| [`helper/seccomp.rs`](../../crates/sandbx-core/src/helper/seccomp.rs) | how the filter reaches the kernel: stacked filters, the x32 gate | [10](10-seccomp.md) |
| [`helper/seccomp/rules.rs`](../../crates/sandbx-core/src/helper/seccomp/rules.rs) | `BLOCKED_SYSCALLS` and the conditional rules — the data half | [10](10-seccomp.md) |
| [`helper/ruleset/mod.rs`](../../crates/sandbx-core/src/helper/ruleset/mod.rs) | `requested` — where the ABI and the policy meet | [09](09-landlock.md) |
| [`helper/ruleset/compat.rs`](../../crates/sandbx-core/src/helper/ruleset/compat.rs) | the ABI floor, ceiling, ladder, and `enforcement_verdict` | [09](09-landlock.md) |
| [`helper/ruleset/rights.rs`](../../crates/sandbx-core/src/helper/ruleset/rights.rs) | `rights_for` — the bit arithmetic from an axis to Landlock rights | [09](09-landlock.md) |
| [`helper/ruleset/opened.rs`](../../crates/sandbx-core/src/helper/ruleset/opened.rs) | `open_grant` — the path opened is the path that was granted | [09](09-landlock.md) |
| [`audit.rs`](../../crates/sandbx-core/src/audit.rs) | `AuditEvent`, `AUDIT_TARGET` — what gets recorded | [14](14-audit-sessions-credentials.md) |
| [`degradation.rs`](../../crates/sandbx-core/src/degradation.rs) | the helper's own channel to the parent, and its wire format | [14](14-audit-sessions-credentials.md) |
| [`digest.rs`](../../crates/sandbx-core/src/digest.rs) | `Sha256Digest`, and the verified open behind a pinned exec | [12](12-a-flag-to-a-kernel-rule.md) |
| [`spawn.rs`](../../crates/sandbx-core/src/spawn.rs) | the one `Command::new` in any crate's `src/` | [05](05-seven-crates.md) |
| [`resolver.rs`](../../crates/sandbx-core/src/resolver.rs) | the three files a bounded resolver replaces, and their bodies | below |
| [`concealment.rs`](../../crates/sandbx-core/src/concealment.rs) | `conceal_process_state` — the one step aimed at sandbx itself | below |
| [`error.rs`](../../crates/sandbx-core/src/error.rs) | `SandboxError`, `Access`, and the label the trail is filtered by | below |
| [`error/refusal.rs`](../../crates/sandbx-core/src/error/refusal.rs) | `HelperRefusal`, and the one place the two sets are mapped | below |
| [`bin/sandbx-helper.rs`](../../crates/sandbx-core/src/bin/sandbx-helper.rs) | a standalone helper binary, so the enforcement path tests end to end | below |
| `helper/seccomp/tests/` | five unit-test files plus the `eval` interpreter they read the filter through | [10](10-seccomp.md) |
| `helper/ruleset/tests/` | six unit-test files, all kernel-free | [09](09-landlock.md) |

Two naming traps. `resolver.rs` *renders* three files and is pure apart from the
lookups, while `helper/resolver.rs` *mounts* what the first produced; the
second's module doc opens by naming the first, which is the quickest way to tell
which file you are in. And there are two types called `Grants`:
`sandbx_core::Grants` is three booleans, what an `Axis` confers, while
`sandbx_cli::Grants` is the clap struct of `--allow-…` flags, the one
[05](05-seven-crates.md) means by "flattened into every subcommand". Nothing
imports both, so the collision is harmless in the code and expensive in
conversation.

## It is Linux-only, and the compiler says so

The second item in the file, straight after the module doc:

```rust
#[cfg(not(target_os = "linux"))]
compile_error!(
    "sandbx-core sandboxes using Landlock, seccomp and Linux namespaces, and has \
     no unsandboxed fallback — it is Linux-only by design. Build for a Linux \
     target, or depend on it only from a Linux-gated target in your manifest."
);
```

`compile_error!` fails the build with its argument as the message, so under a
`cfg` it is a conditional compile failure. This is the "fails closed" thesis of
[01](01-what-sandbx-is.md) pushed as early as it can go: on a macOS host the
failure is a build error naming the design, not a binary that runs tools with
nothing holding them.

## Twelve private modules and one public list

Every `mod` line in `lib.rs` is bare — `mod policy;`, `mod helper;`, twelve of
them, all private — so `sandbx_core::policy::SandboxPolicy` does not resolve
from anywhere and the only spelling is `sandbx_core::SandboxPolicy`. The whole
public surface is ten `pub use` lines re-exporting twenty-nine names, and that
list is the entire API. Two of the twelve modules, `degradation` and `spawn`,
export nothing at all — the visibility half of the spawn monopoly
[05](05-seven-crates.md) describes.

The list is in [guide-repo-map.md](../guide-repo-map.md). The interesting
question is what it tells you, and the answer comes from grepping the other six
crates for each name.

**Six names are what a consumer actually needs.** To build a policy:
`SandboxPolicy`, `VettedPath`, `Axis`. To spend one: `FsGuard` for the
in-process path, `SandboxedCommand` for the spawning one. To report what
happened: `SandboxError`. That is the crate, from outside. Three more are the
binary's rather than a library consumer's — `with_helper_dispatch`,
`conceal_process_state` and `exit_code`, each called once from
[`cli/src/main.rs`](../../crates/sandbx-cli/src/main.rs) or beside it, the
process-shaped work 04's *The CLI architecture* section says `main.rs` keeps.

**Ten are reached from no other crate's `src/`**, and the reasons divide
cleanly:

- **Forced by a signature.** `Access` is a field of a `SandboxError` variant,
  `ObjectId` is `VettedPath::object`'s return, `ReadableWalk` is
  `FsGuard::walk_readable`'s, `DigestParseError` is `Sha256Digest::parse`'s.
  These are public because what they hang off is — and no consumer writes
  `ReadableWalk`, since `grep` and `find` bind the walk without spelling it.
- **Needed by a second binary.** `HelperDispatch`, `HELPER_FLAG` and
  `dispatch_helper_mode` are what
  [`bin/sandbx-helper.rs`](../../crates/sandbx-core/src/bin/sandbx-helper.rs)
  calls, and a `[[bin]]` links the library as an external crate — so "public"
  there means "reachable from a binary". That file has no ordinary mode:
  `NotHelperMode` is a usage error. There is a second such binary outside this
  crate, `sandbx-tools`' `tests/support/helper.rs`, and its module doc says what
  forces the trio public rather than `pub(crate)`: `SandboxedCommand` re-execs
  *the current binary* with `HELPER_FLAG`, which assumes that binary dispatches
  at startup — the shipped `sandbx` does and a test harness does not, so the
  harness ships a binary that does nothing else. `HELPER_INNER_FLAG` is public
  for the doc link in its module comment.
- **Needed by an integration test.** `HelperArgs` and `BLOCKED_SYSCALLS` are
  read by targets under `crates/sandbx-core/tests/`, a separate crate that sees
  only the public surface — the last section of this chapter is that trade.

So this is not an API designed for callers. It is the reachability closure of
six entry types, plus what the crate's own out-of-crate test targets need.

## `policy.rs` — the types, not the trace

[12 — a flag to a kernel rule](12-a-flag-to-a-kernel-rule.md) follows
`--allow-read /tmp/x` *through* these types and is the chapter for `grant`, the
vetting chain, `VettedPath` and `ObjectId`. This section is the other half: what
you meet on opening the file.

Three axes, and one function that says what each means:

```rust
pub const fn grants(self) -> Grants {
    let (read, write, execute) = match self {
        Self::Read => (true, false, false),
        Self::Write => (false, true, false),
        Self::ReadExecute => (true, false, true),
    };
```

`Grants` is three plain `bool`s and its doc says why: "booleans, not Landlock
bits, so a right added here fails to compile at every mapping site." The axis
table has one home, and [decision-axis-table.md](../decision-axis-table.md) is
its record. `Axis::ALL` is a `[Axis; 3]` and the loops that matter run over it
rather than naming variants, so a fourth axis is a build failure rather than a
flag that parses and grants nothing. `NetworkPolicy` — `Denied` (the `Default`),
`AnyPort`, `Ports(Vec<u16>)` — carries a comment on why it is *not*
`#[non_exhaustive]`: "a fourth state is a compile error at every site that would
otherwise leave it unenforced."

### `SandboxPolicy` has eight private fields and no constructor

No `new`, and `Default` is the only way in: "construct with
`SandboxPolicy::default` and widen, so an unconfigured policy is useless, not
open." Widening is a chain of `#[must_use]` builders taking and returning
`self`, and every path builder funnels into `grant(axis, VettedPath)`. Two
things about that funnel are easy to miss having read only 12.

- **Several builders skip rather than refuse.** `allow_env` drops a name that is
  empty or contains `=` or NUL; `allow_dns` drops one empty, over
  `DNS_NAME_LIMIT`, or carrying NUL, whitespace or `#`; `allow_network_port`
  drops port 0. All for one reason: nothing `HelperArgs::encode` emits may be
  something `decode` rejects, so the policy cannot hold a value that would fail
  to survive the argv seam, and the operator-facing refusal lives in the CLI
  instead. `allow_dns`'s skips are load-bearing beyond the seam too — whitespace
  and `#` are what would forge a field or a comment in a rendered hosts file.
- **`allow_system_executables` is the one grant set reached without a vetted
  path in hand,** so the vetting is pinned inside it: it folds `/usr`, `/bin`,
  `/lib` and `/lib64` through `VettedPath::vet(…).ok()`, skipping each absent
  one because Landlock rejects a rule for a path that does not exist. A host
  without `/lib64` would otherwise fail to sandbox at all.

### What the accessors hand back

| method | gives | the detail worth knowing |
|---|---|---|
| `paths(axis)` | `&[VettedPath]` | an exhaustive match; pair with `Axis::ALL` to treat every axis alike |
| `readable_paths` / `writable_paths` / `executable_paths` | `&[VettedPath]` | thin wrappers over `paths`, for the common case |
| `granted_paths` | `impl Iterator<Item = (Axis, &VettedPath)>` | one pair per *grant*, not per path, in `Axis::ALL` order — a path granted on two axes appears twice |
| `working_root` | `Option<&Path>` | the first writable **directory**, else the first readable one |
| `allowed_env` | `&[String]` | names only, "never values; the value is read at spawn time from the harness" |
| `imposed_env` | `&'static [(&str, &str)]` | the one place a value is implied, and only because it is a compile-time constant |
| `permits_env` | `bool` | the single answer `spawn::command` and the helper's inherited-environment check share |

`granted_paths` is the one to internalise, because two consumers are built on
it: `FsGuard::new` folds it into two lists through `axis.grants()`, and
`AuditEvent::spawned` derives its per-axis counts the same way, so a new axis
reaches both without either growing a table of its own. `working_root`
deliberately does *not* take its first entry, because that order puts `Read`
first and `ReadExecute` last, "which would start a writable run read-only, or
one granted only execute inside the system binaries" — and it insists on a
directory, because `chdir` to a file (`--allow-write /dev/null`) fails the
spawn.

### Two methods by which a policy diagnoses itself

`unbounded_resolution` and `grant_bound_by_resolver` are neither builders nor
accessors: each returns an `Option` describing a way this policy is incoherent,
and neither refuses anything itself — a *caller* turns the `Some` into a
`SandboxError`. Both live on the policy rather than in the CLI so an embedder
spawning through `SandboxedCommand` reaches them too, and the asymmetry between
them is the interesting part. `unbounded_resolution` is I/O-free, so it is asked
on *both* sides of the argv seam, in `SandboxedCommand::command_line` and again
in `HelperArgs::decode`. `grant_bound_by_resolver` reads the filesystem, so
`decode` cannot ask it without giving up the no-I/O property
[12](12-a-flag-to-a-kernel-rule.md) calls the invariant the whole trace rests
on. Its doc says so, and names what covers the gap: an entry retargeted after
the harness looked "fails closed — the pair is kept, and the pin refuses the run
in the helper."

`unbounded_resolution` is also where the threat model for `--allow-dns` can be
read off one function. It names four routes to a nameserver that would leave a
name allowlist holding nothing: `--dns-over-tcp`, a pathname unix socket (glibc
asks nscd before it reads `nsswitch.conf`), `AnyPort`, and an allowlist
containing `NAMESERVER_PORT`. `Grants::policy` in the CLI refuses four *other*
shapes; this one is "the fifth, pointless rather than unenforceable".

## `resolver.rs` — three files, and no nameserver in the loop

Thinly covered elsewhere. It answers one question: what does a bounded resolver
look like on disk? Three files, declared as constants and exported as one list:

```rust
pub const RESOLVER_FILES: [&str; 3] = [HOSTS, NSSWITCH, RESOLV_CONF];
```

`RESOLVER_FILES` is public for one reason, stated in its doc: a policy that
bounds resolution also grants read on exactly these three, and `ruleset::rights`
derives those rules from this list. One list, two uses, so the files that get
mounted cannot drift from the files that are readable —
`every_rendered_file_is_one_the_policy_grants_read_on` holds it.

`bound_by_resolver` answers whether a path names one of the three *as the bind
will land on it*, comparing each entry both by its own name and by what it
canonicalizes to, because `mount(2)` resolves its target and a pin does not. On
a systemd host `/etc/resolv.conf` is a symlink, so the bind replaces the stub it
points at — and that stub is the name a grant on it is pinned to. It never
resolves the caller's path, which arrives already resolved, because "resolving
it here would judge a spelling no caller vetted".
`a_symlinked_entry_is_bound_under_the_name_the_bind_lands_on` asserts all three
directions, including that the *directory* holding a bound file is not reported
— a bind leaves its inode alone, which is why `--allow-read /etc` collides with
nothing while `--allow-read /etc/hosts` is refused.

### `files` is the only impure call, and its position is forced

`files(policy)` returns `None` when the policy bounds nothing, keeping a run
with no `--allow-dns` off the mount path entirely. Otherwise it resolves every
allowlisted name through `getaddrinfo` and renders the three bodies — so where
it is called from is a constraint rather than a preference. In
[`helper/hardening.rs`](../../crates/sandbx-core/src/helper/hardening.rs),
`prepare_supervisor` calls it as its first real statement, above the comment
that says why:

```rust
    // What the bound `hosts` file is built from, so they precede `bound_resolution` below; and
    // before the unshare, which for an egress-denying policy leaves no network to resolve on.
    let resolved = crate::resolver::files(policy);
```

Two reasons, and the comment puts the unconditional one first: the bodies
`bound_resolution` binds are rendered from these lookups, so the lookups precede
the bind on every run that has any. The namespace reason holds only where the
policy denies IP egress — and `sandbx-cli` refuses every `--allow-dns` shape
that would leave `allows_network()` false, so it is a constraint on an embedder
calling the library rather than on anything the CLI can produce.

So resolution happens in stage 1 before `isolate`, and the mounting after it:
`super::resolver::bound_resolution` needs the mount namespace `isolate` just
made, and `CAP_SYS_ADMIN` within it, which the capability drops below it take
away. Three steps in one function, each wedged between the two it has to sit
between — and the lookups cannot move up into the harness either, because the
addresses would then have to cross the argv the command can read. A name that
resolves to nothing contributes no line and does not fail the run, "as an absent
path contributes no Landlock rule"; the count comes back as a
`Resolved { files, unresolved }` for the parent to emit as a degradation — a
count and not the names, because [guide-logging.md](../guide-logging.md) keeps
values off the trail.

### What goes in the three bodies

| file | body | if it were absent |
|---|---|---|
| `/etc/hosts` | a header, the loopback lines, then one line per resolved address | required — it is the whole mechanism |
| `/etc/nsswitch.conf` | `hosts: files` and `networks: files`, then every other line of the host's file kept verbatim | required — glibc's built-in default *includes* `dns` |
| `/etc/resolv.conf` | `options attempts:1 timeout:1`, and no `nameserver` line | optional — musl falls back to what this leaves it with anyway |

Four details in the rendering are each a bug someone would otherwise find the
hard way. **The loopback lines go in unconditionally**, because with no `dns`
source left there is nothing else to resolve `localhost` by. **Both address
families get a line**, because a command preferring IPv6 would otherwise lose
the name rather than fall back. **A link-local IPv6 address is dropped**: `ip()`
discards the `scope_id` that makes one routable, a hosts file has no column to
carry it back, and `connect` to a scopeless `fe80::/10` address is `EINVAL`. And
**`nsswitch.conf` is rewritten line by line, not replaced** — only `hosts` and
`networks` bear on a name, while `passwd` and `group` reach `systemd`, `sss` or
LDAP on an ordinary host, so writing `files` over those would leave a command
whose own account lives there unable to look its user up;
`a_database_that_is_not_about_a_name_is_left_as_the_host_had_it` is that
sentence as an assertion.

`RESOLV_BODY`'s comment is the whole argument for the design: glibc has no `dns`
source to use a nameserver with, and musl ignores `nsswitch.conf` and falls back
to `127.0.0.1:53` — which a port allowlist denies at the socket, UDP included.
Two libcs, two mechanisms, one bound. `the_resolver_body_names_no_nameserver`
and `the_nsswitch_body_leaves_no_dns_source` keep it that way, the second by
looping over every non-comment line rather than checking the header it wrote.
[decision-egress-proxy.md](../decision-egress-proxy.md) is why this is a hosts
file rather than a DNS responder of sandbx's own, and it prices the escapes — a
statically linked binary with its own resolver among them — one at a time.

## `concealment.rs` — nineteen lines, aimed at sandbx itself

The smallest module in the crate, and the only one whose subject is sandbx's own
process rather than a child's — a boundary in its own right rather than a
precondition for one, which is how [04](04-the-architecture.md) places it. It is
one function:

```rust
pub fn conceal_process_state() -> Result<(), SandboxError> {
    nix::sys::prctl::set_dumpable(false).map_err(|errno| SandboxError::ProcessConcealment {
        detail: format!("could not clear the dumpable flag: {errno}"),
    })
}
```

Clearing the dumpable flag makes the kernel reparent `/proc/<pid>/` to root, so
`environ`, `mem`, `maps` and `fd/` start failing `__ptrace_may_access` for a
reader running as the same user. What that protects is an exported provider key,
which lives in the harness's own environment, which a shared procfs publishes to
every same-uid process — so a tool granted `/proc` would otherwise read it out
of `/proc/<harness-pid>/environ` (#192).

Five facts the one-line body does not show.

- **It does not close sandbx's own `/proc/self` to sandbx.** Procfs exempts a
  same-thread-group reader from `__ptrace_may_access` for `fd/` and `exe`, and
  does not for `environ` — so the harness's environment closes even to itself,
  while the two reads sandbx depends on survive: `fd_path` in
  [`digest.rs`](../../crates/sandbx-core/src/digest.rs), which is the
  `/proc/self/fd/N` a pinned `execve` is handed instead of a path that could
  resolve twice, and `self_exe` in
  [`command.rs`](../../crates/sandbx-core/src/command.rs), which `read_link`s
  `/proc/self/exe` before the helper re-exec. [07](07-kernel-primer.md) has the
  kernel rule and the comment that names the function.
- **Refusing `/proc` as a path was available and declined twice over.**
  `SECURITY.md` declines refusal-by-name for `/etc`, `/var`, `/proc` and `/sys`
  on the grounds that depth is not sensitivity and a list of dangerous
  directories has a silent first omission; and it would break `sandbox-run`,
  where reading `/proc/self/status` is ordinary and the operator chose the
  command. [decision-harness-owned-paths.md](../decision-harness-owned-paths.md)
  has the argument under "#192 is a different mechanism, not more of this".
- **The helper does not set it, and could not usefully.**
  `harden_process_state` carries a "does NOT set `PR_SET_DUMPABLE`" paragraph:
  the kernel resets the flag to dumpable on every `execve` of an ordinary
  binary, so setting it in stage 1 would cover only that stage's pre-exec
  window. The same reset leaves the sandboxed command unaffected.
- **A failure is a refusal, not a degradation**, unlike the capability bounding
  set — where the bit cannot be spent on any host, and refusing would cost whole
  classes of host a sandbox for nothing. Here the key is exposed on exactly the
  host where the call failed.
- **It costs the two things the flag was for:** no core dump of the harness, and
  no same-uid debugger attach, so `gdb -p` and `strace -p` against a running
  sandbx are refused.

The test is `crates/sandbx-core/tests/concealment.rs`, and it is cross-process
because the claim is that what the flag stops is a same-uid reader, and only a
second process can be one. It spawns `sandbx-concealment-probe`, reads the
probe's `environ` before concealment, asserts a marker variable is actually in
what it read — otherwise the read proves nothing — then tells the probe to
conceal and asserts the second read fails with `PermissionDenied`. It also
skips, loudly, on a host that already hides a child's procfs from its parent,
because a pass there would be evidence of nothing.

- **Worth questioning:** the step is detached from the thing it protects.
  Everything else in this crate converts a rule a human would have to remember
  into something the compiler or the kernel holds — `grant` takes a `VettedPath`
  so an unpinned grant cannot be built, `with_helper_dispatch` takes a closure
  so helper mode cannot be fallen past, `spawn::command` is the only reachable
  way to get a `Command`. Concealment is the opposite shape: a `pub fn` that
  `cli/src/main.rs` happens to call, where omitting it compiles, passes every
  test in the workspace, and silently republishes the key.
  `decision-harness-owned-paths.md` argues carefully for the *mechanism* and for
  *where the call sits* — just after `Cli::parse`, so a refusal exits with the
  subcommand's own code — and does not weigh making the step unskippable. Nor is
  the wiring pinned: `tests/concealment.rs` drives a purpose-built probe, which
  is evidence that the `prctl` works rather than that `sandbx` calls it, and
  [guide-module-layout.md](../guide-module-layout.md) asks for exactly that
  distinction when it says to pair a negative with evidence the mechanism ran. A
  test that spawns the real binary, holds it at a prompt and reads its `environ`
  would be the same shape as the probe test and would cover `main`. The single
  call site covers both agent subcommands today, which is what makes now the
  cheap moment to ask.

## `error.rs` and `error/refusal.rs` — a closed set and a subset of it

Barely covered anywhere else, and one of the most useful files in the crate to
have read, because every refusal in the system is listed in one place.

`Access` has two variants where `Axis` has three, and not as an omission:

```rust
pub enum Access {
    /// Checked against the readable roots.
    Read,
    /// Checked against the writable roots.
    Write,
}
```

`FsGuard` holds a `readable` and a `writable` list and nothing else, because
nothing in-process execs. Three axes become two lists through `Axis::grants()`
inside `FsGuard::new`, so `Axis::ReadExecute` — which confers read — feeds the
readable list, and no second table exists anywhere that could disagree with the
axis table. `Access`'s two `&'static str` accessors are the point of putting it
here: `outside()`'s doc calls it "the one wording, shared by the audit record's
reason and `SandboxError`'s `Display`, so the two cannot disagree." And a
refusal carries the `Access` it was checked against so it can name the grant it
*lacked* rather than implying none was given.

### Twenty-four variants, and every one is a refusal

The enum's doc states the property that makes it safe to reason about: "Every
variant is a refusal — no 'allowed with warning' case — so a caller that
believes it is sandboxed is never worse off than one that gets an error." No
`Ok`-ish arm, no severity field. And no `#[non_exhaustive]`, which is what
"closed" buys: four matches over the enum carry no wildcard arm — `Display`,
`Error::source`, `label` and `refusal` — so a twenty-fifth variant is four
compile errors, one per question it has to answer. How it reads to an operator,
whether it wraps an OS error worth a `source`, what a trail calls it, and
whether a helper stage is the only thing that can decide it.

Reading the list end to end is the fastest tour of the threat model in the repo:

| group | variants | the one worth knowing |
|---|---|---|
| the guard's | `PathNotAllowed`, `Unresolvable`, `NotFound` | absence is normally *concealed* as `PathNotAllowed`, because ENOENT against EACCES over arbitrary paths "would read back as a map of the host" ([11](11-the-two-seams.md)) |
| identity | `GrantRedirected` (#205), `GrantReplaced` and `RootReplaced` (#212), `GrantUnpinnable` | they differ by *which process measured it*, not by what went wrong |
| mechanism | `Landlock`, `Seccomp`, `NamespaceSetupFailed`, `ProcessHardening`, `ProcessConcealment` | one per layer, so a trail names the layer that would not install |
| the pin's | `PinMismatch`, `PinUnreadable`, `PinnedScript` | `PinUnreadable` exists because "a mode-111 binary is executable and unreadable, so it runs unpinned and cannot be pinned" |
| policy coherence | `UnboundedResolution`, `GrantBoundByResolver` | each points back at the policy method above that decides it |
| the relay | `HelperRefused` | not a failure of its own — the helper's, carried across the channel |

Read the `Display` arms for the reasoning in their comments rather than the
wording: `PinMismatch` prints *both* digests, because only the pair tells the
operator whether they pinned the wrong bytes or the bytes changed under them.

### `label()` is exhaustive, and that is a security property

```rust
    pub fn label(&self) -> &'static str {
        match self {
            Self::PathNotAllowed { .. } => "path_not_allowed",
            Self::Unresolvable { .. } => "unresolvable",
```

A stable name per variant, and the doc says what it is for: "the audit trail is
filtered by" it. Three consequences stack up.

- **The match is exhaustive, so a new variant has to decide what a trail calls
  it.** There is no `_ => "unknown"`, which would let a new refusal land on the
  trail under a name no filter catches.
- **No two variants may share a label**, pinned by
  `no_two_variants_share_a_label` — a shared label would make two refusals
  indistinguishable to the `reason=` filter that is the trail's whole point.
- **`HelperRefused` borrows the label of the refusal it relays** rather than
  having one of its own: "a trail filtered by `reason=` cannot tell which side
  of the channel decided it — the same refusal either way." Which is why the
  uniqueness test has to exclude the relay.

`TimedOut`'s label is `"timeout"`, not `"timed_out"`: "the word the operator
typed and the docs use, so it is the word a trail reader greps for."

### `HelperRefusal` is the subset the channel admits

[`error/refusal.rs`](../../crates/sandbx-core/src/error/refusal.rs) holds a
second closed enum: thirteen variants, each documenting the `SandboxError` it
stands for, plus `ALL`, a `label()` returning the same strings, and a
`from_label` that is a lookup over `ALL` rather than a second match — "so a
label `label` can emit is one this accepts by construction".
`a_label_we_did_not_define_is_refused` holds the other direction with `""`,
`"not_a_refusal"`, `"seccomp "` and `"SECCOMP"`: an exact match, no trim and no
case fold, so a near miss off the wire is dropped rather than rounded to the
nearest reason it resembles.

Why a subset at all: a record on the audit channel *outranks* the exit status
the parent watched, so admitting a label the parent or `FsGuard` decides for
itself would let a forged line claim an outcome that never happened.
[14](14-audit-sessions-credentials.md) covers the channel and
[decision-helper-audit-channel.md](../decision-helper-audit-channel.md) is the
record. The criterion is subtler than "what failed": it is whether the label
names *one decider*. `inner_stage_failed` is in and `spawn_failed` is out,
though both name a process that would not start, because two callers return
`SpawnFailed` and so it names no single decider.

`relayed(stderr)` is the other half. It builds `HelperRefused` from the helper's
stderr, strips `HELPER_FAILURE_PREFIX` back off so the CLI printing
`sandbx: {error}` does not read as `sandbx: sandbx: `, and truncates at
`STDERR_LIMIT` — not cosmetically: nothing downstream bounds it, `ToolLimits`
caps a command's output rather than an error's detail, and this detail reaches a
model inside a `tool_result`.

### `SandboxError::refusal` is the one mapping site

```rust
    pub(crate) fn refusal(&self) -> Option<HelperRefusal> {
```

Crate-private, exhaustive, and the only place the two sets are related. The
`None` arm is a single match arm covering eleven variants, carrying a comment
that gives the reason *per variant* — `ProcessConcealment` is decided past
dispatch, which no helper runs (#192); `RootReplaced` is `FsGuard`'s per-access
measurement; `UnboundedResolution` and `GrantBoundByResolver` are decided off
the policy before the spawn. That comment is the closest thing the repo has to a
written-out criterion, and it sits beside the code it governs.

Five tests hold the two sets together, and the division of labour between
compiler and test is the thing to carry away: the exhaustive match makes a new
variant *decide*, but it cannot make the test fixture *know*.

| test | closes |
|---|---|
| `no_two_variants_share_a_label` | two refusals becoming one `reason=` value |
| `a_refusal_is_called_what_the_variant_it_relays_is_called` | a relayed refusal being renamed on the way to the caller |
| `every_refusal_a_variant_reports_is_one_the_channel_admits` | a refusal given arms in `label` and `refusal` but left out of `ALL`, where `from_label` would reject the label its own writer emits (#185) |
| `the_reasons_the_helper_does_not_decide_are_not_refusals` | a variant changing sides unnoticed — `refusal` must answer `None` for exactly the eleven listed here |
| `the_reasons_the_helper_does_not_decide_cannot_cross_the_channel` | a label sandbx decides for itself being accepted off the wire |

The last is derived rather than listed, and its comment says why: "a list goes
one label behind each time a reason is added." Its neighbour above keeps a list
and that list *is* the assertion, so a variant moved across the channel fails
until the list moves with it. All five run off
`every_variant()`, a hand-written sample of each variant — whose own comment is
candid that a variant left out of the array still compiles and "every test
deriving from this skips in silence".

- **Worth questioning:** the label strings are documented as a compatibility
  surface and almost none of them is pinned to the prose that documents them.
  `HelperRefusal::label`'s doc says in as many words that a trail is filtered by
  these strings, so they are a compatibility surface, and
  `decision-helper-audit-channel.md` spells several out in prose —
  `path_not_allowed`, `unresolvable`, `root_replaced`, `grant_replaced`,
  `inner_stage_failed`, `spawn_failed`, `timeout` — as does
  [guide-logging.md](../guide-logging.md). Three of those are hard-coded in test
  assertions and would fail a rename; the rest are not, and no test ties any
  label to the document an operator would have read the filter off. The record
  thought carefully about the adjacent problem: it declines to state a *count*
  of the excluded reasons precisely "because the set is not maintained here",
  deriving membership from the variants instead. The spelling is the half that
  argument does not reach, and the repo already owns the mechanism for it —
  [16](16-how-the-repo-is-maintained.md) describes
  `every_prose_copy_of_the_floor_is_current`, a Rust test that pins one figure
  across seven named files and whose comment says each further copy is another
  way for a trim to break the build. The same walk over `HelperRefusal::ALL` and
  two markdown files would turn a silent compatibility break into a failing
  build.

## Where the tests live, and why it is not one place

Two of the twenty-nine public names made sense only once you knew which test
target needed them, so this is the last piece of the map.
[guide-module-layout.md](../guide-module-layout.md) is the authority and states
the rule rather than the arrangement; what follows is the on-ramp. Three homes,
chosen by what a test needs to *reach*:

| a test that | lives in | because |
|---|---|---|
| touches a private or `pub(crate)` item | an inline `mod tests`, or `foo/tests/` | tests compiled into the crate reach private items |
| drives the public API | `crates/sandbx-core/tests/<topic>.rs` | that is a separate crate and sees only what is `pub` |
| needs a sandbox-capable kernel | the same, behind `sandbox-integration` | the feature is out of the default `cargo test` run |

The thing to notice is the *direction* the rule points. `crates/*/tests/` is a
separate crate, so moving a unit test there means making something public to
suit it — and the guide says never make that trade, because a module is private
precisely so its internals are not an API. That is the instinct
[12](12-a-flag-to-a-kernel-rule.md) points out in `grants/root.rs`, where a
split *narrowed* a surface to `pub(super)` and the tests moved to the code
rather than the reverse.

So `helper/seccomp/tests/` and `helper/ruleset/tests/` are **unit** tests inside
`src/`, despite looking like an integration directory. They got their own
directories by the escalation the guide describes — inline, then `foo/tests.rs`,
then one file per topic — and both `mod.rs` files open by saying they are
kernel-free: the seccomp set evaluates the filter program through an `eval`
interpreter rather than installing it, and the ruleset set takes the ABI as a
parameter. Neither needs root, a network namespace or a Landlock-capable host,
so both run in the ordinary `cargo test`. `crates/sandbx-core/tests/` holds
fifteen targets in three groups, by what gates them: the **ungated** public
contracts (`command.rs`, `fs_guard.rs`, `helper_args.rs`, `policy.rs`,
`audit.rs`, `concealment.rs`) plus `context_docs.rs`, a documentation test this
crate hosts for the whole repo because it already reaches the repo root;
`denylist.rs` and `capability_coverage.rs` under
**`#![cfg(target_os = "linux")]`** only, which spawn nothing and so, as their
module docs put it, "run where the enforcement suite cannot"; and
`enforcement.rs` with its three siblings, `audit_channel.rs` and
`audit_outcome.rs` under
**`#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]`** — gated
whole-file rather than per test, because with the feature off `-D warnings`
would reject the capture harness as dead code.

`tests/support/` is two things in one directory. `mod.rs` is an ordinary module
the enforcement targets include — `vetted`, `runtime_paths`, `allow_probe`,
`run`, `run_pinned` — and its doc states a convention worth knowing: it holds
**the intersection only**, because `dead_code` is per test crate, so a helper
one target does not use warns there and belongs in the file that uses it.
Everything else beside it is a `[[bin]]` probe declared in
[`Cargo.toml`](../../crates/sandbx-core/Cargo.toml) — eight of them, every one
behind `required-features = ["sandbox-integration"]` except
`sandbx-concealment-probe`, which needs no Landlock ABI, "only a second process
to be concealed from". Two manifest comments there are small lessons in their
own right: `io-uring` is `optional = true` rather than a dev-dependency because
the probe that reaches `io_uring_setup` is a `[[bin]]` and "a `[[bin]]` cannot
see dev-dependencies", and `seccompiler` is pinned to a caret range with a note
that widening past it needs the `eval` interpreter in
`helper/seccomp/tests/mod.rs` to learn any new opcode first, because it panics
by name — failing loudly rather than evaluating an instruction it does not
understand.

## You should now be able to explain

- Which chapter to read for a given file in this crate, and why this one does
  not re-explain Landlock, seccomp or the two helper stages.
- What a non-Linux build of `sandbx-core` produces, and what the message argues.
- Why `sandbx_core::policy::SandboxPolicy` does not resolve, and which six names
  a consumer of this crate actually has to be able to say.
- Why `Access` has two variants where `Axis` has three, and where the mapping
  between them lives.
- What `granted_paths` yields for a path granted on two axes, and why
  `working_root` does not just take its first entry.
- Which of the policy's two self-diagnosis methods is asked on both sides of the
  argv seam, which is not, and what covers the one that is not.
- Why resolution happens in stage 1 before the `unshare` and the mounting after
  it, and what each position is forced by.
- Why a bounded resolver rewrites `nsswitch.conf` line by line, not wholesale.
- What clearing the dumpable flag buys, what it costs, why the helper does not
  set it too, and which reads of its own `/proc/self` it leaves sandbx.
- What a twenty-fifth `SandboxError` variant has to answer before the crate
  compiles, and the one thing about it the compiler cannot force.
- Why `HelperRefusal` is a subset of `SandboxError`'s labels, and what
  membership turns on.
- Why `helper/ruleset/tests/` is a unit test directory, and what moving one of
  those tests to `crates/sandbx-core/tests/` would cost.

## Next

[19 — the tools crate](19-crate-tools.md), the layer immediately above this one:
the seven built-ins, each spending a policy it got from here through either
`FsGuard` or `SandboxedCommand`. It is a much smaller crate, and reading it next
is the quickest way to see which half of `sandbx-core`'s public surface is
actually load-bearing for a caller.
