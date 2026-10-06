# Decision: where a credential comes from

Three tiers were designed and two are built. The argument for a second source is
that `agent-run` once read the environment alone, so a user with no
`ANTHROPIC_API_KEY` exported had no way to authenticate at all — an argument that
did not exist before the turn loop had a caller (#109).

| Tier | Source | Where |
|---|---|---|
| 1 | `ANTHROPIC_API_KEY` from the environment, via `resolve_api_key` | `sandbx-providers/src/credentials.rs`, wrapped in `secrecy::SecretString` |
| 2 | OS keyring | dropped, below |
| 3 | `$XDG_CONFIG_HOME/sandbx/credentials.toml` at `0600` | `sandbx-cli/src/auth.rs`, over `auth/store.rs` |

The two live tiers are tried in that order, and the order is the point: exporting
a variable overrides the stored key for one shell without an `auth logout` first.
`auth status` names which answered, and spends three exit codes to do it — 0
found, 1 neither source has one, 2 a source could not be read. The 1 and the 2 are
deliberately different values: a script running `auth status || auth login` would
otherwise log in over a credential it was merely refused.

A tier-3 file is refused rather than read when any group or other bit is set on
the file *or* on the directory holding it, because a file that was already
disclosed cannot be undisclosed by using it, and a directory another user may
write is one they can substitute a file in. The directory is the canonicalised
one, so a symlinked credential is judged by where the key actually sits rather
than by where the link does. Refused, never repaired: a mode sandbx
quietly narrowed would hide that the key needs rotating. `auth logout` is the one
command that tolerates a too-wide file, because refusing there would leave the
exposed key on disk in order to protect it.

A parse failure reports a line number and withholds the parser's own message.
`toml::de::Error` quotes the line it failed on, and for a hand-written
`api_key = sk-ant-…` missing its quotes that line is the key.

`auth login` takes the key on stdin and refuses a tty rather than prompting. A
prompt would echo the key into the terminal's scrollback, and the obvious
alternative — an argument — would publish it through `/proc/<pid>/cmdline` to
every process on the host. Refusing a tty means the documented idiom is
`read -rs KEY && printf %s "$KEY" | sandbx auth login`, which keeps the key out of
scrollback, shell history and argv alike. The cost is that the tty refusal cannot
be tested without a pty; it is not covered.

## Why the keyring was dropped

Tier 2 is not deferred and there is no issue for it. It would buy less than it
costs:

- The Linux backend is secret-service, which links a D-Bus client stack and
  session crypto into the harness process. That collides with a rule
  [SECURITY.md](../SECURITY.md) already states — anything linked into the binary
  runs with the harness's privileges, not a tool's — making it the largest new
  attack surface in the binary, guarding a secret a `0600` file also guards.
- It is unavailable where sandbx runs. secret-service needs a session bus and an
  unlocked collection: absent headless, in a container, in CI, over plain ssh. The
  `linux-native` backend is the kernel keyutils session keyring, which is
  memory-only and gone at logout, so it is not storage.
- Release binaries are static musl, and `linux-native` wants libkeyutils (C).
- "Keyring, else file" is a fail-open shape: misreading a locked collection as an
  absent item authenticates with a different credential than the one stored.
- Linux secret-service has no meaningful per-application ACL — any process running
  as you can ask the daemon. Against a local attacker already running as your uid
  both tiers fall, and the file is at least inspectable.

## What this covers, and what it does not

This is the *harness's own* provider call — sandbx authenticating to Anthropic. It
says nothing about a credential a **sandboxed tool** needs, which is a different
problem with a different answer:

- A sandboxed command no longer inherits the harness's environment (#98). The
  policy names what crosses, so a key in sandbx's environment is not in the
  child's. See [decision-environment-allowlist.md](decision-environment-allowlist.md).
- Handing a tool a credential it legitimately needs — `bash` running `gh` — is
  #41. The shape sketched there is an opaque placeholder plus a TLS-terminating
  proxy that resolves the real value per request, so the secret never enters the
  child's memory. It waits on a tool needing one.

The ordering matters: #41 could not be designed while the environment was shared
wholesale, which is why #98 landed first and separately.
