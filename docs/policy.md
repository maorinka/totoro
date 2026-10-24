# Policy

Wisp's behaviour is defined by four plain-text files in `/etc/wisp/`. All of
them are reloaded on `systemctl reload wispd` (SIGHUP) or by a console
rollout of **Reload policy**. Nothing needs a restart.

| File | Decides |
|---|---|
| [`rules.conf`](#rules) | which process executions are suspicious, and what to do about them |
| [`catalog.conf`](#catalog) | which packages, IDE extensions and AI tools are sanctioned |
| [`netpolicy.conf`](#network-policy) | which outbound connections are allowed, denied or rate-limited |
| [`fim.conf`](#file-integrity) | which files and directories are watched for changes |

**Malformed lines fail closed.** A line Wisp cannot parse is reported with its
`file:line` and skipped. It is never reinterpreted as something more
permissive. Check every change before it ships, ideally in CI against your
policy repository:

```bash
wispd -c /etc/wisp/wisp.conf --check-config
```

## Recommended rollout

1. Deploy in **monitor** mode (the default). Rules that would kill report
   `would-block` instead.
2. Watch **Alerts** for a week or two. Tune noisy rules: tighten conditions,
   add exclusions such as `!comm=git`, or set a rule's action to `ignore`.
3. Move to **enforce** with a [staged rollout](console.md#rollouts): 5% of a
   group first, then 25%, then 100%. Canary hosts stay in every later stage.
4. Pin individual high-confidence rules to `mode=enforce` early if you like.
   They block even on monitor-mode hosts.

## Rules

`rules.conf`, one rule per line. **The first matching rule wins.**

```
<id> <severity> <action> <mitre|-> "<title>" [mode=monitor|enforce] <condition>...
```

| Part | Values |
|---|---|
| `id` | any short identifier, shown in alerts (`CRED-001`) |
| `severity` | `info`, `low`, `medium`, `high`, `critical` |
| `action` | `ignore` (match and stop: an allow-list entry), `alert`, `kill` (terminate the process), `quarantine` (kill, and move the executable to `state_dir/quarantine`) |
| `mitre` | ATT&CK technique ID, or `-` |
| `title` | quoted, shown in the console |
| `mode=` | optional per-rule override of the host's mode |

`kill` and `quarantine` act only in enforce mode. In monitor mode the alert's
response reads `would-block`.

### Conditions

All conditions must match (AND). Comma-separated values are alternatives (OR).
A leading `!` negates the condition.

```
<field><op><value>[,<value>...]
```

| Field | Matched against |
|---|---|
| `exe` | the executable's path |
| `cmd` | the full command line |
| `comm` | the program name |
| `pcomm` | the parent's program name |
| `actor` | who is behind the process: `human`, `ai`, `code`, `ci`, `service`, `unknown` |
| `src` | the actor's source, e.g. `claude`, `cursor`, `sshd`, `github-runner` |
| `uid` | numeric user id |
| `tty` | `yes` if the process has a terminal, else `no` |

| Operator | Meaning |
|---|---|
| `=` | equals |
| `^=` | starts with |
| `$=` | ends with |
| `*=` | contains |

Quote a condition that contains spaces: `"cmd*=sudo ,pkexec "`.

### Examples

```
# ignore the system package manager run by a human on a terminal
ALLOW-001 info ignore - "system package manager" comm=apt,dpkg tty=yes

# credential access, except by the tools that legitimately do it
CRED-001 high alert T1552.001 "Read of SSH private key" cmd*=/.ssh/id_ !comm=ssh,git,ssh-add

# an AI agent running privileged commands: block, even on monitor hosts
AI-002 high kill T1059 "AI agent ran privileged command" mode=enforce actor=ai "cmd^=sudo ,pkexec ,doas "

# reverse shells
RSHELL-01 critical kill T1059.004 "Shell spawned with network redirection" cmd*=/dev/tcp/,/dev/udp/
```

The shipped `rules.conf` covers credential theft, reverse shells,
living-off-the-land, persistence, privilege escalation, risky package
installs and AI-agent activity. Start from it.

## Catalog

`catalog.conf` curates what may be installed or run. Each kind is checked at
a different point:

| Kind | Checked when | In enforce mode |
|---|---|---|
| `npm` | `npm`, `yarn`, `pnpm` or `bun` installs a package | the install is stopped |
| `pip` | `pip`, `pip3`, `uv`, `pipx` or `poetry` installs a package | the install is stopped |
| `ai` | an AI agent starts (identified by actor attribution) | the agent is stopped |
| `vsx` | an IDE extension appears in a VS Code, VS Code Server or Cursor extensions directory, at startup or on install | **alert only**: the extension is already on disk, and the sensor never deletes a developer's files |

Violations raise `CAT-NPM`, `CAT-PIP`, `CAT-AI` or `CAT-VSX`.

```
default <kind> allow|deny            # behaviour for names not listed
<kind> <name> allow|deny [version|*] # an entry; a version pins it
```

- `default npm allow` with a few `deny` lines is a **block-list**.
- `default vsx deny` with `allow` lines is an **allow-list**: anything not
  listed is a violation.
- `npm typescript allow 5.4.5` **pins** a version. Installing any other
  version is a violation. `*` allows every version.

```
default npm allow
npm event-stream deny
npm typescript allow 5.4.5

default ai deny          # anything not listed is Shadow AI
ai claude allow
ai cursor allow
```

## Network policy

`netpolicy.conf` governs outbound TCP connections, attributed to the same
actors as processes. **The first matching `allow` or `deny` wins.** `limit`
lines are not terminal (see below).

```
allow|deny <network>[:port|:any] [actor=<actor>]
limit      <network>[:port|:any] <N>/s|<N>/m [actor=<actor>]
```

- `network` is `any` or an IPv4 CIDR (`10.0.0.0/8`, `203.0.113.7`). IPv6
  flows are matched by port and actor only.
- `actor` is one of `human`, `ai`, `code`, `ci`, `service`, `unknown`.
- A denied flow raises `NET-POLICY` and, in enforce mode, the connecting
  process is stopped.

**Rate limiting.** A `limit` rule gives each process a budget of N new
connections per second or minute to the matching destination. Within budget,
evaluation continues to later rules. Over budget, the flow raises `NET-RATE`
and, in enforce mode, the process is stopped. The limit is on connection
attempts per process, not on requests multiplexed over one kept-alive
connection.

```
limit any:443      60/m actor=ai    # AI agents: at most 60 new HTTPS connections/min per process
deny  any:22            actor=ai    # AI agents may not SSH out
allow 10.0.0.0/8:any                # internal network is fine
deny  any:any           actor=ai    # default-deny egress for AI agents
```

## File integrity

`fim.conf` lists paths to watch, one per line, with an optional severity
(`critical`, `high` or `medium`; the default is `high`). Changes to a watched
file, or to anything directly inside a watched directory, raise a `FIM` alert.

```
/etc/passwd           critical
/etc/sudoers.d        critical
/etc/ssh              high
/root/.ssh            high
```

## Built-in detections

Some alerts come from the sensor itself rather than `rules.conf`:

| Rule | Raised when |
|---|---|
| `CAT-<KIND>` | a package, extension or AI tool violates the catalog |
| `NET-POLICY` | an outbound connection is denied by `netpolicy.conf` |
| `NET-RATE` | a process exceeds a `limit` rule |
| `FIM` | a watched file changes |
| `ANOM-001` | a program runs that this host has never run before (after `anomaly_learn`) |
| `HOST-ID-MISMATCH` | (console) a hostname reconnects with a different hardware/platform identity |
| `VAULT-ACCESS` | (console, info) a vault secret was read |
