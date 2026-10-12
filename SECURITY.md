# Security Policy

LinTest runs as a background monitor on a server, so it is written to be
boring from a security point of view: it needs no root privileges, no inbound
network access, and it holds exactly one secret.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x (current) | ✅ |
| < 1.0 | ❌ |

## Reporting a vulnerability

Please report suspected vulnerabilities through **GitHub's private
vulnerability reporting** ("Security" → "Report a vulnerability" on the
repository). That keeps the details out of public issues until a fix is
released. Include:

- affected version/commit,
- a minimal reproduction or the exact command output,
- impact assessment (what an attacker gains).

Please do **not** attach real `auth.log` excerpts, bot tokens or `.env` files.
Synthetic lines such as `Jul 15 10:30:00 srv1 sshd[1]: Failed password for root
from 203.0.113.5 port 2200 ssh2` are enough.

Expect an acknowledgement within a few days. There is no bug bounty.

## Secret handling

| Aspect | Behaviour |
|---|---|
| Where secrets live | Only in the environment (`LINTEST_TELEGRAM_TOKEN`, `LINTEST_TELEGRAM_CHAT_ID` by default). `config.yaml` stores only the *names* of those variables. |
| On disk | `install.sh` creates `/opt/lintest/.env` once, with mode `640` and owner `root:lintest`; it is never overwritten by an upgrade. |
| In git | `.gitignore` excludes `.env` and `*.env`; only `.env.example` (placeholders) is committed. A test asserts the known bot-token pattern never appears in the working tree. |
| In logs | The Telegram channel redacts the token from every message it logs (`<bot-token>`), including `requests` exception text, which embeds the token-bearing URL. |
| In reports | JSON/HTML reports contain check results and messages — never credentials. |
| Retention | The state file holds error messages and timestamps only, mode `0600`. |

## Privilege model

- The service runs as the unprivileged system account `lintest` with
  `NoNewPrivileges=true`; `install.sh` never needs sudo for LinTest itself and
  never installs a sudoers rule.
- `/opt/lintest` is `root:root` with the group/other write bits cleared, so the
  monitored service user cannot edit the monitor's own code or configuration.
- The systemd unit runs with `ProtectSystem=strict`, `ProtectHome=read-only`,
  `PrivateTmp`, `ProtectKernelTunables`, `ProtectControlGroups` and
  `RestrictSUIDSGID`, and may only write inside `/var/lib/lintest`
  (`StateDirectory=`) and `/var/log/lintest` (`LogsDirectory=`).
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` keeps outbound
  sockets needed for checks and the libc resolver, and nothing else.
- `TimeoutStartSec=120` bounds a wedged pass so a hung probe cannot pile up.

### Reading logs (least privilege)

The SSH check needs one readable source of authentication events:

- **Debian/Ubuntu**: `/var/log/auth.log` is `0640 root:adm`, so `install.sh`
  adds the service user to the `adm` group when it exists.
- **RHEL/Fedora**: `/var/log/secure` is root-only; the journal is used instead,
  which requires membership of `systemd-journal` (also granted automatically
  when the group exists).
- If neither is available the check reports a WARNING ("no SSH auth source
  available") instead of pretending everything is fine — or worse, making your
  monitoring blind. Fix the group membership or point
  `security.auth_log_path` at a readable copy.

## Command execution

- Every external command goes through `lintest/utils/shell.py`, which executes
  an **argv list with `shell=False`** — there is no string interpolation into a
  shell, so values from `config.yaml` (hostnames, service names, mount points)
  cannot inject commands.
- Missing binaries, non-zero exits and timeouts are returned as data
  (`CommandResult.missing` / `.timed_out` / `.returncode`), never as
  exceptions, so a broken tool degrades into a visible ERROR result.

## Network exposure

- LinTest opens only **outbound** connections: ICMP/TCP to configured hosts,
  DNS, `systemctl` over a local socket, and HTTPS to `api.telegram.org`.
- It ships no listening socket, no HTTP server and no dashboard.
- The HTML report is written as a **static file** with all dynamic values
  HTML-escaped. It contains no JavaScript and no external resources, so it is
  safe to serve from any web root.

## Threat model notes

In scope:

- privilege escalation from the monitor's own account,
- command injection through configuration values,
- secret disclosure through git, logs, reports or process arguments,
- denial of service against the host by the monitor itself (unbounded reads,
  unbounded subprocesses, log spam).

Out of scope / accepted:

- Telegram's own transport security (we rely on HTTPS, no certificate pinning),
- an attacker who already controls the monitored metrics (they can generate
  alerts — the monitor is an observer, not a preventive control),
- alert delivery guarantees: a network partition silently delays alerts; the
  manager logs and retries rather than guaranteeing delivery,
- the state file and `config.yaml` are readable by the service user; treat the
  host's own trust boundary as given.

## Verifying the security posture yourself

```bash
# 1. Static lint + full test suite (includes secret-hygiene and install.sh checks)
python -m ruff check lintest tests
python -m pytest tests

# 2. Confirm no secret ever reaches the tree
git grep -nE '\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b' || echo "no bot tokens committed"

# 3. Inspect the effective sandbox of the running unit
systemd-analyze security lintest.service

# 4. Validate the shipped units before installing
systemd-analyze verify systemd/lintest.service systemd/lintest.timer
```

`systemd-analyze security` reports the sandbox exposure of the installed unit;
the shipped unit is designed for a low exposure score (no root, strict
filesystem protection, restricted address families, no new privileges).
