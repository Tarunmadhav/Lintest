# LinTest

[![CI](https://github.com/Tarunmadhav/Lintest/actions/workflows/ci.yml/badge.svg)](https://github.com/Tarunmadhav/Lintest/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License MIT](https://img.shields.io/badge/license-MIT-green)

**Linux server health monitor with alerting** — a Python 3.10+ CLI tool that checks system metrics, systemd services, network reachability and failed SSH logins, then alerts via **Telegram** (with a console fallback) when thresholds are breached. Designed to run unattended from a **systemd timer** (every 5 minutes) or **cron**.

---

## Overview

LinTest answers four questions about a Linux host and tells you when something is wrong:

| Area | What it checks | Source |
|---|---|---|
| **System** | CPU %, RAM %, disk usage per mount, load average (per core) | `psutil` |
| **Services** | Is each configured systemd unit running? (`critical` and `warning` tiers) | `systemctl is-active` |
| **Network** | ICMP ping latency, TCP port reachability, DNS resolution | `ping`, sockets, `dig` |
| **Security** | Failed SSH logins in the last N minutes + top offending IPs | `/var/log/auth.log`, fallback `journalctl` |

Each check produces a **severity** — `OK`, `WARNING` (inside the early-warning band below a limit, or degraded-but-working), `CRITICAL` (limit breached), or `ERROR` (the check itself failed). The band is `min(10 points, 25 % of the limit)`: percentage thresholds keep the familiar 10-point band, while small thresholds such as `load1_per_core: 1.5` get a proportional one instead of classifying every value as a warning. Problems are dispatched as **alerts** through Telegram/console with **cooldown** (no repeat spam) and **recovery** (a "RECOVERED" message when a problem clears).

Sample output of one pass:

```
$ lintest --config /etc/lintest/config.yaml
LinTest 1.0.0 | host prod-web-01 | 2026-09-29 14:00:03Z
------------------------------------------------------------------------------
 . OK       system.cpu         [cpu]        CPU usage 12.3% (8 cores)
 . OK       system.ram         [ram]        RAM usage 41.2% (13.2/32.0 GiB)
 . OK       system.disk        [/]          disk / 38.5% used (215.0/350.0 GiB free on ext4)
 . OK       system.load        [load]       load1 0.35 (0.04/core over 8 cores; 5m 0.42, 15m 0.39)
 . OK       services.active    [sshd]       service 'sshd' is active
 ! WARNING  services.active    [nginx]      service 'nginx' is inactive (tier: warning)
 . OK       network.ping       [1.1.1.1]    host 1.1.1.1 reachable: avg 12 ms, loss 0%
 . OK       network.dns        [google.com] resolved google.com -> 142.250.75.238 (system resolver)
 X CRITICAL security.ssh       [ssh]        34 failed SSH logins in the last 15 min (top: 203.0.113.5 x29) -- at or above the critical threshold (20)
------------------------------------------------------------------------------
Result: CRITICAL (7 ok, 1 warning(s), 1 critical, 0 error(s) in 2.1s) | exit code 1
```

## Features

- **System metrics** — CPU/RAM %, per-mount disk usage with per-mount threshold overrides, load average normalized by core count
- **Service checks** — `systemctl is-active`, split into *critical* (drives exit code 1) and *warning* tiers
- **Network checks** — ping with automatic TCP-latency fallback when ICMP is unavailable *or* the probe produces no usable output, TCP port probes (`host:port`, IPv6 as `[::1]:443`), DNS via system resolver or explicit `dig @server` (a missing `dig` degrades to the system resolver instead of a false DNS outage)
- **Security check** — failed SSH logins counted over a rolling window with per-IP ranking; tolerant parser (auth.log + journalctl formats including `sshd-session`, year roll-over safe, malformed lines skipped, tail-only reads)
- **Alerting** — Telegram Bot API + console fallback; per-check cooldown persisted to disk across runs; automatic RECOVERED messages
- **Configuration** — single `config.yaml`, validated on startup with *all* errors reported together
- **Crash isolation** — every check runs behind a guard; one failing check becomes an ERROR result instead of aborting the run
- **Reporting** — text, `--output json` (pipe into `jq`), `--report <path>` standalone HTML page, rotating log file
- **Automation** — systemd service + timer (5 min) or cron; exit code `1` when any CRITICAL was found

---

## Architecture

### High-level flow

```
                +-----------------------------+
 config.yaml -->| lintest.config              |  strict validation, all errors
 env vars ----->| load_config()               |  reported in ONE message
                +-------------+---------------+
                              |
                              v
                +-----------------------------+
                | lintest.main                |  argparse: --config --output
                | run_pass() orchestration    |  --report --once --verbose
                +-------------+---------------+  exit codes 0/1/2/130
                              |
         +--------------------+----------------------+
         v                    v                      v
 +---------------+    +---------------+      +---------------+   +----------------+
 | checks/       |    | checks/       |      | checks/       |   | checks/        |
 | system.py     |    | services.py   |      | network.py    |   | security.py    |
 | psutil:       |    | systemctl     |      | ping / TCP    |   | auth.log |     |
 | CPU RAM disk  |    | is-active     |      | ports / DNS   |   | journalctl     |
 | load          |    | critical/warn |      | TCP fallback  |   | top-IP ranking |
 +-------+-------+    +-------+-------+      +-------+-------+   +--------+-------+
         |                    |                      |                    |
         +--------------------+----------+-----------+--------------------+
                                          |
                          List[CheckResult]  (never raises -- each area is
                          wrapped by checks/base.run_check crash guard)
                                          |
                                          v
                +-----------------------------+
                | alerts/manager.py           |
                | AlertManager.dispatch()     |  cooldown via JSON state file
                | suppress / send / recover   |  (survives timer restarts)
                +-------------+---------------+
                       |                    |
              +--------+--------+  +--------v---------+
              | alerts/console  |  | alerts/telegram  |
              | stderr + colour |  | Bot API (HTML)   |
              +-----------------+  +------------------+
                                          |
                                          v
                +-----------------------------+     +--------------------------+
                | reporting/json_output.py    |     | reporting/html_report.py |
                | --output json (stdout)      |     | --report (standalone)    |
                +-----------------------------+     +--------------------------+
                +-----------------------------+
                | utils/logging_setup.py      |  RotatingFileHandler
                | utils/shell.py              |  run_command(): never raises
                +-----------------------------+
```

### Run model

Everything flows through one small data model:

```
CheckResult(check, severity, message, subject, details)
    check    machine name, e.g. "system.disk"
    severity OK | INFO | WARNING | CRITICAL | ERROR
    subject  what it's about: mount point, service name, host, IP...
    details  structured extras for JSON/HTML (percentages, counts, RTTs)

key = check::subject          <- identity used for cooldown bookkeeping
```

- Each area runner returns `List[CheckResult]`; `main.collect_results()` aggregates them into a `CheckReport`.
- `CheckReport.exit_code` is `1` if any CRITICAL result exists, else `0` (config errors exit `2`).
- The **alert key** `check::subject` is what cooldown/recovery tracks: `system.disk::/data` and `system.disk::/var` alert independently.

### Design guarantees

1. **A failing check never crashes the run.** `checks/base.run_check()` wraps every sub-check; an exception becomes one ERROR result (`check crashed: ...`) and the remaining checks still execute.
2. **External commands never raise.** `utils/shell.run_command()` returns a `CommandResult` with `missing` / `timed_out` flags; callers turn those into ERROR/CRITICAL results.
3. **Alert delivery never raises.** Channels return `True`/`False`; if no channel delivers, the cooldown state is *not* armed, so the next run retries the alert.
4. **Secrets never touch disk or git.** The Telegram token/chat id are read from environment variables (names configured in `config.yaml`); only `.env.example` is committed.
5. **State survives restarts.** Cooldown bookkeeping is a small JSON file (`/var/lib/lintest/state.json`), so a systemd *timer* (new process every 5 min) still suppresses repeats. Writes are atomic and mode `0600`; a corrupt or half-written state file is dropped entry by entry instead of aborting the pass.
6. **Bounded resource use.** The SSH log is read from the **tail only** (last 4 MiB), every subprocess runs with a timeout, and a probe that cannot produce usable evidence degrades to a documented fallback instead of a false CRITICAL.
7. **Secrets never reach logs.** The Telegram token is redacted from every log line, including `requests` exception text.

### Key modules

| Module | Responsibility |
|---|---|
| `lintest/config.py` | YAML loading, strict validation, threshold classification helpers |
| `lintest/models.py` | `CheckResult`, `Severity`, `CheckReport`, exit-code logic |
| `lintest/checks/base.py` | Crash guard around every check |
| `lintest/checks/system.py` | psutil metrics + threshold classification |
| `lintest/checks/services.py` | `systemctl is-active` with critical/warning tiers |
| `lintest/checks/network.py` | Ping (with TCP fallback), TCP ports, DNS |
| `lintest/checks/security.py` | Failed-SSH parser, time window, top-IP aggregation |
| `lintest/alerts/manager.py` | Cooldown, recovery, multi-channel fan-out, JSON state |
| `lintest/alerts/telegram.py` | Telegram Bot API (HTML parse mode, env-based secrets) |
| `lintest/reporting/` | JSON and standalone-HTML output |
| `lintest/utils/` | Rotating logging setup; safe subprocess wrapper |
| `lintest/main.py` | CLI, orchestration, exit codes |

### Verification status

| Gate | Result |
|---|---|
| Unit tests | **413 passed, 2 skipped** on native Windows, **414 passed, 1 skipped** on Linux (415 collected; skips: `systemd-analyze` unavailable + POSIX-permissions on Windows, "not a git checkout" in the staged Linux copy) |
| Coverage | **96 %** of `lintest` (was 55 % before the hardening pass) |
| Lint | `ruff check lintest tests` — clean (`E`, `F`, `W`, `I`) |
| Python versions | tested on 3.11 locally and 3.14 (Linux); CI matrix covers 3.10–3.13 |
| Linux behaviour | real pass against a Linux host (WSL Ubuntu, systemd present) incl. `systemctl`, `ping`, log sources |
| Packaging | `python -m build` + wheel installed into a clean venv, `lintest --version` / real pass OK |
| systemd units | `systemd-analyze verify` clean |
| Installer | `install.sh` verified end to end on Linux: install with systemd timer → timer fires real passes (cooldown persists across runs, no overlapping processes, `SuccessExitStatus=1` honoured in the journal) → re-install (config/`.env` preserved, `config.yaml.new` written) → uninstall (config backup kept) → `--purge` |
| Gate outputs | raw, timestamped output of every gate above — incl. `systemd-analyze`, build, `twine check` and a clean-venv wheel install — saved in [docs/verification/](docs/verification/) with exit codes |
| Native Windows | verified **outside WSL**: real ICMP ping (`ping -n/-w ms`), real `C:\`/`D:\`/`E:\` disk values, services/security reported as "unsupported/skipped", exit codes 0/1/2, cp1252-safe output — see [docs/verification/windows-native.txt](docs/verification/windows-native.txt) |

See [CHANGELOG.md](CHANGELOG.md) for the full defect list, [SECURITY.md](SECURITY.md) for the threat model, and [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) for the release gates and known limitations.

---

## Getting started

### Prerequisites

- Linux (any modern distro with systemd; works without systemd too — service checks degrade to ERROR results, cron replaces the timer)
- Python **3.10+**
- For Telegram alerts: a bot token and your chat id (2 minutes to set up, below)

### 1. Clone and install

```bash
git clone https://github.com/Tarunmadhav/Lintest.git
cd Lintest

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure

The shipped `config.yaml` works out of the box (sane thresholds, checks `sshd`/`nginx`/`docker`, pings 1.1.1.1/8.8.8.8). Edit what you need:

```bash
$EDITOR config.yaml
```

The parts you'll most likely touch:

```yaml
thresholds:
  cpu_percent: 85            # >= limit -> CRITICAL; within the warning band -> WARNING
  disk_overrides: { "/": 85, "/data/db": 95 }
  load1_per_core: 1.5        # the band is min(10 points, 25 % of the limit)
  failed_ssh_logins: 20      # within security.window_minutes

services:
  critical: [sshd]           # stopped -> CRITICAL (exit code 1)
  warning:  [nginx, docker]  # stopped -> WARNING only

network:
  ping_hosts: [1.1.1.1, 8.8.8.8]
  tcp_ports: ["db.internal:5432"]
```

### 3. Set up Telegram secrets (optional but recommended)

```bash
cp .env.example .env
$EDITOR .env
```

1. Create a bot: message **@BotFather** on Telegram → `/newbot` → copy the token into `.env`.
2. Get your chat id: message your new bot once, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy the `chat.id` value into `.env`.

For manual runs, export the variables:

```bash
set -a; source .env; set +a
```

> No secrets? The tool still works — Telegram disables itself with a warning and the console channel delivers everything.

### 4. First run

```bash
python -m lintest --config config.yaml          # one pass, text report
python -m lintest --output json | jq .summary   # machine-readable
python -m lintest --report status.html          # standalone HTML status page
python -m lintest --once --dry-run -v           # checks only, no alerts sent
```

CLI reference:

| Flag | Meaning |
|---|---|
| `--config PATH` | config file (default: `./config.yaml` if present, else built-in defaults) |
| `--output text\|json` | human or machine output (JSON goes to stdout, logs to stderr) |
| `--report PATH\|html` | write an HTML status report to PATH (`html` → `./lintest-report.html`) |
| `--once` | exactly one pass even in daemon mode |
| `--verbose` / `-v` | DEBUG logging |
| `--dry-run` | run checks, skip alert dispatch and state writes |

Exit codes: `0` healthy · `1` any CRITICAL · `2` configuration error · `130` interrupted.

### 5. Run it on a schedule

**Option A — systemd timer (recommended):**

```bash
sudo ./install.sh
systemctl list-timers lintest.timer     # verify next-fire time
journalctl -u lintest.service -f        # watch passes live
```

`install.sh` creates a `lintest` system user, installs to `/opt/lintest`, sets up a venv, log dir `/var/log/lintest`, state dir `/var/lib/lintest`, a `640 root:lintest` `.env`, adds the service user to `adm`/`systemd-journal` (so the SSH check can read authentication events), runs a real smoke-test pass as that user, and enables the 5-minute timer.

| Invocation | Effect |
|---|---|
| `sudo ./install.sh` | install + systemd service/timer (falls back to cron automatically) |
| `sudo ./install.sh --cron` | install + cron entry |
| `sudo ./install.sh --no-schedule` | install files, venv and smoke test only |
| `sudo ./install.sh` (again) | **upgrade**: replaces code, keeps your `config.yaml` and `.env`, writes a differing default config to `config.yaml.new` |
| `sudo ./install.sh --uninstall` | remove code + scheduler, keep logs, state and a timestamped config backup in `/var/backups/lintest/` |
| `sudo ./install.sh --uninstall --purge` | also remove logs, state and the `lintest` user |

Security posture of the installed setup: the application tree is `root:root` and not group/world-writable, the unit runs with `ProtectSystem=strict` (write access only to `/var/lib/lintest` and `/var/log/lintest`), `NoNewPrivileges=true` and restricted address families — see [SECURITY.md](SECURITY.md).

**Option B — cron:**

```bash
crontab -u lintest cron/lintest.cron     # the line sources /opt/lintest/.env itself
```

Cron does not read systemd's `EnvironmentFile`, so the installed cron job sources `/opt/lintest/.env` before running the check — without it the Telegram channel would silently have no credentials.

**Option C — daemon loop (no scheduler):**

```yaml
schedule:
  mode: daemon
  interval_seconds: 300
```

```bash
python -m lintest --config config.yaml
```

### 6. Verify alerts end to end

```bash
# force a CRITICAL by filling a small tmpfs above its threshold... or simply
sudo systemctl stop nginx          # WARNING tier per shipped config
python -m lintest --config config.yaml
# console channel prints the alert; Telegram receives it if .env is set up

sudo systemctl start nginx
python -m lintest --config config.yaml
# -> RECOVERED message
```

---

## Testing locally

```bash
pip install -r requirements-dev.txt
ruff check lintest tests        # lint gate (also runs in CI)
pytest                          # 415 tests
pytest --cov=lintest            # 96 % coverage
```

The suite is hermetic: no test touches the real system, the network or your
cooldown state (`LINTEST_STATE_FILE` is redirected per test), so it passes on
Linux, macOS and Windows and on Python 3.10–3.14.

What is covered: threshold classification and the WARNING band, config
validation (every validator branch, all errors reported together), service/
network/system checks with faked `systemctl`/`ping`/`psutil` (missing binary,
timeout, unusable output, TCP fallback), SSH log parsing (year rollover,
boundary timestamps, `sshd-session`, tail reads, malformed lines, journalctl
fallback), alert cooldown/recovery and retry semantics, state-file corruption
and concurrent writes, Telegram HTTP/timeout/redaction paths, CLI exit codes and
output modes, error isolation between check areas, plus static checks on
`install.sh`, the systemd units, the cron template and secret hygiene.

### Simulate failures on a Linux box

```bash
# High CPU (1 busy core):
yes > /dev/null &
python -m lintest          # system.cpu -> WARNING/CRITICAL
kill %1                    # next pass -> RECOVERED

# All cores (needs stress-ng):
stress-ng --cpu $(nproc) --timeout 120s &

# Stopped service:
sudo systemctl stop nginx && python -m lintest

# SSH brute force:
for i in $(seq 1 25); do ssh -o BatchMode=yes wronguser@localhost; done
python -m lintest          # security.ssh -> CRITICAL with top offending IPs
```

### Simulating on non-Linux machines (e.g. developing on Windows/macOS)

The checks degrade gracefully: `systemctl` missing → ERROR results; no `/var/log/auth.log` and no `journalctl` → a WARNING ("no SSH auth source available"); `ping` output differs → TCP fallback and DNS still exercise the network path. Unit tests never touch the real system, so the full suite passes on any OS.

---

## Project layout

```
Lintest/
├── config.yaml               # commented default configuration
├── requirements.txt          # psutil, PyYAML, requests
├── requirements-dev.txt      # + pytest, pytest-cov, ruff, build
├── pyproject.toml            # packaging, pytest, coverage and ruff config
├── install.sh                # idempotent installer (systemd / cron / upgrade / uninstall / purge)
├── CHANGELOG.md              # keep-a-changelog history + fixed defects
├── SECURITY.md               # threat model, privileged access, secret handling
├── docs/RELEASE_CHECKLIST.md # release gates and known limitations
├── .github/workflows/ci.yml  # tests, coverage, lint, packaging, installer, units
├── systemd/lintest.service   # oneshot service unit (sandboxed)
├── systemd/lintest.timer     # 5-minute timer (no overlapping passes)
├── cron/lintest.cron         # cron alternative (sources .env)
├── .env.example              # template for Telegram secrets
├── lintest/
│   ├── main.py               # CLI + orchestration
│   ├── config.py             # YAML loading + validation
│   ├── models.py             # CheckResult / Severity / CheckReport
│   ├── checks/               # base guard, system, services, network, security
│   ├── alerts/               # base, console, telegram, manager (cooldown)
│   ├── reporting/            # json_output, html_report
│   └── utils/                # logging_setup, shell
└── tests/                    # pytest suite (415 tests, 96 % coverage)
```

## Operating notes

- **Cooldown location.** Cooldown/recovery state defaults to
  `/var/lib/lintest/state.json` (then `/run/lintest`, then `~/.cache/lintest`);
  override with `LINTEST_STATE_FILE`. State on `/run` is lost on reboot.
- **Read-only sandbox.** The unit may only write to `/var/lib/lintest` and
  `/var/log/lintest`. If you point `logging.file` somewhere else, add that path
  to `ReadWritePaths=` in the unit or logging falls back to the console.
- **SSH log access.** For failed-login detection the service user needs to read
  the auth log (`adm` group on Debian/Ubuntu) or the journal
  (`systemd-journal`). Without either, `security.ssh` reports a WARNING — it
  never silently reports "0 failures".
- **ICMP.** If `ping` is unavailable or ICMP is filtered, the host check falls
  back to a TCP-connect probe to port 443 and says so in the result details
  (`method: tcp_fallback`); it does not claim packet loss.
- **Exit codes** are written for schedulers: `0` healthy, `1` CRITICAL found,
  `2` configuration error, `130` interrupted. The systemd unit declares
  `SuccessExitStatus=1` so a CRITICAL does not mark the monitor itself failed.

## Roadmap

- [ ] Event-triggered checks (only re-probe an area when its inputs changed)
- [ ] Webhook channel (Slack / Discord / generic JSON POST)
- [ ] Concurrent check execution with per-check deadlines (`asyncio`)
- [ ] Metric history + trend-based anomaly detection
- [ ] Config hot-reload in daemon mode
- [ ] Debian package + Ansible role

Not planned by design: automatic service restarts (the monitor is an observer),
a web dashboard, and a Prometheus endpoint.

## License

MIT — see [pyproject.toml](pyproject.toml).
