# LinTest

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

Each check produces a **severity** — `OK`, `WARNING` (within 10 points of a limit, or degraded-but-working), `CRITICAL` (limit breached), or `ERROR` (the check itself failed). Problems are dispatched as **alerts** through Telegram/console with **cooldown** (no repeat spam) and **recovery** (a "RECOVERED" message when a problem clears).

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
- **Network checks** — ping with automatic TCP-latency fallback when ICMP is unavailable, TCP port probes (`host:port`, IPv6 as `[::1]:443`), DNS via system resolver or explicit `dig @server`
- **Security check** — failed SSH logins counted over a rolling window with per-IP ranking; tolerant parser (auth.log + journalctl formats, year roll-over safe)
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
5. **State survives restarts.** Cooldown bookkeeping is a small JSON file (`/var/lib/lintest/state.json`), so a systemd *timer* (new process every 5 min) still suppresses repeats.

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
  cpu_percent: 85            # >= limit -> CRITICAL; within 10 points -> WARNING
  disk_overrides: { "/": 85, "/data/db": 95 }
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

`install.sh` creates a `lintest` system user, installs to `/opt/lintest`, sets up a venv, log dir `/var/log/lintest`, state dir `/var/lib/lintest`, a 600-permission `.env`, and enables the 5-minute timer. Alternatives: `sudo ./install.sh --cron`, `--no-schedule`, `--uninstall`.

**Option B — cron:**

```bash
crontab -u lintest cron/lintest.cron
```

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
pytest                 # 62 tests: thresholds, config validation, log parser, cooldown/recovery
pytest --cov=lintest   # with coverage
```

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
├── requirements-dev.txt      # + pytest, pytest-cov
├── pyproject.toml            # packaging + `lintest` console script
├── install.sh                # one-shot installer (systemd / cron / uninstall)
├── systemd/lintest.service   # oneshot service unit
├── systemd/lintest.timer     # 5-minute timer
├── cron/lintest.cron         # cron alternative
├── .env.example              # template for Telegram secrets
├── lintest/
│   ├── main.py               # CLI + orchestration
│   ├── config.py             # YAML loading + validation
│   ├── models.py             # CheckResult / Severity / CheckReport
│   ├── checks/               # base guard, system, services, network, security
│   ├── alerts/               # base, console, telegram, manager (cooldown)
│   ├── reporting/            # json_output, html_report
│   └── utils/                # logging_setup, shell
└── tests/                    # pytest suite (62 tests)
```

## Roadmap

- [ ] Webhook channel (Slack / Discord / generic JSON POST)
- [ ] Concurrent check execution with per-check deadlines (`asyncio`)
- [ ] Prometheus `/metrics` endpoint alongside the HTML page
- [ ] Metric history + trend-based anomaly detection
- [ ] Auto-remediation hooks (guarded `systemctl restart` for warning-tier services)
- [ ] Config hot-reload in daemon mode
- [ ] Debian package + Ansible role

## License

MIT — see [pyproject.toml](pyproject.toml).
