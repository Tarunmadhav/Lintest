# LinTest — Project Memory Image

> Snapshot of the Production Readiness Milestone, generated 2026-10-12.
> Purpose: let any future session resume work without re-discovering the
> codebase, verification environment, or what has already been proven.

## 1. Project identity

- **LinTest** — Linux server health monitor (CPU/RAM/disk/load, services,
  ping/TCP/DNS, SSH log security scan) with cooldown-aware alerting
  (console + Telegram), JSON/HTML reporting, systemd timer / cron scheduling.
- Repo: <https://github.com/Tarunmadhav/Lintest> — local checkout on `main`
  at commit `8dd829a` (v1.0.0). **All milestone work is UNCOMMITTED in the
  working tree. Do not commit, push, or tag without explicit authorization.**
- CLI preserved: `lintest [--config ...] [--dry-run] [--json ...] [--html ...]`;
  exit codes: 0 OK / WARNING, 1 CRITICAL, 2 usage-config error (verify against
  [README.md](../README.md) "Operating notes" before changing).

## 2. Architecture map

| Path | Role |
|---|---|
| `lintest/config.py` | YAML schema, validation, `warning_band()` = `min(10 pts, 25 % of threshold)` |
| `lintest/checks/system.py` | cpu/ram/disk/load; load uses proportional band |
| `lintest/checks/network.py` | `_ping_argv` whole-second `-W/-w`, `PingOutcome.parseable`, TCP fallback, `ResolveOutcome` + missing-`dig` → system resolver |
| `lintest/checks/security.py` | tail-reads last 4 MiB of auth.log, `sshd(?:-session)?`, junk timestamps skipped |
| `lintest/checks/services.py` | systemctl tiers (critical/warning) |
| `lintest/alerts/manager.py` | cooldown/recovery, corruption-tolerant `_load_state`, atomic `_save_state` (per-write `mkstemp` + `os.replace`, 0600) |
| `lintest/alerts/telegram.py` | Bot API; `_redact()` strips token from all log output |
| `lintest/main.py` | orchestration, per-area error isolation, exit codes |
| `install.sh` | root preflight, idempotent upgrade (preserves `config.yaml` + `.env`, writes `config.yaml.new`), `--uninstall [--purge]` with config backup to `/var/backups/lintest/` |
| `systemd/lintest.service` | `StateDirectory/LogsDirectory=lintest`, `ProtectSystem=strict`, `SuccessExitStatus=1` |
| `systemd/lintest.timer` | `OnUnitInactiveSec=5min`, `RandomizedDelaySec=30s`, no `Persistent=` (no-op on monotonic timers); **never add `After=lintest.service` (ordering cycle)** |
| `.github/workflows/ci.yml` | 5 jobs: tests py3.10–3.13, linux-integration, packaging, installer E2E, systemd-units |

## 3. Verified results (all executed, this milestone)

| Gate | Baseline (before) | Final |
|---|---|---|
| Unit tests | 62 passed | **Native Windows: 413 passed, 2 skipped** · **Linux WSL: 414 passed, 1 skipped** (415 collected both) |
| Coverage (`lintest`) | 55 % | **96 %** (1351 stmts, ~59 missed) |
| Ruff (`E,F,W,I`, len 120) | pre-existing violations | **clean on both platforms** |
| Packaging | — | `python -m build` + `twine check` **PASSED** (WSL) |
| systemd units | — | `systemd-analyze verify` **clean** |
| Installer E2E (WSL Ubuntu, systemd PID 1) | — | install → timer fires (run 1: alerts sent 3; run 2: suppressed 3, cooldown persisted; `ExecMainStatus=1` + `Result=success`) → upgrade preserves config/.env → uninstall+purge clean with config backup |
| Wheel install in clean venv | — | `lintest --version` + real pass (13 checks, exit 1 on CRITICAL) OK |
| **Native Windows (non-WSL), Windows 10** | — | **413 passed, 2 skipped, 96 %, ruff clean** in `%TEMP%\lintest-win-venv`; live CLI verified: real `ping -n/-w ms` ICMP, `C:\`/`D:\`/`E:\` values, services/security "unsupported/skipped" INFO, exit codes 0/1/2, cp1252-safe output, state at `~/.lintest/state.json` with cross-run cooldown — evidence `docs/verification/windows-native.txt` |

Reproduce (Windows): `python -m ruff check lintest tests` then
`python -m pytest tests --cov=lintest --cov-report=term`.
Note: `pyproject` has `addopts = -q`; adding another `-q` hides the summary line.

## 4. Environment facts (critical for resuming)

- **Windows**: Git Bash/MINGW; `python` → 3.11.9 (`python3` not on PATH);
  ruff 0.16.1 + build 1.5.0 installed as modules. Docker daemon NOT running.
- **WSL Ubuntu 26.04 (root)** — the real Linux verification box; systemd is
  PID 1, `ping`/`systemctl`/`crontab`/`auth.log` present, `dig` missing
  (exercises the DNS fallback), `rsync` present. Python 3.14.4.
- **Persistent Linux venv**: `/var/tmp/lintest-verify/venv`
  (psutil, PyYAML, requests, pytest, pytest-cov, ruff, build, twine).
  Source staged to `/var/tmp/lintest-verify/src`.
  **`/tmp` is tmpfs and gets wiped — always use `/var/tmp`.**
- **Native Windows venv**: `%TEMP%\lintest-win-venv` — in Git Bash `$TEMP`
  is `/tmp`, which IS `C:\Users\tarun\AppData\Local\Temp` (verify with
  `cygpath -w /tmp` before assuming).  Use `python` (3.11.9), never `python3`.
  Git Bash rewrites args starting with `/` (MSYS path conversion) — wrap
  paths for WSL in `bash -c "cat /var/tmp/..."` or they come back mangled.
- Sync source: `tar -cf - --exclude=.git ... . | wsl.exe -d Ubuntu -u root -- bash -c 'tar -xf - -C /var/tmp/lintest-verify/src ...'`
- Run tests on Linux with `TZ=UTC`. Long scripts feed via
  `wsl.exe -d Ubuntu -u root -- bash -s <<'EOF' ... EOF`.
- The freebuff shell tool **blocks `sudo`** in commands; WSL already runs as
  root, so drop it.
- WSL install artifacts were purged clean at the end of the session; the
  venv + src staging remain for the next run.

## 5. Defect log (all fixed in working tree)

1. WARNING band fixed at 10 pts → load could never be OK (threshold 1.5).
2. Ping passed ms to iputils' seconds `-W`; unparseable output claimed
   "100 % packet loss" → TCP fallback; missing `dig` → false CRITICAL.
3. Whole auth.log read each pass (unbounded memory) → 4 MiB tail.
4. `sshd-session` lines invisible; junk timestamps failed the whole area.
5. Corrupt state JSON shapes crashed dispatch (`AttributeError`/`TypeError`);
   state writes were not crash-safe → tolerant load + atomic per-write save.
6. Failed recovery delivery marked entry idle → never retried (now stays firing).
7. Telegram token leaked via `requests` exception URLs → `_redact()`.
8. `install.sh`: root check after uninstall branch; `crontab -r` nuked the
   whole crontab; config backup into just-deleted dir; upgrade clobbered
   operator config; `lintest` console script never installed (ExecStart
   exit 127); smoke test needed sudo/`rsync`.
9. `.env.example` had invalid `[TEMPLATE]` line (broke systemd EnvironmentFile).
10. Timer: `OnUnitActiveSec` overlap + no-op `Persistent=true`; my own
    `After=lintest.service` caused an ordering cycle (caught by
    `systemd-analyze verify`, removed).
11. **State temp file named `{state}.{pid}.tmp`** — threads in one process
    shared the temp file → interleaved JSON could be renamed onto
    `state.json` (found by a flaky full-suite run) → per-write `mkstemp`.
12. **Windows was never actually exercised** (found 2026-10-12 by a native
    non-WSL run): ping used iputils flags → always TCP fallback, Windows
    output `(100% loss)`/`Average = 12ms` unparseable; missing
    systemctl/auth.log → ERROR/WARNING that would alert every pass; cp1252
    console could crash the report with `UnicodeEncodeError`. Fixed with
    explicit `sys.platform == "win32"` branches: `ping -n -w <ms>` + parser,
    INFO "unsupported/skipped on Windows", `_safe_print` lossy fallback.
    Linux behaviour untouched (tests pin `sys.platform`).

## 6. Known limitations (recorded, not claimed as tested)

- ICMP/firewall edge cases verified on one host only.
- Installer/timer tested on Ubuntu WSL; no real RHEL/Debian/Arch host, no
  non-systemd cron daemon (static + `bash -n` only).
- Telegram delivery unit-tested with mocks — no live bot (no secrets in repo).
- Multi-process alert state is last-writer-wins bookkeeping (no lock —
  `docs/STATE_LOCK_PROPOSAL.md`, not implemented).
- **Windows**: daemon/long-run mode not exercised; state-file mode shows
  `666` (Windows has no POSIX permission bits — `os.chmod(0o600)` is a
  no-op, does not crash); Windows is not in the CI matrix (CI runs Linux);
  installer/systemd/cron are Linux-only by design.
- CI workflow is valid YAML but has not run on GitHub (push not authorized).

## 7. Release next steps

1. Review diff → **commit** (await authorization; keep `.freebuff/` out).
2. Push → confirm 5 CI jobs green on py3.10–3.13.
3. Clean-clone Linux gate: installer E2E + `systemd-analyze verify`.
4. Tag `v1.1.0` (CHANGELOG `[Unreleased]` ready to retitle), attach
   wheel + sdist, final `twine check`.
5. Copy the §6 limitations into the GitHub release notes.
