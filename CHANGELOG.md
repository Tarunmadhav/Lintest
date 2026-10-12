# Changelog

All notable changes to LinTest are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Production-readiness hardening pass. No CLI, configuration or architecture
changes were made except where a verified defect required one.

### Fixed

- **Load average could never report OK.** The WARNING band was a fixed 10
  points, so any threshold at or below 10 classified *every* possible value as
  WARNING — `thresholds.load1_per_core: 1.5` meant a load of 0.05/core was
  "within 10 points of critical". The band is now
  `min(10 points, 25 % of the threshold)`: percentage thresholds keep the
  documented 10-point band, small thresholds get a proportional one.
- **Ping produced false `100% packet loss` verdicts.** The probe passed a
  millisecond value to iputils' seconds-based `-W` option (so
  `ping_timeout_seconds: 2` meant "wait 2000 s per reply") and mapped *any*
  unparseable output to "host unreachable: 100% packet loss" — including hosts
  where `ping` rejects our options, lacks ICMP privileges or is a different
  implementation. `-W`/`-w` now carry whole-second values derived from
  `ping_count × ping_timeout_seconds`, and a probe without parseable evidence
  falls back to the TCP latency probe (INFO when reachable) instead of claiming
  packet loss.
- **DNS check blamed the servers for a missing tool.** With
  `network.dns_servers` configured and no `dig` binary, every server "failed"
  and the result was CRITICAL. Missing `dig` now degrades to the system
  resolver with a WARNING naming the real cause.
- **A malformed log line could fail the whole security check.** A line whose
  shape matched but whose timestamp was nonsense (`Jul 32 99:99:99`) raised
  `ValueError`, which `run_check` turned into an ERROR result for the entire
  area. Such lines are now skipped, exactly like any other unrecognised line.
- **`sshd-session[pid]` lines were invisible.** OpenSSH 9.8+ logs some messages
  from `sshd-session`; those lines were silently ignored (reporting "0 failed
  logins"). The prefix is now accepted.
- **Security check slurped the whole auth.log.** Only the last 4 MiB are read
  per pass, and a partial first line is dropped; a multi-hundred-megabyte
  `auth.log` can no longer exhaust memory every five minutes.
- **Corrupt alert state crashed the run.** A state file that was valid JSON but
  not an object (`[1,2,3]`, `"x"`, `42`) raised `AttributeError` inside
  dispatch; a non-string or naive `last_sent` raised `TypeError`. Corrupt
  entries are now dropped individually with a warning and the run continues.
- **Concurrent runs could tear the alert state file.** The write temp file was
  named after the PID only, so two dispatchers inside one process (threads)
  wrote the *same* temp file concurrently and the interleaved JSON could be
  renamed onto `state.json`. Each write now gets its own `mkstemp` file, so
  overlapping runs — thread or process — can only ever produce a complete
  old-or-new file.
- **Failed recovery notifications were lost.** The state entry was marked idle
  even when the recovery message could not be delivered, so it was never
  retried. Failed recovery delivery now keeps the entry firing (alerts already
  behaved this way).
- **The Telegram token could be written to logs.** `requests` embeds the
  token-bearing request URL in its exception text; failed sends and API error
  bodies are now redacted (`<bot-token>`).
- **`install.sh`**
  - the root check ran *after* the uninstall branch, so uninstalling without
    root silently did nothing while reporting success;
  - uninstall removed the operator's **entire crontab** (`crontab -r`) instead
    of just LinTest's own line;
  - uninstall's config backup was moved back into the directory it had just
    deleted, so the preserved config was lost;
  - re-installing (upgrading) **overwrote an edited `/opt/lintest/config.yaml`**
    and used `/tmp` as an implicit scratch space;
  - cron mode never loaded `/opt/lintest/.env`, so Telegram alerts could never
    work under cron even with correct secrets;
  - an operator-installed `/opt/lintest` was writable by the monitor's own
    service user;
  - `sudo` was required for the smoke test (breaks on systems without sudo),
    `rsync` was mandatory, and a CRITICAL smoke-test result (exit code 1)
    aborted the installation.
- **`.env.example` was not a valid environment file.** It started with
  `[TEMPLATE]`, which systemd logs as an invalid assignment and which breaks
  `source .env`.
- **systemd timer semantics.** `Persistent=true` has no effect on monotonic
  timers (it only applies to `OnCalendar=`), and `OnUnitActiveSec` measures from
  service *start*, so a slow pass could delay the following one. The timer now
  uses `OnUnitInactiveSec=5min` (no overlap possible), the no-op `Persistent=`
  line was removed entirely, and the real behaviour is documented.
- **Native Windows behaviour (found by a native, non-WSL verification run).**
  `ping` was built with iputils flags (`-c/-W/-w`, seconds), so every probe
  silently degraded to the TCP fallback and real Windows ping output
  (`(100% loss)`, `Average = 12ms`) could not be parsed; a missing
  `systemctl`/`auth.log` produced ERROR/WARNING results that would alert on
  every Windows pass; and a report line containing characters outside the
  console code page (cp1252) crashed with `UnicodeEncodeError`.  Windows now
  gets `ping -n/-w ms` with a matching parser (a dead host reports true 100 %
  packet loss, not a parse failure), explicit "unsupported/skipped on Windows"
  INFO statuses, and lossy-but-crash-free console output.  Evidence:
  `docs/verification/windows-native.txt`.
- `run_daemon` kept a dead `last_code` variable (ruff F841).

### Added

- **GitHub Actions CI** (`.github/workflows/ci.yml`), 5 jobs: unit tests with
  coverage on Python 3.10–3.13, a Linux integration pass against the real
  machine (`systemctl`, `ping`, log sources), package build + `twine check` +
  wheel install/smoke test, installer install/upgrade/uninstall/`--purge`
  checks, and `systemd-analyze verify` for the units.
- **Test suite grown from 62 to 415 tests** (413 passed + 2 skips on native
  Windows; 414 passed + 1 skip on Linux), coverage **55 % → 96 %**.
  New suites cover malformed
  configurations, unavailable system utilities (`systemctl`, `ping`, `dig`,
  `journalctl`), missing log sources, SSH log year rollover, bounded reads,
  Telegram timeouts/HTTP failures/token redaction, failed delivery and recovery
  retries, concurrent invocations, state-file corruption, per-area error
  isolation, CLI exit codes, JSON/HTML rendering, and static checks on the
  shipped automation files.
- **Atomic state writes**: temp file (`mkstemp`, unique per write) +
  `os.replace()`, mode `0600`, so a crash or overlapping run can never leave a
  torn state file.
- **Retry accounting**: an alert (or recovery) that no channel could deliver is
  never marked as sent.
- **Verification evidence**: raw output of every release gate (ruff, tests +
  coverage on Windows and Linux, `systemd-analyze verify`, package build,
  `twine check`, clean-venv wheel install and a real pass) saved under
  `docs/verification/`, each file recording the exact command, platform and
  exit code.
- **systemd hardening**: `StateDirectory=`, `LogsDirectory=`,
  `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`,
  `ProtectKernelTunables`, `ProtectControlGroups`, `RestrictSUIDSGID`,
  `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, explicit
  `LINTEST_STATE_FILE`, and `TimeoutStartSec=120`. The monitor cannot write to
  its own code, config, or anything outside `/var/lib/lintest` and
  `/var/log/lintest`.
- **Installer hardening**: non-destructive upgrades (config and `.env` are
  preserved; a differing default config lands next to the old one as
  `config.yaml.new`), root-owned application tree (`chmod -R go-w`), `.env`
  created once with mode `640 root:lintest`, log access via the `adm` and
  `systemd-journal` groups, real single-pass smoke test as the service user,
  cron lines that source `.env` and are marked `# lintest`, `--purge` for a
  complete removal, and operator config preserved to
  `/var/backups/lintest/config.yaml.<timestamp>`.
- **Lint gate**: ruff (`E`, `F`, `W`, `I`, line length 120) configured in
  `pyproject.toml` and enforced in CI; `ruff`/`build` added to
  `requirements-dev.txt`.
- `SECURITY.md` (threat model, secret handling, hardening, reporting) and
  `docs/RELEASE_CHECKLIST.md`.

### Security

- Secrets stay in the environment: `token_env`/`chat_id_env` name variables
  only, `.env` is git-ignored and only `.env.example` is committed, and the
  token is redacted from every log line the Telegram channel can produce.
- The service user cannot modify the installed code or configuration (root
  ownership + `ProtectSystem=strict`), and the service runs with
  `NoNewPrivileges=true` and no sudo anywhere in the install path.
- A repository-wide test asserts that no real Telegram bot token pattern exists
  in the working tree and that no log/state/secret artifacts are tracked.

## [1.0.0] - 2026-09-29

Initial release.

### Added

- System checks (psutil CPU/RAM/per-mount disk/load with per-mount threshold
  overrides), systemd service checks with critical/warning tiers, network checks
  (ping with TCP fallback, TCP ports, DNS), and failed-SSH-login detection from
  `/var/log/auth.log` or `journalctl` with per-IP ranking.
- Thresholds with a 10-point early-warning band, `WARNING → CRITICAL` mapping,
  and `INFO`/`ERROR` results.
- Alert dispatch to Telegram and the console with per-`check::subject` cooldown
  persisted across runs, recovery notifications, and no cooldown arming when
  delivery fails.
- Crash-isolated check execution, command wrapper that never raises, strict
  config validation reporting all errors at once.
- Text/JSON/HTML reporting, rotating log file, daemon mode.
- systemd service + timer units, cron template, `install.sh` with uninstall
  support, and a 62-test pytest suite.

[Unreleased]: https://github.com/Tarunmadhav/Lintest/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Tarunmadhav/Lintest/releases/tag/v1.0.0
