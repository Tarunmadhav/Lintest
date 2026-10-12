# Release checklist

Copy this into the release PR (or issue) and tick every box. Anything that
cannot be run must be recorded as a known limitation in the release notes —
never ticked.

## 1. Prepare

- [ ] Working tree is clean; the branch being released is merged into `main`.
- [ ] `pyproject.toml` version is bumped (`1.0.0` → `1.0.1` for a patch).
- [ ] `CHANGELOG.md`: move `## [Unreleased]` entries under
      `## [<version>] - <YYYY-MM-DD>` and update the compare links.
- [ ] `README.md` numbers (test count, coverage) still match reality.
- [ ] No secrets in the diff:
      `git grep -nE '\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b' -- . || echo clean`
- [ ] No real logs, state files or `.env` files staged:
      `git status --short` and `git ls-files | grep -E '\.(log|env|state\.json)$'` (must be empty).

## 2. Quality gates (all must pass locally before pushing)

- [ ] Lint: `python -m ruff check lintest tests`
- [ ] Full suite: `python -m pytest tests`
- [ ] Coverage: `python -m pytest tests --cov=lintest --cov-report=term-missing`
      → record the percentage in the release notes (no regression from the
      previous release).
- [ ] Package build: `python -m build` and `python -m twine check dist/*`
- [ ] Wheel works in a clean venv:
      `python -m venv /tmp/v && /tmp/v/bin/pip install dist/*.whl && /tmp/v/bin/lintest --version`
- [ ] Installer syntax: `bash -n install.sh`
- [ ] systemd units: `systemd-analyze verify systemd/lintest.service systemd/lintest.timer`

## 3. Linux verification (a real Linux host or WSL, not a mocked run)

- [ ] One real pass produces plausible values for the host:
      `python -m lintest --config config.yaml --dry-run --once`
- [ ] JSON mode parses: `python -m lintest --output json --dry-run --once | python -m json.tool | head`
- [ ] HTML report renders (open it) and contains no unescaped dynamic text.
- [ ] `install.sh` (as root, on a disposable host/VM/WSL):
      - `sudo ./install.sh --no-schedule` completes and the smoke test passes;
      - running it a second time keeps an edited `config.yaml` and `.env`;
      - `sudo ./install.sh --uninstall` keeps logs, state and a config backup
        under `/var/backups/lintest/`;
      - `sudo ./install.sh --uninstall --purge` removes everything it created.
- [ ] Timer/service path: `systemctl start lintest.service`,
      `journalctl -u lintest.service -n 30` shows a real pass, and
      `systemctl list-timers lintest.timer` shows the next fire time.
- [ ] If a scheduler is installed: no overlapping `lintest` processes after an
      hour (`systemctl status lintest.service`, `ps -ef | grep lintest`).
- [ ] Cooldown/recovery against the real Telegram API (test bot + test chat):
      one CRITICAL, silence inside `cooldown_minutes`, then a RECOVERED message.
- [ ] Failed delivery does not silence the next attempt (block
      `api.telegram.org` via `/etc/hosts` or stop the network, confirm the alert
      is re-sent once connectivity returns).

## 4. CI

- [ ] `.github/workflows/ci.yml` ran green on the release commit
      (all five jobs: tests ×4 Python versions, linux-integration, packaging,
      installer, install assets).
- [ ] The coverage artifact from CI matches the locally recorded percentage.

## 5. Release

- [ ] Tag: `git tag -a v<version> -m "LinTest <version>"` and
      `git push origin v<version>`.
- [ ] GitHub release notes: paste the `CHANGELOG.md` section and attach the
      `dist/` artifacts.
- [ ] Post-release: bump the `Unreleased` section in `CHANGELOG.md` if anything
      was deferred, and open follow-up issues for known limitations.

## Known limitations (as of this release)

- **No automated test can prove ICMP behaviour on every network.** The ping
  parser is covered for iputils/BusyBox/Windows-style outputs and the TCP
  fallback is covered directly, but a firewall that silently drops ICMP is
  verified manually only.
- **The installer's systemd branch is verified on Ubuntu (WSL) and by
  `systemd-analyze verify`, not on RHEL/Debian/Arch.** The cron branch is
  syntax-checked and its `.env` loading is asserted, but not exercised by a real
  cron daemon in CI.
- **Alert delivery is best-effort.** A network outage delays alerts until the
  next pass; there is no outbound queue.
- **No auto-remediation.** LinTest never restarts services (by design).
- **Single-host.** There is no central aggregation; each host reports on itself.
