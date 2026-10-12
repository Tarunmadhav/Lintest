# v1.1.0 release drafts — NOT APPLIED

Everything here is a draft for review. The retitle, commit message and
release notes below are **not applied**: `CHANGELOG.md` still says
`[Unreleased]`, and no tag or GitHub release has been published from them.

---

## 1. CHANGELOG retitle (draft)

Apply at tag time (do **not** apply yet):

```diff
-## [Unreleased]
+## [1.1.0] - <YYYY-MM-DD of the tag>
```

and replace the link block at the bottom of `CHANGELOG.md` with:

```markdown
[Unreleased]: https://github.com/Tarunmadhav/Lintest/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Tarunmadhav/Lintest/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Tarunmadhav/Lintest/releases/tag/v1.0.0
```

---

## 2. Commit message (draft)

Scope note: 18 modified files, 13 new test files, plus `.github/`, and
`docs/` (RELEASE_CHECKLIST, MEMORY_IMAGE, STATE_LOCK_PROPOSAL, verification
evidence, this file). `.freebuff/` must **not** be staged.

```
Production readiness hardening: fix verified defects, add CI, grow tests 62 -> 404

Fix defects found by auditing the real implementation:
- load check could never report OK (fixed 10-point warning band > threshold)
- ping passed ms to iputils' seconds -W and claimed "100% packet loss" on
  unparseable output; missing dig produced false CRITICAL DNS results
- security check read all of auth.log; sshd-session lines ignored; junk
  timestamps failed the whole area
- corrupt alert state crashed dispatch; failed recovery delivery was never
  retried; Telegram token leaked via requests exception URLs
- state temp file was PID-named, so threads in one process could interleave
  writes and tear state.json -> per-write mkstemp (atomic os.replace, 0600)
- install.sh: root check after uninstall branch, crontab -r wiped the whole
  crontab, upgrade clobbered operator config, lintest console script never
  installed (smoke test exit 127); timer OnUnitActiveSec overlap and
  Persistent no-op removed

Add GitHub Actions CI (tests x py3.10-3.13, linux integration, packaging,
installer E2E, systemd asset checks) and harden the service unit sandbox.

Grow the test suite from 62 to 404 tests (96% coverage): malformed configs,
missing utilities and log sources, SSH year rollover, Telegram timeouts,
failed delivery/recovery retries, concurrency, state corruption, error
isolation, CLI exit codes, reporting, and automation-file regression checks.

Document actual behavior: README, CHANGELOG, SECURITY threat model, release
checklist, raw gate outputs with exit codes under docs/verification/, plus a
project memory image and a (not implemented) flock state-lock proposal.

Verified: 402 passed + 2 skipped (Windows), 403 passed + 1 skipped (WSL
Ubuntu), 96% coverage, ruff clean, build + twine PASSED, systemd-analyze
clean, installer E2E incl. timer fires with cross-run cooldown.

🤖 Generated with Codebuff
Co-Authored-By: Codebuff <noreply@codebuff.com>
```

(If you commit yourself, drop the Codebuff footer or keep it — your call.)

---

## 3. GitHub release notes (draft)

**Title:** `LinTest v1.1.0 — Production readiness hardening`

LinTest v1.1.0 is a hardening release: no CLI, configuration or architecture
changes except where a verified defect required one. Every claim below was
executed; raw gate outputs with exit codes ship in `docs/verification/`.

### Highlights

- **11 verified defects fixed** — see the changelog for the full list; the
  worst were a load check that could never report OK, ping's millisecond /
  seconds `-W` mix-up producing false "100 % packet loss", alert state that
  could crash a run or be torn by overlapping writes, and an installer that
  never actually installed the `lintest` console script.
- **Test suite 62 → 404 tests, coverage 55 % → 96 %**, ruff-clean.
- **GitHub Actions CI** on Python 3.10–3.13 with Linux integration,
  packaging and installer jobs.
- **Hardened install & runtime**: least-privilege systemd sandbox, idempotent
  upgrades, safe uninstall with config backup, `.env` handling that works
  under systemd and cron.
- **Verified on real Linux (WSL Ubuntu, systemd)**: installer end-to-end,
  timer-fired passes with cooldown persisting across runs, no overlapping
  processes, packaging (`build` + `twine`), clean-venv wheel install and a
  real 13-check pass.

### Verification summary

| Gate | Result |
|---|---|
| Unit tests | 402 passed + 2 skipped (Windows), 403 passed + 1 skipped (Linux) |
| Coverage | 96 % of `lintest` (was 55 %) |
| Lint | ruff clean (E, F, W, I) |
| Packaging | `python -m build` + `twine check` PASSED |
| systemd units | `systemd-analyze verify` exit 0, clean |
| Installer | install → upgrade → timer E2E → uninstall → purge, all exit 0 |

### Known Limitations

(from the project memory image; also mirrored in `docs/RELEASE_CHECKLIST.md`)

- **ICMP/firewall edge cases verified on one host only.** The ping parser and
  TCP fallback are unit-tested, but a firewall silently dropping ICMP is
  manual verification only.
- **Installer/timer tested on Ubuntu WSL**; no real RHEL/Debian/Arch host and
  no non-systemd cron daemon (cron branch is syntax-checked only).
- **Telegram delivery is best-effort and unit-tested with mocks** — no live
  bot call was made (no secrets in the repo); a network outage delays alerts
  until the next pass, there is no outbound queue.
- **Multi-process alert state is last-writer-wins bookkeeping (no lock).**
  The timer cannot overlap itself and writes are atomic, but cron + manual
  runs can race; an `fcntl.flock` proposal is in `docs/STATE_LOCK_PROPOSAL.md`
  (not implemented).
- **CI has not run yet at draft time** — confirm all five jobs are green on
  the release commit before publishing these notes.
- **By design:** no auto-remediation (LinTest never restarts services), no
  Prometheus/web dashboard, single-host only (no central aggregation).
