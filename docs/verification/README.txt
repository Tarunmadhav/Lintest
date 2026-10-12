Raw outputs of every release gate, captured 2026-10-12.
Each file starts with the exact command and platform and ends with its exit code.

windows-ruff-check.txt           ruff check lintest tests, Windows, python 3.11.9       exit 0
windows-pytest-coverage.txt      pytest + coverage, Windows                             exit 0 (402 passed, 2 skipped, 96 %)
linux-ruff-check.txt             ruff check lintest tests, WSL Ubuntu, python 3.14.4     exit 0
linux-pytest-coverage.txt        pytest + coverage, TZ=UTC, WSL Ubuntu                  exit 0 (403 passed, 1 skipped, 96 %)
linux-systemd-analyze.txt        systemd-analyze verify (service + timer)                exit 0
linux-build.txt                  python -m build (wheel + sdist)                        exit 0
linux-twine-check.txt            python -m twine check dist/*                           exit 0 (both artifacts PASSED)
linux-wheel-install.txt          clean venv: pip install the wheel, lintest --version,
                                 then a real pass against config.yaml
                                 pip install 0, --version 0,
                                 real pass 1 (EXPECTED: see note)
linux-installer-for-verify.txt   install.sh --no-schedule -- created /opt/lintest so
                                 systemd-analyze could resolve ExecStart; purged after
                                 verification                                            exit 0

Notes:
- The real pass exits 1 by design on this host: the default config marks the
  inactive 'sshd' service as CRITICAL and exit code 1 is LinTest's documented
  CRITICAL exit status. All 13 checks ran with real values.
- systemd-analyze exits 1 when run while LinTest is not installed, because the
  unit's ExecStart path (/opt/lintest/.venv/bin/lintest) does not exist.
  linux-systemd-analyze.txt was captured with the app installed; the install
  log is linux-installer-for-verify.txt. The unit's findings are empty.
- The WSL install used for that evidence was purged afterwards
  (--uninstall --purge, exit 0).
