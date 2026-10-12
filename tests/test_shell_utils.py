"""Tests for the subprocess helper: missing tools, timeouts, exit codes."""

from __future__ import annotations

import sys

import pytest

from lintest.utils.shell import CommandError, CommandResult, run_command

MISSING_BINARY = "lintest-definitely-not-installed-xyz"


class TestRunCommand:
    def test_successful_command_captures_stdout(self):
        res = run_command([sys.executable, "-c", "print('hello')"], timeout=30)
        assert res.ran is True
        assert res.missing is False
        assert res.timed_out is False
        assert res.returncode == 0
        assert res.stdout.strip() == "hello"

    def test_nonzero_exit_is_not_an_exception(self):
        res = run_command([sys.executable, "-c", "import sys; sys.stderr.write('bad'); sys.exit(3)"],
                          timeout=30)
        assert res.ran is True
        assert res.returncode == 3
        assert "bad" in res.stderr

    def test_missing_binary_is_flagged(self):
        res = run_command([MISSING_BINARY], timeout=5)
        assert res.missing is True
        assert res.ran is False
        assert res.returncode == -1
        assert MISSING_BINARY in res.stderr

    def test_timeout_is_flagged(self):
        res = run_command([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)
        assert res.timed_out is True
        assert res.ran is False

    def test_empty_argv_is_a_programming_error(self):
        with pytest.raises(CommandError):
            run_command([])

    def test_permission_error_is_treated_as_unavailable(self, monkeypatch):
        import lintest.utils.shell as shell

        def boom(*a, **k):
            raise PermissionError("not executable")
        monkeypatch.setattr(shell.subprocess, "run", boom)
        res = run_command(["/root/secret"], timeout=5)
        assert res.missing is True
        assert res.ran is False

    def test_no_shell_injection(self, tmp_path):
        """argv is passed verbatim: shell metacharacters must not be interpreted."""
        marker = tmp_path / "pwned"
        res = run_command([sys.executable, "-c",
                           "import sys; print(sys.argv[1])", f"; touch {marker}"], timeout=30)
        assert res.returncode == 0
        assert not marker.exists()
        assert f"; touch {marker}" in res.stdout


class TestCommandResult:
    def test_first_line_skips_blank_lines(self):
        res = CommandResult(argv=["x"], returncode=0, stdout="\n\nactive\ninactive\n")
        assert res.first_line() == "active"

    def test_first_line_of_empty_output(self):
        assert CommandResult(argv=["x"], returncode=0).first_line() == ""

    def test_ran_requires_start_and_finish(self):
        assert CommandResult(argv=["x"], returncode=0).ran is True
        assert CommandResult(argv=["x"], returncode=0, missing=True).ran is False
        assert CommandResult(argv=["x"], returncode=0, timed_out=True).ran is False
