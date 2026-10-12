"""Regression tests for the shipped automation files and secret hygiene.

These are static/behavioural checks (no root required): they lock in the
hardening decisions so a later edit cannot silently reintroduce the old
behaviour.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INSTALL = ROOT / "install.sh"
UNIT = ROOT / "systemd" / "lintest.service"
TIMER = ROOT / "systemd" / "lintest.timer"
CRON = ROOT / "cron" / "lintest.cron"
ENV_EXAMPLE = ROOT / ".env.example"
CONFIG = ROOT / "config.yaml"

IPV4_PLACEHOLDERS = ("203.0.113.", "198.51.100.", "192.0.2.")
TELEGRAM_TOKEN_RE = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class TestInstallScript:
    def test_syntax_is_valid(self):
        bash = shutil.which("bash")
        if bash is None:
            pytest.skip("bash not available")
        proc = subprocess.run([bash, "-n", str(INSTALL)], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr

    def test_root_check_happens_before_uninstall(self):
        body = text(INSTALL)
        assert body.index("run with sudo") < body.index("if [[ $UNINSTALL -eq 1 ]]")

    def test_operator_config_survives_an_upgrade(self):
        body = text(INSTALL)
        assert "--exclude 'config.yaml'" in body
        assert "config.yaml.new" in body

    def test_secrets_are_created_once_and_locked_down(self):
        body = text(INSTALL)
        assert 'if [[ -f $INSTALL_DIR/.env ]]' in body
        assert "chmod 640" in body
        assert '.env.example' in body

    def test_log_and_state_directories_belong_to_the_service_user(self):
        body = text(INSTALL)
        assert 'install -d -m 750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$LOG_DIR" "$STATE_DIR"' in body

    def test_application_tree_is_not_owned_by_the_service_user(self):
        body = text(INSTALL)
        assert "chown -R root:root \"$INSTALL_DIR\"" in body
        assert "chmod -R go-w" in body

    def test_log_access_groups_are_granted(self):
        body = text(INSTALL)
        assert "adm" in body and "systemd-journal" in body
        assert "usermod -aG" in body

    def test_uninstall_never_wipes_foreign_crontab_entries(self):
        body = text(INSTALL)
        assert "crontab -r" not in body
        assert "grep -v 'lintest'" in body

    def test_uninstall_preserves_the_config_outside_the_install_dir(self):
        body = text(INSTALL)
        assert "/var/backups/lintest" in body
        assert "/tmp/lintest-config.yaml.bak" not in body

    def test_rsync_is_optional(self):
        body = text(INSTALL)
        assert "command -v rsync" in body
        assert "falling back to cp" in body

    def test_cron_mode_loads_the_env_file(self):
        body = text(INSTALL)
        assert ". $INSTALL_DIR/.env" in body

    def test_smoke_test_runs_as_the_service_user(self):
        body = text(INSTALL)
        assert "run_as_service_user" in body
        assert "--dry-run" in body

    def test_upgrade_restarts_the_timer(self):
        assert "systemctl restart lintest.timer" in text(INSTALL)

    def test_no_destructive_commands(self):
        body = text(INSTALL)
        for dangerous in ("rm -rf /", "rm -rf $HOME", "dd if=", "mkfs"):
            assert dangerous not in body


class TestSystemdUnits:
    @pytest.mark.parametrize("directive", [
        "User=lintest",
        "Group=lintest",
        "Type=oneshot",
        "SuccessExitStatus=1",
        "EnvironmentFile=/opt/lintest/.env",
        "StateDirectory=lintest",
        "LogsDirectory=lintest",
        "Environment=LINTEST_STATE_FILE=/var/lib/lintest/state.json",
        "TimeoutStartSec=120",
    ])
    def test_service_has_directive(self, directive):
        assert directive in text(UNIT)

    @pytest.mark.parametrize("directive", [
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "PrivateTmp=true",
        "ProtectKernelTunables=true",
        "ProtectControlGroups=true",
        "RestrictSUIDSGID=true",
    ])
    def test_service_hardening_directive(self, directive):
        assert directive in text(UNIT)

    def test_service_does_not_grant_write_access_globally(self):
        body = text(UNIT)
        assert "ProtectSystem=full" not in body  # superseded by strict
        assert "ReadWritePaths=/ /" not in body

    def test_restrict_address_families_keeps_netlink(self):
        """The libc resolver needs AF_NETLINK; dropping it breaks DNS."""
        assert "AF_NETLINK" in text(UNIT)

    def test_timer_cannot_overlap_runs(self):
        body = text(TIMER)
        assert "OnUnitInactiveSec=5min" in body
        # ...and no *directive* uses the overlapping variant (comments may
        # mention it by name).
        directives = [ln.strip() for ln in body.splitlines()
                      if ln.strip() and not ln.strip().startswith(("#", "["))]
        assert not [d for d in directives if d.startswith("OnUnitActiveSec")]

    def test_timer_has_no_persistent_directive(self):
        """Persistent= is a no-op on monotonic timers; keep it out entirely."""
        directives = [ln.strip() for ln in text(TIMER).splitlines()
                      if ln.strip() and not ln.strip().startswith(("#", "["))]
        assert not [d for d in directives if d.startswith("Persistent=")]

    def test_timer_wiring(self):
        body = text(TIMER)
        assert "Unit=lintest.service" in body
        assert "WantedBy=timers.target" in body

    def test_timer_does_not_order_itself_after_its_own_service(self):
        """Regression: After=lintest.service here causes an ordering cycle."""
        directives = [ln.strip() for ln in text(TIMER).splitlines()
                      if ln.strip() and not ln.strip().startswith(("#", "["))]
        assert "After=lintest.service" not in directives

    def test_units_pass_systemd_analyze_when_available(self):
        if not shutil.which("systemd-analyze"):
            pytest.skip("systemd-analyze not available")
        proc = subprocess.run(
            ["systemd-analyze", "verify", str(UNIT), str(TIMER)],
            capture_output=True, text=True,
        )
        report = proc.stdout + proc.stderr
        for forbidden in ("Unknown key", "Failed to parse", "Invalid setting",
                          "Invalid argument", "ordering cycle", "cyclic ordering"):
            assert forbidden not in report, f"{forbidden!r} in systemd-analyze output:\n{report}"


class TestCronTemplate:
    def test_line_is_marked_and_sources_the_env_file(self):
        body = text(CRON)
        line = [ln for ln in body.splitlines() if ln.startswith("*/5")]
        assert len(line) == 1
        assert ". /opt/lintest/.env" in line[0]
        assert line[0].rstrip().endswith("# lintest")

    def test_redirects_output(self):
        line = [ln for ln in text(CRON).splitlines() if ln.startswith("*/5")][0]
        assert ">> /var/log/lintest/cron.log 2>&1" in line


class TestSecretHygiene:
    def test_env_example_is_a_valid_env_file(self):
        """Regression: a '[TEMPLATE]' header line made the file unusable."""
        for number, raw in enumerate(text(ENV_EXAMPLE).splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            assert re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", line), \
                f".env.example line {number} is not NAME=value: {raw!r}"

    def test_env_example_documents_the_required_variables(self):
        body = text(ENV_EXAMPLE)
        assert "LINTEST_TELEGRAM_TOKEN=" in body
        assert "LINTEST_TELEGRAM_CHAT_ID=" in body

    def test_no_real_telegram_token_anywhere_in_the_sources(self):
        offenders = []
        for path in ROOT.rglob("*"):
            if not path.is_file() or ".git" in path.parts or ".freebuff" in path.parts:
                continue
            if path.suffix in {".pyc", ".png", ".jpg", ".ico", ".zip", ".whl"}:
                continue
            try:
                body = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:  # pragma: no cover - unreadable file
                continue
            if TELEGRAM_TOKEN_RE.search(body):
                offenders.append(str(path.relative_to(ROOT)))
        assert offenders == []

    def test_config_file_uses_env_var_names_not_values(self):
        body = text(CONFIG)
        assert "token_env: LINTEST_TELEGRAM_TOKEN" in body
        assert "chat_id_env: LINTEST_TELEGRAM_CHAT_ID" in body

    def test_gitignore_protects_secrets_and_runtime_state(self):
        body = text(ROOT / ".gitignore")
        for pattern in (".env", "!.env.example", "*.state.json", "__pycache__"):
            assert pattern in body

    def test_no_log_or_state_artifacts_are_tracked(self):
        git = shutil.which("git")
        if git is None or not (ROOT / ".git").exists():
            pytest.skip("not a git checkout")
        proc = subprocess.run([git, "ls-files"], cwd=ROOT, capture_output=True, text=True)
        assert proc.returncode == 0
        tracked = proc.stdout.split()
        bad = [f for f in tracked if f.endswith((".log", ".state.json", ".env"))]
        assert bad == []

    def test_test_ips_are_documentation_ranges(self):
        """Synthetic log lines in tests must not embed real addresses."""
        body = text(ROOT / "tests" / "conftest.py")
        assert any(prefix in body for prefix in IPV4_PLACEHOLDERS)
