"""Tests for configuration loading, validation and threshold logic."""

from __future__ import annotations

import pytest

from lintest.config import ConfigError, ThresholdsConfig, load_config

VALID_YAML = """
thresholds:
  cpu_percent: 80
  failed_ssh_logins: 10
services:
  critical: [sshd]
  warning: [nginx, docker]
network:
  ping_hosts: [1.1.1.1]
  tcp_ports: ["db.internal:5432", "[::1]:443"]
security:
  window_minutes: 30
  auth_log_path: /var/log/secure
alerts:
  cooldown_minutes: 45
  send_recovery: false
logging:
  level: debug
  file: ""
"""


def write_cfg(tmp_path, text: str):
    p = tmp_path / "config.yaml"
    p.write_text(text, encoding="utf-8")
    return str(p)


class TestLoadConfig:
    def test_valid_yaml_loads(self, tmp_path):
        cfg = load_config(write_cfg(tmp_path, VALID_YAML))
        assert cfg.thresholds.cpu_percent == 80.0
        assert cfg.thresholds.failed_ssh_logins == 10
        assert cfg.services.critical == ["sshd"]
        assert cfg.services.warning == ["nginx", "docker"]
        assert cfg.network.tcp_ports == ["db.internal:5432", "[::1]:443"]
        assert cfg.security.window_minutes == 30
        assert cfg.alerts.cooldown_minutes == 45
        assert cfg.alerts.send_recovery is False
        assert cfg.logging.level == "DEBUG"

    def test_missing_file_raises(self):
        with pytest.raises(ConfigError, match="not found"):
            load_config("/nonexistent/config.yaml")

    def test_empty_file_uses_defaults(self, tmp_path):
        cfg = load_config(write_cfg(tmp_path, ""))
        assert cfg.thresholds.cpu_percent == 85.0
        assert cfg.schedule.mode == "timer"

    def test_invalid_yaml_raises(self, tmp_path):
        with pytest.raises(ConfigError, match="Invalid YAML"):
            load_config(write_cfg(tmp_path, "thresholds: [oops"))

    def test_non_mapping_top_level(self, tmp_path):
        with pytest.raises(ConfigError, match="must be a mapping"):
            load_config(write_cfg(tmp_path, "- just\n- a\n- list"))

    def test_bad_tcp_port_spec(self, tmp_path):
        bad = VALID_YAML.replace('"[::1]:443"', '"99999"')
        with pytest.raises(ConfigError, match="host:port"):
            load_config(write_cfg(tmp_path, bad))

    def test_unknown_section_reported(self, tmp_path):
        with pytest.raises(ConfigError, match="unknown section 'tresholds'"):
            load_config(write_cfg(tmp_path, VALID_YAML + "\ntresholds:\n  cpu_percent: 5\n"))

    def test_all_errors_listed_at_once(self, tmp_path):
        bad = VALID_YAML.replace("cpu_percent: 80", "cpu_percent: 500") \
                        .replace("cooldown_minutes: 45", "cooldown_minutes: -3") \
                        .replace("level: debug", "level: loud")
        with pytest.raises(ConfigError) as excinfo:
            load_config(write_cfg(tmp_path, bad))
        msg = str(excinfo.value)
        assert "3 configuration problem(s)" in msg
        assert "cpu_percent" in msg and "cooldown_minutes" in msg and "logging.level" in msg


class TestThresholds:
    def test_classify_critical(self):
        sev, _ = ThresholdsConfig().classify(96.0, 90.0)
        assert sev == "CRITICAL"

    def test_classify_at_threshold_is_critical(self):
        sev, _ = ThresholdsConfig().classify(90.0, 90.0)
        assert sev == "CRITICAL"

    def test_classify_warning_band(self):
        sev, _ = ThresholdsConfig().classify(82.0, 90.0)
        assert sev == "WARNING"

    def test_classify_below_band_ok(self):
        sev, reason = ThresholdsConfig().classify(50.0, 90.0)
        assert sev == "OK"
        assert reason is None

    def test_disk_threshold_default(self):
        assert ThresholdsConfig().disk_threshold_for("/srv") == 90.0

    def test_disk_threshold_override_exact(self):
        t = ThresholdsConfig(disk_percent=90.0, disk_overrides={"/data": 75.0})
        assert t.disk_threshold_for("/data") == 75.0

    def test_disk_threshold_longest_prefix_wins(self):
        t = ThresholdsConfig(disk_overrides={"/data": 75.0, "/data/db": 95.0})
        assert t.disk_threshold_for("/data/db") == 95.0
        assert t.disk_threshold_for("/data/db/backups") == 95.0
        assert t.disk_threshold_for("/data/media") == 75.0
        assert t.disk_threshold_for("/var") == 90.0
