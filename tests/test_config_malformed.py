"""Malformed configuration matrix: every validator must report, never crash."""

from __future__ import annotations

import pytest
import yaml

from lintest.config import ConfigError, load_config


def write(tmp_path, text: str) -> str:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def expect_error(tmp_path, text: str, *needles: str) -> str:
    with pytest.raises(ConfigError) as excinfo:
        load_config(write(tmp_path, text))
    message = str(excinfo.value)
    for needle in needles:
        assert needle in message, f"{needle!r} not in config error:\n{message}"
    return message


class TestStructureErrors:
    def test_missing_explicit_file(self, tmp_path):
        with pytest.raises(ConfigError, match="Config file not found"):
            load_config(str(tmp_path / "absent.yaml"))

    def test_directory_instead_of_file(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_config(str(tmp_path))

    def test_invalid_yaml(self, tmp_path):
        expect_error(tmp_path, "thresholds: [1,\n", "Invalid YAML")

    def test_top_level_list(self, tmp_path):
        expect_error(tmp_path, "- a\n- b\n", "must be a mapping")

    def test_top_level_scalar(self, tmp_path):
        expect_error(tmp_path, "42\n", "must be a mapping")

    def test_unknown_section_is_reported(self, tmp_path):
        expect_error(tmp_path, "tresholds:\n  cpu_percent: 80\n", "unknown section 'tresholds'")

    def test_section_that_is_not_a_mapping(self, tmp_path):
        expect_error(tmp_path, "thresholds: 5\n", "[thresholds] must be a mapping")

    def test_section_explicitly_null_uses_defaults(self, tmp_path):
        cfg = load_config(write(tmp_path, "thresholds:\nsystem:\n"))
        assert cfg.thresholds.cpu_percent == 85.0
        assert cfg.system.enabled is True

    def test_empty_and_comment_only_files_use_defaults(self, tmp_path):
        assert load_config(write(tmp_path, "")).thresholds.disk_percent == 90.0
        assert load_config(write(tmp_path, "# nothing but comments\n")).thresholds.cpu_percent == 85.0

    def test_default_lookup_uses_builtin_defaults_without_a_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        cfg = load_config(None)
        assert cfg.config_path is None
        assert cfg.thresholds.cpu_percent == 85.0
        assert cfg.schedule.mode == "timer"


class TestTypeErrors:
    def test_number_given_a_string(self, tmp_path):
        expect_error(tmp_path, "thresholds:\n  cpu_percent: high\n",
                     "thresholds.cpu_percent must be a number", "'high'")

    def test_number_given_a_bool(self, tmp_path):
        expect_error(tmp_path, "thresholds:\n  cpu_percent: true\n",
                     "must be a number")

    def test_bool_given_a_string(self, tmp_path):
        expect_error(tmp_path, "system:\n  enabled: yes-please\n",
                     "system.enabled must be true or false")

    def test_bool_given_a_number(self, tmp_path):
        expect_error(tmp_path, "services:\n  enabled: 1\n",
                     "services.enabled must be true or false")

    def test_string_list_given_a_string(self, tmp_path):
        expect_error(tmp_path, "services:\n  critical: sshd\n",
                     "services.critical must be a list of strings")

    def test_string_list_with_non_string_items(self, tmp_path):
        expect_error(tmp_path, "services:\n  warning: [nginx, 5]\n",
                     "services.warning must be a list of strings")

    def test_mapping_given_a_list(self, tmp_path):
        expect_error(tmp_path, "thresholds:\n  disk_overrides: [\"/\", 80]\n",
                     "disk_overrides must be a mapping")


class TestRangeErrors:
    @pytest.mark.parametrize("text,needle", [
        ("thresholds:\n  cpu_percent: 0\n", "must be >= 1"),
        ("thresholds:\n  cpu_percent: 101\n", "must be <= 100"),
        ("thresholds:\n  ram_percent: 150\n", "must be <= 100"),
        ("thresholds:\n  disk_percent: -5\n", "must be >= 1"),
        ("thresholds:\n  load1_per_core: 0\n", "must be >= 0.1"),
        ("thresholds:\n  failed_ssh_logins: 0\n", "must be >= 1"),
        ("schedule:\n  interval_seconds: 5\n", "must be >= 10"),
        ("schedule:\n  interval_seconds: 999999\n", "must be <= 86400"),
        ("general:\n  check_timeout_seconds: 0\n", "must be >= 0.1"),
        ("general:\n  check_timeout_seconds: 9999\n", "must be <= 600"),
        ("network:\n  ping_count: 100\n", "must be <= 10"),
        ("network:\n  ping_timeout_seconds: 0\n", "must be >= 0.1"),
        ("network:\n  tcp_timeout_seconds: 99\n", "must be <= 30"),
        ("security:\n  window_minutes: 0\n", "must be >= 1"),
        ("security:\n  top_ips: 1000\n", "must be <= 50"),
        ("alerts:\n  cooldown_minutes: -1\n", "must be >= 0"),
        ("alerts:\n  cooldown_minutes: 99999999\n", "must be <= 10080"),
        ("alerts:\n  telegram:\n    timeout_seconds: 0\n", "must be >= 1"),
        ("logging:\n  max_bytes: 10\n", "must be >= 1024"),
        ("logging:\n  backup_count: 1000\n", "must be <= 100"),
    ])
    def test_out_of_range_values(self, tmp_path, text, needle):
        expect_error(tmp_path, text, needle)


class TestPathAndEnumErrors:
    def test_relative_auth_log_path(self, tmp_path):
        expect_error(tmp_path, "security:\n  auth_log_path: var/log/auth.log\n",
                     "security.auth_log_path must be an absolute path")

    def test_relative_logging_file(self, tmp_path):
        expect_error(tmp_path, "logging:\n  file: logs/lintest.log\n",
                     "logging.file must be an absolute path")

    def test_invalid_schedule_mode(self, tmp_path):
        expect_error(tmp_path, "schedule:\n  mode: every-minute\n",
                     "schedule.mode must be one of")

    def test_invalid_log_level(self, tmp_path):
        expect_error(tmp_path, "logging:\n  level: LOUD\n", "logging.level must be one of")

    def test_invalid_parse_mode(self, tmp_path):
        expect_error(tmp_path, "alerts:\n  telegram:\n    parse_mode: Cursed\n",
                     "alerts.telegram.parse_mode must be one of")

    def test_invalid_env_variable_name(self, tmp_path):
        expect_error(tmp_path, "alerts:\n  telegram:\n    token_env: '2FA_TOKEN'\n",
                     "is not a valid name")

    def test_disk_override_relative_mount(self, tmp_path):
        expect_error(tmp_path, "thresholds:\n  disk_overrides:\n    data: 70\n",
                     "must be an absolute path string")

    @pytest.mark.parametrize("value", ["0", "150"])
    def test_disk_override_out_of_range(self, tmp_path, value):
        expect_error(tmp_path, f"thresholds:\n  disk_overrides:\n    \"/data\": {value}\n",
                     "must be within (0, 100]")

    def test_disk_override_non_numeric(self, tmp_path):
        expect_error(tmp_path, "thresholds:\n  disk_overrides:\n    \"/data\": plenty\n",
                     "must be a number")


class TestNetworkListErrors:
    @pytest.mark.parametrize("spec", ["abc", "1.1.1.1:0", "1.1.1.1:99999", "host:"])
    def test_invalid_tcp_port_specs(self, tmp_path, spec):
        expect_error(tmp_path, f"network:\n  tcp_ports:\n    - \"{spec}\"\n", "host:port")

    def test_empty_ping_host(self, tmp_path):
        expect_error(tmp_path, "network:\n  ping_hosts:\n    - \"  \"\n",
                     "must be non-empty hostnames or IPs")

    def test_empty_dns_server(self, tmp_path):
        expect_error(tmp_path, "network:\n  dns_servers:\n    - \"\"\n",
                     "must be non-empty IP addresses")

    def test_valid_specs_are_accepted(self, tmp_path):
        cfg = load_config(write(tmp_path, """
network:
  tcp_ports: ["db.internal:5432", "[::1]:443", "127.0.0.1:1", "::1:443"]
  ping_hosts: ["1.1.1.1", "example.com"]
  dns_servers: ["8.8.8.8"]
"""))
        assert cfg.network.tcp_ports == ["db.internal:5432", "[::1]:443", "127.0.0.1:1", "::1:443"]
        assert cfg.network.ping_hosts == ["1.1.1.1", "example.com"]
        assert cfg.network.dns_servers == ["8.8.8.8"]


class TestErrorAggregation:
    def test_every_problem_is_reported_together(self, tmp_path):
        message = expect_error(tmp_path, """
thresholds:
  cpu_percent: 500
  load1_per_core: -1
schedule:
  mode: nope
services:
  critical: sshd
logging:
  level: LOUD
""", "cpu_percent", "load1_per_core", "schedule.mode", "services.critical", "logging.level")
        assert "5 configuration problem(s)" in message
        # The message is a numbered list, one entry per problem.
        assert "  1. " in message and "  5. " in message

    def test_error_message_names_the_file(self, tmp_path):
        path = write(tmp_path, "thresholds:\n  cpu_percent: 500\n")
        with pytest.raises(ConfigError) as excinfo:
            load_config(path)
        assert path in str(excinfo.value)


class TestBoundaryAcceptance:
    def test_extreme_but_valid_config_loads(self, tmp_path):
        cfg = load_config(write(tmp_path, """
general:
  check_timeout_seconds: 0.1
schedule:
  mode: daemon
  interval_seconds: 10
thresholds:
  cpu_percent: 100
  ram_percent: 1
  disk_percent: 100
  disk_overrides:
    "/": 100.0
  load1_per_core: 100
  failed_ssh_logins: 1
system:
  enabled: false
  ignore_mount_prefixes: []
  exclude_filesystems: []
services:
  enabled: false
  critical: []
  warning: []
network:
  enabled: false
  ping_hosts: []
  ping_count: 10
  tcp_ports: []
  dns_host: ""
security:
  enabled: false
  auth_log_path: /var/log/auth.log
  window_minutes: 1440
  top_ips: 50
alerts:
  cooldown_minutes: 0
  console:
    enabled: false
  telegram:
    enabled: false
    parse_mode: ""
logging:
  level: CRITICAL
  file: ""
  max_bytes: 1024
  backup_count: 0
"""))
        assert cfg.schedule.mode == "daemon"
        assert cfg.schedule.interval_seconds == 10
        assert cfg.network.ping_count == 10
        assert cfg.alerts.cooldown_minutes == 0
        assert cfg.logging.backup_count == 0

    def test_telegram_env_var_names_are_configurable(self, tmp_path):
        cfg = load_config(write(tmp_path, """
alerts:
  telegram:
    token_env: MY_BOT_TOKEN
    chat_id_env: MY_CHAT_ID
"""))
        assert cfg.alerts.telegram.token_env == "MY_BOT_TOKEN"
        assert cfg.alerts.telegram.chat_id_env == "MY_CHAT_ID"

    def test_shipped_config_file_is_valid(self):
        """config.yaml in the repository must always load cleanly."""
        cfg = load_config("config.yaml")
        assert cfg.alerts.telegram.token_env == "LINTEST_TELEGRAM_TOKEN"
        assert cfg.thresholds.disk_overrides["/"] == 85.0

    def test_shipped_config_has_no_secrets(self):
        text = open("config.yaml", encoding="utf-8").read()
        assert "TOKEN=" not in text
        assert yaml.safe_load(text)["alerts"]["telegram"]["enabled"] is True
