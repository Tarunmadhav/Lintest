"""Configuration loading and validation for LinTest.

The YAML file is parsed with PyYAML and converted into dataclasses with
sane defaults, so a minimal config file still produces a working setup.
Everything is validated up front and all problems are collected into a
single :class:`ConfigError` whose message lists every issue found -- the
operator should not have to fix the config one error at a time.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)

#: Log levels accepted in ``logging.level`` (upper-cased before comparison).
VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
#: Parse modes accepted for Telegram messages.
VALID_PARSE_MODES = ("", "HTML", "Markdown", "MarkdownV2")
#: Schedule modes accepted in ``schedule.mode``.
VALID_SCHEDULE_MODES = ("timer", "daemon")
#: Absolute early-warning band, in the same unit as the threshold (percent
#: points for CPU/RAM/disk).
WARNING_BAND = 10.0
#: Relative early-warning band, used when a threshold is too small for the
#: absolute band to make sense (e.g. ``load1_per_core: 1.5`` -- a fixed 10 point
#: band would classify *every* observable value as a WARNING).
WARNING_BAND_FRACTION = 0.25


def warning_band(threshold: float) -> float:
    """Return the WARNING band for *threshold*.

    The band is the smaller of :data:`WARNING_BAND` and
    :data:`WARNING_BAND_FRACTION` of the threshold, so a value is WARNING when
    it is within 10 percent-points of a percentage threshold (unchanged
    behaviour) or within 25% of a small threshold such as ``load1_per_core``.
    """
    return min(WARNING_BAND, threshold * WARNING_BAND_FRACTION)


class ConfigError(Exception):
    """Raised when the configuration file is missing, unreadable or invalid."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GeneralConfig:
    """Cross-cutting options."""

    check_timeout_seconds: float = 5.0

    def timeout_for(self, override: Optional[float]) -> float:
        """Return *override* if set, else the general timeout."""
        return override if override and override > 0 else self.check_timeout_seconds


@dataclass(frozen=True)
class ScheduleConfig:
    """How the program paces its check passes."""

    mode: str = "timer"
    interval_seconds: int = 300


@dataclass(frozen=True)
class ThresholdsConfig:
    """Alert thresholds.

    A value at or above the threshold is CRITICAL; a value within
    :data:`WARNING_BAND` percent-points below it is WARNING.
    """

    cpu_percent: float = 85.0
    ram_percent: float = 90.0
    disk_percent: float = 90.0
    disk_overrides: Dict[str, float] = field(default_factory=dict)
    load1_per_core: float = 1.5
    failed_ssh_logins: int = 20

    def classify(self, value: float, threshold: float) -> Tuple[str, Optional[str]]:
        """Classify *value* against *threshold*.

        Returns ``(severity, reason)`` where severity is one of
        ``"OK"``, ``"WARNING"`` or ``"CRITICAL"`` and reason is a human
        readable explanation (``None`` when OK).
        """
        if value >= threshold:
            return (
                "CRITICAL",
                f"{value:.1f} is at or above the critical threshold "
                f"({threshold:.1f})",
            )
        band = warning_band(threshold)
        if value >= threshold - band:
            return (
                "WARNING",
                f"{value:.1f} is within {band:g} points of the "
                f"critical threshold ({threshold:.1f})",
            )
        return ("OK", None)

    def disk_threshold_for(self, mount: str) -> float:
        """Return the disk threshold for *mount*, honouring overrides.

        The longest matching override prefix wins, so ``/data/db`` can be
        configured separately from ``/data``.
        """
        best: Optional[float] = None
        best_len = -1
        for prefix, limit in self.disk_overrides.items():
            norm = prefix if prefix.endswith("/") else prefix + "/"
            if (mount + "/").startswith(norm) and len(prefix) > best_len:
                best, best_len = limit, len(prefix)
        return self.disk_percent if best is None else best


@dataclass(frozen=True)
class SystemConfig:
    """System metric check options."""

    enabled: bool = True
    ignore_mount_prefixes: List[str] = field(
        default_factory=lambda: ["/snap", "/boot/efi", "/run/user", "/proc", "/sys", "/dev"]
    )
    exclude_filesystems: List[str] = field(
        default_factory=lambda: ["tmpfs", "devtmpfs", "squashfs", "overlay", "iso9660", "vfat"]
    )


@dataclass(frozen=True)
class ServicesConfig:
    """systemd service check options."""

    enabled: bool = True
    critical: List[str] = field(default_factory=lambda: ["sshd"])
    warning: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class NetworkConfig:
    """Network check options."""

    enabled: bool = True
    ping_hosts: List[str] = field(default_factory=lambda: ["1.1.1.1"])
    ping_count: int = 3
    ping_timeout_seconds: float = 2.0
    tcp_ports: List[str] = field(default_factory=list)
    tcp_timeout_seconds: float = 3.0
    dns_host: str = "google.com"
    dns_servers: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class SecurityConfig:
    """Failed-SSH-login check options."""

    enabled: bool = True
    auth_log_path: str = "/var/log/auth.log"
    use_journalctl_fallback: bool = True
    window_minutes: int = 15
    top_ips: int = 5


@dataclass(frozen=True)
class TelegramConfig:
    """Telegram channel settings (secrets come from the environment)."""

    enabled: bool = True
    token_env: str = "LINTEST_TELEGRAM_TOKEN"
    chat_id_env: str = "LINTEST_TELEGRAM_CHAT_ID"
    parse_mode: str = "HTML"
    timeout_seconds: float = 10.0

    def resolve_token(self) -> Optional[str]:
        """Return the bot token from the environment, or ``None``."""
        return os.environ.get(self.token_env) or None

    def resolve_chat_id(self) -> Optional[str]:
        """Return the chat id from the environment, or ``None``."""
        return os.environ.get(self.chat_id_env) or None


@dataclass(frozen=True)
class ConsoleConfig:
    """Console alert channel settings."""

    enabled: bool = True


@dataclass(frozen=True)
class AlertsConfig:
    """Alert routing, cooldown and recovery settings."""

    cooldown_minutes: int = 30
    send_recovery: bool = True
    console: ConsoleConfig = field(default_factory=ConsoleConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)


@dataclass(frozen=True)
class LoggingConfig:
    """File logging settings (a rotating file handler is used)."""

    level: str = "INFO"
    file: str = ""  # empty -> file logging disabled
    max_bytes: int = 1_048_576
    backup_count: int = 5


@dataclass(frozen=True)
class Config:
    """Fully validated LinTest configuration."""

    config_path: Optional[Path] = None
    general: GeneralConfig = field(default_factory=GeneralConfig)
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)
    thresholds: ThresholdsConfig = field(default_factory=ThresholdsConfig)
    system: SystemConfig = field(default_factory=SystemConfig)
    services: ServicesConfig = field(default_factory=ServicesConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _section(raw: Mapping[str, Any], name: str, errors: List[str]) -> Dict[str, Any]:
    """Return section *name* as a dict, recording an error when malformed."""
    value = raw.get(name, {})
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        errors.append(f"[{name}] must be a mapping, got {type(value).__name__}")
        return {}
    return dict(value)


def _num(
    section: Mapping[str, Any],
    key: str,
    errors: List[str],
    path: str,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
    default: Optional[float] = None,
    cast=float,
) -> Any:
    """Validate a numeric field, returning *default* when absent/None."""
    value = section.get(key, default)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(f"{path}.{key} must be a number, got {value!r}")
        return default
    value = cast(value)
    if minimum is not None and value < minimum:
        errors.append(f"{path}.{key} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        errors.append(f"{path}.{key} must be <= {maximum}, got {value}")
    return value


def _int(*args: Any, **kwargs: Any) -> Any:
    """Wrapper around :func:`_num` that casts to int."""
    return _num(*args, cast=int, **kwargs)


def _bool(section: Mapping[str, Any], key: str, errors: List[str], path: str, default: bool) -> bool:
    """Validate a boolean field."""
    value = section.get(key, default)
    if value is None:
        return default
    if not isinstance(value, bool):
        errors.append(f"{path}.{key} must be true or false, got {value!r}")
        return default
    return value


def _str_list(section: Mapping[str, Any], key: str, errors: List[str], path: str) -> List[str]:
    """Validate a list-of-strings field (empty/None allowed)."""
    value = section.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        errors.append(f"{path}.{key} must be a list of strings, got {value!r}")
        return []
    return list(value)


def _str_field(section: Mapping[str, Any], key: str, errors: List[str], path: str, default: str) -> str:
    """Validate a plain string field."""
    value = section.get(key, default)
    if value is None:
        return default
    if not isinstance(value, str):
        errors.append(f"{path}.{key} must be a string, got {value!r}")
        return default
    return value


def _enum(
    section: Mapping[str, Any],
    key: str,
    errors: List[str],
    path: str,
    allowed: Tuple[str, ...],
    default: str,
) -> str:
    """Validate a string field that must be one of *allowed*."""
    value = _str_field(section, key, errors, path, default)
    if value not in allowed:
        errors.append(f"{path}.{key} must be one of {list(allowed)}, got {value!r}")
        return default
    return value


def _mapping_field(
    section: Mapping[str, Any], key: str, errors: List[str], path: str
) -> Dict[str, Any]:
    """Validate a string->number mapping (e.g. disk_overrides)."""
    value = section.get(key, {})
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        errors.append(f"{path}.{key} must be a mapping of mount point -> number, got {value!r}")
        return {}
    out: Dict[str, Any] = {}
    for mount, limit in value.items():
        if not isinstance(mount, str) or not mount.startswith("/"):
            errors.append(f"{path}.{key}: mount {mount!r} must be an absolute path string")
            continue
        if isinstance(limit, bool) or not isinstance(limit, (int, float)):
            errors.append(f"{path}.{key}[{mount}] must be a number, got {limit!r}")
            continue
        if not 0 < limit <= 100:
            errors.append(f"{path}.{key}[{mount}] must be within (0, 100], got {limit}")
            continue
        out[mount] = float(limit)
    return out


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _parse_general(raw: Mapping[str, Any], errors: List[str]) -> GeneralConfig:
    s = _section(raw, "general", errors)
    return GeneralConfig(
        check_timeout_seconds=_num(s, "check_timeout_seconds", errors, "general",
                                   minimum=0.1, maximum=600, default=5.0),
    )


def _parse_schedule(raw: Mapping[str, Any], errors: List[str]) -> ScheduleConfig:
    s = _section(raw, "schedule", errors)
    return ScheduleConfig(
        mode=_enum(s, "mode", errors, "schedule", VALID_SCHEDULE_MODES, "timer"),
        interval_seconds=_int(s, "interval_seconds", errors, "schedule", minimum=10, maximum=86400, default=300),
    )


def _parse_thresholds(raw: Mapping[str, Any], errors: List[str]) -> ThresholdsConfig:
    s = _section(raw, "thresholds", errors)
    return ThresholdsConfig(
        cpu_percent=_num(s, "cpu_percent", errors, "thresholds", minimum=1, maximum=100, default=85.0),
        ram_percent=_num(s, "ram_percent", errors, "thresholds", minimum=1, maximum=100, default=90.0),
        disk_percent=_num(s, "disk_percent", errors, "thresholds", minimum=1, maximum=100, default=90.0),
        disk_overrides=_mapping_field(s, "disk_overrides", errors, "thresholds"),
        load1_per_core=_num(s, "load1_per_core", errors, "thresholds", minimum=0.1, maximum=100, default=1.5),
        failed_ssh_logins=_int(s, "failed_ssh_logins", errors, "thresholds", minimum=1, default=20),
    )


def _parse_system(raw: Mapping[str, Any], errors: List[str]) -> SystemConfig:
    s = _section(raw, "system", errors)
    return SystemConfig(
        enabled=_bool(s, "enabled", errors, "system", True),
        ignore_mount_prefixes=_str_list(s, "ignore_mount_prefixes", errors, "system"),
        exclude_filesystems=_str_list(s, "exclude_filesystems", errors, "system"),
    )


def _parse_services(raw: Mapping[str, Any], errors: List[str]) -> ServicesConfig:
    s = _section(raw, "services", errors)
    return ServicesConfig(
        enabled=_bool(s, "enabled", errors, "services", True),
        critical=_str_list(s, "critical", errors, "services"),
        warning=_str_list(s, "warning", errors, "services"),
    )


def _parse_network(raw: Mapping[str, Any], errors: List[str]) -> NetworkConfig:
    s = _section(raw, "network", errors)
    ports = _str_list(s, "tcp_ports", errors, "network")
    for port in ports:
        host, _, port_str = port.rpartition(":")
        ok = bool(host) and port_str.isdigit() and 1 <= int(port_str) <= 65535
        if not ok:
            errors.append(
                f"network.tcp_ports entry {port!r} must look like host:port "
                f"(e.g. 'db.internal:5432' or '[::1]:443')"
            )
    ping_hosts = _str_list(s, "ping_hosts", errors, "network")
    for host in ping_hosts:
        if not host.strip():
            errors.append("network.ping_hosts entries must be non-empty hostnames or IPs")
    dns_servers = _str_list(s, "dns_servers", errors, "network")
    for server in dns_servers:
        if not server.strip():
            errors.append("network.dns_servers entries must be non-empty IP addresses")
    return NetworkConfig(
        enabled=_bool(s, "enabled", errors, "network", True),
        ping_hosts=ping_hosts,
        ping_count=_int(s, "ping_count", errors, "network", minimum=1, maximum=10, default=3),
        ping_timeout_seconds=_num(s, "ping_timeout_seconds", errors, "network", minimum=0.1, maximum=30, default=2.0),
        tcp_ports=ports,
        tcp_timeout_seconds=_num(s, "tcp_timeout_seconds", errors, "network", minimum=0.1, maximum=30, default=3.0),
        dns_host=_str_field(s, "dns_host", errors, "network", "google.com"),
        dns_servers=dns_servers,
    )


def _parse_security(raw: Mapping[str, Any], errors: List[str]) -> SecurityConfig:
    s = _section(raw, "security", errors)
    path = _str_field(s, "auth_log_path", errors, "security", "/var/log/auth.log")
    if path and not path.startswith("/"):
        errors.append(f"security.auth_log_path must be an absolute path, got {path!r}")
    return SecurityConfig(
        enabled=_bool(s, "enabled", errors, "security", True),
        auth_log_path=path,
        use_journalctl_fallback=_bool(s, "use_journalctl_fallback", errors, "security", True),
        window_minutes=_int(s, "window_minutes", errors, "security", minimum=1, maximum=1440, default=15),
        top_ips=_int(s, "top_ips", errors, "security", minimum=1, maximum=50, default=5),
    )


def _parse_alerts(raw: Mapping[str, Any], errors: List[str]) -> AlertsConfig:
    s = _section(raw, "alerts", errors)
    console_s = _section(s, "console", errors)
    telegram_s = _section(s, "telegram", errors)
    telegram = TelegramConfig(
        enabled=_bool(telegram_s, "enabled", errors, "alerts.telegram", True),
        token_env=_str_field(telegram_s, "token_env", errors, "alerts.telegram", "LINTEST_TELEGRAM_TOKEN"),
        chat_id_env=_str_field(telegram_s, "chat_id_env", errors, "alerts.telegram", "LINTEST_TELEGRAM_CHAT_ID"),
        parse_mode=_enum(telegram_s, "parse_mode", errors, "alerts.telegram", VALID_PARSE_MODES, "HTML"),
        timeout_seconds=_num(telegram_s, "timeout_seconds", errors, "alerts.telegram",
                             minimum=1, maximum=60, default=10.0),
    )
    for env_name in (telegram.token_env, telegram.chat_id_env):
        if not env_name.replace("_", "").isalnum() or not env_name.isidentifier():
            errors.append(
                f"alerts.telegram environment variable name {env_name!r} is not a valid name"
            )
    return AlertsConfig(
        cooldown_minutes=_int(s, "cooldown_minutes", errors, "alerts", minimum=0, maximum=10080, default=30),
        send_recovery=_bool(s, "send_recovery", errors, "alerts", True),
        console=ConsoleConfig(enabled=_bool(console_s, "enabled", errors, "alerts.console", True)),
        telegram=telegram,
    )


def _parse_logging(raw: Mapping[str, Any], errors: List[str]) -> LoggingConfig:
    s = _section(raw, "logging", errors)
    level = _str_field(s, "level", errors, "logging", "INFO").upper()
    if level not in VALID_LOG_LEVELS:
        errors.append(f"logging.level must be one of {list(VALID_LOG_LEVELS)}, got {level!r}")
        level = "INFO"
    log_file = _str_field(s, "file", errors, "logging", "")
    if log_file and not log_file.startswith("/"):
        errors.append(f"logging.file must be an absolute path, got {log_file!r}")
    return LoggingConfig(
        level=level,
        file=log_file,
        max_bytes=_int(s, "max_bytes", errors, "logging", minimum=1024, default=1_048_576),
        backup_count=_int(s, "backup_count", errors, "logging", minimum=0, maximum=100, default=5),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_config(path: Optional[str] = None) -> Config:
    """Load and validate a LinTest configuration file.

    Args:
        path: Path to a YAML config file.  ``None`` uses ``config.yaml``
            from the current working directory when present; otherwise the
            compiled-in defaults are used.

    Returns:
        A validated :class:`Config`.

    Raises:
        ConfigError: When the file is unreadable, not valid YAML, or any
            validation rule fails.  The message lists *all* problems.
    """
    errors: List[str] = []
    resolved: Optional[Path]

    if path is None:
        candidate = Path("config.yaml")
        if not candidate.is_file():
            logger.info("No config file found; using built-in defaults")
            return Config(config_path=None)
        resolved = candidate
    else:
        resolved = Path(path)
        if not resolved.is_file():
            raise ConfigError(f"Config file not found: {resolved}")

    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read config file {resolved}: {exc}") from exc

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {resolved}:\n{exc}") from exc

    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        raise ConfigError(f"Top level of {resolved} must be a mapping, got {type(raw).__name__}")

    # Unknown top-level sections are almost always typos -- surface them.
    known = {"general", "schedule", "thresholds", "system", "services", "network", "security", "alerts", "logging"}
    for key in raw:
        if key not in known:
            errors.append(
                f"unknown section '{key}' (expected one of {sorted(known)}) -- typo?"
            )

    cfg = Config(
        config_path=resolved,
        general=_parse_general(raw, errors),
        schedule=_parse_schedule(raw, errors),
        thresholds=_parse_thresholds(raw, errors),
        system=_parse_system(raw, errors),
        services=_parse_services(raw, errors),
        network=_parse_network(raw, errors),
        security=_parse_security(raw, errors),
        alerts=_parse_alerts(raw, errors),
        logging=_parse_logging(raw, errors),
    )

    if errors:
        details = "\n".join(f"  {i}. {err}" for i, err in enumerate(errors, start=1))
        raise ConfigError(f"{len(errors)} configuration problem(s) in {resolved}:\n{details}")

    logger.debug("Loaded config from %s", resolved)
    return cfg
