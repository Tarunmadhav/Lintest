"""Shared pytest fixtures and helpers for the LinTest test suite."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from lintest.config import (
    Config,
    SecurityConfig,
    ServicesConfig,
    ThresholdsConfig,
)


@pytest.fixture()
def now() -> datetime:
    """A fixed 'current time' used across parser tests (naive local)."""
    return datetime(2025, 7, 15, 10, 30, 0)


def sshd_line(dt: datetime, ip: str = "203.0.113.9", user: str = "root") -> str:
    """Build an auth.log-style failed-password line at *dt* (naive local)."""
    return (
        f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S} srv1 sshd[4242]: "
        f"Failed password for {user} from {ip} port 2200 ssh2"
    )


def invalid_user_line(dt: datetime, ip: str = "198.51.100.7", user: str = "oracle") -> str:
    """Build an auth.log-style 'Invalid user' pre-auth line at *dt*."""
    return (
        f"{dt:%b} {dt.day:>2} {dt:%H:%M:%S} srv1 sshd[4242]: "
        f"Invalid user {user} from {ip} port 51022"
    )


def journalctl_line(dt: datetime, ip: str = "203.0.113.9") -> str:
    """Build a journalctl short-precise failed-password line at *dt* (UTC)."""
    return (
        f"2025-07-15T{dt:%H:%M:%S}.123456+00:00 srv1 sshd[4242]: "
        f"Failed password for root from {ip} port 2200 ssh2"
    )


def make_security_cfg(log_path: Path, threshold: int = 2, window: int = 15) -> Config:
    """A minimal Config wired for the security check against *log_path*."""
    return Config(
        thresholds=ThresholdsConfig(failed_ssh_logins=threshold),
        security=SecurityConfig(
            auth_log_path=str(log_path),
            use_journalctl_fallback=False,
            window_minutes=window,
            top_ips=3,
        ),
        services=ServicesConfig(enabled=False),
    )
