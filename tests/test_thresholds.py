"""Tests for the system-check threshold logic (CPU/RAM/disk/load classification)."""

from __future__ import annotations

import pytest

from lintest.checks.system import _classify, _should_skip_mount
from lintest.config import Config, SystemConfig, ThresholdsConfig


class TestClassify:
    def test_critical(self):
        severity, reason = _classify(90.0, 91.5)
        assert severity.value == "CRITICAL"
        assert "at or above" in reason

    def test_warning_band(self):
        severity, reason = _classify(90.0, 83.0)
        assert severity.value == "WARNING"
        assert "within 10 points" in reason

    def test_ok(self):
        severity, reason = _classify(90.0, 50.0)
        assert severity.value == "OK"
        assert reason == ""

    @pytest.mark.parametrize("threshold,value", [
        (85.0, 74.0),   # just under the warning band (85 - 10 = 75)
        (60.0, 49.0),   # generic band
    ])
    def test_parametrized_ok(self, threshold, value):
        assert _classify(threshold, value)[0].value == "OK"

    @pytest.mark.parametrize("threshold,value", [
        (85.0, 75.0),   # exactly at the band boundary -> WARNING
        (60.0, 55.0),   # inside the band
    ])
    def test_parametrized_warning(self, threshold, value):
        assert _classify(threshold, value)[0].value == "WARNING"


class TestMountFiltering:
    def _cfg(self, prefixes, filesystems):
        return Config(system=SystemConfig(
            ignore_mount_prefixes=list(prefixes),
            exclude_filesystems=list(filesystems),
        ))

    def test_prefix_skip(self):
        cfg = self._cfg(["/snap", "/boot/efi"], [])
        assert _should_skip_mount("/snap/core20/123", "squashfs", cfg)
        assert _should_skip_mount("/boot/efi", "ext4", cfg)      # exact prefix match
        assert _should_skip_mount("/boot", "vfat", cfg) is False  # shorter than prefix
        assert _should_skip_mount("/bootx", "vfat", cfg) is False  # not a path prefix

    def test_exact_root_not_skipped_by_prefix_logic(self):
        cfg = self._cfg(["/srv"], [])
        assert _should_skip_mount("/", "ext4", cfg) is False
        assert _should_skip_mount("/srv/data", "ext4", cfg)

    def test_filesystem_skip(self):
        cfg = self._cfg([], ["tmpfs", "squashfs"])
        assert _should_skip_mount("/run", "tmpfs", cfg)
        assert _should_skip_mount("/snap", "squashfs", cfg)

    def test_real_mount_kept(self):
        cfg = self._cfg(["/snap"], ["tmpfs"])
        assert _should_skip_mount("/home", "ext4", cfg) is False


class TestDiskOverrides:
    def test_longest_prefix_used(self):
        t = ThresholdsConfig(disk_percent=90.0, disk_overrides={"/": 80.0, "/data": 70.0})
        assert t.disk_threshold_for("/") == 80.0
        assert t.disk_threshold_for("/data") == 70.0
        assert t.disk_threshold_for("/data/deep/path") == 70.0
        assert t.disk_threshold_for("/etc") == 80.0
        # A '/' override intentionally cascades to every mount under it.
        assert t.disk_threshold_for("/var/log") == 80.0
