"""System metric check tests with psutil fully faked."""

from __future__ import annotations

from lintest.checks import system as system_mod
from lintest.config import Config, SystemConfig, ThresholdsConfig
from lintest.models import Severity


class FakeUsage:
    def __init__(self, percent, free=10.0, total=100.0):
        self.percent = percent
        self.free = free * 1024**3
        self.total = total * 1024**3


class FakePart:
    def __init__(self, mountpoint, fstype="ext4"):
        self.mountpoint = mountpoint
        self.fstype = fstype


class FakeMem:
    percent = 55.0
    used = 4 * 1024**3
    total = 16 * 1024**3


def cfg(**thresholds) -> Config:
    return Config(
        thresholds=ThresholdsConfig(**thresholds),
        system=SystemConfig(ignore_mount_prefixes=["/snap"], exclude_filesystems=["tmpfs"]),
    )


def patch_disks(monkeypatch, parts, usages):
    monkeypatch.setattr(system_mod.psutil, "disk_partitions", lambda all=False: list(parts))

    def disk_usage(mount):
        if isinstance(usages.get(mount), Exception):
            raise usages[mount]
        return usages[mount]
    monkeypatch.setattr(system_mod.psutil, "disk_usage", disk_usage)


class TestCpuRamLoad:
    def test_cpu_critical(self, monkeypatch):
        monkeypatch.setattr(system_mod.psutil, "cpu_percent", lambda interval=0: 95.0)
        monkeypatch.setattr(system_mod.psutil, "cpu_count", lambda logical=True: 4)
        check = system_mod._check_cpu(cfg(cpu_percent=85.0))
        assert check.severity is Severity.CRITICAL
        assert check.details["percent"] == 95.0

    def test_cpu_warning_band(self, monkeypatch):
        monkeypatch.setattr(system_mod.psutil, "cpu_percent", lambda interval=0: 80.0)
        monkeypatch.setattr(system_mod.psutil, "cpu_count", lambda logical=True: 4)
        assert system_mod._check_cpu(cfg(cpu_percent=85.0)).severity is Severity.WARNING

    def test_cpu_ok(self, monkeypatch):
        monkeypatch.setattr(system_mod.psutil, "cpu_percent", lambda interval=0: 10.0)
        monkeypatch.setattr(system_mod.psutil, "cpu_count", lambda logical=True: 2)
        assert system_mod._check_cpu(cfg()).severity is Severity.OK

    def test_ram_critical(self, monkeypatch):
        monkeypatch.setattr(system_mod.psutil, "virtual_memory", lambda: FakeMem())
        check = system_mod._check_ram(cfg(ram_percent=50.0))
        assert check.severity is Severity.CRITICAL

    def test_ram_ok(self, monkeypatch):
        monkeypatch.setattr(system_mod.psutil, "virtual_memory", lambda: FakeMem())
        check = system_mod._check_ram(cfg(ram_percent=90.0))
        assert check.severity is Severity.OK
        assert check.details["total_gib"] == 16.0

    def test_load_per_core_critical(self, monkeypatch):
        monkeypatch.setattr(system_mod.os, "getloadavg", lambda: (8.0, 7.0, 6.0), raising=False)
        monkeypatch.setattr(system_mod.psutil, "cpu_count", lambda logical=True: 4)
        check = system_mod._check_load(cfg(load1_per_core=1.5))[0]
        assert check.severity is Severity.CRITICAL
        assert check.details["per_core"] == 2.0

    def test_load_ok(self, monkeypatch):
        monkeypatch.setattr(system_mod.os, "getloadavg", lambda: (0.4, 0.5, 0.6), raising=False)
        monkeypatch.setattr(system_mod.psutil, "cpu_count", lambda logical=True: 4)
        assert system_mod._check_load(cfg(load1_per_core=1.5))[0].severity is Severity.OK

    def test_load_warning_band_is_proportional_to_a_small_threshold(self, monkeypatch):
        """Regression: a fixed 10-point band made every load value a WARNING."""
        monkeypatch.setattr(system_mod.os, "getloadavg", lambda: (4.8, 4.0, 3.0), raising=False)
        monkeypatch.setattr(system_mod.psutil, "cpu_count", lambda logical=True: 4)
        # 1.2 per core is inside the 25% band below 1.5 (1.125) but below it.
        assert system_mod._check_load(cfg(load1_per_core=1.5))[0].severity is Severity.WARNING

    def test_load_far_below_threshold_is_ok(self, monkeypatch):
        monkeypatch.setattr(system_mod.os, "getloadavg", lambda: (0.8, 0.4, 0.2), raising=False)
        monkeypatch.setattr(system_mod.psutil, "cpu_count", lambda logical=True: 4)
        # 0.2 per core is well under the warning band (1.125).
        assert system_mod._check_load(cfg(load1_per_core=1.5))[0].severity is Severity.OK

    def test_load_unavailable_platform(self, monkeypatch):
        monkeypatch.delattr(system_mod.os, "getloadavg", raising=False)
        results = system_mod._check_load(cfg())
        assert results[0].severity is Severity.OK
        assert "not available" in results[0].message

    def test_load_oserror_is_warning(self, monkeypatch):
        def boom():
            raise OSError("no loadavg")
        monkeypatch.setattr(system_mod.os, "getloadavg", boom, raising=False)
        assert system_mod._check_load(cfg())[0].severity is Severity.WARNING


class TestDiskChecks:
    def test_critical_at_threshold(self, monkeypatch):
        patch_disks(monkeypatch, [FakePart("/")], {"/": FakeUsage(90.0)})
        check = system_mod._check_disks(cfg(disk_percent=90.0))[0]
        assert check.severity is Severity.CRITICAL
        assert check.details["percent"] == 90.0

    def test_per_mount_override_is_applied(self, monkeypatch):
        patch_disks(monkeypatch, [FakePart("/"), FakePart("/data")],
                    {"/": FakeUsage(20.0), "/data": FakeUsage(78.0)})
        checks = {c.subject: c for c in system_mod._check_disks(
            cfg(disk_percent=90.0, disk_overrides={"/data": 70.0}))}
        assert checks["/data"].severity is Severity.CRITICAL
        assert checks["/data"].details["threshold"] == 70.0
        assert checks["/"].severity is Severity.OK

    def test_excluded_filesystems_are_skipped(self, monkeypatch):
        patch_disks(monkeypatch, [FakePart("/", "ext4"), FakePart("/run", "tmpfs")],
                    {"/": FakeUsage(10.0), "/run": FakeUsage(99.0)})
        checks = system_mod._check_disks(cfg())
        assert [c.subject for c in checks] == ["/"]

    def test_ignored_prefixes_are_skipped(self, monkeypatch):
        patch_disks(monkeypatch, [FakePart("/snap/core20/1", "squashfs"), FakePart("/srv")],
                    {"/srv": FakeUsage(10.0)})
        checks = system_mod._check_disks(cfg())
        assert [c.subject for c in checks] == ["/srv"]

    def test_unreadable_mount_is_a_warning_not_a_crash(self, monkeypatch):
        patch_disks(monkeypatch, [FakePart("/secret")], {"/secret": PermissionError("denied")})
        check = system_mod._check_disks(cfg())[0]
        assert check.severity is Severity.WARNING
        assert "cannot read usage" in check.message

    def test_no_mounts_yields_ok_placeholder(self, monkeypatch):
        patch_disks(monkeypatch, [], {})
        check = system_mod._check_disks(cfg())[0]
        assert check.severity is Severity.OK
        assert "no real mount points" in check.message

    def test_disk_partitions_failure_is_tolerated(self, monkeypatch):
        def boom(all=False):
            raise RuntimeError("psutil exploded")
        monkeypatch.setattr(system_mod.psutil, "disk_partitions", boom)
        check = system_mod._check_disks(cfg())[0]
        assert check.severity is Severity.OK


class TestRunSystemChecksIsolation:
    def test_a_crashing_metric_does_not_stop_the_others(self, monkeypatch):
        def boom(interval=0):
            raise RuntimeError("cpu probe died")
        monkeypatch.setattr(system_mod.psutil, "cpu_percent", boom)
        monkeypatch.setattr(system_mod.psutil, "virtual_memory", lambda: FakeMem())
        monkeypatch.setattr(system_mod.psutil, "cpu_count", lambda logical=True: 2)
        monkeypatch.setattr(system_mod.os, "getloadavg", lambda: (0.1, 0.1, 0.1), raising=False)
        patch_disks(monkeypatch, [FakePart("/")], {"/": FakeUsage(10.0)})

        results = system_mod.run_system_checks(cfg())
        by_check = {r.check: r for r in results}
        assert by_check["system.cpu"].severity is Severity.ERROR
        assert "cpu probe died" in by_check["system.cpu"].message
        assert by_check["system.ram"].severity is Severity.OK
        assert by_check["system.disk"].severity is Severity.OK
        assert by_check["system.load"].severity is Severity.OK

    def test_all_four_metrics_always_reported(self, monkeypatch):
        monkeypatch.setattr(system_mod.psutil, "cpu_percent", lambda interval=0: 5.0)
        monkeypatch.setattr(system_mod.psutil, "virtual_memory", lambda: FakeMem())
        monkeypatch.setattr(system_mod.psutil, "cpu_count", lambda logical=True: 2)
        monkeypatch.setattr(system_mod.os, "getloadavg", lambda: (0.1, 0.1, 0.1), raising=False)
        patch_disks(monkeypatch, [FakePart("/")], {"/": FakeUsage(10.0)})
        checks = {r.check for r in system_mod.run_system_checks(cfg())}
        assert checks == {"system.cpu", "system.ram", "system.disk", "system.load"}
