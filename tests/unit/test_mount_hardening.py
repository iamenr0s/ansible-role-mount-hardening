"""Unit tests for the mount_hardening_plan filter."""

import importlib.util
import json
import pathlib

_SPEC = importlib.util.spec_from_file_location(
    "mount_hardening", pathlib.Path(__file__).parents[2] / "filter_plugins" / "mount_hardening.py")
mh = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(mh)

OPP = {"nodev": "dev", "nosuid": "suid", "noexec": "exec", "ro": "rw"}
TMPFS = ["/tmp", "/dev/shm"]


def findmnt(*mounts):
    """Build findmnt --json output from (target, source, fstype, options) tuples."""
    return json.dumps({"filesystems": [dict(zip(("target", "source", "fstype", "options"), m)) for m in mounts]})


def run(mounts, fstab, wanted, existing=None, create=False):
    """Run the planner with the shared opposites and tmpfs paths."""
    existing = existing if existing is not None else list(wanted)
    return mh.plan(findmnt(*mounts), fstab, wanted, existing, OPP, TMPFS, create)


def test_last_option_wins_and_defaults_undoes():
    """The last of an option, its opposite or defaults wins."""
    assert mh._has(["nodev"], "nodev", OPP)
    assert not mh._has(["nodev", "dev"], "nodev", OPP)
    assert not mh._has(["nodev", "defaults"], "nodev", OPP)
    assert mh._has(["defaults", "nodev"], "nodev", OPP)


def test_compliant_mount_needs_nothing():
    """A mount that already has every option needs no step or finding."""
    out = run([("/dev/shm", "tmpfs", "tmpfs", "rw,nosuid,nodev,noexec")],
              "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0\n", {"/dev/shm": ["nodev", "nosuid", "noexec"]})
    assert out == {"plan": [], "findings": []}


def test_fstab_line_replaces_the_opposite_and_keeps_other_options():
    """The new fstab line drops the opposite and keeps the rest."""
    out = run([("/home", "/dev/sda2", "ext4", "rw,relatime")],
              "# comment\nUUID=1 /home ext4 defaults,dev,relatime 0 2\n", {"/home": ["nodev"]})
    assert out["plan"] == [{"path": "/home", "mount_new": False, "remount": "nodev",
                            "fstab_line": "UUID=1 /home ext4 defaults,relatime,nodev 0 2"}]
    assert [f["key"] for f in out["findings"]] == ["/home mount options (running)", "/home mount options (fstab)"]
    assert all(f["fixable"] for f in out["findings"])


def test_running_tmpfs_without_fstab_entry_gets_one():
    """A running tmpfs missing from fstab gets an fstab line."""
    out = run([("/dev/shm", "tmpfs", "tmpfs", "rw,nosuid")], "", {"/dev/shm": ["nodev", "nosuid"]})
    assert out["plan"] == [{"path": "/dev/shm", "mount_new": False, "remount": "nodev",
                            "fstab_line": "tmpfs /dev/shm tmpfs defaults,nodev,nosuid 0 0"}]


def test_mount_outside_fstab_is_reported_only():
    """A non-tmpfs mount outside fstab is reported, not fixed."""
    out = run([("/srv", "/dev/sdb1", "xfs", "rw")], "", {"/srv": ["nodev"]})
    assert out["plan"] == [{"path": "/srv", "mount_new": False, "remount": "", "fstab_line": ""}]
    assert out["findings"][-1] == {"key": "/srv fstab entry", "expected": "present",
                                   "actual": "missing, mounted outside fstab (reported only: a systemd unit?)",
                                   "fixable": False}


def test_missing_mount_point_is_a_tmpfs_only_when_allowed():
    """A missing mount becomes a tmpfs only when allowed."""
    wanted = {"/tmp": ["nodev", "nosuid", "noexec"], "/var/tmp": ["nodev"]}
    off = run([], "", wanted)
    assert off["plan"] == []
    assert [f["fixable"] for f in off["findings"]] == [False, False]
    assert "linux_hardening_mount_create_tmpfs" in off["findings"][0]["actual"]
    assert "needs a partition" in off["findings"][1]["actual"]

    on = run([], "", wanted, create=True)
    assert on["plan"] == [{"path": "/tmp", "mount_new": True, "remount": "",
                           "fstab_line": "tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0"}]


def test_absent_path_is_skipped():
    """A path that does not exist on disk is skipped."""
    assert run([], "", {"/tmp": ["nodev"]}, existing=[]) == {"plan": [], "findings": []}


def test_filter_is_registered():
    """The filter is exposed under its public name."""
    assert mh.FilterModule().filters()["mount_hardening_plan"] is mh.plan
