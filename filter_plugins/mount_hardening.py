"""Filter that compares mount points with the wanted options and plans the fix for mount_hardening.

``mount_hardening_plan(findmnt_json, fstab, wanted, existing, opposite, tmpfs_paths, create_tmpfs)``
    Input: the stdout of ``findmnt --json --list --output TARGET,SOURCE,FSTYPE,OPTIONS``, the text of
    the fstab, the wanted options per mount point (``{path: [option]}``), the mount points that exist
    on disk, the option that undoes each hardening option (``{nodev: dev, ...}``), the paths the role
    may create as a tmpfs, and whether it may.
    Output: ``{'plan': [{'path', 'mount_new', 'fstab_line', 'remount'}],
    'findings': [{'key', 'expected', 'actual', 'fixable'}]}``. ``fstab_line`` is the full new fstab
    line ('' when the fstab needs no change); ``remount`` is the options to apply live ('' for none).

Example::

    - ansible.builtin.set_fact:
        result: >-
          {{ findmnt.stdout | mount_hardening_plan(fstab_text, {'/dev/shm': ['nodev', 'nosuid']},
                                                   ['/dev/shm'], {'nodev': 'dev'}, ['/tmp', '/dev/shm'], false) }}
"""

from __future__ import annotations

import json
from typing import Any


def _has(opts: list[str], want: str, opposite: dict[str, str]) -> bool:
    """Tell whether an option list ends up with ``want`` set.

    The last of ``want``, its opposite or ``defaults`` wins, as in mount(8).

    :param opts: the mount options in order
    :param want: the option that should be in effect
    :param opposite: option to the option that undoes it
    :return: whether ``want`` is in effect
    """
    undo = opposite.get(want, "")
    on = False
    for opt in opts:
        if opt == want:
            on = True
        elif undo and opt in (undo, "defaults"):
            on = False
    return on


def _parse_fstab(text: str) -> dict[str, dict[str, Any]]:
    """Parse fstab text into entries keyed by mount point (a later line wins).

    :param text: the fstab content
    :return: ``{mount point: {'spec', 'type', 'opts', 'dump', 'pass'}}``
    """
    tab = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 4 and not line.lstrip().startswith("#"):
            tab[fields[1]] = {
                "spec": fields[0],
                "type": fields[2],
                "opts": fields[3].split(","),
                "dump": fields[4] if len(fields) > 4 else "0",
                "pass": fields[5] if len(fields) > 5 else "0",
            }
    return tab


def _tmpfs_line(path: str, req: list[str]) -> str:
    """Build a tmpfs fstab line.

    :param path: the mount point
    :param req: the wanted options
    :return: the fstab line
    """
    return f"tmpfs {path} tmpfs {','.join(['defaults', *req])} 0 0"


def plan(findmnt_json: str, fstab: str, wanted: dict[str, list[str]], existing: list[str],
         opposite: dict[str, str], tmpfs_paths: list[str], create_tmpfs: bool) -> dict[str, list[dict[str, Any]]]:
    """Compare the mounts with the wanted options and plan the fix.

    :param findmnt_json: ``findmnt --json --list`` output
    :param fstab: the fstab text
    :param wanted: wanted options per mount point
    :param existing: mount points that exist on disk
    :param opposite: option to the option that undoes it
    :param tmpfs_paths: paths the role may create as a tmpfs
    :param create_tmpfs: whether it may create them
    :return: ``{'plan': [...], 'findings': [...]}``
    """
    running = {m["target"]: m for m in json.loads(findmnt_json)["filesystems"]}
    tab = _parse_fstab(fstab)
    steps: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    def finding(key: str, expected: str, actual: str, fixable: bool) -> None:
        findings.append({"key": key, "expected": expected, "actual": actual, "fixable": fixable})

    for path, req in wanted.items():
        run, ent = running.get(path), tab.get(path)
        want_s = ",".join(req)

        if run is None and ent is None:
            if path not in existing:
                continue
            if path in tmpfs_paths and create_tmpfs:
                finding(f"{path} separate mount", f"tmpfs with {want_s}", "not a mount", True)
                steps.append({"path": path, "mount_new": True, "remount": "", "fstab_line": _tmpfs_line(path, req)})
            else:
                how = ("set linux_hardening_mount_create_tmpfs to mount a tmpfs" if path in tmpfs_paths
                       else "needs a partition")
                finding(f"{path} separate mount", f"a mount with {want_s}",
                        f"not a mount (reported only: {how})", False)
            continue

        miss_run = [r for r in req if not _has(run["options"].split(","), r, opposite)] if run is not None else []
        if miss_run:
            finding(f"{path} mount options (running)", want_s, run["options"], True)

        new_line = ""
        if ent is not None:
            if any(not _has(ent["opts"], r, opposite) for r in req):
                undo = [opposite[r] for r in req if r in opposite]
                kept = [o for o in ent["opts"] if o not in req and o not in undo]
                new_line = f"{ent['spec']} {path} {ent['type']} {','.join(kept + req)} {ent['dump']} {ent['pass']}"
                finding(f"{path} mount options (fstab)", want_s, ",".join(ent["opts"]), True)
        elif miss_run:
            if run["fstype"] == "tmpfs":
                new_line = _tmpfs_line(path, req)
                finding(f"{path} fstab entry", "present", "missing", True)
            else:
                finding(f"{path} fstab entry", "present",
                        "missing, mounted outside fstab (reported only: a systemd unit?)", False)

        if miss_run or new_line:
            can_remount = run is not None and (ent is not None or run["fstype"] == "tmpfs")
            steps.append({"path": path, "mount_new": False, "fstab_line": new_line,
                          "remount": ",".join(miss_run) if can_remount else ""})

    return {"plan": steps, "findings": findings}


class FilterModule:
    """Register the mount_hardening filters."""

    def filters(self) -> dict[str, Any]:
        """Return the filter name to function map.

        :return: filter mapping
        """
        return {"mount_hardening_plan": plan}
