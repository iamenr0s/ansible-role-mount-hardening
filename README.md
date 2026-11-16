[![Molecule](https://github.com/iamenr0s/ansible-role-mount-hardening/actions/workflows/molecule.yml/badge.svg)](https://github.com/iamenr0s/ansible-role-mount-hardening/actions/workflows/molecule.yml) ![Ansible Role](https://img.shields.io/ansible/role/d/iamenr0s/mount_hardening) [![CodeFactor](https://www.codefactor.io/repository/github/iamenr0s/ansible-role-mount-hardening/badge)](https://www.codefactor.io/repository/github/iamenr0s/ansible-role-mount-hardening)

# Ansible Role: Mount Hardening

> Standalone copy of `mount_hardening` from the [iamenr0s.linux_hardening](https://github.com/iamenr0s/linux-hardening-collection) collection. Variables keep the collection-wide `linux_hardening_*` prefix.

Audit-first mount options. It owns `/etc/fstab` mount options and the running mounts for a short list of paths; it never partitions or reformats anything and never reboots.

## What it checks
For each managed path the role requires a set of options, both **running** (`findmnt`) and **persisted** (`/etc/fstab`):

| Path | Required options |
|---|---|
| `/tmp`, `/var/tmp`, `/dev/shm` | `nodev,nosuid,noexec` |
| `/var/log`, `/var/log/audit` | `nodev,nosuid,noexec` |
| `/home` | `nodev,nosuid` |

Add or change entries with `linux_hardening_mount_extra: {/srv/data: [nodev, nosuid, noexec]}` (any option name works), skip paths with `linux_hardening_mount_exclude`. The selection is ours, **not a verified CIS mapping**.

| Situation | Remediation |
|---|---|
| Mounted, options missing at runtime | `mount -o remount,<options> <path>` |
| fstab entry without the options | entry rewritten (other fields and options kept; an option that undoes ours, e.g. `exec`, is dropped) |
| A tmpfs (`/tmp` on Debian 13, `/dev/shm`) mounted outside the fstab | a `tmpfs` fstab entry is added |
| `/tmp` or `/dev/shm` not a mount at all | **needs `linux_hardening_mount_create_tmpfs: true`**: fstab entry plus `mount` |
| Any other path that is not a separate mount (`/home`, `/var/log`, ...) | **reported only** (`fixable: false`): it needs a partition |
| Mounted outside the fstab and not a tmpfs | reported only |

A path that does not exist and is not mounted is silently skipped.

## Safety
- The fstab is edited **before** anything is remounted, so a refused edit leaves the running system untouched.
- The edit is checked with `findmnt --verify`, and the fstab is backed up (`linux_hardening_backup`). If the fstab already fails that check, validation is skipped (there is nothing to compare with) rather than blocking every change.
- `noexec` can break software: dpkg/rpm scriptlets and installers that run from `/tmp` or `/var/tmp`, and anything that executes from `/dev/shm`. Test before enabling on `/var/tmp` in particular.
- Mounting a tmpfs over `/tmp` uses RAM (tmpfs default: half) and **hides the current contents of `/tmp`** until the next reboot. That is why it needs its own switch. (Ansible itself unpacks modules under `/tmp`, so this one step runs with `raw`, otherwise it would crash its own module.)

## Modes
`audit` (default) is read-only and sets `linux_hardening_mount_findings` (`key, expected, actual, fixable`). `remediate` needs `linux_hardening_confirm_remediation: true`; afterwards only fixable findings fail the run.

## Example
```yaml
- hosts: all
  roles:
    - role: iamenr0s.linux_hardening.mount_hardening
      vars:
        linux_hardening_mode: remediate
        linux_hardening_confirm_remediation: true
        linux_hardening_mount_create_tmpfs: true
        linux_hardening_mount_exclude: [/var/tmp]
```

## Verification
Container scenarios `default` (remediates `/dev/shm`, requiring an extra `noatime` because a container's `/dev/shm` is already `noexec`; checks the fstab line and the running options), `audit` (read-only, fstab unchanged), `refuse`. **VM scenario `vagrant`** (libvirt; `sg libvirt -c "molecule test -s vagrant"`; box `MOLECULE_VAGRANT_BOX`, default `almalinux/9`): creates a real loop-mounted ext4 with its own fstab line, remediates with `/tmp` created as a tmpfs, checks idempotence, then **reboots** and checks again that the machine boots from the edited fstab with the options in place. Tested: AlmaLinux 9 VM (`/tmp` not a mount, so the tmpfs is created) and Debian 13 VM (`/tmp` is a systemd tmpfs outside the fstab, so an entry is added), both idempotent and reboot-proven; AlmaLinux 9, Debian 13, Ubuntu 24.04 and Fedora 44 containers. CI runs the container scenarios only. The scenario's reboot uses `post_reboot_delay: 45`: polling sshd during early boot never got through authentication on the 1-CPU test VM (reproduced with the role's changes removed).

## Rollback
Restore the backup (`/etc/fstab.<timestamp>~`), then `mount -o remount,exec,suid,dev <path>`.

## Known gaps
- Not tested on an Ubuntu or Fedora VM, or on EL8/EL10.
- Bind mounts (e.g. `/var/tmp` bound to `/tmp`) and the `systemd`-unit-only mounts are not managed; `findmnt` source/escape handling covers plain paths only.
- A compliant running mount with no fstab entry is not reported (a systemd unit may be setting the options); only a deficient one triggers an fstab entry.
- CIS IDs not mapped.

CI & Release (maintainers)
----------------------------
A single workflow (`.github/workflows/molecule.yml`) runs lint and the full Molecule distro matrix on pushes to `main`, PRs, and `v*` tags. On `v*` tags, a `release` job publishes to Ansible Galaxy after all tests pass.

One-time setup:

```bash
# Galaxy publishing key (environment-scoped, get it from galaxy.ansible.com/ui/token)
gh secret set GALAXY_API_KEY --repo iamenr0s/ansible-role-mount-hardening

# Code scanning notifications (Slack webhook URL; for Discord append /slack to the webhook URL)
gh secret set SECURITY_ALERT_WEBHOOK --repo iamenr0s/ansible-role-mount-hardening
```

`.github/workflows/code-scanning-notify.yml` polls the code-scanning API every 6 hours and posts new or updated open alerts to that webhook (GitHub Actions cannot trigger on `code_scanning_alert` directly).

To release: tag a commit `vX.Y.Z` and push the tag — CI gates the Galaxy publish.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
local pipeline commands and pull request checklist. This project follows the
[Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## Security

See [SECURITY.md](SECURITY.md) — GitHub private vulnerability reporting, no
public issues for security bugs.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

## License

This project is licensed under the [MIT License](LICENSE).

## Author Information

Author: iamenr0s

Galaxy: `iamenr0s.mount_hardening`
