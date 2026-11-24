# Changelog

## Unreleased
- Internal: the mount comparison and fix plan moved from an 80-line Jinja block into `filter_plugins/mount_hardening.py`, unit-tested in `tests/unit` (run by pre-commit with ruff).
- Change: dropped the `linux_hardening_mode` assert that repeated `meta/argument_specs.yml` (which already rejects other values).
- Security: mount paths and options are shell-quoted in the remount and tmpfs mount commands.
- Docs: README adds a Role Variables table.
- Test: the default Molecule scenario runs a `check` (dry-run remediate) step first.
- CI: every platform in `meta/main.yml` gates the release (no `continue-on-error` legs); lint runs the pinned pre-commit hooks; pre-commit adds gitleaks; actions are pinned by commit SHA.

## 1.0.0
- Split out of the iamenr0s.linux_hardening collection; no functional change.
