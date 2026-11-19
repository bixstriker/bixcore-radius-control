# Public release audit — v1.0.1

Date: 2026-11-19. Scope: public, privacy-sanitized export of BiXCore RADIUS Control v1.0.1.

## Release isolation

- A separate directory was created from **selected tracked source files**.
- No private `.git` directory, refs, commits, tags, credentials or local files were copied.
- Excluded: private host inventory and incident journals, Recovery Runbook, internal
  service notes, one-time Accounting repair script, production snapshots and backups.
- New public README and architecture/security instructions are included.
- Deployment addresses in code, fixtures and Compose examples were replaced with
  documentation-only IP ranges. Device MACs and hostnames are synthetic.
- Sensitive runtime files are blocked by `.gitignore`. Real authentication data,
  CoA secrets and SSH private/public host keys are **not** part of this release.

## Verification

- Full regression suite: **258 tests executed, 257 passed, 1 skipped**.
- Node.js syntax check: `app/static/app.js`, `app/static/ui.js`,
  `app/static/login.js` passed.
- Python source compilation: passed.
- All 19 included Compose YAML files parsed as YAML.
- File-level checks reported no original internal network identifiers, original
  domain, private-key PEM/OpenSSH material, embedded CoA credentials or
  real operational configuration files in the public export.
- The production NAS/OPNsense installation and the private repository were
  not changed in creating this export.

## Important limitations

The original system was built for a specific home/lab environment.
This is a privacy-sanitized **source release**, not an automatic installer.
Review every example constant and restricted-command endpoint before use.
Sample documentation IPs and `example.test` are non-routable and deliberately
do not point to a real system. Tests use mock or synthetic data; they do not
constitute an end-to-end field test of another installation.

The first public snapshot had no project license; the current public release is
licensed under MIT, which permits commercial use and redistribution under its
notice-preservation terms. Third-party dependency licenses remain separate.

## Linux CI compatibility correction
The first Linux GitHub Actions run exposed two test-host assumptions: the OPNsense lock file is root-owned in production but test temp locks are not, and Linux runners may have less than 45 seconds of monotonic uptime. The public source now skips the Omada cooldown only when there has been no previous attempt; the test suite mocks the root-owned lock state without relaxing production ownership enforcement. The original private deployment and its helper remain unchanged.

## MIT completion (19 November 2026)

MIT license, attribution, third-party notices, contribution/security guidance and a qualified quickstart were added after successful Linux CI. No change to the private deployed instance.
