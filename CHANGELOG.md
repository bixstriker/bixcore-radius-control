## v1.0.2 candidate — not released

- UniFi RadSec/direct UDP Accounting Detail compatibility.
- Strict NAS/SID/MAC/NAS-Identifier validation, ambiguous identity rejection.
- New mocked tests; production live acceptance pending.
- See [technical notes](docs/RADSEC_UNIFI_COMPAT_V102.md).

# Changelog — public distribution

## v1.0.1-public.3 — 2026-11-19

- First completed MIT-licensed source distribution.
- Root `LICENSE` and copyright attribution.
- Dependency license inventory, user quickstart and configuration warnings.
- Contribution guidelines and private vulnerability reporting instructions.
- Independent public Git history; real IPs, hostnames, MACs and secrets excluded.
- GitHub Actions tests and static JS/Python validation.

## v1.0.1-public.2 — 2026-11-19

- Privacy-sanitized v1.0.1 source snapshot; CI portability fixes.
- FastAPI web interface with desktop/mobile layouts, four languages, FreeRADIUS
  Accounting and conditional UniFi/Omada control workflows.

**Compatibility note:** the public release's example constants are deliberately
not compatible with the private, deployed installation.
