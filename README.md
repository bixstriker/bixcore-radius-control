# BiXCore RADIUS Control

BiXCore RADIUS Control is a web console for FreeRADIUS/OPNsense accounting and
802.1X session administration, with optional per-client UniFi Wi-Fi and Omada
wired Disconnect operations.

**Public source release: v1.0.1 — privacy-sanitized export.** This is a
source-code distribution, **not** a ready-to-deploy template for an arbitrary
network. It is based on the tested private v1.0.1 version, but all deployment
identifiers, addresses, and simulated client details were replaced with
examples. It has an independent Git history and no secrets.

## Features

- RADIUS accounting sessions, local users and Captive Portal views.
- Session history and stale accounting inspection.
- Optional local-user enabled/VLAN controls through restricted SSH handlers.
- Per-client UniFi EAP reauthentication, Disconnect, PMKSA management.
- Per-client Omada wired 802.1X Disconnect with authenticated ACK handling.
- Safe old accounting close only when a matching successor Accounting-Start
  has appeared after the authenticated ACK.
- Administrator login, password change, audit trail, manual snapshot refresh.
- Multilingual (Russian, English, German, Ukrainian), desktop/tablet/mobile UI.

## Important deployment warning

This repository contains **example addresses only**, including `192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`, and the `example.test` domain.
They do not identify a real deployed system and **will not work in production**.
The code originated as an installation-specific solution, not yet a fully
multi-tenant, zero-config product. Before using it, review and replace example
defaults / source constants and update both ends of restricted SSH helpers.

See [Architecture and configuration](docs/CONFIGURATION.md) and
[Security and release notes](docs/SECURITY.md). `compose.demo.yaml` is supplied
for a localhost-only synthetic-data demonstration; `compose.v1.0.1.release.yaml` is an advanced
deployment **example**, not a safe direct production command.

## Prerequisites

- Python 3.13 or compatible runtime.
- FreeRADIUS with SQLite accounting and tested read-only export helpers.
- OPNsense for the provided privileged helpers.
- Docker Compose, root-owned secrets, pinned host keys and dedicated restricted
  SSH keys. An external HTTPS reverse proxy is recommended.

## Development and tests

```sh
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m unittest discover -s tests -q
docker compose -f compose.demo.yaml config --quiet
```

Do not run a destructive Disconnect against a production client as a smoke
test. Unit tests use mocked session and transport data.

## Repository organization

- `app/`: REST API, auth, audit, UI and server-side session logic.
- `sync/`: restricted snapshot/command orchestration.
- `deploy/opnsense/`: reviewed FreeBSD/OPNsense helper scripts.
- `deploy/`: socket and worker service examples.
- `tests/`: isolated regression tests.
- `data/`: synthetic demo fixtures.
- `compose.demo.yaml`: demonstration; `compose.v1.0.1.release.yaml`:
  installation-specific production sample, with Omada disabled by default.

## Privacy and security

No production IPs, DNS names, MAC addresses, passwords, private keys, host
backups, historical private change ledgers or accounting databases are
distributed. Git history begins from a new root commit.

Never commit credentials or take an example `authorized_keys` entry
without understanding the source-IP, forced-command and host-key restrictions.

## Quick start

For a localhost-only **synthetic data** demo, see [Quickstart](docs/QUICKSTART.md).
See [Configuration](docs/CONFIGURATION.md) before adapting the example server
or OPNsense helpers to any real network. The demo is not an automatic installer.

## License

Copyright (c) 2026 **bixstriker**. BiXCore's source code is licensed under the
[MIT License](LICENSE). Dependencies retain their separate licenses and
notices; see [third-party inventory](THIRD_PARTY_NOTICES.md).

Contributions: [CONTRIBUTING.md](CONTRIBUTING.md).
Security reports: [SECURITY.md](SECURITY.md).
Public changelog: [CHANGELOG.md](CHANGELOG.md).
