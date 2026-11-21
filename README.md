# BiXCore RADIUS Control — public source v1.0.2

**Current: 21 November 2026.** This is a **sanitized public source
and UniFi helper maintenance release**, not new Docker images.
The verified private deployment continues to use web `1.0.1-web`,
control `0.10.9.1-worker` and sync `0.10.4-worker`.
No `1.0.2-web` image is claimed.

## Features

- Web admin authentication, change password and audit log.
- FreeRADIUS EAP-TLS Accounting: fresh/stale/ended sessions.
- Local user Enabled/VLAN and Captive Portal / guest Wi-Fi controls.
- Single-station UniFi Disconnect with authenticated DAS ACK,
  targeted PMKSA cleanup and EAPOL_REAUTH.
- Wired Omada Disconnect with verified ACK and guarded
  previous Accounting closure only after a matching successor Start.
- Split web / control / sync services with restricted
  SSH and filesystem boundaries.

## RadSec compatibility in v1.0.2

UniFi DAS helper scripts validate the exact RadSec TLS
client name, source IP /32 and named TLS profile in the
local `radsecproxy.conf` before using the RFC 6614 fixed
`radsec` value. **This value is valid for DAS only when
the actual AP is independently configured to accept it.**
The proxy-to-FreeRADIUS backend UDP `Secret` is distinct
and is never used for UniFi DAS. Old FreeRADIUS
`clients.conf` lookup has been retired for these helpers.

The Disconnect helper also handles the RadSec proxy-source
Accounting Detail directory without trusting arbitrary files,
and validates the original NAS, MAC, SID and identifier.

## Verified acceptance scope

Real pilot tests on 21 November 2026 confirmed an authenticated
UniFi Disconnect-ACK with PMKSA cleanup and replacement
Accounting session, an Omada pilot-port ACK with guarded
cleanup, and a separate UniFi EAPOL_REAUTH followed by
Accounting Stop and new Start. These tests do **not**
establish universal FT-EAP/802.11r or TLS resumption revocation,
nor a strict Access-Reject policy for every disabled user.

## Quick start: synthetic demo only

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -q
docker compose -f compose.demo.yaml config --quiet
docker compose -f compose.demo.yaml up -d --build
```

The demo is local/synthetic and does not send production
RADIUS or Wi-Fi commands. Release Compose templates require
operator review and adaptation; never deploy them directly
over a live system with secrets or persistent data.

## Documentation

- [Release v1.0.2](docs/RELEASE_V1.0.2.md)
- [Configuration boundaries](docs/CONFIGURATION.md)
- [Quick start](docs/QUICKSTART.md)
- [RadSec compatibility](docs/RADSEC_UNIFI_COMPAT_V102.md)
- [Security](docs/SECURITY.md)
- [Public release audit](docs/PUBLIC_RELEASE_AUDIT.md)
- [Changelog](CHANGELOG.md)
- [Contribution guidelines](CONTRIBUTING.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

The actual network, passwords, private keys, MAC/session IDs,
RADIUS/Accounting databases, certificates and hostnames
are **not** included. Older release states remain available
in repository Git history and the v1.0.1-public tags.

## License

MIT — see [LICENSE](LICENSE).
