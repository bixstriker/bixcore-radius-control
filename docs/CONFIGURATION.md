# Configuration and deployment boundaries — public v1.0.2

This is a sanitized source tree with example addresses and
client names. A Git checkout alone cannot reproduce
a private installation: operating-system settings,
NAS-local activated Compose, restricted SSH keys,
RADIUS CA material, private databases and backups
are deliberately absent.

## Current release scope

v1.0.2 changes restricted UniFi OPNsense helper sources
for RadSec compatibility. No `1.0.2-web` Docker image
was built or installed in the verified pilot.
The installed reference system continues to use:
web `1.0.1-web`, control `0.10.9.1-worker`,
sync `0.10.4-worker`. `compose.v1.0.1.release.yaml`
is a template, **not** a drop-in live replacement.

## External dependencies and required adaptation

1. RadSecProxy TLS listener, certificates and exact
   client blocks for each known AP. Verify AP identity
   and destination, TLS type, host /32 and TLS profile.
2. FreeRADIUS EAP-TLS backend and Accounting database.
   Preserve the original NAS-IP-Address in proxy detail.
3. The actual AP DAS receiver's source allowlist,
   UDP/3799 and shared secret. Only use `radsec` for
   DAS when it is independently confirmed on that AP.
4. Source-restricted SSH forced-command keys,
   protected files, host-key pinning, audit storage
   and worker permissions.
5. Physical or virtual management network and
   rollback access; never alter an active system
   merely to match example files in this repository.

The RadSec client block's absence of an explicit `Secret`
does not license reading the local backend UDP
`server Secret`. The exact TLS-client mapping is
validated by both UniFi helpers; mismatch fails closed.
Do not copy real secret values into public files.

## Synthetic validation

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -q
docker compose -f compose.demo.yaml config --quiet
```

[Quickstart](QUICKSTART.md) ·
[Release](RELEASE_V1.0.2.md) ·
[Security](SECURITY.md).
