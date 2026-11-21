# Quick start — BiXCore public source v1.0.2

**Use synthetic data only.** This repository is a
privacy-sanitized export, not a prepared management
installation for any real NAS, firewall or wireless AP.

## 1. Unit tests

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -q
```

The recorded release baseline was 288 unit tests
(287 passed, 1 skipped), with GitHub Actions passing
on the public main branch.

## 2. Local demonstration

```sh
docker compose -f compose.demo.yaml config --quiet
docker compose -f compose.demo.yaml up -d --build
```

The demonstration does not contain real RADIUS
credentials, AP SSH keys or live Accounting records.

## 3. Live installation is a separate operation

Do not treat `compose.v1.0.1.release.yaml` as
an activated production Compose. Review deployment
and rollback independently before any live change.
UniFi RadSec helper installation requires an
exact named TLS client mapping, verified AP DAS
credential, protected forced-command, exact NAS
identity and live Accounting validation. No
`1.0.2-web` Docker image is part of this release.

[Configuration](CONFIGURATION.md) ·
[RadSec](RADSEC_UNIFI_COMPAT_V102.md) ·
[Release](RELEASE_V1.0.2.md).
