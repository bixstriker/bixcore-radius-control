# Current source release note — v1.0.2

These demonstration quickstart steps apply to the sanitized v1.0.2
source tree. A new v1.0.2 Docker image is not provided. RadSecProxy
DAS fixes require exact local TLS client mapping and correspondingly
configured UniFi DAS secret. See
[release notes](RELEASE_V1.0.2.md).


---

# Getting started

The public source distribution is an **adaptation reference** from a working
FreeRADIUS/OPNsense installation. It contains example IP addresses in the
[RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation ranges,
synthetic MACs and fake `example.test` DNS names.

## 1. Inspect the demonstration

Requirements: Docker Engine + Docker Compose plugin.

```sh
git clone https://github.com/bixstriker/bixcore-radius-control.git
cd bixcore-radius-control
docker compose -f compose.demo.yaml config --quiet
docker compose -f compose.demo.yaml up --build -d
docker compose -f compose.demo.yaml ps
```

The demo binds to **127.0.0.1:8765** only. Open
[http://127.0.0.1:8765](http://127.0.0.1:8765) on the same machine. It
loads the repository's **synthetic** `data/demo_snapshot.json`; no real RADIUS,
OPNsense, UniFi or Omada equipment is connected. Administrative controls
are not activated by the demo Compose configuration.

```sh
docker compose -f compose.demo.yaml down
```

**Not tested in this release:** an actual Docker daemon was unavailable on
the maintainer's Windows workstation. The Compose file was inspected and YAML
parsed, but the sample Docker container was not launched in this release.

## 2. Run unit tests

Use Python 3.13 and Node.js for the included syntax checks.

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -q
node --check app/static/app.js
node --check app/static/ui.js
node --check app/static/login.js
```

On the verified GitHub Actions Linux runner, 257 tests passed and 1 was
skipped for the public snapshot.

## 3. Adapt the live deployment

**Do not deploy** any example `compose.v*.release.yaml` file to a real network
without tailoring it. The project is not an auto-discovering or self-contained
OPNsense plugin. Follow [CONFIGURATION.md](CONFIGURATION.md):

1. Inventory your own RADIUS server, switches, APs, client VLANs and EAP policies.
2. Replace the example NAS IPs and DNS in the app and OPNsense helper modules.
3. Configure real OPNsense FreeRADIUS, Accounting, SQLite schema and restricted exporter.
4. Set up SSH key isolation, `authorized_keys` forced commands and host-key pinning.
5. Configure your external HTTPS origin, admin account and private signing key.
6. Provision Docker volumes and Unix socket permissions for separate web/sync/control.
7. First verify **read-only** health, snapshot and login behavior.
8. Enable individual Disconnect controls only after explicit target-by-target
   testing with your own RADIUS clients and switches.

No automatic migration or safety assurance is provided for an untested
network. Never point example CoA/RADIUS controls at production without a
separate change plan and reliable backups.
