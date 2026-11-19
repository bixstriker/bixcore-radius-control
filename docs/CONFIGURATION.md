# Architecture and configuration

This is an **example**. All `192.0.2.x` addresses, `example.test` names,
MACs beginning with `02:00:00` and the `/srv/bixcore-radius-control` path are
synthetic placeholders for documentation and unit tests.

## Data path

FreeRADIUS/OPNsense -> restricted, read-only exporter -> sync worker ->
JSON snapshot -> web UI. Actions travel from authenticated UI -> constrained
control worker / SSH forced command -> specific network access server.
Only the server-side helper decides whether a requested target still matches
the authoritative Accounting record.

## Adaptation checklist

1. Choose your real NAS, OPNsense, AP and switch addresses. Update the
   installation-specific constants in `app/logic.py`,
   `app/unifi_workflow.py`, `app/omada_wired.py`, `sync/` and the
   `deploy/opnsense/` helpers. Audit `app/main.py` for allowed NAS lists.
2. Set `BIX_CONTROL_ORIGIN` to the exact HTTPS origin for CSRF protection.
   The included `https://radius.example.test` is not reachable.
3. Create SSH key pairs on your administrator host and set restrictive
   `authorized_keys` command/from/restrict options on OPNsense. Pin host keys.
4. Create secret files with host owner-only permissions, outside this repo.
5. Configure FreeRADIUS client definitions, CoA shared secrets, EAP-TLS/LDAP
   policies, VLAN mappings, OPNsense restricted helpers and NAS port IDs.
6. Provision the Docker runtime root (default example:
   `/srv/bixcore-radius-control`), exact UID/GID file ownerships, sockets,
   audit store and snapshot directories. Prefer separate web, sync and
   control services; do not expose workers to the internet.
7. Confirm `docker compose -f compose.v1.0.1.release.yaml config --quiet`
   **with a complete local runtime and selected environment**, then test
   authentication and read-only snapshot first.
8. Activate dangerous controls only after authorized live tests of exact
   target matching and authenticated ACK; Omada flag defaults OFF.

## Rollback and upgrade

Record image SHA-256, activated Compose and secret-file permissions before
every upgrade. For a UI-only change, recreate only the web container;
preserve the audit and FreeRADIUS SQLite DB. Never restore a stale Accounting
database merely to roll back a code release.

## Scope limitations

This release is the generalizable source of a specific installation. It does
not ship a default OPNsense plugin or automated installer, and network-specific
addresses are still defaults in some modules. Adaptation is required.
