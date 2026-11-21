# BiXCore RADIUS Control — public changelog

## v1.0.2 (2026-11-21): accepted RadSec UniFi helper maintenance

- UniFi Disconnect reads permitted RadSecProxy-source Accounting
  Detail directories with exact original NAS, SID, MAC and unique
  NAS-Identifier validation.
- Both UniFi DAS helpers resolve the exact RadSec TLS client
  and TLS profile before selecting the fixed RFC 6614 value.
  Backend UDP Secret and legacy FreeRADIUS clients.conf
  are explicitly excluded.
- Targeted live acceptance: UniFi Disconnect ACK/PMKSA,
  Omada wired ACK/guarded cleanup, UniFi EAPOL_REAUTH
  with successor Accounting sessions.
- Full suites: 288 tests (287 pass, 1 skipped), successful CI.
- Source/helper release only; no newly deployed Docker image.

## Previous releases

v1.0.1-public.1/.2/.3: prior sanitized v1.0.1 web/control/
sync baseline, layout, authentication and release audit.
The prior detailed chronological changelog remains
available in Git history.

[Public v1.0.2 release](docs/RELEASE_V1.0.2.md).
