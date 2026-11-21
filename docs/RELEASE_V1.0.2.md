# Public v1.0.2 — accepted RadSec UniFi DAS maintenance, 2026-11-21

This public release contains sanitized **source, deployment helpers,
tests and documentation**. It is not a Docker 1.0.2 image release.
No direct credentials, real site IPs, hostnames, private keys or
customer session identifiers are published.

## Changes

- Verified exact local radsecproxy TLS client block, host /32 and TLS
  profile for each allowlisted AP before selecting the fixed
  `radsec` RADIUS/TLS value. The UniFi AP's actual DAS dispatcher
  in the pilot is also configured for this value; RFC 6614 by itself
  does not mandate using the same value for UDP DAS.
- Restricted UniFi Disconnect reads Accounting Detail from both direct
  NAS sender and local RadSec proxy sender, with original NAS IP,
  SID, MAC and unique identifier validation.
- Targeted PMKSA helper reads the same verified secret source.
- No broad PMKSA wipe, no automatic destructive retry, no changed
  RADIUS/802.1X, EAP-TLS or certificate policy.

## Tests and acceptance

- 288 tests (287 passed, 1 skipped), and public CI passing.
- A real UniFi active station produced verified Disconnect-ACK
  and PMKSA cleanup; a replacement Accounting session followed.
- A real wired Omada pilot port produced ACK and guarded old
  Accounting closure after a successor Start.
- A distinct UniFi device completed EAPOL_REAUTH with
  subsequent Accounting Stop and new Start.
- This is targeted functional evidence, not exhaustive FT-EAP or
  TLS-resumption revocation verification.

## Operator requirements and deployment boundary

Sanitized template AP IPs and client names MUST be customized for
each installation. Fixed RadSec `radsec` value can only serve as
a UniFi DAS secret where the AP is independently provisioned to
accept it. Protect generated radsecproxy.conf with root ownership
and non-writable permissions. Do not use the proxy backend UDP
`Secret` directives as AP DAS secrets. No separate config secret
was added to this example. Previous `clients.conf` lookup
is retired for the RadSec DAS helpers.

The private installed NAS still runs web `1.0.1-web`,
control `0.10.9.1-worker`, sync `0.10.4-worker`;
only the restricted OPNsense UniFi helpers were updated.
No `1.0.2-web` Docker image is claimed.
