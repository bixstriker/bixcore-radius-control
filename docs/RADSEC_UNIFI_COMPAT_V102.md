# Final acceptance update — 2026-11-21

Pilot v1.0.2 compatible UniFi DAS helper changes have passed live
Disconnect-ACK/PMKSA and EAPOL_REAUTH tests. Omada wired pilot also
passed ACK+Accounting cleanup. The earlier "unresolved", "pending",
"candidate" statements below are **historical observations**,
not the latest acceptance result. See
[release v1.0.2](RELEASE_V1.0.2.md).


---

# UniFi RadSec compatibility — v1.0.2 candidate (not released)

This change lets the restricted UniFi Disconnect helper find NAS-Identifier
in both **direct UDP** and **locally terminated RadSec** Accounting Detail.
No reliance on an arbitrary packet-source directory, a whole-tree search, or
unsafe fallback to an unverified identifier.

- Static allowlist of source NAS IP and local RadSecProxy backend IP
  (public example addresses: 192.0.2.4, 192.0.2.5, 192.0.2.1).
- Exact NAS-IP-Address, Acct-Session-Id and Calling-Station-Id matching.
- Require one unambiguous valid NAS-Identifier; different identifiers
  fail closed, as do missing data, malformed identities and symlink paths.
- Read bounded current/prior-day file tails (max 8 MiB/file).
- Preexisting read-only SQL session/freshness/roaming validation
  and exact DAS UDP/3799 + authenticated ACK checks stay unchanged.
- No change to UniFi EAPOL_REAUTH, PMKSA helper, Omada wired helper,
  LDAP, client EAP-TLS, certificates or RADIUS listener configuration.

The public integration is **source only**, with synthetic NAS identifiers
and no private host inventory. Operators must review and adapt backend proxy
address, NAS mapping and secrets to their own installation.

Testing: 15 new synthetic unit tests; private code base has 273 tests total
(272 pass, one skipped). Live read-only accounting lookup verified on
a private installation; full real-world Disconnect and PMKSA acceptance
**not yet completed**. This is a review branch, **not v1.0.2 stable**.

## Field acceptance finding (21 November 2026; unresolved)

A controlled user-triggered Disconnect at a RadSec-enabled UniFi access point
reached its UDP/3799 listener. The AP-side DAS dispatcher logged a **shared-secret
mismatch**, dropped the request, and returned no ACK. The current helper reads its
per-AP DAS secret from the RADIUS client definitions, which may no longer match
separately provisioned DAS credentials after RadSec migration. No active secret
was modified. This finding is independent of the fixed Accounting Detail path.

Required next step: compare the DAS secret provisioned on each AP against the
respective server-side source without disclosing it, then design a dedicated
restricted per-AP DAS secret source. Do not infer the DAS secret from the RadSec
transport secret, accept unknown senders, disable authentication, or automatically
retry a failed Disconnect. PMKSA uses the same legacy secret source and must be
validated independently. This remains an **unreleased candidate**.

## DAS secret selection from local radsecproxy configuration (candidate)

On a production-style TLS deployment, the fixed RADIUS/TLS shared-secret
value `radsec` is defined by RFC 6614. It need **not** be explicitly present
in a TLS client section; the radsecproxy `server` UDP backend `Secret` is a
*different credential* and is not used for DAS.

The UniFi Disconnect and targeted PMKSA helpers now verify that their exact
allowlisted client name and /32 source IP appear as `Type tls`, with the
expected named TLS profile, in the local generated radsecproxy configuration.
Only then do they select the standard `radsec` value for UniFi DAS.
This mirrors the particular UniFi provisioning where the access point
uses `radsec` for the UDP/3799 DAS dispatcher as well. It is **not** a
general rule that every RadSec device uses the same DAS secret.

The check rejects a missing or duplicate client, changed transport, wrong
IP, wrong TLS profile, non-root-owned or writable configuration file (on
POSIX), oversized file, or symlink. No fallback to FreeRADIUS
`clients.conf` or the proxy's backend `Secret`, and no new secret file.
Configuration names and example addresses in this public sample must be
adapted by each operator. The previously supported direct-UDP Accounting
Detail lookup remains, but this resolver requires an explicitly configured
RadSec TLS client for DAS operations. A direct-UDP-only deployment needs
a separate, reviewed credential source.

15 additional mocked tests added. Full suite: 288 tests, one skipped.
A private candidate installation was source-hash verified, but live
Disconnect-ACK and PMKSA acceptance remain **pending**. No stable v1.0.2
release is implied by this review branch.

## Field acceptance: three control operations (2026-11-21)

- UniFi active station: guarded Disconnect returned authenticated ACK;
  per-station PMKSA cleanup returned complete; old accounting row
  closed and successor session started. A new PMKSA entry for the
  newly authenticated connection is expected and was observed.
- Omada wired pilot port: authenticated Disconnect-ACK, controlled
  close of previous accounting row and successor Start. Protected
  independent wired client was unaffected.
- UniFi EAPOL_REAUTH: AP command accepted, prior Accounting-Stop
  and new Accounting-Start observed; two APs scanned afterward,
  unique authorized association confirmed. This flow is independent
  of the RadSec UDP/3799 DAS secret resolver.

These results substantiate the targeted pilot acceptance, not a blanket
claim about all clients, FT-EAP cache invalidation or TLS resumption.
Both review branches still require deliberate release/merge management.
