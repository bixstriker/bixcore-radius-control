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
