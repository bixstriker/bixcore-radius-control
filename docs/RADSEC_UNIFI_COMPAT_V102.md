# UniFi RadSec / DAS compatibility — accepted v1.0.2

**Current as of 21 November 2026:** the targeted
pilot has passed. Earlier failures below were resolved
before the v1.0.2 source/helper release.

## Problem 1 — Accounting Detail source

After switching an AP to RadSec, FreeRADIUS may record
Accounting Detail under the **proxy's source IP directory**
instead of the original AP IP directory, although the RADIUS
NAS-IP-Address attribute still identifies the original AP.

The restricted Disconnect helper now searches only the
explicitly allowlisted original NAS and local proxy source
directories, reads bounded current/previous Detail files,
and requires exact NAS-IP-Address, MAC, SID and a unique
NAS-Identifier. An untrusted requested path is never used.

## Problem 2 — DAS shared secret

The earlier helper derived the AP secret from FreeRADIUS
`clients.conf`. After RadSec migration that source was
obsolete. AP logs recorded a DAS secret mismatch and
dropped the UDP/3799 Disconnect request without ACK.

Under RFC 6614, RADIUS/TLS uses the fixed string
`radsec`, whether or not a TLS-client block explicitly
contains a `Secret` property. The proxy's local backend
UDP `server Secret` is separate and **must not** be used
as the AP DAS secret.

Both UniFi helpers now validate the *exact* RadSec TLS
client name, IP /32, `Type tls` and TLS profile in the
generated local radsecproxy configuration; only then
can they select `radsec` for DAS. This is valid for the
verified deployment because the AP's actual DAS dispatcher
also uses `radsec`. **RFC 6614 does not require every
vendor's UDP DAS implementation to share this value.**

Missing, duplicate, untrusted, incorrectly mapped or
non-TLS client configurations fail closed. No fallback
to old FreeRADIUS clients or to the proxy backend Secret;
no new secret file. Operators must substitute their
own approved AP names/IPs/TLS profile and independently
verify the DAS credential.

## Functional acceptance

On 21 November 2026, an authorized UniFi pilot station
received Disconnect-ACK and targeted PMKSA cleanup,
followed by a new Accounting session. A wired Omada
pilot produced ACK and guarded cleanup after a
matching successor Start; another active switchport
was untouched. A separate UniFi device accepted
EAPOL_REAUTH and had a subsequent Accounting Stop/Start.

A newly associated station's new PMKSA entry is expected.
Do not mistake it for failure to purge the old PMKSA.
EAPOL_REAUTH is an AP control flow independent of the
RadSec DAS secret fix.

## Testing and release boundary

Full suites: 288 tests (287 passed, 1 skipped);
public CI on main passed. This public release is
source/helpers and docs, **not** a Docker-image rollout.
Tests are targeted, not proof of full 802.11r/FT-EAP,
TLS resumption or policy Access-Reject revocation.

[Release](RELEASE_V1.0.2.md) ·
[Configuration](CONFIGURATION.md).

## Earlier incident timeline

The previous sanitized, chronological report remains [in the archive](history/RADSEC_V102_CHRONOLOGICAL_WORKLOG_SANITIZED_2026-11-21.md). Its intermediate pending labels were superseded by acceptance above.
