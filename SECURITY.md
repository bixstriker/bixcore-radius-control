# Security policy

## Scope

BiXCore RADIUS Control v1.0.1 public source is a privacy-sanitized distribution,
**not** a hardened automatic installer for arbitrary networks. The default
addresses and identity names are examples. Production deployment requires
independent OPNsense, NAS, HTTPS, SSH and RADIUS security review.

## Reporting vulnerabilities

Please **do not publish** credentials, working exploit details, secret keys
or network-identifying packet captures in GitHub issues.

Use GitHub's **Private vulnerability reporting** for this repository if it is
enabled (Security tab → Report a vulnerability). If it is unavailable,
open a public issue containing *no exploit detail or confidential data* to
request a private reporting channel.

Maintainers do not guarantee an SLA. Critical issues in third-party components
must also be reported to their upstream maintainers.

## Key controls

- Administrator authentication with secure cookies and CSRF Origin checking.
- Dedicated, constrained executor keys and forced-command authorization.
- Exact NAS/session/MAC/port validation and fail-closed behavior.
- Never automatically retry an ambiguous RADIUS Disconnect.
- Only close old Accounting after authenticated ACK and verified successor Start.
- No mass PMKSA or global FT cache flush in production.
- Keep the runtime state and TLS signing keys outside the repository.
- Do not expose the demo service beyond localhost.
