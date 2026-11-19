# Security model and release notes

Version: v1.0.1 privacy-sanitized source snapshot.

- All state-changing actions require authenticated operator context and
  purpose-scoped SSH forced commands. Preserve independent authoritative
  checks on OPNsense.
- A Disconnect-ACK must be authenticated; do not retry uncertain operations.
- Omada old Accounting rows are closed only if a single different valid
  successor Start matches NAS / port / MAC / username and the predecessor
  remains unchanged; bounded wait in the original design: 35 seconds.
- No global PMK/FT cache flush is implemented. TLS Session Resumption and
  802.11r behavior depend on your infrastructure.
- Web cookies, CSRF Origin, file permissions, audit DB and private signing
  keys require real deployment review. No application secret is bundled.
- Public source intentionally excludes real operating documentation,
  host-change audit, passwords, SSH private keys, MACs and IPs. Do not
  copy public test fixtures into production authentication databases.
- This snapshot did **not** change a live NAS/OPNsense installation.

Known limitation: this source is adapted from one environment. You must
review every hard-coded example before installation; it is not designed to be
directly pointed at real switches without that review.
