# Contributing to BiXCore RADIUS Control

Thanks for your interest. This is an installation-derived networking project,
so safety and privacy are essential.

## Before sending a pull request

- Open an issue explaining the expected behavior and affected NAS/vendor.
- Use **only synthetic** MAC addresses, identities, RFC 5737 example IP ranges
  and `example.test` hostnames in code, tests and screenshots.
- Never submit secrets, real client certificates, private keys, RADIUS
  `clients.conf`, production SQLite/Accounting data, internal IP inventories,
  service logs or packet captures containing real identifiers.
- Keep disconnect, PMKSA and Accounting write actions disabled by default.
  A verified Disconnect-ACK and matching successor record are required before
  any stale Accounting cleanup.
- Include regression tests and run the full Python suite.
- Follow the existing naming/formatting conventions and describe operational
  risks and rollback behavior in the pull request.

## Test command

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -q
```

## Licensing

By submitting a contribution you agree to license that contribution under
the repository's [MIT License](LICENSE). Do not contribute code that you
cannot license on those terms. Third-party code must retain its original
notices and be reviewed before inclusion.
