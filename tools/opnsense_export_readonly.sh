#!/bin/sh
# Future root-owned forced command, NOT INSTALLED on RadiusGateway.
# Does not alter OPNsense state. Execute only after independent security review.
set -eu
umask 077
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1
unset PYTHONPATH PYTHONHOME
# Script must be root-owned, not writable by SSH principal, and deployed at
# approved path. The read-only exporter projects only safe fields to stdout.
exec /usr/local/bin/python3 -B /usr/local/libexec/bixradius/export_opnsense_snapshot.py
