#!/usr/bin/env python3
"""Future read-only pull using preprovisioned, restricted SSH key and forced command.

No root credentials, no API keys, no OPNsense writes. This is NOT configured or
scheduled by default; safe deployment requires verifying the helper's DB ACL.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess

from app.source import MAX_BYTES
from .import_snapshot import install_payload

SAFE_NAME = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")


def pull(host: str, user: str, known_hosts: Path, identity: Path, dest: Path, port: int = 22):
    if not SAFE_NAME.fullmatch(host) or not SAFE_NAME.fullmatch(user) or user.lower() == "root":
        raise ValueError("Invalid host or user")
    if port < 1 or port > 65535:
        raise ValueError("Invalid port")
    if not known_hosts.is_file() or not identity.is_file():
        raise ValueError("Key and pinned known_hosts must already exist")
    command = [
        "ssh", "-T", "-p", str(port),
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ClearAllForwardings=yes",
        "-o", "ConnectTimeout=5",
        "-o", "NumberOfPasswordPrompts=0",
        "-o", "LogLevel=ERROR",
        "-o", "UserKnownHostsFile=" + str(known_hosts.resolve()),
        "-i", str(identity.resolve()),
        user + "@" + host,
        # This string MUST be accepted only by the approved forced-command helper.
        "bixradius-readonly-snapshot-v03",
    ]
    result = subprocess.run(command, capture_output=True, timeout=25, check=False)
    if result.returncode != 0:
        raise RuntimeError("Restricted read-only SSH helper failed")
    if len(result.stdout) > MAX_BYTES:
        raise ValueError("Received oversized export")
    install_payload(result.stdout, dest)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--known-hosts", type=Path, required=True)
    p.add_argument("--identity", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--port", type=int, default=22)
    args = p.parse_args()
    pull(args.host, args.user, args.known_hosts, args.identity, args.out, args.port)
    print("Imported sanitized read-only RadiusGateway snapshot")


if __name__ == "__main__":
    main()
