#!/usr/bin/env python3
"""One-way, read-only, sanitized RADIUS snapshot pull for NAS.
No passwords or arbitrary OPNsense commands; validates before atomic replace.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ROOT = Path(os.environ.get("BIX_SYNC_ROOT", "/srv/bixcore-radius-control"))
KEYS = Path(os.environ.get("BIX_SYNC_KEYS_DIR", str(ROOT / "keys")))
PRIVATE = Path(os.environ.get("BIX_SYNC_PRIVATE_DIR", str(ROOT / "private")))
TARGET = PRIVATE / "current.json"
MAX_BYTES = 8 * 1024 * 1024

def main() -> int:
    if os.geteuid() != 0 and not (
        os.environ.get("BIX_SYNC_CONTAINER") == "1" and os.geteuid() == 10002
    ):
        raise RuntimeError("run as the designated collector identity")
    sys.path.insert(0, str(ROOT))
    from app.source import validate_snapshot
    from app.logic import timestamp
    cmd = [
        "/usr/bin/ssh",
        "-F", "/dev/null",
        "-i", str(KEYS / "pull_ed25519"),
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + str(KEYS / "known_hosts"),
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=8",
        "-o", "ConnectionAttempts=1",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=2",
        "-o", "LogLevel=ERROR",
        "-T", "root@192.0.2.1",
        "radius-readonly-export"
    ]
    # Force-command key ignores the requested command; it always executes the exporter.
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=False, timeout=35)
    except subprocess.TimeoutExpired:
        raise RuntimeError("OPNsense read-only SSH timed out")
    if proc.returncode != 0:
        raise RuntimeError("OPNsense read-only SSH returned " + str(proc.returncode)
                           + ": " + proc.stderr.decode("utf-8", "replace")[:150])
    if len(proc.stdout) > MAX_BYTES:
        raise RuntimeError("Snapshot exceeded 8 MiB safety limit")
    try:
        snap = validate_snapshot(json.loads(proc.stdout.decode("utf-8")))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise RuntimeError("Incoming snapshot failed strict schema validation") from exc
    if snap["source"] != "sanitized_export":
        raise RuntimeError("Unexpected snapshot source")
    if snap.get("users_collected") is not True or snap.get("portal_collected") is not True:
        raise RuntimeError("Missing users/portal data; retaining last valid snapshot")
    when = timestamp(snap["as_of"])
    age = (datetime.now(timezone.utc) - when).total_seconds()
    if age < -120 or age > 180:
        raise RuntimeError("Exporter timestamp out of sync")
    if TARGET.exists():
        try:
            current = json.loads(TARGET.read_text(encoding="utf-8"))
            previous = timestamp(current.get("as_of"))
            if previous is not None and when < previous:
                raise RuntimeError("Older snapshot received; refusing rollback")
        except (json.JSONDecodeError, UnicodeError):
            # Existing invalid file is replaced only with a valid new snapshot.
            pass
    if not PRIVATE.is_dir() or PRIVATE.is_symlink():
        raise RuntimeError("Private snapshot directory missing or unsafe")
    fd, temp_path = tempfile.mkstemp(prefix=".current-", suffix=".tmp", dir=str(PRIVATE))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(proc.stdout)
            f.flush()
            os.fsync(f.fileno())
        if os.environ.get("BIX_SYNC_CONTAINER") == "1":
            # Non-root sync UID 10002, shared snapshot group 10005. Web gets read-only mount.
            os.chmod(temp_path, 0o440)
        else:
            os.chown(temp_path, 10001, 10001)
            os.chmod(temp_path, 0o400)
        os.replace(temp_path, TARGET)
        dfd = os.open(str(PRIVATE), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    print("SYNC_OK age_seconds={} accounting={} users={} captive_portal={}".format(
        round(age), len(snap["sessions"]), len(snap["local_users"]), len(snap["portal_sessions"])))
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("SYNC_FAILED: " + str(exc)[:230], file=sys.stderr)
        sys.exit(1)
