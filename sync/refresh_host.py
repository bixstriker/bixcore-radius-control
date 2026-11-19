#!/usr/bin/env python3
"""Socket-activated single-purpose systemd bridge for manual RADIUS export.

Input: exactly REFRESH\\n via systemd StandardInput=socket.
Output: one bounded JSON line on StandardOutput=socket.
Never interprets a command, path, parameter, or credential from the client.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

SNAPSHOT = Path("/srv/bixcore-radius-control/private/current.json")
PULL_UNIT = "bixcore-radius-pull.service"
SYSTEMCTL = "/usr/bin/systemctl"

def run_pull(snapshot: Path = SNAPSHOT) -> str:
    before = snapshot.stat().st_mtime_ns if snapshot.is_file() else -1
    proc = subprocess.run(
        [SYSTEMCTL, "start", PULL_UNIT],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        timeout=48, check=False,
    )
    if proc.returncode:
        raise RuntimeError("PULL_SERVICE_FAILED")
    if not snapshot.is_file() or snapshot.stat().st_mtime_ns <= before:
        raise RuntimeError("SNAPSHOT_NOT_UPDATED")
    with snapshot.open(encoding="utf-8") as handle:
        data = json.load(handle)
    as_of = data.get("as_of") if isinstance(data, dict) else None
    if not isinstance(data, dict) or data.get("source") != "sanitized_export" or not isinstance(as_of, str):
        raise RuntimeError("SNAPSHOT_INVALID")
    return as_of

def handle(request: bytes) -> dict:
    if request != b"REFRESH\n":
        return {"ok": False, "error": "BAD_REQUEST"}
    try:
        return {"ok": True, "as_of": run_pull()}
    except (OSError, ValueError, subprocess.TimeoutExpired, RuntimeError) as exc:
        print("BIX_MANUAL_REFRESH error=" + str(exc)[:80], file=sys.stderr)
        return {"ok": False, "error": "REFRESH_FAILED"}

def main() -> None:
    request = sys.stdin.buffer.readline(32)
    # Prevent malformed / oversized / partially sent commands.
    result = handle(request) if os.geteuid() == 0 else {"ok": False, "error": "NOT_ROOT"}
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    sys.stdout.flush()

if __name__ == "__main__":
    main()
