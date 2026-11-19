#!/usr/bin/env python3
"""Validate and atomically install a SANITIZED snapshot into a local private file.

This does not connect to OPNsense. An operator must supply sanitized JSON.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import tempfile

from app.logic import timestamp
from app.source import MAX_BYTES, validate_snapshot


def install(source_file: Path, dest: Path) -> None:
    if source_file.stat().st_size > MAX_BYTES:
        raise ValueError("Export exceeds maximum size")
    payload = source_file.read_bytes()
    install_payload(payload, dest)


def install_payload(payload: bytes, dest: Path) -> None:
    if len(payload) > MAX_BYTES:
        raise ValueError("Export exceeds maximum size")
    if dest.is_symlink():
        raise ValueError("Destination must not be a symlink")
    snap = validate_snapshot(json.loads(payload.decode("utf-8")))
    if snap["source"] != "sanitized_export":
        raise ValueError("Only sanitized_export can be imported")
    as_of = timestamp(snap["as_of"])
    if as_of > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise ValueError("Snapshot clock is in the future")
    if not dest.parent.is_dir():
        raise ValueError("Destination directory must already exist")
    data = (json.dumps(snap, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    fd, stage = tempfile.mkstemp(prefix=".snapshot-", suffix=".json", dir=dest.parent)
    try:
        os.chmod(stage, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(stage, dest)
    finally:
        if os.path.exists(stage):
            os.unlink(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Sanitized JSON export, not raw API response")
    parser.add_argument("--out", type=Path, required=True, help="Private output path (parent directory must exist)")
    args = parser.parse_args()
    install(args.input, args.out)
    print("Snapshot validated and atomically installed")


if __name__ == "__main__":
    main()
