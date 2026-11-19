#!/usr/bin/env python3
"""Export a sanitized OFFLINE snapshot from a LOCAL SQLite file using read-only SQL.

Do NOT mount live OPNsense SQLite over NFS/SMB. This script is NOT a production
transport mechanism. Future deployment requires a dedicated restricted helper.
No passwords, API keys or NAS shared secrets are read or included.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from urllib.parse import quote

ALLOWED_USER_FIELDS = ("uuid", "username", "enabled", "vlan")
SESSION_COLUMNS = (
    "username", "nasipaddress", "callingstationid", "acctsessionid",
    "acctstarttime", "acctupdatetime", "acctstoptime",
)


def export(db_file: Path, users_file: Path | None, output_file: Path, limit: int) -> int:
    if db_file.resolve() == output_file.resolve():
        raise ValueError("Output cannot overwrite the SQLite source")
    if users_file is None:
        source_users = []
    else:
        with users_file.open(encoding="utf-8") as f:
            source_users = json.load(f)
    if not isinstance(source_users, list):
        raise ValueError("Users input must be a JSON array of sanitized records")
    users = []
    for row in source_users:
        if not isinstance(row, dict) or set(row) - set(ALLOWED_USER_FIELDS) or not row.get("uuid") or not row.get("username"):
            raise ValueError("Each user needs uuid and username")
        # Explicit allowlist of fields; raw API responses must NEVER be used as exports.
        users.append({field: row.get(field) for field in ALLOWED_USER_FIELDS})
    # mode=ro and PRAGMA query_only, no writes to database.
    uri = "file:" + quote(str(db_file.resolve()), safe="/:") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=3)
    try:
        conn.execute("PRAGMA query_only = ON")
        rows = conn.execute(
            "SELECT " + ", ".join(SESSION_COLUMNS) +
            " FROM radacct ORDER BY COALESCE(acctupdatetime,acctstarttime) DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    sessions = [dict(zip(SESSION_COLUMNS, row)) for row in rows]
    output = {
        "source": "sanitized_export",
        "as_of": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "sessions": sessions,
        "local_users": users,
        "users_collected": users_file is not None,
        "portal_sessions": [],
        "portal_collected": False,
    }
    # WARNING: Contains personal device identifiers and session metadata.
    # Parent directory must already exist; atomic replace avoids half-written snapshots.
    from tools.import_snapshot import install_payload
    install_payload((json.dumps(output, ensure_ascii=False) + "\n").encode("utf-8"), output_file)
    return len(sessions)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--db", type=Path, required=True, help="Local SQLite file. NEVER a network share.")
    p.add_argument("--users-json", type=Path,
                   help="Sanitized local users list: uuid, username, enabled, vlan only.")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--limit", type=int, default=5000)
    args = p.parse_args()
    if not 1 <= args.limit <= 50000:
        p.error("--limit must be 1..50000")
    count = export(args.db, args.users_json, args.out, args.limit)
    print(f"Exported {count} sanitized accounting records to {args.out}")


if __name__ == "__main__":
    main()
