"""Read-only, anonymized Omada wired Accounting port preflight.

This report NEVER authorizes Disconnect, edits Accounting, or infers permission
from observed clients. Separate explicit authorization is required for each port.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import time
from pathlib import Path


def inventory(db_path: str, nas_ip: str, *, now: int | None = None,
              window_seconds: int = 604800) -> dict:
    if window_seconds < 1 or window_seconds > 2678400:
        raise ValueError("INVALID_WINDOW")
    if not nas_ip or len(nas_ip) > 64:
        raise ValueError("INVALID_NAS")
    cutoff = int(time.time() if now is None else now) - window_seconds
    path = Path(db_path).resolve(strict=True)
    if not path.is_file():
        raise ValueError("NOT_A_DATABASE_FILE")
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=3)
    try:
        db.execute("PRAGMA query_only=ON")
        rows = db.execute("""
            SELECT nasportid,
                   COUNT(*) AS records,
                   SUM(CASE WHEN acctstoptime IS NULL THEN 1 ELSE 0 END) AS open_rows,
                   COUNT(DISTINCT lower(replace(replace(replace(
                     callingstationid, '-', ''), ':', ''), '.', ''))) AS clients,
                   COUNT(DISTINCT username) AS identities,
                   SUM(CASE WHEN acctstoptime IS NULL
                       AND COALESCE(acctupdatetime,acctstarttime)>=? THEN 1 ELSE 0 END)
                     AS fresh_open
            FROM radacct
            WHERE nasipaddress=? AND acctstarttime>=?
            GROUP BY nasportid ORDER BY nasportid
        """, (cutoff, nas_ip, cutoff)).fetchall()
    finally:
        db.close()
    return {"nas_ip": nas_ip, "window_seconds": window_seconds,
            "authorization": "none; observation is not permission",
            "ports": [{"port_id": str(r[0] or ""), "records": int(r[1]),
                       "open_rows": int(r[2] or 0), "distinct_macs": int(r[3]),
                       "distinct_users": int(r[4]), "fresh_open": int(r[5] or 0),
                       "decision": "manual_review_required"} for r in rows]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True)
    parser.add_argument("--nas", default="192.0.2.6")
    parser.add_argument("--days", type=int, default=7)
    args = parser.parse_args()
    print(json.dumps(inventory(args.db, args.nas,
                               window_seconds=args.days * 86400),
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
