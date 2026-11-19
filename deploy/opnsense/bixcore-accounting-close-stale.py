#!/usr/local/bin/python3.13
"""Close one stale, unended FreeRADIUS SQL Accounting record; not a Wi-Fi Disconnect.

Invoked only by an OPNsense SSH forced-command key. The exact snapshot identity
and both Accounting timestamps must still match the live SQLite row. Fresh,
already ended, changed, ambiguous or too recent records are never modified.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time

DATABASE = "/usr/local/etc/raddb/freeradius.db"
STALE_AFTER_SECONDS = 15 * 60
MAX_REQUEST_BYTES = 2048
VALID_NAS = frozenset({"192.0.2.4", "192.0.2.5", "192.0.2.6"})
SID_PATTERN = re.compile(r"[A-Za-z0-9._:@/+=-]{1,64}\Z")
MAC_PATTERN = re.compile(r"[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\Z")
USER_PATTERN = re.compile(r"[A-Za-z0-9._:/@+-]{1,128}\Z")
TERM_CAUSE = "Admin-Stale-Cleanup"


class StaleCloseError(Exception):
    """A safe, bounded failure with no internal details sent to the browser."""


def validate(payload: dict) -> dict:
    if not isinstance(payload, dict) or set(payload) != {
        "nas_ip", "session_id", "mac", "username", "started", "updated"
    }:
        raise StaleCloseError("INVALID_REQUEST")
    if payload["nas_ip"] not in VALID_NAS:
        raise StaleCloseError("NAS_NOT_ALLOWED")
    for key, pattern in (
        ("session_id", SID_PATTERN),
        ("mac", MAC_PATTERN),
        ("username", USER_PATTERN),
    ):
        if not isinstance(payload[key], str) or not pattern.fullmatch(payload[key]):
            raise StaleCloseError("INVALID_IDENTITY")
    for key in ("started", "updated"):
        value = payload[key]
        if type(value) is not int or not 1_600_000_000 < value < 4_000_000_000:
            raise StaleCloseError("INVALID_TIMESTAMP")
    if payload["started"] > payload["updated"]:
        raise StaleCloseError("INVALID_TIMESTAMP")
    return payload


def close_stale(payload: dict, *, db_path: str = DATABASE, now: int | None = None) -> dict:
    body = validate(payload)
    current_time = int(time.time()) if now is None else int(now)
    if not (STALE_AFTER_SECONDS <= current_time - body["updated"] <= 60 * 60 * 24 * 60):
        raise StaleCloseError("SESSION_NOT_STALE")
    # BEGIN IMMEDIATE ensures the row checked here is the row subsequently
    # changed: concurrent FreeRADIUS interim updates cannot slip in between.
    db = sqlite3.connect(db_path, timeout=3, isolation_level=None)
    try:
        db.execute("PRAGMA busy_timeout=3000")
        db.execute("BEGIN IMMEDIATE")
        matching = db.execute(
            """SELECT radacctid FROM radacct
               WHERE nasipaddress=? AND acctsessionid=? AND callingstationid=?
                 AND username=? AND acctstarttime=? AND acctupdatetime=?
                 AND acctstoptime IS NULL LIMIT 2""",
            (body["nas_ip"], body["session_id"], body["mac"], body["username"],
             body["started"], body["updated"]),
        ).fetchall()
        if len(matching) != 1:
            raise StaleCloseError("SESSION_CHANGED_OR_AMBIGUOUS")
        cursor = db.execute(
            """UPDATE radacct
               SET acctstoptime=?, acctterminatecause=?
               WHERE radacctid=? AND acctstoptime IS NULL AND acctupdatetime=?""",
            (body["updated"], TERM_CAUSE, matching[0][0], body["updated"]),
        )
        if cursor.rowcount != 1:
            raise StaleCloseError("SESSION_CHANGED")
        db.execute("COMMIT")
        return {"ok": True, "result": "closed", "closed_at": body["updated"]}
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    finally:
        db.close()


def main() -> int:
    # Reject arbitrary executions: only the exact authorized_keys SSH command.
    original = os.environ.get("SSH_ORIGINAL_COMMAND")
    if os.geteuid() != 0 or original != "bixcore-accounting-close-stale":
        print(json.dumps({"ok": False, "reason": "NOT_AUTHORIZED"}))
        return 1
    raw = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
        print(json.dumps({"ok": False, "reason": "BAD_REQUEST"}))
        return 1
    if sys.stdin.buffer.read(1):
        print(json.dumps({"ok": False, "reason": "BAD_REQUEST"}))
        return 1
    try:
        body = json.loads(raw)
        if body == {"probe": True}:
            print(json.dumps({"ok": True, "result": "probe"}))
            return 0
        result = close_stale(body)
    except (StaleCloseError, ValueError, TypeError) as error:
        result = {"ok": False, "reason": str(error)[:64]}
    except (OSError, sqlite3.Error):
        result = {"ok": False, "reason": "STORAGE_UNAVAILABLE"}
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
