"""Validate field-limited local snapshots. Never serve raw OPNsense config/API output."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .logic import timestamp

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SNAPSHOT = ROOT / "data" / "demo_snapshot.json"
DEFAULT_ALLOWLIST = ROOT / "data" / "demo_allowlist.json"
MAX_BYTES = 8 * 1024 * 1024
MAX_SESSIONS = 10_000
SESSION_FIELDS = frozenset({"username", "nasipaddress", "callingstationid", "acctsessionid",
                            "acctstarttime", "acctupdatetime", "acctstoptime"})
USER_FIELDS = frozenset({"uuid", "username", "enabled", "vlan"})
PORTAL_FIELDS = frozenset({"sessionId", "zoneid", "userName", "ipAddress", "macAddress",
                           "startTime", "last_accessed", "authenticated_via"})
TOP_FIELDS = frozenset({"source", "as_of", "sessions", "local_users", "portal_sessions",
                        "users_collected", "portal_collected", "note"})


def _read_json(path: Path) -> Any:
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("JSON snapshot too large")
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _text(value: Any, max_length: int = 512) -> bool:
    return isinstance(value, str) and len(value) <= max_length


def validate_snapshot(snap: Any) -> dict[str, Any]:
    """Reject unknown fields everywhere, even if they are nested secrets."""
    if not isinstance(snap, dict) or set(snap) - TOP_FIELDS:
        raise ValueError("Unsupported snapshot fields")
    if snap.get("source") not in ("demo", "sanitized_export"):
        raise ValueError("Unsupported snapshot source")
    if timestamp(snap.get("as_of")) is None:
        raise ValueError("Snapshot timestamp must be timezone-aware")
    if not isinstance(snap.get("sessions"), list) or not isinstance(snap.get("local_users"), list):
        raise ValueError("Expected sessions and local_users lists")
    sessions = snap["sessions"]
    users = snap["local_users"]
    portals = snap.get("portal_sessions", [])
    if not isinstance(portals, list) or len(portals) > 10000:
        raise ValueError("Invalid portal sessions")
    if len(sessions) > MAX_SESSIONS or len(users) > 10000:
        raise ValueError("Too many records")
    for flag in ("users_collected", "portal_collected"):
        if flag in snap and type(snap[flag]) is not bool:
            raise ValueError("Invalid source availability flag")
    if "note" in snap and not _text(snap["note"], 1024):
        raise ValueError("Invalid note")
    for rec in sessions:
        if not isinstance(rec, dict) or set(rec) - SESSION_FIELDS:
            raise ValueError("Session contains unsupported fields")
        if not all(_text(rec.get(k)) for k in ("username", "nasipaddress", "acctsessionid", "callingstationid")):
            raise ValueError("Session identity fields invalid")
        if any(rec.get(k) is not None and (isinstance(rec[k], bool) or not isinstance(rec[k], (int,float,str)))
               for k in ("acctstarttime", "acctupdatetime", "acctstoptime")):
            raise ValueError("Session timestamps invalid")
    for rec in users:
        if not isinstance(rec, dict) or set(rec) - USER_FIELDS:
            raise ValueError("Local user contains unsupported fields")
        if not _text(rec.get("username"),256) or not _text(rec.get("uuid"),128):
            raise ValueError("Local user identity fields invalid")
        if rec.get("enabled") not in (None, True, False, 0, 1, "0", "1"):
            raise ValueError("Local user enabled invalid")
        if rec.get("vlan") is not None and (type(rec["vlan"]) is not int or not 1 <= rec["vlan"] <= 4094):
            raise ValueError("Local user VLAN invalid")
    for rec in portals:
        if not isinstance(rec, dict) or set(rec) - PORTAL_FIELDS:
            raise ValueError("Portal contains unsupported fields")
        if not all(_text(rec.get(k),256) for k in ("sessionId","userName","ipAddress","macAddress","authenticated_via")):
            raise ValueError("Portal identity fields invalid")
        if not isinstance(rec.get("zoneid"), (str, int)) or isinstance(rec.get("zoneid"), bool):
            raise ValueError("Portal zone ID invalid")
        if len(str(rec["zoneid"])) > 12:
            raise ValueError("Portal zone ID too long")
        if any(rec.get(k) is not None and (isinstance(rec[k],bool) or not isinstance(rec[k],(int,float,str)))
               for k in ("startTime","last_accessed")):
            raise ValueError("Portal timestamps invalid")
    return snap


def load_bundle() -> tuple[dict[str, Any], dict[str, Any]]:
    snapshot = validate_snapshot(_read_json(Path(os.getenv("BIX_RADIUS_SNAPSHOT",str(DEFAULT_SNAPSHOT)))))
    allowlist = _read_json(Path(os.getenv("BIX_RADIUS_ALLOWLIST",str(DEFAULT_ALLOWLIST))))
    if not isinstance(allowlist, dict) or set(allowlist) - {"phones","source"}:
        raise ValueError("Invalid legacy allowlist")
    if not isinstance(allowlist.get("phones"),list):
        raise ValueError("Invalid allowlist")
    for row in allowlist["phones"]:
        if not isinstance(row,dict) or set(row) != {"uuid","cn"}:
            raise ValueError("Invalid allowlist item")
    return snapshot, allowlist
