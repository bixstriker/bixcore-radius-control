#!/usr/local/bin/python3.13
"""Dedicated forced SSH command: one NAS/BSS/MAC-scoped offline PMKSA DAS.

No arbitrary shell, no AP SSH, no blanket PMKSA_FLUSH, no EAP policy edits.
Exact identity must exist in FreeRADIUS accounting. A recently online
station causes a fail-closed refusal. Caller must independently verify
AP's particular PMKID disappeared after the Disconnect-ACK.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import os
import sqlite3
import subprocess
import sys
import tempfile
import time

NAS = {"192.0.2.4": "UniFi1", "192.0.2.5": "UniFi2"}
DB = "/usr/local/etc/raddb/freeradius.db"
CLIENTS = "/usr/local/etc/raddb/clients.conf"
MAC = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}\Z")
BSSID = MAC
SID = re.compile(r"[A-Za-z0-9._:@/+=-]{1,64}\Z")
USER = re.compile(r"[A-Za-z0-9._@:/+-]{1,128}\Z")
PMKID = re.compile(r"[0-9a-f]{32}\Z")


class Rejected(Exception):
    pass


def normalized(value: object) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def validate(data: object) -> dict:
    if not isinstance(data, dict) or set(data) != {
        "op", "nas_ip", "source_nas", "session_id", "username",
        "mac", "bssid", "pmkid",
    } or data["op"] != "cache_pmk":
        raise Rejected("INVALID_REQUEST")
    if data["nas_ip"] not in NAS or data["source_nas"] not in NAS:
        raise Rejected("INVALID_NAS")
    if not isinstance(data["mac"], str) or not MAC.fullmatch(data["mac"]):
        raise Rejected("INVALID_MAC")
    if not isinstance(data["bssid"], str) or not BSSID.fullmatch(data["bssid"]):
        raise Rejected("INVALID_BSSID")
    if not isinstance(data["pmkid"], str) or not PMKID.fullmatch(data["pmkid"]):
        raise Rejected("INVALID_PMKID")
    if not isinstance(data["session_id"], str) or not SID.fullmatch(data["session_id"]):
        raise Rejected("INVALID_SESSION_ID")
    if not isinstance(data["username"], str) or not USER.fullmatch(data["username"]):
        raise Rejected("INVALID_USERNAME")
    if data["username"].lower().startswith("host/LAB-DC0"):
        raise Rejected("PROTECTED_IDENTITY")
    return data


def verify_identity(conn: sqlite3.Connection, data: dict, now: int) -> str:
    """Read-only SQL guard linking client MAC+identity to both selected BSS and source session."""
    rows = conn.execute(
        """SELECT callingstationid,acctupdatetime FROM radacct
           WHERE nasipaddress=? AND acctsessionid=? AND username=?""",
        (data["source_nas"], data["session_id"], data["username"]),
    ).fetchall()
    src = [r for r in rows if normalized(r[0]) == normalized(data["mac"])
           and r[1] is not None and -120 <= now - int(r[1]) < 30 * 86400]
    if len(src) != 1:
        raise Rejected("SOURCE_SESSION_NOT_PROVEN")
    # The BSSID must have actually appeared in live RADIUS Accounting on
    # this target NAS under the *BiX* SSID in the last 30 days.
    # PMKSA can be pushed to another BSS, even if this MAC never
    # authenticated there; do NOT require the target BSSID to belong to
    # this MAC's historic accounting row.
    bss = conn.execute(
        """SELECT DISTINCT calledstationid FROM radacct
           WHERE nasipaddress=? AND acctupdatetime>=?""",
        (data["nas_ip"], now - 30 * 86400),
    ).fetchall()
    target = normalized(data["bssid"])
    allowed = set()
    for (called,) in bss:
        if not isinstance(called, str) or not called.endswith(":BiX"):
            continue
        raw = called[:-4]  # strip the exact :BiX suffix; BSSID itself may contain colons
        if len(normalized(raw)) == 12:
            allowed.add(normalized(raw))
    if target not in allowed:
        raise Rejected("TARGET_BSSID_NOT_IN_ACCOUNTING")
    # A client may reconnect between an AP scan and the DAS request.
    recent = conn.execute(
        """SELECT callingstationid FROM radacct
           WHERE nasipaddress IN ('192.0.2.4','192.0.2.5')
             AND acctstoptime IS NULL AND acctupdatetime >= ?""",
        (now - 180,),
    ).fetchall()
    if any(normalized(row[0]) == normalized(data["mac"]) for row in recent):
        raise Rejected("CLIENT_RECENTLY_ONLINE")
    return src[0][0]


def secret_for(nas: str) -> str:
    text = Path(CLIENTS).read_text(encoding="utf8")
    name = NAS[nas]
    matches = re.findall(
        r'(?ms)^\s*client\s+["\']?' + re.escape(name) + r'["\']?\s*\{(.*?)^\s*\}',
        text,
    )
    if len(matches) != 1:
        raise Rejected("NAS_CLIENT_MISSING")
    secret = re.search(r"(?m)^\s*secret\s*=\s*(\S(?:.*\S)?)\s*$", matches[0])
    if not secret:
        raise Rejected("NAS_SECRET_MISSING")
    value = secret.group(1).split(" #", 1)[0].strip().strip("\"'")
    if not value:
        raise Rejected("NAS_SECRET_MISSING")
    return value


def execute(data: dict, *, db_path: str = DB, now: int | None = None,
            send=None) -> dict:
    body = validate(data)
    moment = int(time.time()) if now is None else now
    db = sqlite3.connect("file:" + db_path + "?mode=ro", uri=True, timeout=4)
    try:
        db.execute("PRAGMA query_only=ON")
        mac_accounting = verify_identity(db, body, moment)
    finally:
        db.close()
    # Use exact Calling-Station-Id spelling from Accounting, not a guessed
    # representation of the MAC.
    attrs = (
        'NAS-Identifier = "' + normalized(body["bssid"]) + '"\n'
        + 'NAS-IP-Address = ' + body["nas_ip"] + '\n'
        + 'Calling-Station-Id = "' + mac_accounting + '"\n'
        + 'Message-Authenticator = 0x00\n'
    )
    if send is not None:
        return send(body["nas_ip"], attrs)
    secret = secret_for(body["nas_ip"])
    fd, tmp = tempfile.mkstemp(prefix="bixcore-pmksa-", dir="/tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf8") as f:
            f.write(secret + "\n")
        result = subprocess.run(
            ["/usr/local/bin/radclient", "-x", "-t", "3", "-r", "1",
             "-S", tmp, body["nas_ip"] + ":3799", "disconnect"],
            input=attrs, text=True, capture_output=True, timeout=10,
        )
        feedback = (result.stdout or "") + "\n" + (result.stderr or "")
        if "Disconnect-ACK" in feedback:
            return {"ok": True, "result": "ack"}
        if "Disconnect-NAK" in feedback:
            return {"ok": False, "reason": "AP_DISCONNECT_NAK"}
        return {"ok": False, "reason": "NO_ACK"}
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def main() -> int:
    try:
        if os.geteuid() != 0 or os.environ.get("SSH_ORIGINAL_COMMAND") != "bixcore-unifi-pmksa-clean":
            raise Rejected("UNAUTHORIZED_EXECUTION")
        raw = sys.stdin.buffer.readline(2049)
        if not raw or len(raw) > 2048 or not raw.endswith(b"\n") or sys.stdin.buffer.read(1):
            raise Rejected("INVALID_REQUEST")
        body = json.loads(raw)
        if body == {"probe": True}:
            output = {"ok": True, "result": "probe"}
        else:
            output = execute(body)
    except (Rejected, ValueError, TypeError) as exc:
        output = {"ok": False, "reason": str(exc)[:80]}
    except (OSError, sqlite3.Error, subprocess.TimeoutExpired):
        output = {"ok": False, "reason": "SOURCE_OR_TRANSPORT_FAILURE"}
    print(json.dumps(output, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
