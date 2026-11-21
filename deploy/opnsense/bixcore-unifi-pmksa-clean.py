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


# RadSec TLS profiles carry the RFC 6614 fixed RADIUS shared secret.
# UniFi also provisions this same value as DAS secret on this installation.
# Only trust the exact configured UniFi TLS client, never FreeRADIUS clients.conf
# or the backend UDP server Secret in radsecproxy.
RADSEC_CONFIG=Path("/usr/local/etc/radsecproxy.conf")
RADSEC_CLIENTS={"192.0.2.4":"UniFi_AP1","192.0.2.5":"UniFi_AP2"}
TLS_PROFILE="example_radsec_tls"

def secret_for(nas):
    if nas not in NAS or nas not in RADSEC_CLIENTS:
        raise ValueError("INVALID_NAS")
    path=RADSEC_CONFIG
    if path.is_symlink():
        raise ValueError("RADSEC_CONFIG_UNTRUSTED")
    st=path.stat()
    if not path.is_file() or (os.name=="posix" and (st.st_uid!=0 or st.st_mode & 0o022)) or st.st_size>65536:
        raise ValueError("RADSEC_CONFIG_UNTRUSTED")
    text=path.read_text(encoding="utf-8")
    # radsecproxy syntax: client NAME { ... }; comments and directives
    # are line-oriented. No name, IP, type or TLS-profile fallbacks.
    blocks=re.findall(r"(?ms)^\s*client\s+([A-Za-z0-9_-]+)\s*\{([^{}]*)^\s*\}",text)
    wanted=RADSEC_CLIENTS[nas]
    found=[body for name,body in blocks if name==wanted]
    if len(found)!=1:
        raise ValueError("RADSEC_CLIENT_MISSING_OR_AMBIGUOUS")
    def values(body, key):
        found_values=[]
        for line in body.splitlines():
            line=line.strip()
            if not line or line.startswith("#"):
                continue
            match=re.fullmatch(r"([A-Za-z]+)\s+([^#\s]+)\s*(?:#.*)?",line)
            if match and match.group(1).lower()==key.lower():
                found_values.append(match.group(2).strip().strip(chr(34)+chr(39)))
        return found_values
    attrs={k:values(found[0],k) for k in ("Host","Type","Tls","Secret")}
    if (attrs["Host"]!=[nas+"/32"] or
        [x.lower() for x in attrs["Type"]]!=["tls"] or
        attrs["Tls"]!=[TLS_PROFILE] or attrs["Secret"]):
        raise ValueError("RADSEC_CLIENT_CONFIG_MISMATCH")
    profiles=re.findall(r"(?ms)^\s*tls\s+([A-Za-z0-9_-]+)\s*\{([^{}]*)^\s*\}",text)
    if len([x for x,_ in profiles if x==TLS_PROFILE])!=1:
        raise ValueError("RADSEC_TLS_PROFILE_MISSING")
    return "radsec"  # RFC 6614 section 2.3: TLS shared secret


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
