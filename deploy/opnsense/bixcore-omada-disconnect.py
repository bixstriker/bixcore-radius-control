#!/usr/local/bin/python3.13
"""Single-purpose Omada wired RADIUS Disconnect, constrained to the BiX pilot.

Designed for an OPNsense root-owned forced-command SSH key. No shell, MAC
wildcards, configurable targets or unverified success states are exposed.
No production installation is performed by this source file alone.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import stat
import struct
import sys
import time

NAS_IP = "192.0.2.6"
SOURCE_IP = "192.0.2.1"
COA_PORT = 3799
PILOT_PORT = 2
PILOT_MAC = "020000000010"
PILOT_USERNAME = "host/LAB-WORKSTATION.ad.example.test"
DB = "/usr/local/etc/raddb/freeradius.db"
SECRET = "/usr/local/etc/bixcore/secrets/omada-coa.key"
LOCK = "/var/run/bixcore-omada-disconnect.lock"
SID = re.compile(r"[0-9A-Fa-f]{8}\Z")
MAC = re.compile(r"[0-9a-f]{12}\Z")
COOLDOWN_SECONDS = 45
FRESH_SECONDS = 650
CLEANUP_WAIT_SECONDS = 35
CLEANUP_POLL_SECONDS = 0.75
CLEANUP_TERM_CAUSE = "Admin-Omada-Disconnect-Cleanup"


def outcome(state: str, reason: str = "", **details: object) -> dict:
    return {"result": state, "reason": reason, **details}


def normalized_mac(value: object) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def parse_request(raw: bytes) -> tuple[str, str, str] | None:
    if not raw or len(raw) > 1024:
        raise ValueError("REQUEST_SIZE")
    request = json.loads(raw)
    if request == {"probe": True}:
        return None
    if not isinstance(request, dict) or set(request) != {"nas_ip", "session_id", "mac"}:
        raise ValueError("REQUEST_FIELDS")
    nas, sid, raw_mac = request["nas_ip"], request["session_id"], request["mac"]
    if nas != NAS_IP or not isinstance(sid, str) or not SID.fullmatch(sid):
        raise ValueError("TARGET_NOT_ALLOWED")
    if (not isinstance(raw_mac, str) or
            not MAC.fullmatch(normalized_mac(raw_mac))):
        raise ValueError("MAC_NOT_ALLOWED")
    return nas, sid, normalized_mac(raw_mac)


def verify_accounting(sid: str, now: float | None = None, db_path: str = DB,
                      mac: str = PILOT_MAC) -> dict:
    """Enforce session/port/MAC/identity against live authoritative Accounting.

    Historical unclosed rows for the SAME client are permitted, but the
    requested row must be newest on its discovered port. An unrelated client
    or any fresh moved session causes a fail-closed result.
    """
    now = time.time() if now is None else now
    db = sqlite3.connect("file:" + db_path + "?mode=ro", uri=True, timeout=3)
    try:
        db.execute("PRAGMA query_only=ON")
        rows = db.execute(
            """SELECT radacctid,username,callingstationid,acctsessionid,
                      nasportid,acctupdatetime,acctstarttime
               FROM radacct
               WHERE nasipaddress=? AND acctstoptime IS NULL""",
            (NAS_IP,),
        ).fetchall()
        matches = [r for r in rows if normalized_mac(r[2]) == mac and r[3] == sid]
        if len(matches) != 1:
            raise ValueError("SESSION_NOT_UNIQUE")
        newest = matches[0]
        port = str(newest[4] or "")
        username = newest[1]
        if not port.isdecimal() or not 0 < int(port) <= 4294967295 or not username:
            raise ValueError("PORT_OR_IDENTITY_INVALID")
        on_port = [r for r in rows if str(r[4]) == port]
        if any(normalized_mac(r[2]) != mac or r[1] != username for r in on_port):
            raise ValueError("PORT_NOT_EXCLUSIVELY_CLIENT")
        if newest is not max(on_port, key=lambda r: (float(r[6] or 0), int(r[0]))):
            raise ValueError("SESSION_CHANGED")
        age = now - float(newest[5] or newest[6] or 0)
        if not (-90 <= age <= FRESH_SECONDS):
            raise ValueError("ACCOUNTING_NOT_FRESH")
        if any(
            normalized_mac(r[2]) == mac and str(r[4]) != port
            and -90 <= now - float(r[5] or r[6] or 0) <= FRESH_SECONDS
            for r in rows
        ):
            raise ValueError("CLIENT_MOVED_PORT")
        max_id = db.execute(
            "SELECT MAX(radacctid) FROM radacct WHERE nasipaddress=? AND nasportid=?",
            (NAS_IP, port),
        ).fetchone()[0]
    finally:
        db.close()
    return {"row_id": int(newest[0]), "port": port,
            "mac": mac, "username": username,
            "sid": sid, "started": int(newest[6]),
            "updated": int(newest[5] or newest[6]),
            "max_before": int(max_id or newest[0])}


def read_secret(path: str = SECRET) -> bytes:
    info = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError("COA_SECRET_PERMISSIONS")
    raw = Path(path).read_bytes().strip()
    if not 16 <= len(raw) <= 128 or b"\n" in raw or b"\r" in raw:
        raise ValueError("COA_SECRET_INVALID")
    return raw


def attribute(code: int, value: bytes) -> bytes:
    if not 0 <= code <= 255 or not 1 <= len(value) <= 253:
        raise ValueError("RADIUS_ATTRIBUTE_INVALID")
    return bytes((code, len(value) + 2)) + value


def build_request(sid: str, secret: bytes, identifier: int, *,
                  port: int = PILOT_PORT, mac: str = PILOT_MAC,
                  username: str = PILOT_USERNAME) -> tuple[bytes, bytes]:
    if not SID.fullmatch(sid) or not 0 <= identifier <= 255:
        raise ValueError("INVALID_SESSION")
    if not (0 < port <= 4294967295 and MAC.fullmatch(mac) and
            isinstance(username, str) and 0 < len(username.encode("utf-8")) <= 253):
        raise ValueError("INVALID_ACCOUNTING_IDENTITY")
    mac = "-".join(mac[i:i+2] for i in range(0, 12, 2)).upper()
    attrs = b"".join((
        attribute(1, username.encode("utf-8")),
        attribute(5, struct.pack("!I", port)),
        attribute(31, mac.encode("ascii")),
        # Do NOT include Acct-Session-Id (44) in Omada's wire packet:
        # newer 802.1X sessions can have a stale internal Session Context.
        # The exact SID is still verified against authoritative Accounting
        # immediately before send_once, to prevent targeting a changed client.
    ))
    header = struct.pack("!BBH", 40, identifier, 20 + len(attrs))
    request_auth = hashlib.md5(header + b"\x00" * 16 + attrs + secret).digest()
    return header + request_auth + attrs, request_auth


def decode_reply(packet: bytes, peer: tuple, identifier: int,
                 request_auth: bytes, secret: bytes) -> dict | None:
    if peer[:2] != (NAS_IP, COA_PORT):
        return None
    if len(packet) < 20 or len(packet) > 4096:
        return None
    code, response_id, total = struct.unpack("!BBH", packet[:4])
    if code not in (41, 42) or response_id != identifier or total != len(packet):
        return None
    expected = hashlib.md5(packet[:4] + request_auth + packet[20:] + secret).digest()
    if not hmac.compare_digest(expected, packet[4:20]):
        return None
    if code == 41:
        return outcome("ack", "AUTHENTICATED_DISCONNECT_ACK")
    cause = None
    cursor = 20
    while cursor < len(packet):
        if cursor + 2 > len(packet):
            return None
        typ, length = packet[cursor], packet[cursor + 1]
        if length < 2 or cursor + length > len(packet):
            return None
        if typ == 101 and length == 6:
            cause = struct.unpack("!I", packet[cursor + 2:cursor + 6])[0]
        cursor += length
    return outcome("nak", "DISCONNECT_REJECTED", error_cause=cause)


def close_acked_predecessor(sid: str, before: dict, sent_at: int,
                            db_path: str = DB) -> dict:
    """Perform a single atomic safe close, only after a verified ACK.

    Caller must have verified ACK cryptographically. A NEW Accounting-Start
    must have appeared after the pre-send high-water mark for precisely the
    same NAS, numeric port, MAC and username. The OLD record must remain
    unclosed and unchanged. Never close the successor.
    """
    db = sqlite3.connect(db_path, timeout=3, isolation_level=None)
    try:
        db.execute("PRAGMA busy_timeout=3000")
        db.execute("BEGIN IMMEDIATE")
        old = db.execute(
            """SELECT radacctid,acctsessionid,username,callingstationid,
                      nasipaddress,nasportid,acctstarttime,acctupdatetime,acctstoptime
               FROM radacct WHERE radacctid=?""",
            (before["row_id"],),
        ).fetchone()
        port = str(before.get("port", PILOT_PORT))
        mac = before.get("mac", PILOT_MAC)
        username = before.get("username", PILOT_USERNAME)
        if not old or (
            old[1] != sid or old[2] != username or
            normalized_mac(old[3]) != mac or old[4] != NAS_IP or
            str(old[5]) != port or int(old[6]) != before["started"]
        ):
            db.execute("ROLLBACK")
            return {"cleanup": "old_session_changed"}
        if old[8] is not None:
            db.execute("ROLLBACK")
            return {"cleanup": "already_ended"}
        if int(old[7] or old[6]) != before["updated"]:
            db.execute("ROLLBACK")
            return {"cleanup": "old_interim_changed"}

        # An open record for another client on this wired port blocks cleanup.
        open_rows = db.execute(
            """SELECT radacctid,acctsessionid,username,callingstationid,
                      acctstarttime,acctupdatetime
               FROM radacct WHERE nasipaddress=? AND nasportid=?
                 AND acctstoptime IS NULL""",
            (NAS_IP, port),
        ).fetchall()
        if any(r[2] != username or
               normalized_mac(r[3]) != mac for r in open_rows):
            db.execute("ROLLBACK")
            return {"cleanup": "port_identity_changed"}

        successors = [
            r for r in open_rows
            if int(r[0]) > before["max_before"]
            and r[1] != sid
            and SID.fullmatch(str(r[1] or ""))
            and r[1] != "00000000"
            and int(r[4] or 0) > before["started"]
            and int(r[4] or 0) >= sent_at - 1
        ]
        if not successors:
            db.execute("ROLLBACK")
            return {"cleanup": "waiting_new_start"}
        if len(successors) != 1:
            db.execute("ROLLBACK")
            return {"cleanup": "ambiguous_successor"}
        successor = successors[0]
        if int(old[7] or old[6]) > int(successor[4]):
            db.execute("ROLLBACK")
            return {"cleanup": "old_interim_after_start"}

        # A synthetic Accounting close, not a real RADIUS Accounting-Stop.
        # Use the new session's Accounting-Start as an upper time bound.
        stop_at = int(successor[4])
        cur = db.execute(
            """UPDATE radacct
               SET acctstoptime=?, acctterminatecause=?
               WHERE radacctid=? AND acctstoptime IS NULL
                 AND acctsessionid=? AND acctupdatetime=?""",
            (stop_at, CLEANUP_TERM_CAUSE, before["row_id"], sid,
             before["updated"]),
        )
        if cur.rowcount != 1:
            db.execute("ROLLBACK")
            return {"cleanup": "old_session_changed"}
        db.execute("COMMIT")
        return {"cleanup": "closed", "new_session_id": successor[1],
                "closed_at": stop_at}
    except BaseException:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    finally:
        db.close()


def wait_for_accounting_successor(sid: str, before: dict, sent_at: int,
                                  *, max_wait: float = CLEANUP_WAIT_SECONDS,
                                  poll: float = CLEANUP_POLL_SECONDS,
                                  db_path: str = DB) -> dict:
    """Never modify Accounting until ACK was verified and NEW Start arrives."""
    deadline = time.monotonic() + max_wait
    while True:
        try:
            result = close_acked_predecessor(
                sid, before, sent_at, db_path=db_path)
        except (sqlite3.Error, OSError, ValueError, TypeError):
            return {"cleanup": "storage_error"}
        if result["cleanup"] != "waiting_new_start":
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"cleanup": "no_new_start"}
        time.sleep(min(poll, remaining))


def send_once(sid: str, secret: bytes, *, timeout: float = 3.0,
              port: int = PILOT_PORT, mac: str = PILOT_MAC,
              username: str = PILOT_USERNAME) -> dict:
    identifier = secrets.randbelow(256)
    packet, auth = build_request(sid, secret, identifier,
                                 port=port, mac=mac, username=username)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        try:
            # The tested Omada firmware replies to UDP 3799 regardless of
            # the actual request source port. Bind BEFORE sending anything.
            channel.bind((SOURCE_IP, COA_PORT))
        except OSError:
            return outcome("error", "LOCAL_UDP_3799_UNAVAILABLE")
        channel.settimeout(timeout)
        try:
            sent = channel.sendto(packet, (NAS_IP, COA_PORT))
        except OSError:
            return outcome("error", "SEND_FAILED")
        if sent != len(packet):
            return outcome("unknown", "PARTIAL_DATAGRAM_SEND")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            channel.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                reply, peer = channel.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                return outcome("unknown", "RESPONSE_RECEIVE_FAILURE")
            verified = decode_reply(reply, peer, identifier, auth, secret)
            if verified is not None:
                return verified
        # A live Disconnect may have succeeded even when no ACK arrived.
        return outcome("unknown", "NO_AUTHENTICATED_RESPONSE")


def locked_execute(sid: str, mac: str = PILOT_MAC) -> dict:
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(LOCK, flags, 0o600)
    try:
        if os.fstat(fd).st_uid != 0 or stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
            raise ValueError("LOCK_PERMISSIONS")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return outcome("error", "ACTION_IN_PROGRESS")
        prev = os.read(fd, 128).decode("ascii", "replace").split()
        if len(prev) == 1:
            try:
                if time.time() - float(prev[0]) < COOLDOWN_SECONDS:
                    return outcome("error", "ACTION_COOLDOWN")
            except ValueError:
                pass
        before = verify_accounting(sid, mac=mac)
        secret = read_secret()
        # Record the attempt BEFORE the network send: no automatic retries.
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        os.write(fd, str(time.time()).encode("ascii"))
        os.fsync(fd)
        sent_at = int(time.time())
        answer = send_once(sid, secret, port=int(before["port"]),
                           mac=before["mac"], username=before["username"])
        if answer["result"] != "ack":
            # Never close Accounting for NAK, timeout or unauthenticated reply.
            return answer
        answer.update(wait_for_accounting_successor(sid, before, sent_at))
        return answer
    finally:
        os.close(fd)


def main() -> None:
    try:
        if os.geteuid() != 0 or os.environ.get("SSH_ORIGINAL_COMMAND") != "bixcore-omada-disconnect":
            answer = outcome("error", "FORCED_COMMAND_ONLY")
        else:
            request = parse_request(sys.stdin.buffer.read(1025))
            answer = (outcome("probe", "FORCED_COMMAND_AVAILABLE") if request is None
                      else locked_execute(request[1], request[2]))
    except (ValueError, TypeError, json.JSONDecodeError, sqlite3.Error) as exc:
        # Never echo arbitrary exception text, paths, credentials or payloads.
        reason = str(exc)
        answer = outcome("error", reason if re.fullmatch(r"[A-Z0-9_]{3,70}", reason) else "SOURCE_FAILURE")
    except OSError:
        answer = outcome("error", "SOURCE_OR_TRANSPORT_FAILURE")
    print(json.dumps(answer, separators=(",", ":")))


if __name__ == "__main__":
    main()
