"""Persistent security audit trail for BiXCore administrative operations.

Every accepted management POST writes a durable STARTED row before its handler runs.
The result is completed after the response. An interrupted process leaves STARTED
as honest evidence that the action's outcome is unknown. No credentials or arbitrary
request/response payloads are persisted.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import threading
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException

ACTIONS = {
    "/api/auth/login": "ADMIN_LOGIN",
    "/api/auth/logout": "ADMIN_LOGOUT",
    "/api/auth/change-password": "ADMIN_PASSWORD_CHANGE",
    "/api/snapshot/refresh": "SNAPSHOT_REFRESH",
    "/api/unifi/reauth": "UNIFI_EAP_REAUTH",
    "/api/unifi/disconnect": "UNIFI_DISCONNECT_PMKSA",
    "/api/accounting/close-stale": "ACCOUNTING_CLOSE",
    "/api/users/set-enabled": "RADIUS_USER_ENABLED",
    "/api/users/set-vlan": "RADIUS_USER_VLAN",
    "/api/portal-users/set-enabled": "PORTAL_USER_ENABLED",
    "/api/portal-sessions/disconnect": "PORTAL_SESSION_END",
    "/api/guest-wifi/set-enabled": "GUEST_WIFI_ENABLED",
    "/api/guest-wifi/disconnect-all": "GUEST_WIFI_DISCONNECT_BATCH",
    "/api/omada/disconnect": "OMADA_DISCONNECT",
}
TARGET_KEYS = (
    "username", "uuid", "nas_ip", "mac", "session_id",
    "zone_id", "vlan", "expected_vlan", "enabled",
    "expected_enabled", "expected_count", "offline",
)
SAFE_VALUE = re.compile(r"^[\w .:@/\-+]{1,160}$", re.UNICODE)
DATABASE_PATH = "/app/audit/events.sqlite3"
SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 started_at TEXT NOT NULL,
 finished_at TEXT,
 actor TEXT NOT NULL,
 action TEXT NOT NULL,
 target_json TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('started','success','partial','rejected','error')),
 http_status INTEGER,
 outcome_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_by_time ON audit_events(id DESC);
CREATE INDEX IF NOT EXISTS audit_by_action ON audit_events(action,id DESC);
"""
_LOCK = threading.RLock()
_ANON_LOCK = threading.Lock()
_ANON_LOGIN = {}
_ANON_LIMIT = 12
_ANON_WINDOW = 300


def allow_anonymous_login(ip: str) -> bool:
    """Bound unauthenticated audit writes per source. Never persist source IP."""
    now = time.monotonic()
    key = ip[:80] if isinstance(ip, str) else "unknown"
    with _ANON_LOCK:
        if len(_ANON_LOGIN) > 1024:
            for host, stamps in list(_ANON_LOGIN.items()):
                fresh = [t for t in stamps if now-t < _ANON_WINDOW]
                if fresh:
                    _ANON_LOGIN[host] = fresh
                else:
                    del _ANON_LOGIN[host]
        attempts = [t for t in _ANON_LOGIN.get(key, ()) if now-t < _ANON_WINDOW]
        if len(attempts) >= _ANON_LIMIT:
            return False
        attempts.append(now)
        _ANON_LOGIN[key] = attempts
        return True


def enabled() -> bool:
    return os.getenv("BIX_AUDIT_ENABLED") == "1"


def _path() -> Path:
    return Path(os.getenv("BIX_AUDIT_DB", DATABASE_PATH))


def _connection() -> sqlite3.Connection:
    path = _path()
    if path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        raise OSError("AUDIT_PATH_NOT_SAFE")
    if path.exists() and (not path.is_file() or not stat.S_ISREG(path.stat().st_mode)):
        raise OSError("AUDIT_FILE_NOT_REGULAR")
    connection = sqlite3.connect(str(path), timeout=5)
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA synchronous=FULL")
    connection.executescript(SCHEMA)
    if path.stat().st_mode & 0o077:
        os.chmod(path, 0o600)
    return connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sanitize_target(raw: bytes, action: str) -> dict:
    if action in ("ADMIN_LOGIN", "ADMIN_LOGOUT", "ADMIN_PASSWORD_CHANGE"):
        return {"subject": "administrator"}
    if len(raw) > 16384:
        return {}
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {}
    except (ValueError, TypeError, UnicodeError):
        return {}
    cleaned = {}
    for field in TARGET_KEYS:
        value = data.get(field)
        if type(value) in (bool, int):
            cleaned[field] = value
        elif isinstance(value, str) and SAFE_VALUE.fullmatch(value):
            cleaned[field] = value[:160]
    return cleaned


def _outcome(body: bytes, status: int) -> tuple[str, dict]:
    result = "success" if 200 <= status < 300 else ("rejected" if status < 500 else "error")
    info = {}
    try:
        data = json.loads(body[:32768]) if len(body) <= 32768 else {}
        if not isinstance(data, dict):
            data = {}
    except (TypeError, ValueError, UnicodeError):
        data = {}
    for field in ("ack", "nak", "error", "requested"):
        value = data.get(field)
        if type(value) is int and 0 <= value <= 10000:
            info[field] = value
    for field in ("result", "cleanup"):
        value = data.get(field)
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,35}", value):
            info[field] = value
    successor = data.get("new_session_id")
    if isinstance(successor, str) and re.fullmatch(r"[0-9A-Fa-f]{8}", successor):
        info["new_session_id"] = successor
    for field in ("disconnect_ack", "ok"):
        if type(data.get(field)) is bool:
            info[field] = data[field]
    pmksa = data.get("pmksa")
    if isinstance(pmksa, dict) and type(pmksa.get("complete")) is bool:
        info["pmksa_complete"] = pmksa["complete"]
    if status < 300 and (data.get("ok") is False or data.get("result") == "partial"):
        result = "partial"
    return result, info


def begin(*, actor: str, action: str, request_body: bytes) -> int:
    if action not in ACTIONS.values():
        raise ValueError("NOT_AN_AUDIT_ACTION")
    if not enabled():
        raise OSError("AUDIT_DISABLED")
    target = sanitize_target(request_body, action)
    with _LOCK, closing(_connection()) as con, con:
        cursor = con.execute(
            "INSERT INTO audit_events(started_at,actor,action,target_json,state) VALUES(?,?,?,?,?)",
            (_now(), actor, action, json.dumps(target, ensure_ascii=False, separators=(",", ":")), "started"),
        )
        return int(cursor.lastrowid)


def finish(event_id: int, status: int, response_body: bytes) -> None:
    state, outcome = _outcome(response_body, status)
    with _LOCK, closing(_connection()) as con, con:
        con.execute(
            "UPDATE audit_events SET finished_at=?,state=?,http_status=?,outcome_json=? "
            "WHERE id=? AND state='started'",
            (_now(), state, int(status),
             json.dumps(outcome, ensure_ascii=False, separators=(",", ":")), event_id),
        )


def entries(*, limit: int = 50, offset: int = 0, action: str | None = None,
            state: str | None = None) -> dict:
    if not enabled():
        raise HTTPException(503, detail="Журнал аудита отключён")
    if action and action not in ACTIONS.values():
        raise HTTPException(400, detail="Неизвестное действие")
    if state and state not in ("started", "success", "partial", "rejected", "error"):
        raise HTTPException(400, detail="Неизвестный результат")
    limit = max(1, min(100, limit))
    offset = max(0, min(5000, offset))
    where, args = [], []
    if action:
        where.append("action=?")
        args.append(action)
    if state:
        where.append("state=?")
        args.append(state)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    try:
        with _LOCK, closing(_connection()) as con, con:
            total = con.execute("SELECT count(*) FROM audit_events" + clause, args).fetchone()[0]
            rows = con.execute(
                "SELECT id,started_at,finished_at,actor,action,target_json,state,http_status,outcome_json "
                "FROM audit_events" + clause + " ORDER BY id DESC LIMIT ? OFFSET ?",
                (*args, limit, offset),
            ).fetchall()
    except (sqlite3.Error, OSError):
        raise HTTPException(503, detail="Журнал аудита недоступен") from None
    return {
        "total": total, "limit": limit, "offset": offset,
        "items": [
            {"id": row[0], "started_at": row[1], "finished_at": row[2],
             "actor": row[3], "action": row[4],
             "target": json.loads(row[5]), "state": row[6],
             "http_status": row[7], "outcome": json.loads(row[8])}
            for row in rows
        ],
    }


class AuditMiddleware:
    """ASGI guard: commit an audit STARTED event before executing an action.

    Collect only bounded JSON for a fixed route allowlist. Preserve ASGI send
    semantics. Completion is logged after receiving the last response chunk.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if not enabled() or scope["type"] != "http" or scope.get("method") != "POST":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        action = ACTIONS.get(path)
        if not action:
            return await self.app(scope, receive, send)

        headers = dict(scope.get("headers", []))
        from . import auth
        cookie = next(
            (part.split(b"=", 1)[1].decode("ascii", "ignore")
             for part in headers.get(b"cookie", b"").split(b";")
             if part.strip().startswith(auth.COOKIE_NAME.encode("ascii") + b"=")), None
        )
        actor = "admin" if auth.enabled() and auth.valid_cookie(cookie) else "anonymous"
        if actor == "anonymous":
            if action != "ADMIN_LOGIN":
                # The auth gate rejects these: no need to let anonymous POSTs fill SQLite.
                return await self.app(scope, receive, send)
            ip = (scope.get("client") or ("unknown",))[0]
            if not allow_anonymous_login(ip):
                return await self._error(send, 429, b'{"detail":"Too many login attempts"}')
        frames = []
        total = 0
        while True:
            item = await receive()
            frames.append(item)
            if item["type"] != "http.request":
                break
            total += len(item.get("body", b""))
            if total > 16384:
                return await self._error(send, 413, b'{"detail":"Request too large"}')
            if not item.get("more_body", False):
                break
        raw = b"".join(frame.get("body", b"") for frame in frames)
        try:
            event_id = begin(actor=actor, action=action, request_body=raw)
        except (sqlite3.Error, OSError, ValueError):
            return await self._error(send, 503, b'{"detail":"Audit store unavailable"}')
        position = 0
        async def replay():
            nonlocal position
            if position < len(frames):
                frame = frames[position]
                position += 1
                return frame
            return await receive()
        status = 500
        response = bytearray()
        closed = False
        async def capture(message):
            nonlocal status, closed
            if message["type"] == "http.response.start":
                status = int(message.get("status", 500))
            if message["type"] == "http.response.body":
                data = message.get("body", b"")
                if len(response) + len(data) <= 32768:
                    response.extend(data)
                if not message.get("more_body", False):
                    closed = True
                    self._finish(event_id, status, bytes(response))
            await send(message)
        try:
            await self.app(scope, replay, capture)
        except BaseException:
            if not closed:
                self._finish(event_id, 500, b"")
            raise

    @staticmethod
    def _finish(event_id, status, raw):
        try:
            finish(event_id, status, raw)
        except (sqlite3.Error, OSError):
            import logging
            logging.getLogger("uvicorn.error").error("AUDIT_COMPLETION_UNAVAILABLE id=%s", event_id)

    @staticmethod
    async def _error(send, status: int, body: bytes):
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": body, "more_body": False})
