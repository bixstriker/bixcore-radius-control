"""Manual sanitized export trigger over a narrowly scoped NAS Unix socket.

The web container can only request the existing root-owned systemd pull.
No SSH key, systemd D-Bus, host shell or snapshot write permission is exposed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat

DEFAULT_SOCKET = "/run/bixcore-refresh/trigger.sock"
MAX_REPLY = 2048

def socket_path() -> Path:
    return Path(os.getenv("BIX_MANUAL_REFRESH_SOCKET", DEFAULT_SOCKET))

def available() -> bool:
    if os.getenv("BIX_MANUAL_REFRESH_ENABLED") != "1":
        return False
    path = socket_path()
    try:
        return path.is_absolute() and stat.S_ISSOCK(path.stat().st_mode)
    except OSError:
        return False

def trigger(timeout: float = 52.0) -> str:
    """Return the export's as_of timestamp, or a fixed, non-sensitive error code."""
    if not available():
        raise RuntimeError("REFRESH_UNAVAILABLE")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(timeout)
            channel.connect(str(socket_path()))
            channel.sendall(
                b'{"op":"refresh"}\n' if os.getenv("BIX_COMPOSE_SYNC_ENABLED") == "1"
                else b"REFRESH\n"
            )
            channel.shutdown(socket.SHUT_WR)
            buf = bytearray()
            while b"\n" not in buf and len(buf) <= MAX_REPLY:
                chunk = channel.recv(min(512, MAX_REPLY + 1 - len(buf)))
                if not chunk:
                    break
                buf.extend(chunk)
    except (OSError, TimeoutError) as exc:
        raise RuntimeError("REFRESH_CONNECTION_FAILED") from exc
    if len(buf) > MAX_REPLY or b"\n" not in buf:
        raise RuntimeError("REFRESH_BAD_RESPONSE")
    try:
        response = json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
        if not isinstance(response, dict) or response.get("ok") is not True:
            raise RuntimeError("REFRESH_HOST_REJECTED")
        as_of = response.get("as_of")
        if not isinstance(as_of, str) or len(as_of) > 80:
            raise RuntimeError("REFRESH_BAD_RESPONSE")
        return as_of
    except (UnicodeError, ValueError, TypeError) as exc:
        raise RuntimeError("REFRESH_BAD_RESPONSE") from exc
