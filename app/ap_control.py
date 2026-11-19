"""Constrained Unix-socket client for UniFi inspection and EAPOL_REAUTH.

Never mounts AP SSH keys inside the web container. The host listener supports
only a read-only MAC scan and a target-bound, soft EAPOL_REAUTH request.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat

DEFAULT_SOCKET = "/run/bixcore-unifi/trigger.sock"
MAX_REPLY = 32768


def socket_path() -> Path:
    return Path(os.getenv("BIX_UNIFI_CONTROL_SOCKET", DEFAULT_SOCKET))


def available() -> bool:
    if os.getenv("BIX_UNIFI_CONTROL_ENABLED") != "1":
        return False
    path = socket_path()
    try:
        return path.is_absolute() and stat.S_ISSOCK(path.stat().st_mode)
    except OSError:
        return False


class UnifiError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def call(request: dict, timeout: float = 65.0) -> dict:
    if not available():
        raise UnifiError("UNIFI_CONTROL_UNAVAILABLE")
    raw = (json.dumps(request, separators=(",", ":")) + "\n").encode("utf8")
    if len(raw) > 2048:
        raise UnifiError("REQUEST_TOO_LARGE")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(timeout)
            channel.connect(str(socket_path()))
            channel.sendall(raw)
            channel.shutdown(socket.SHUT_WR)
            data = bytearray()
            while b"\n" not in data and len(data) <= MAX_REPLY:
                chunk = channel.recv(min(2048, MAX_REPLY + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
    except (OSError, TimeoutError) as exc:
        raise UnifiError("UNIFI_TRANSPORT_FAILED") from exc
    if b"\n" not in data or len(data) > MAX_REPLY:
        raise UnifiError("UNIFI_BAD_REPLY")
    try:
        reply = json.loads(data.split(b"\n", 1)[0])
    except (ValueError, UnicodeError) as exc:
        raise UnifiError("UNIFI_BAD_REPLY") from exc
    if not isinstance(reply, dict) or reply.get("ok") is not True:
        code = str(reply.get("error", "UNIFI_REJECTED")) if isinstance(reply, dict) else "UNIFI_BAD_REPLY"
        raise UnifiError(code[:64])
    return reply
