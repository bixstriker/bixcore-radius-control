"""Local Unix RPC server shared by the isolated worker containers."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import socketserver
import stat
from typing import Callable

MAX_REQUEST = 2048
MAX_REPLY = 32768


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        # Do not let stalled clients hold all worker threads while framing requests.
        self.request.settimeout(5.0)
        with self.server.limit:
            try:
                raw = self.rfile.readline(MAX_REQUEST + 2)
                if not raw or len(raw) > MAX_REQUEST or not raw.endswith(b"\n"):
                    raise ValueError("REQUEST_INVALID")
                if self.rfile.read(1):
                    raise ValueError("REQUEST_TRAILING_DATA")
                request = json.loads(raw.decode("utf-8"))
                reply = self.server.callback(request)
                if not isinstance(reply, dict):
                    raise ValueError("REPLY_INVALID")
            except (ValueError, UnicodeError, TimeoutError, OSError):
                reply = {"ok": False, "error": "REQUEST_INVALID"}
            except Exception:
                reply = {"ok": False, "error": "WORKER_FAILED"}
            wire = (json.dumps(reply, separators=(",", ":")) + "\n").encode("utf-8")
            if len(wire) > MAX_REPLY:
                wire = b'{"ok":false,"error":"REPLY_TOO_LARGE"}\n'
            self.wfile.write(wire)
            self.wfile.flush()


# Windows lacks socketserver.UnixStreamServer; Linux runs the actual AF_UNIX server.
_UnixBase = getattr(socketserver, "UnixStreamServer", socketserver.TCPServer)


class UnixRPCServer(socketserver.ThreadingMixIn, _UnixBase):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, path: str, callback: Callable[[object], dict]) -> None:
        target = Path(path)
        if not target.is_absolute() or not target.parent.is_dir():
            raise RuntimeError("SOCKET_DIRECTORY_UNAVAILABLE")
        # Never unlink another live server or a regular file/symlink.
        if target.is_symlink():
            raise RuntimeError("SOCKET_PATH_IS_SYMLINK")
        if target.exists():
            if not stat.S_ISSOCK(target.lstat().st_mode):
                raise RuntimeError("SOCKET_PATH_UNSAFE")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.4)
                try:
                    probe.connect(str(target))
                except ConnectionRefusedError:
                    target.unlink()
                else:
                    raise RuntimeError("SOCKET_ALREADY_LISTENING")
        self.callback = callback
        import threading
        self.limit = threading.BoundedSemaphore(4)
        super().__init__(str(target), _Handler)
        os.chmod(target, 0o660)

    def server_close(self) -> None:
        name = self.server_address
        try:
            super().server_close()
        finally:
            try:
                Path(name).unlink(missing_ok=True)
            except OSError:
                pass
