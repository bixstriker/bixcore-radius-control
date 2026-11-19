"""Health probe that verifies the worker actually responds on its Unix socket."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import sys


def check(path: str) -> bool:
    if not Path(path).is_absolute() or not hasattr(socket, "AF_UNIX"):
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(3)
            channel.connect(path)
            channel.sendall(b'{"probe":true}\n')
            channel.shutdown(socket.SHUT_WR)
            with channel.makefile("rb") as handle:
                response = handle.readline(2049)
        result = json.loads(response)
    except (OSError, ValueError, UnicodeError, TimeoutError):
        return False
    return result == {"ok": True, "result": "probe"}


if __name__ == "__main__":
    sys.exit(0 if len(sys.argv) == 2 and check(sys.argv[1]) else 1)
