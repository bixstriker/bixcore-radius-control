"""Container-native periodic snapshot sync and requested refresh over a local Unix socket."""
from __future__ import annotations

import json
import os
from pathlib import Path
import threading
import time
from . import pull_snapshot
from .compose_rpc import UnixRPCServer

SYNC_SOCKET = "/run/bixcore-refresh/trigger.sock"


class SnapshotWorker:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.period = max(20, int(os.environ.get("BIX_SYNC_INTERVAL_SECONDS", "60")))

    def pull(self) -> dict:
        if not self.lock.acquire(blocking=False):
            return {"ok": False, "error": "PULL_ALREADY_RUNNING"}
        try:
            previous = pull_snapshot.TARGET.stat().st_mtime_ns if pull_snapshot.TARGET.exists() else -1
            if pull_snapshot.main() != 0:
                return {"ok": False, "error": "PULL_FAILED"}
            if not pull_snapshot.TARGET.is_file() or pull_snapshot.TARGET.stat().st_mtime_ns <= previous:
                return {"ok": False, "error": "SNAPSHOT_NOT_UPDATED"}
            with pull_snapshot.TARGET.open(encoding="utf-8") as handle:
                snap = json.load(handle)
            if snap.get("source") != "sanitized_export" or not isinstance(snap.get("as_of"), str):
                return {"ok": False, "error": "SNAPSHOT_INVALID"}
            return {"ok": True, "as_of": snap["as_of"]}
        except Exception:
            return {"ok": False, "error": "SNAPSHOT_PULL_FAILED"}
        finally:
            self.lock.release()

    def dispatch(self, request: object) -> dict:
        if request == {"probe": True}:
            return {"ok": True, "result": "probe"}
        if request == {"op": "refresh"}:
            return self.pull()
        return {"ok": False, "error": "INVALID_REQUEST"}

    def background(self) -> None:
        while True:
            self.pull()
            time.sleep(self.period)


def main() -> None:
    worker = SnapshotWorker()
    socket_path = os.environ.get("BIX_MANUAL_REFRESH_SOCKET", SYNC_SOCKET)
    with UnixRPCServer(socket_path, worker.dispatch) as server:
        threading.Thread(target=worker.background, daemon=True, name="radius-snapshot-pull").start()
        server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
