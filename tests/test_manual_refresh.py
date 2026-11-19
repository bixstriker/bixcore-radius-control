"""Manual snapshot refresh: privilege boundary, transport and API tests."""
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
from app import main, refresh
from sync import refresh_host


class ManualRefreshTests(unittest.TestCase):
    def setUp(self):
        main._MANUAL_REFRESH_LAST = 0

    def test_disabled_returns_503_and_does_not_export(self):
        with TestClient(main.app) as client, patch.object(main.auth,"enabled",return_value=True), \
             patch.object(main.auth,"valid_cookie",return_value=True), \
             patch.object(refresh,"available",return_value=False), \
             patch.object(refresh,"trigger") as trigger:
            res=client.post("/api/snapshot/refresh",headers={"origin":"https://radius.example.test"})
        self.assertEqual(res.status_code,503)
        trigger.assert_not_called()

    def test_requires_cookie_and_origin(self):
        with TestClient(main.app) as client, patch.object(main.auth,"enabled",return_value=True), \
             patch.object(main.auth,"valid_cookie",return_value=False), \
             patch.object(refresh,"available",return_value=True):
            self.assertEqual(client.post("/api/snapshot/refresh",headers={"origin":"https://radius.example.test"}).status_code,401)
        with TestClient(main.app) as client, patch.object(main.auth,"enabled",return_value=True), \
             patch.object(main.auth,"valid_cookie",return_value=True), \
             patch.object(refresh,"available",return_value=True):
            self.assertEqual(client.post("/api/snapshot/refresh",headers={"origin":"https://bad.invalid"}).status_code,403)

    def test_one_export_then_cooldown(self):
        as_of=datetime.now(timezone.utc).isoformat()
        bundle=({"source":"sanitized_export","as_of":as_of},None,None,None)
        with TestClient(main.app) as client, patch.object(main.auth,"enabled",return_value=True), \
             patch.object(main.auth,"valid_cookie",return_value=True), \
             patch.object(refresh,"available",return_value=True), \
             patch.object(refresh,"trigger",return_value=as_of) as trigger, \
             patch.object(main,"bundle",return_value=bundle):
            headers={"origin":"https://radius.example.test"}
            first=client.post("/api/snapshot/refresh",headers=headers)
            second=client.post("/api/snapshot/refresh",headers=headers)
        self.assertEqual(first.status_code,200,first.text)
        self.assertTrue(first.json()["ok"])
        self.assertEqual(second.status_code,429)
        trigger.assert_called_once()

    def test_busy_fails_closed(self):
        self.assertTrue(main._MANUAL_REFRESH_LOCK.acquire(blocking=False))
        try:
            with TestClient(main.app) as client, patch.object(main.auth,"enabled",return_value=True), \
                 patch.object(main.auth,"valid_cookie",return_value=True), \
                 patch.object(refresh,"available",return_value=True):
                res=client.post("/api/snapshot/refresh",headers={"origin":"https://radius.example.test"})
        finally:
            main._MANUAL_REFRESH_LOCK.release()
        self.assertEqual(res.status_code,409)

    def test_unix_socket_roundtrip(self):
        if not hasattr(socket,"AF_UNIX"):
            self.skipTest("AF_UNIX not present")
        with tempfile.TemporaryDirectory() as dirpath:
            sockpath=Path(dirpath)/"a.sock"
            observed=[]
            ready=threading.Event()
            def server():
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
                    s.bind(str(sockpath))
                    s.listen(1)
                    ready.set()
                    conn,_=s.accept()
                    with conn:
                        observed.append(conn.recv(64))
                        conn.sendall(b'{"ok":true,"as_of":"2026-11-16T17:00:00+00:00"}\n')
            thread=threading.Thread(target=server,daemon=True)
            thread.start()
            self.assertTrue(ready.wait(4))
            with patch.dict(os.environ,{"BIX_MANUAL_REFRESH_ENABLED":"1","BIX_MANUAL_REFRESH_SOCKET":str(sockpath)}):
                self.assertTrue(refresh.available())
                as_of=refresh.trigger(timeout=4)
            thread.join(4)
            self.assertEqual(as_of,"2026-11-16T17:00:00+00:00")
            self.assertEqual(observed,[b"REFRESH\n"])

    def test_systemd_socket_has_no_unresolvable_host_user(self):
        unit=(Path(__file__).resolve().parent.parent/
              "deploy/bixcore-radius-refresh.socket").read_text(encoding="utf-8")
        self.assertIn("Accept=yes", unit)
        self.assertIn("SocketMode=0666", unit)
        self.assertNotIn("SocketUser=", unit)
        self.assertIn("ListenStream=/srv/bixcore-radius-control/private/refresh_socket/trigger.sock", unit)

    def test_host_bridge_only_accepts_fixed_command(self):
        with patch.object(refresh_host,"run_pull") as run:
            result=refresh_host.handle(b"systemctl stop radiusd\n")
        self.assertEqual(result,{"ok":False,"error":"BAD_REQUEST"})
        run.assert_not_called()

    def test_host_bridge_starts_exact_systemd_unit_and_checks_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"current.json"
            path.write_text('{"source":"sanitized_export","as_of":"2026-11-16T00:00:00+00:00"}')
            before=path.stat().st_mtime_ns
            def fake_run(args,**kw):
                self.assertEqual(args,[refresh_host.SYSTEMCTL,"start","bixcore-radius-pull.service"])
                path.write_text('{"source":"sanitized_export","as_of":"2026-11-16T01:00:00+00:00"}')
                os.utime(path,ns=(before+2_000_000_000,before+2_000_000_000))
                return SimpleNamespace(returncode=0)
            with patch.object(refresh_host.subprocess,"run",side_effect=fake_run):
                self.assertEqual(refresh_host.run_pull(path),"2026-11-16T01:00:00+00:00")

    def test_host_bridge_rejects_export_without_replaced_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"current.json"
            path.write_text('{"source":"sanitized_export","as_of":"2026-11-16T00:00:00+00:00"}')
            with patch.object(refresh_host.subprocess,"run",return_value=SimpleNamespace(returncode=0)):
                with self.assertRaisesRegex(RuntimeError,"SNAPSHOT_NOT_UPDATED"):
                    refresh_host.run_pull(path)

if __name__=="__main__":
    unittest.main()
