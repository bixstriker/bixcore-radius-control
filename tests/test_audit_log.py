"""Audit events are durable and credential-free, including rejected requests."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from contextlib import closing
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from fastapi import FastAPI

from app import audit
from app.main import app


class AuditDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.temp.name) / "audit.sqlite3")
        self.env = patch.dict(os.environ, {"BIX_AUDIT_ENABLED": "1", "BIX_AUDIT_DB": self.db, "BIX_ADMIN_AUTH_ENABLED": "1"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_credentials_never_stored(self):
        event = audit.begin(
            actor="admin", action="ADMIN_PASSWORD_CHANGE",
            request_body=json.dumps({"current_password": "old-secret",
                                     "new_password": "new-secret",
                                     "confirm_password": "new-secret"}).encode(),
        )
        audit.finish(event, 200, b'{"ok":true}')
        text = Path(self.db).read_bytes()
        self.assertNotIn(b"old-secret", text)
        self.assertNotIn(b"new-secret", text)
        record = audit.entries()["items"][0]
        self.assertEqual(record["target"], {"subject": "administrator"})
        self.assertEqual(record["state"], "success")
        self.assertEqual(record["outcome"], {"ok": True})
        self.assertEqual(record["actor"], "admin")

    def test_partial_and_failed_results(self):
        one = audit.begin(actor="admin", action="GUEST_WIFI_DISCONNECT_BATCH",
                          request_body=b'{"expected_count":2,"confirmation":"disconnect_guest_wifi"}')
        audit.finish(one, 200, b'{"ok":false,"result":"completed","requested":2,"ack":1,"nak":1,"error":0}')
        entry = audit.entries()["items"][0]
        self.assertEqual(entry["state"], "partial")
        self.assertEqual(entry["outcome"]["ack"], 1)
        self.assertEqual(entry["outcome"]["nak"], 1)
        two = audit.begin(actor="admin", action="RADIUS_USER_VLAN",
                          request_body=b'{"username":"user1","vlan":30,"current_password":"hidden"}')
        audit.finish(two, 409, b'{"detail":"some private error"}')
        self.assertEqual(audit.entries()["items"][0]["state"], "rejected")
        self.assertNotIn(b"hidden", Path(self.db).read_bytes())
        self.assertNotIn(b"some private error", Path(self.db).read_bytes())

    def test_started_persists_if_handler_does_not_finish(self):
        event_id = audit.begin(actor="admin", action="UNIFI_DISCONNECT_PMKSA",
                               request_body=b'{"nas_ip":"192.0.2.4","mac":"02:00:00:00:00:22"}')
        row = audit.entries()["items"][0]
        self.assertEqual(row["id"], event_id)
        self.assertEqual(row["state"], "started")
        self.assertIsNone(row["finished_at"])
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_filters_and_page_limits(self):
        for state, code in (("success", 200), ("rejected", 409)):
            eid = audit.begin(actor="admin", action="SNAPSHOT_REFRESH", request_body=b"")
            audit.finish(eid, code, b'{}')
        self.assertEqual(audit.entries(state="rejected")["total"], 1)
        self.assertEqual(audit.entries(action="SNAPSHOT_REFRESH")["total"], 2)
        self.assertEqual(len(audit.entries(limit=1)["items"]), 1)
        self.assertEqual(audit.entries(offset=1)["items"][0]["state"], "success")

    def test_invalid_fields_and_oversize_not_persisted(self):
        row = audit.sanitize_target(b'{"username":"allowed","password":"p","cookie":"s",'
                                    b'"uuid":"../? bad","enabled":false,"vlan":30}',"RADIUS_USER_ENABLED")
        self.assertEqual(row, {"username":"allowed","enabled":False,"vlan":30})
        self.assertEqual(audit.sanitize_target(b"x" * 16385, "RADIUS_USER_ENABLED"), {})

    def test_unauthenticated_posts_do_not_fill_audit_store(self):
        with TestClient(app) as client:
            for _ in range(5):
                response = client.post("/api/users/set-enabled", json={"username": "fake"})
                self.assertEqual(response.status_code, 401)
        self.assertEqual(audit.entries()["total"], 0)

    def test_audit_is_fail_closed_before_authenticated_mutation(self):
        from app import auth
        with patch.object(auth, "valid_cookie", return_value=True):
            with TestClient(app) as client:
                client.cookies.set(auth.COOKIE_NAME, "test")
                response = client.post("/api/users/set-enabled", json={"username": "fake"},
                                       headers={"Origin":"https://radius.example.test"})
                self.assertEqual(response.status_code, 422)
            events = audit.entries()
            self.assertEqual(events["total"], 1)
            self.assertEqual(events["items"][0]["state"], "rejected")
            self.assertEqual(events["items"][0]["actor"], "admin")
            with patch.dict(os.environ, {"BIX_AUDIT_DB": str(Path(self.temp.name) / "missing" / "fail.sqlite3")}):
                with TestClient(app) as client:
                    client.cookies.set(auth.COOKIE_NAME, "test")
                    response = client.post("/api/users/set-enabled", json={"username": "fake"})
                    self.assertEqual(response.status_code, 503)

    def test_anonymous_login_is_rate_limited(self):
        from app import auth
        audit._ANON_LOGIN.clear()
        with patch.object(auth, "valid_cookie", return_value=False):
            with TestClient(app) as client:
                responses = [client.post("/api/auth/login", json={"username": "wrong", "password": "wrong"})
                             for _ in range(14)]
        self.assertEqual(audit.entries()["total"], 12)
        self.assertTrue(all(r.status_code != 429 for r in responses[:12]))
        self.assertEqual([r.status_code for r in responses[12:]], [429, 429])
        audit._ANON_LOGIN.clear()

    def test_asgi_captures_successful_api_result(self):
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.applications import Starlette
        async def result(request):
            return JSONResponse({"ok": True, "result": "complete", "disconnect_ack": True})
        isolated = Starlette(routes=[Route("/api/unifi/disconnect", result, methods=["POST"])])
        isolated.add_middleware(audit.AuditMiddleware)
        from app import auth
        with patch.object(auth, "enabled", return_value=True), patch.object(auth, "valid_cookie", return_value=True):
            with TestClient(isolated) as client:
                client.cookies.set(auth.COOKIE_NAME, "test")
                out = client.post("/api/unifi/disconnect",
                                  json={"nas_ip":"192.0.2.4","mac":"02-00-00-00-00-22"})
                self.assertEqual(out.status_code, 200)
        event = audit.entries()["items"][0]
        self.assertEqual(event["state"], "success")
        self.assertEqual(event["outcome"]["disconnect_ack"], True)


if __name__ == "__main__":
    unittest.main()
