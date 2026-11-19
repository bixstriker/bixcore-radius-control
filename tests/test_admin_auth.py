"""No real AP connections or production credentials are used in these tests."""
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from app.main import app
from app import auth


class AdministratorLoginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.credential = Path(self.temp.name) / "admin_auth.json"
        self.secret = Path(self.temp.name) / "admin_session_key"
        self.password = "TEST_ONLY_BiXCore_password_012345"
        self.credential.write_text(json.dumps(auth.make_password_record(self.password)), encoding="utf8")
        self.secret.write_bytes(secrets.token_bytes(32))
        self.env = patch.dict(os.environ, {
            "BIX_ADMIN_AUTH_ENABLED": "1",
            "BIX_ADMIN_CREDENTIALS_PATH": str(self.credential),
            "BIX_ADMIN_SIGNING_KEY_PATH": str(self.secret),
            "BIX_CONTROL_ORIGIN": "https://radius.example.test",
        })
        self.env.start()
        auth.clear_failures("testclient")
        self.client = TestClient(app, base_url="https://radius.example.test", follow_redirects=False)
        self.headers = {"Origin": "https://radius.example.test"}

    def tearDown(self):
        self.client.close()
        auth.clear_failures("testclient")
        self.env.stop()
        self.temp.cleanup()

    def login(self, password=None, username="admin", origin=True):
        h = self.headers if origin else {}
        return self.client.post("/api/auth/login", headers=h,
                                json={"username": username, "password": password or self.password})

    def test_private_pages_and_data_api_without_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers.get("location"), "/login")
        for url in ("/api/overview", "/api/sessions", "/api/users", "/api/portal-users",
                    "/api/guest-disconnect-preview", "/static/app.js"):
            self.assertEqual(self.client.get(url).status_code, 401, url)
        self.assertEqual(self.client.get("/api/health").status_code, 200)
        self.assertEqual(self.client.get("/login").status_code, 200)
        self.assertEqual(self.client.get("/static/style.css").status_code, 200)
        self.assertEqual(self.client.get("/static/login.js").status_code, 200)
        for asset in ("/static/ui.js", "/static/ui-theme.css", "/static/responsive.css", "/static/favicon.svg"):
            self.assertEqual(self.client.get(asset).status_code, 200, asset)
        self.assertEqual(self.client.get("/static/app.js").status_code, 401)

    def test_incorrect_password_and_username(self):
        self.assertEqual(self.login(password="WRONG-TEST-PASSWORD").status_code, 401)
        self.assertEqual(self.login(username="someone").status_code, 401)
        self.assertEqual(self.client.get("/api/overview").status_code, 401)

    def test_origin_required_on_login(self):
        self.assertEqual(self.login(origin=False).status_code, 403)
        self.assertEqual(self.client.post("/api/auth/login", headers={"Origin":"https://not-ours.example"},
                         json={"username":"admin","password":self.password}).status_code, 403)

    def test_successful_login_cookie_protects_subsequent_requests(self):
        r = self.login()
        self.assertEqual(r.status_code, 200, r.text)
        cookie = r.headers.get("set-cookie", "")
        self.assertIn(auth.COOKIE_NAME, cookie)
        self.assertIn("secure", cookie.lower())
        self.assertIn("httponly", cookie.lower())
        self.assertIn("samesite=strict", cookie.lower())
        self.assertIn("path=/", cookie.lower())
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/api/overview").status_code, 200)
        self.assertEqual(self.client.get("/static/app.js").status_code, 200)
        self.assertEqual(self.client.get("/login").status_code, 303)

    def test_logout_clears_cookie(self):
        self.assertEqual(self.login().status_code, 200)
        self.assertEqual(self.client.post("/api/auth/logout", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get("/api/users").status_code, 401)

    def test_mutation_requires_valid_origin_even_when_logged_in(self):
        self.assertEqual(self.login().status_code, 200)
        body = {"nas_ip":"192.0.2.6","session_id":"does-not-exist","mac":"02:00:00:00:00:02"}
        self.assertEqual(self.client.post("/api/unifi/disconnect", json=body).status_code, 403)
        self.assertEqual(self.client.post("/api/unifi/disconnect", json=body, headers=self.headers).status_code, 503)

    def test_tampered_expired_and_rotated_cookies(self):
        self.assertEqual(self.login().status_code, 200)
        token = self.client.cookies.get(auth.COOKIE_NAME)
        self.assertTrue(auth.valid_cookie(token))
        self.assertFalse(auth.valid_cookie(token[:-3] + "bad"))
        with patch("app.auth.time.time", return_value=9999999999):
            self.assertFalse(auth.valid_cookie(token))
        self.credential.write_text(json.dumps(auth.make_password_record("CHANGED-TEST-ADMIN-PASSWORD_123456")),encoding="utf8")
        self.assertFalse(auth.valid_cookie(token))

    def test_fail_closed_if_credentials_missing(self):
        self.credential.unlink()
        self.assertEqual(self.login().status_code, 503)
        self.assertEqual(self.client.get("/api/sessions").status_code, 401)

    def test_rate_limit(self):
        for _ in range(auth.MAX_FAILURES):
            self.assertEqual(self.login(password="BAD_TEST_PASSWORD").status_code, 401)
        self.assertEqual(self.login().status_code, 429)
        auth.clear_failures("testclient")


if __name__ == "__main__":
    unittest.main()
