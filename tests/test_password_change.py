"""Password-change integration tests; only synthetic credentials and local TestClient."""
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app import auth
from app.main import app


class PasswordChangeTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.credential=Path(self.directory.name)/"credentials.json"
        self.key=Path(self.directory.name)/"signing.key"
        self.old="DEMO_ONLY_valid_current_password_0123"
        self.new="DEMO_ONLY_distinct_new_password_5678"
        self.credential.write_text(json.dumps(auth.make_password_record(self.old)),encoding="utf8")
        self.key.write_bytes(secrets.token_bytes(32))
        self.env=patch.dict(os.environ,{
            "BIX_ADMIN_AUTH_ENABLED":"1",
            "BIX_ADMIN_CREDENTIALS_PATH":str(self.credential),
            "BIX_ADMIN_SIGNING_KEY_PATH":str(self.key),
            "BIX_CONTROL_ORIGIN":"https://radius.example.test",
        })
        self.env.start()
        auth.clear_failures("testclient")
        self.client=TestClient(app,base_url="https://radius.example.test",follow_redirects=False)
        self.headers={"Origin":"https://radius.example.test"}
    def tearDown(self):
        self.client.close()
        self.env.stop()
        auth.clear_failures("testclient")
        self.directory.cleanup()
    def login(self,pw=None):
        return self.client.post("/api/auth/login",headers=self.headers,
                json={"username":"admin","password":pw if pw is not None else self.old})
    def change(self,current=None,new=None,confirm=None,headers=None):
        return self.client.post("/api/auth/change-password",
            headers=self.headers if headers is None else headers,
            json={"current_password":self.old if current is None else current,
                  "new_password":self.new if new is None else new,
                  "confirm_password":self.new if confirm is None else confirm})

    def test_login_required(self):
        r=self.change()
        self.assertEqual(r.status_code,401)
        self.assertTrue(auth.password_matches("admin",self.old))

    def test_csrf_origin_required(self):
        self.assertEqual(self.login().status_code,200)
        self.assertEqual(self.change(headers={}).status_code,403)
        self.assertEqual(self.change(headers={"Origin":"https://fake.example"}).status_code,403)
        self.assertTrue(auth.password_matches("admin",self.old))

    def test_wrong_current_password_rejected(self):
        self.assertEqual(self.login().status_code,200)
        r=self.change(current="WRONG_CURRENT_PASSWORD")
        self.assertEqual(r.status_code,403)
        self.assertIn("текущий пароль",r.text)
        self.assertTrue(auth.password_matches("admin",self.old))

    def test_mismatched_confirmation_and_same_password(self):
        self.assertEqual(self.login().status_code,200)
        self.assertEqual(self.change(confirm="not-the-new-password").status_code,400)
        self.assertEqual(self.change(new=self.old,confirm=self.old).status_code,400)
        self.assertEqual(self.change(new="short",confirm="short").status_code,422)
        self.assertTrue(auth.password_matches("admin",self.old))

    def test_password_change_effective_without_restart(self):
        self.assertEqual(self.login().status_code,200)
        old_cookie=self.client.cookies.get(auth.COOKIE_NAME)
        self.assertTrue(auth.valid_cookie(old_cookie))
        initial_key=self.key.read_bytes()
        r=self.change()
        self.assertEqual(r.status_code,200,r.text)
        self.assertTrue(r.json()["ok"])
        self.assertIn("max-age=0",r.headers.get("set-cookie","").lower())
        self.assertNotIn(self.old,r.text)
        self.assertNotIn(self.new,r.text)
        saved=json.loads(self.credential.read_text(encoding="utf8"))
        self.assertEqual(saved["algorithm"],"scrypt-16384-8-1")
        self.assertNotIn(self.old,self.credential.read_text(encoding="utf8"))
        self.assertNotIn(self.new,self.credential.read_text(encoding="utf8"))
        self.assertEqual(initial_key,self.key.read_bytes())
        self.assertFalse(auth.valid_cookie(old_cookie))
        self.assertFalse(auth.password_matches("admin",self.old))
        self.assertTrue(auth.password_matches("admin",self.new))
        self.assertEqual(self.client.get("/api/sessions").status_code,401)
        self.assertEqual(self.login().status_code,401)
        self.assertEqual(self.login(self.new).status_code,200)
        self.assertEqual(self.client.get("/api/overview").status_code,200)

    def test_failed_store_write_preserves_current_password(self):
        self.assertEqual(self.login().status_code,200)
        with patch("app.auth.tempfile.mkstemp",side_effect=PermissionError("no write")):
            r=self.change()
        self.assertEqual(r.status_code,503)
        self.assertTrue(auth.password_matches("admin",self.old))

    def test_ui_modal_markers(self):
        src=Path(__file__).resolve().parents[1]/"app"/"static"
        html=(src/"index.html").read_text(encoding="utf8")
        js=(src/"app.js").read_text(encoding="utf8")
        self.assertIn('id="password-change-dialog"',html)
        for item in ("password-current","password-new","password-confirm","password-change-submit"):
            self.assertIn(f'id="{item}"',html)
        self.assertIn("/api/auth/change-password",js)
        self.assertIn("passwordDialog.showModal()",js)
        self.assertIn("current_password:current,new_password:next,confirm_password:confirm",js)
        self.assertNotIn("window.prompt(",js)

if __name__ == "__main__":
    unittest.main()
