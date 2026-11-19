import os
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app,management_ready

class TestUniFiDisconnect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client=TestClient(app)
    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_no_management_channel(self):
        with patch.dict(os.environ,{"BIX_UNIFI_DISCONNECT_ENABLED":"0"}):
            r=self.client.post("/api/unifi/disconnect",
                json={"nas_ip":"192.0.2.4","session_id":"abc","mac":"02-00-00-00-00-22"},
                headers={"Origin":"https://radius.example.test"})
        self.assertEqual(r.status_code,503)

    def test_no_origin_rejected_without_pin(self):
        with patch("app.main.management_ready",return_value=True):
            r=self.client.post("/api/unifi/disconnect",
                json={"nas_ip":"192.0.2.4","session_id":"abc","mac":"02-00-00-00-00-22"})
        self.assertEqual(r.status_code,403)

    def test_wrong_origin_rejected_without_pin(self):
        with patch("app.main.management_ready",return_value=True):
            r=self.client.post("/api/unifi/disconnect",
                json={"nas_ip":"192.0.2.4","session_id":"abc","mac":"02-00-00-00-00-22"},
                headers={"Origin":"https://untrusted.example"})
        self.assertEqual(r.status_code,403)

    def test_management_ready_does_not_require_pin_file(self):
        with patch.dict(os.environ,{"BIX_UNIFI_DISCONNECT_ENABLED":"1"}),patch("app.main.Path.is_file",return_value=True) as f:
            self.assertTrue(management_ready())
            self.assertEqual(f.call_count,2)

    def test_no_pin_needed_but_demo_still_cannot_disconnect(self):
        with patch("app.main.management_ready",return_value=True),patch("app.main.subprocess.run") as run:
            r=self.client.post("/api/unifi/disconnect",
                json={"nas_ip":"192.0.2.4","session_id":"session-demo","mac":"02-00-00-00-00-22"},
                headers={"Origin":"https://radius.example.test"})
        self.assertEqual(r.status_code,409)
        run.assert_not_called()

    def test_omada_refused_without_pin(self):
        with patch("app.main.management_ready",return_value=True),patch("app.main.subprocess.run") as run:
            r=self.client.post("/api/unifi/disconnect",
                json={"nas_ip":"192.0.2.6","session_id":"a123","mac":"02-00-00-00-00-22"},
                headers={"Origin":"https://radius.example.test"})
        self.assertEqual(r.status_code,400)
        run.assert_not_called()

if __name__=="__main__":
    unittest.main()
