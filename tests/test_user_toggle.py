"""Manual VLAN10 user toggle API tests: no network, no real service changes."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app
from app.logic import prepare_users


def fixture():
    userrows=[
        {"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-02000000001a","username":"demo_phone11","enabled":True,"vlan":10},
        {"uuid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","username":"host/LAB-DC01.ad.example.test","enabled":True,"vlan":10},
        {"uuid":"cccccccc-cccc-cccc-cccc-cccccccccccc","username":"host/LAB-DC02.ad.example.test","enabled":True,"vlan":10},
        {"uuid":"dddddddd-dddd-dddd-dddd-dddddddddddd","username":"guestwlan","enabled":True,"vlan":30},
        {"uuid":"eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee","username":"guest1","enabled":True,"vlan":None},
    ]
    snap={
        "source":"sanitized_export","as_of":datetime.now(timezone.utc).isoformat(),
        "sessions":[],"local_users":userrows,"portal_sessions":[],
        "users_collected":True,"portal_collected":True,
    }
    return snap,prepare_users(userrows),[],[]


class UserToggleAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client=TestClient(app,base_url="https://radius.example.test",follow_redirects=False)
    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        self.env=patch.dict(os.environ,{"BIX_ADMIN_AUTH_ENABLED":"0"})
        self.env.start()
        self.ready=patch("app.main.user_management_ready",return_value=True)
        self.ready.start()
        self.bundle=patch("app.main.bundle",side_effect=fixture)
        self.bundle.start()
        self.request={
            "uuid":"aaaaaaaa-aaaa-aaaa-aaaa-02000000001a",
            "username":"demo_phone11","expected_enabled":True,"enabled":False,
        }

    def tearDown(self):
        self.bundle.stop()
        self.ready.stop()
        self.env.stop()

    def post(self,body=None):
        return self.client.post("/api/users/set-enabled",json=body if body is not None else self.request,
                                headers={"Origin":"https://radius.example.test"})

    def test_disabled_channel_blocks_operation(self):
        with patch("app.main.user_management_ready",return_value=False),patch("app.main.subprocess.run") as call:
            self.assertEqual(self.post().status_code,503)
            call.assert_not_called()

    def test_live_snapshot_age_required(self):
        snap, users, _,_ = fixture()
        snap["as_of"]="2026-01-01T00:00:00Z"
        with patch("app.main.bundle",return_value=(snap,users,[],[])),patch("app.main.subprocess.run") as call:
            self.assertEqual(self.post().status_code,409)
            call.assert_not_called()

    def test_both_infrastructure_accounts_blocked(self):
        for name,uuid in [
            ("host/LAB-DC01.ad.example.test","bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            ("host/LAB-DC02.ad.example.test","cccccccc-cccc-cccc-cccc-cccccccccccc"),
        ]:
            with self.subTest(name=name),patch("app.main.subprocess.run") as call:
                r=self.post({**self.request,"uuid":uuid,"username":name})
                self.assertEqual(r.status_code,403)
                call.assert_not_called()

    def test_guest_and_portal_user_blocked(self):
        for name,uuid in [("guestwlan","dddddddd-dddd-dddd-dddd-dddddddddddd"),
                          ("guest1","eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")]:
            with self.subTest(name=name),patch("app.main.subprocess.run") as call:
                r=self.post({**self.request,"uuid":uuid,"username":name})
                self.assertEqual(r.status_code,403)
                call.assert_not_called()

    def test_wrong_uuid_expected_state_and_idempotent_request(self):
        variations=[
          ({**self.request,"uuid":"ffffffff-ffff-ffff-ffff-ffffffffffff"},403),
          ({**self.request,"expected_enabled":False,"enabled":True},409),
          ({**self.request,"enabled":True},400),
          ({**self.request,"uuid":"../../etc/passwd"},422),
        ]
        for body,expected in variations:
            with self.subTest(body=body),patch("app.main.subprocess.run") as call:
                self.assertEqual(self.post(body).status_code,expected)
                call.assert_not_called()

    def test_single_allowed_user_success_and_exact_ssh_payload(self):
        response={"ok":True,"result":"applied","username":"demo_phone11",
                  "uuid":self.request["uuid"],"enabled":False,
                  "radius_pid_unchanged":True}
        r=subprocess.CompletedProcess(args=[],returncode=0,stdout=json.dumps(response),stderr="")
        with patch("app.main.subprocess.run",return_value=r) as call:
            out=self.post()
            self.assertEqual(out.status_code,200,out.text)
            self.assertEqual(out.json()["enabled"],False)
            args=call.call_args
            self.assertIn("/run/secrets/bix_radius_user_toggle_key",args.args[0])
            self.assertIn("bixcore-radius-user-toggle",args.args[0])
            self.assertEqual(json.loads(args.kwargs["input"]),self.request)

    def test_rejected_or_unparseable_executor_response(self):
        for proc,status in [
          (subprocess.CompletedProcess([],1,json.dumps({"result":"error","reason":"STATE_CHANGED"}),""),409),
          (subprocess.CompletedProcess([],1,json.dumps({"result":"error","reason":"APPLY_FAILED_ROLLED_BACK"}),""),409),
          (subprocess.CompletedProcess([],0,"invalid json",""),502),
        ]:
            with self.subTest(status=status),patch("app.main.subprocess.run",return_value=proc):
                self.assertEqual(self.post().status_code,status)

    def test_read_only_users_remain_uneditable_without_management(self):
        with patch("app.main.user_management_ready",return_value=False):
            r=self.client.get("/api/users?category=wifi_device")
            self.assertEqual(r.status_code,200)
            self.assertFalse(any(x["editable"] for x in r.json()["items"]))
        r=self.client.get("/api/users?category=wifi_device")
        self.assertEqual(r.status_code,200)
        self.assertTrue(r.json()["items"][0]["editable"])
        r=self.client.get("/api/users?category=infrastructure")
        self.assertTrue(all(not x["editable"] for x in r.json()["items"]))

    def test_only_v10_account_eligible(self):
        root=Path(__file__).resolve().parents[1]
        php=(root/"deploy/opnsense/bixcore-radius-user-toggle.php").read_text(encoding="utf8")
        helper=(root/"deploy/opnsense/bixcore-radius-user-toggle.py").read_text(encoding="utf8")
        self.assertIn("VLAN_MISMATCH",php)
        self.assertIn("LAB-DC0[12]",php)
        self.assertIn("guestwlan",php)
        self.assertIn("PROTECTED_USER",helper)
        self.assertIn("signal.SIGHUP",helper)
        self.assertNotIn("radiusd restart",helper)
        self.assertNotIn("freeradius restart",helper)

if __name__=="__main__":
    unittest.main()
