"""Captive Portal v0.9.0 restricted management tests; no real mutations."""
import ast
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app
from app.logic import prepare_users,prepare_portal_sessions

ROOT=Path(__file__).resolve().parents[1]
UUID_A="aaaaaaaa-aaaa-aaaa-aaaa-02000000001a"
UUID_B="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
UUID_C="cccccccc-cccc-cccc-cccc-cccccccccccc"
UUID_DC="dddddddd-dddd-dddd-dddd-dddddddddddd"
UUID_WIFI="eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
SID="Gb.ckGzSqYqP0TfL7o997+A=="


def fixture():
    users=[
        {"uuid":UUID_A,"username":"NewGuestOne","enabled":True,"vlan":None},
        {"uuid":UUID_B,"username":"NewGuestTwo","enabled":False,"vlan":None},
        {"uuid":UUID_C,"username":"guestwlan","enabled":True,"vlan":30},
        {"uuid":UUID_DC,"username":"host/LAB-DC01.ad.example.test","enabled":True,"vlan":10},
        {"uuid":UUID_WIFI,"username":"AnotherPhone","enabled":True,"vlan":20},
    ]
    portals=[
        {"sessionId":SID,"zoneid":"0","userName":"NewGuestOne",
         "ipAddress":"203.0.113.108","macAddress":"02:00:00:00:00:23",
         "authenticated_via":"Local FreeRADIUS","startTime":1730000000,
         "last_accessed":1730000001}
    ]
    snap={"source":"sanitized_export","as_of":datetime.now(timezone.utc).isoformat(),
          "sessions":[],"local_users":users,"portal_sessions":portals,
          "users_collected":True,"portal_collected":True}
    return snap,prepare_users(users),[],prepare_portal_sessions(portals,datetime.now(timezone.utc))


class PortalControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client=TestClient(app,base_url="https://radius.example.test",follow_redirects=False)
    @classmethod
    def tearDownClass(cls):
        cls.client.close()
    def setUp(self):
        self.env=patch.dict(os.environ,{"BIX_ADMIN_AUTH_ENABLED":"0",
           "BIX_RADIUS_GUEST_PORTAL_ZONES":"0"})
        self.env.start()
        self.ready=patch("app.main.user_management_ready",return_value=True)
        self.ready.start()
        self.bundle=patch("app.main.bundle",side_effect=fixture)
        self.bundle.start()
        self.enabled={"uuid":UUID_A,"username":"NewGuestOne",
                      "expected_enabled":True,"enabled":False}
        self.disconnect={"uuid":UUID_A,"username":"NewGuestOne",
                         "expected_enabled":True,"zone_id":"0","session_id":SID,
                         "ip":"203.0.113.108","mac":"02:00:00:00:00:23"}
    def tearDown(self):
        self.bundle.stop();self.ready.stop();self.env.stop()
    def post(self,path,body):
        return self.client.post(path,json=body,headers={"Origin":"https://radius.example.test"})

    def test_new_arbitrary_no_vlan_accounts_show_in_portal(self):
        data=self.client.get("/api/portal-users").json()
        self.assertEqual(data["total"],2)
        names={u["username"]:u for u in data["items"]}
        self.assertEqual(set(names),{"NewGuestOne","NewGuestTwo"})
        self.assertTrue(all(u["editable"] for u in names.values()))
        self.assertTrue(names["NewGuestOne"]["disconnect_available"])
        self.assertFalse(names["NewGuestTwo"]["disconnect_available"])
        self.assertEqual(names["NewGuestOne"]["authorization_status"],"authorized")
        self.assertEqual(names["NewGuestTwo"]["authorization_status"],"not_authorized")
        self.assertEqual(self.client.get("/api/users?category=wifi_device").json()["total"],1)

    def test_disabled_account_can_be_enabled(self):
        body={"uuid":UUID_B,"username":"NewGuestTwo","expected_enabled":False,"enabled":True}
        answer={"result":"applied","uuid":UUID_B,"enabled":True}
        with patch("app.main.subprocess.run",return_value=subprocess.CompletedProcess([],0,json.dumps(answer),"")) as cmd:
            r=self.post("/api/portal-users/set-enabled",body)
            self.assertEqual(r.status_code,200,r.text)
            self.assertIn("portal_enabled",cmd.call_args.kwargs["input"])

    def test_portal_toggle_success(self):
        answer={"result":"applied","uuid":UUID_A,"enabled":False}
        with patch("app.main.subprocess.run",return_value=subprocess.CompletedProcess([],0,json.dumps(answer),"")) as cmd:
            r=self.post("/api/portal-users/set-enabled",self.enabled)
            self.assertEqual(r.status_code,200,r.text)
            self.assertFalse(r.json()["enabled"])
            payload=json.loads(cmd.call_args.kwargs["input"])
            self.assertEqual(payload,{"action":"portal_enabled",**self.enabled})
            self.assertIn("bixcore-radius-user-toggle",cmd.call_args.args[0])

    def test_protected_and_vlan_users_cannot_toggle(self):
        cases=[
            (UUID_C,"guestwlan"),(UUID_DC,"host/LAB-DC01.ad.example.test"),
            (UUID_WIFI,"AnotherPhone"),(UUID_A,"doesnotexist"),
        ]
        for uid,name in cases:
            with self.subTest(name=name),patch("app.main.subprocess.run") as cmd:
                r=self.post("/api/portal-users/set-enabled",
                            {**self.enabled,"uuid":uid,"username":name})
                self.assertEqual(r.status_code,403,r.text)
                cmd.assert_not_called()

    def test_stale_snapshot_and_stale_enabled_denied(self):
        with patch("app.main.subprocess.run") as cmd:
            r=self.post("/api/portal-users/set-enabled",
                        {**self.enabled,"expected_enabled":False,"enabled":True})
            self.assertEqual(r.status_code,409)
            cmd.assert_not_called()
        snap,users,sessions,portal=fixture()
        snap["as_of"]="2026-01-01T00:00:00Z"
        with patch("app.main.bundle",return_value=(snap,users,sessions,portal)):
            self.assertEqual(self.post("/api/portal-users/set-enabled",self.enabled).status_code,409)

    def test_noop_and_disabled_management(self):
        with patch("app.main.subprocess.run") as cmd:
            self.assertEqual(self.post("/api/portal-users/set-enabled",
                {**self.enabled,"enabled":True}).status_code,400)
            cmd.assert_not_called()
        with patch("app.main.user_management_ready",return_value=False):
            self.assertEqual(self.post("/api/portal-users/set-enabled",self.enabled).status_code,503)

    def test_disconnect_one_exact_session(self):
        answer={"result":"disconnected","session_id":SID,"zone_id":"0"}
        with patch("app.main.subprocess.run",return_value=subprocess.CompletedProcess([],0,json.dumps(answer),"")) as cmd:
            r=self.post("/api/portal-sessions/disconnect",self.disconnect)
            self.assertEqual(r.status_code,200,r.text)
            self.assertEqual(json.loads(cmd.call_args.kwargs["input"]),
                             {"action":"portal_disconnect","zone_id":"0","session_id":SID,
                              "username":"NewGuestOne","ip":"203.0.113.108",
                              "mac":"02:00:00:00:00:23"})

    def test_disconnect_bad_session_zone_or_account_denied(self):
        for variant,status in [
            ({"zone_id":"1"},403),({"zone_id":"xx"},400),
            ({"session_id":"invalid"},409),({"ip":"203.0.113.109"},409),
            ({"mac":"02:00:00:00:00:01"},409),({"username":"other"},403),
            ({"uuid":UUID_WIFI,"username":"AnotherPhone"},403),
        ]:
            with self.subTest(v=variant),patch("app.main.subprocess.run") as cmd:
                r=self.post("/api/portal-sessions/disconnect",
                            {**self.disconnect,**variant})
                self.assertEqual(r.status_code,status,r.text)
                cmd.assert_not_called()

    def test_no_automatic_disconnect_on_disable(self):
        src=(ROOT/"app/static/app.js").read_text(encoding="utf8")
        self.assertIn("/api/portal-users/set-enabled",src)
        self.assertIn("/api/portal-sessions/disconnect",src)
        self.assertIn('id="portal-action-dialog"',
                      (ROOT/"app/static/index.html").read_text(encoding="utf8"))
        php=(ROOT/"deploy/opnsense/bixcore-radius-user-toggle.php").read_text(encoding="utf8")
        self.assertIn("portal_enabled",php)
        self.assertIn("if ($oldVlan!=='')",php)

    def test_executor_portal_disconnect_scope_and_no_reload(self):
        src=(ROOT/"deploy/opnsense/bixcore-radius-user-toggle.py").read_text(encoding="utf8")
        tree=ast.parse(src)
        defs={x.name:x for x in tree.body if isinstance(x,ast.FunctionDef)}
        self.assertIn("execute_portal_disconnect",defs)
        segment=ast.get_source_segment(src,defs["execute_portal_disconnect"])
        self.assertIn('PORTAL_ZONES',segment)
        self.assertIn('"Admin-Reset"',segment)
        self.assertIn('portal_live_sessions()',segment)
        self.assertNotIn('signal.SIGHUP',segment)
        self.assertNotIn('configctl","template"',segment)

if __name__=="__main__":
    unittest.main()
