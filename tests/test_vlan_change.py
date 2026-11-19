"""v0.8.0: permanent manual VLAN change, with no production mutation."""
from datetime import datetime, timezone
import ast
import re
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
from app.main import app
from app.logic import prepare_users, user_kind

ROOT=Path(__file__).resolve().parents[1]


def fixture():
    raw=[
        {"uuid":"aaaaaaaa-aaaa-aaaa-aaaa-02000000001a","username":"demo_phone11","enabled":True,"vlan":10},
        {"uuid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","username":"Secondary_15TPro","enabled":True,"vlan":20},
        {"uuid":"cccccccc-cccc-cccc-cccc-cccccccccccc","username":"Lenovo","enabled":False,"vlan":10},
        {"uuid":"dddddddd-dddd-dddd-dddd-dddddddddddd","username":"guestwlan","enabled":True,"vlan":30},
        {"uuid":"eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee","username":"guest123","enabled":True,"vlan":None},
        {"uuid":"ffffffff-ffff-ffff-ffff-ffffffffffff","username":"host/LAB-DC01.ad.example.test","enabled":True,"vlan":10},
        {"uuid":"10101010-1010-1010-1010-101010101010","username":"host/LAB-DC02.ad.example.test","enabled":True,"vlan":20},
    ]
    snap={"source":"sanitized_export","as_of":datetime.now(timezone.utc).isoformat(),
          "sessions":[],"local_users":raw,"portal_sessions":[],
          "users_collected":True,"portal_collected":True}
    return snap,prepare_users(raw),[],[]


class UserVlanTests(unittest.TestCase):
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
        self.data=patch("app.main.bundle",side_effect=fixture)
        self.data.start()
        self.body={
           "uuid":"aaaaaaaa-aaaa-aaaa-aaaa-02000000001a",
           "username":"demo_phone11","expected_vlan":10,"vlan":30,"expected_enabled":True
        }
    def tearDown(self):
        self.data.stop()
        self.ready.stop()
        self.env.stop()
    def post(self,body=None):
        return self.client.post("/api/users/set-vlan",
          headers={"Origin":"https://radius.example.test"},
          json=self.body if body is None else body)

    def test_users_with_any_vlan_remain_radius_users(self):
        self.assertEqual(user_kind("Secondary_15TPro",20),"wifi_device")
        self.assertEqual(user_kind("demo_phone11",30),"wifi_device")
        self.assertEqual(user_kind("guestwlan",30),"guest_wifi")
        self.assertEqual(user_kind("guest123",None),"portal_user")
        self.assertEqual(user_kind("host/LAB-DC02.ad.example.test",20),"infrastructure")
        r=self.client.get("/api/users?category=wifi_device")
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json()["total"],3)
        self.assertTrue(all(x["editable"] for x in r.json()["items"]))

    def test_restricted_channel_off(self):
        with patch("app.main.user_management_ready",return_value=False),patch("app.main.subprocess.run") as run:
            self.assertEqual(self.post().status_code,503)
            run.assert_not_called()

    def test_old_snapshot_rejected(self):
        snap,users,_,_=fixture()
        snap["as_of"]="2026-01-01T00:00:00Z"
        with patch("app.main.bundle",return_value=(snap,users,[],[])),patch("app.main.subprocess.run") as run:
            self.assertEqual(self.post().status_code,409)
            run.assert_not_called()

    def test_protected_users_denied(self):
        cases=[
           ("guestwlan","dddddddd-dddd-dddd-dddd-dddddddddddd"),
           ("guest123","eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
           ("host/LAB-DC01.ad.example.test","ffffffff-ffff-ffff-ffff-ffffffffffff"),
           ("host/LAB-DC02.ad.example.test","10101010-1010-1010-1010-101010101010"),
        ]
        for name,uuid in cases:
            with self.subTest(name=name),patch("app.main.subprocess.run") as run:
                r=self.post({**self.body,"username":name,"uuid":uuid})
                self.assertEqual(r.status_code,403,r.text)
                run.assert_not_called()

    def test_invalid_range_or_stale_identity(self):
        for body,expected in [
            ({**self.body,"vlan":0},422),
            ({**self.body,"vlan":4095},422),
            ({**self.body,"vlan":10},400),
            ({**self.body,"vlan":True},422),
            ({**self.body,"expected_vlan":11},403),
            ({**self.body,"username":"SomeoneElse"},403),
            ({**self.body,"uuid":"../../etc/passwd"},422),
            ({**self.body,"expected_enabled":False},409),
        ]:
            with self.subTest(case=body),patch("app.main.subprocess.run") as run:
                self.assertEqual(self.post(body).status_code,expected)
                run.assert_not_called()

    def test_valid_change_and_exact_ssh_request(self):
        reply={"ok":True,"result":"applied","uuid":self.body["uuid"],
               "username":"demo_phone11","vlan":30,"radius_pid_unchanged":True}
        result=subprocess.CompletedProcess([],0,json.dumps(reply),"")
        with patch("app.main.subprocess.run",return_value=result) as run:
            r=self.post()
            self.assertEqual(r.status_code,200,r.text)
            self.assertEqual(r.json()["vlan"],30)
            cmd=run.call_args.args[0]
            self.assertIn("bixcore-radius-user-toggle",cmd)
            self.assertIn("/run/secrets/bix_radius_user_toggle_key",cmd)
            self.assertEqual(json.loads(run.call_args.kwargs["input"]),{
                "action":"set_vlan",**self.body})

    def test_disabled_user_can_be_assigned_vlan(self):
        body={"uuid":"cccccccc-cccc-cccc-cccc-cccccccccccc",
              "username":"Lenovo","expected_vlan":10,"vlan":20,"expected_enabled":False}
        response={"ok":True,"result":"applied","uuid":body["uuid"],
                  "username":"Lenovo","vlan":20}
        with patch("app.main.subprocess.run",return_value=subprocess.CompletedProcess([],0,json.dumps(response),"")):
            self.assertEqual(self.post(body).status_code,200)

    def test_executor_error_handling(self):
        for result,expected in [
           (subprocess.CompletedProcess([],1,json.dumps({"result":"error","reason":"VLAN_CHANGED"}),""),409),
           (subprocess.CompletedProcess([],1,json.dumps({"result":"error","reason":"APPLY_FAILED_ROLLED_BACK"}),""),409),
           (subprocess.CompletedProcess([],0,"garbage",""),502),
        ]:
            with self.subTest(code=expected),patch("app.main.subprocess.run",return_value=result):
                self.assertEqual(self.post().status_code,expected)

    def test_authorize_vlan_parser(self):
        src=ROOT/"deploy"/"opnsense"/"bixcore-radius-user-toggle.py"
        # Extract pure parsers from the FreeBSD-only module (Windows has no fcntl).
        tree=ast.parse(src.read_text(encoding="utf8"))
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)
               and n.name in ("vlan_in_authorize","present_in_authorize")]
        self.assertEqual(len(nodes),2)
        module=ast.Module(body=nodes,type_ignores=[])
        env={"re":re,"AUTHORIZE":None}
        exec(compile(module,str(src),"exec"),env)
        with tempfile.TemporaryDirectory() as temp:
            file=Path(temp)/"authorize"
            file.write_text('''demo_phone11 Cleartext-Password := "not-a-real-secret"
       Tunnel-Type = VLAN,
       Tunnel-Medium-Type = IEEE-802,
       Tunnel-Private-Group-Id = 30,
       Framed-Protocol = PPP

otheruser Cleartext-Password := "other"
       Tunnel-Private-Group-Id = 10,

''',encoding="utf8")
            env["AUTHORIZE"]=file
            self.assertTrue(env["vlan_in_authorize"]("demo_phone11",30))
            self.assertFalse(env["vlan_in_authorize"]("demo_phone11",10))
            self.assertFalse(env["vlan_in_authorize"]("missing",30))
            self.assertTrue(env["present_in_authorize"]("demo_phone11"))

    def test_php_and_frontend_have_strict_vlan_guards(self):
        php=(ROOT/"deploy/opnsense/bixcore-radius-user-toggle.php").read_text(encoding="utf8")
        helper=(ROOT/"deploy/opnsense/bixcore-radius-user-toggle.py").read_text(encoding="utf8")
        ui=(ROOT/"app/static/app.js").read_text(encoding="utf8")
        page=(ROOT/"app/static/index.html").read_text(encoding="utf8")
        self.assertIn("'set_vlan'",php)
        self.assertIn("4094",php)
        self.assertIn("guestwlan",php)
        self.assertIn("LAB-DC0[12]",php)
        self.assertIn("signal.SIGHUP",helper)
        self.assertIn("render_check_hup_vlan(name,new,enabled,pid)",helper)
        self.assertIn("/api/users/set-vlan",ui)
        self.assertIn('id="user-vlan-dialog"',page)
        self.assertNotIn("window.prompt(",ui)

if __name__=="__main__":
    unittest.main()
