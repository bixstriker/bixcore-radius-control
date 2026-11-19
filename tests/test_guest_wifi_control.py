"""v0.10.0 guest Wi-Fi master control; all tests synthetic and non-destructive."""
from datetime import datetime,timezone,timedelta
import ast
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
import subprocess

from fastapi.testclient import TestClient
from app.main import app
from app.logic import build_guest_wifi_batch,prepare_sessions,prepare_users

ROOT=Path(__file__).resolve().parents[1]
GUEST_UUID="aaaaaaaa-aaaa-aaaa-aaaa-02000000001a"


def fixture():
    now=datetime.now(timezone.utc)
    current=(now-timedelta(minutes=1)).isoformat()
    earlier=(now-timedelta(minutes=25)).isoformat()
    raw=[
        {"uuid":GUEST_UUID,"username":"guestwlan","vlan":30,"enabled":True},
        {"uuid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","username":"demo_phone11","vlan":30,"enabled":True},
        {"uuid":"cccccccc-cccc-cccc-cccc-cccccccccccc","username":"GuestVisitor","vlan":None,"enabled":True},
        {"uuid":"dddddddd-dddd-dddd-dddd-dddddddddddd","username":"host/LAB-DC01.ad.example.test","vlan":10,"enabled":True},
    ]
    def rec(name,nas,sid,mac,timestamp):
        return {"username":name,"nasipaddress":nas,"acctsessionid":sid,
                "callingstationid":mac,"acctstarttime":earlier,"acctupdatetime":timestamp,
                "acctstoptime":None}
    rows=[
        rec("guestwlan","192.0.2.4","sid-A","02-00-00-00-00-1B",current),
        rec("guestwlan","192.0.2.5","sid-B","02-00-00-00-00-1C",current),
        rec("guestwlan","192.0.2.6","sid-Omada","02-00-00-00-00-1D",current),
        rec("GuestVisitor","127.0.0.1","sid-Portal","02-00-00-00-00-1E",current),
        rec("demo_phone11","192.0.2.4","sid-Normal","02-00-00-00-00-1F",current),
        rec("guestwlan","192.0.2.4","sid-Stale","02-00-00-00-00-20",earlier),
        rec("guestwlan","192.0.2.4","sid-OldAP","02-00-00-00-00-1C",
            (now-timedelta(minutes=2)).isoformat()),
    ]
    users=prepare_users(raw)
    sessions=prepare_sessions(rows,users,now)
    snap={"source":"sanitized_export","as_of":now.isoformat(),"local_users":raw,
          "sessions":rows,"portal_sessions":[],"users_collected":True,"portal_collected":True}
    return snap,users,sessions,[]


class GuestWiFiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client=TestClient(app,base_url="https://radius.example.test",follow_redirects=False)
    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        self.env=patch.dict(os.environ,{"BIX_ADMIN_AUTH_ENABLED":"0"})
        self.env.start()
        self.source=fixture()
        self.bundle=patch("app.main.bundle",return_value=self.source)
        self.bundle.start()
        self.management=patch("app.main.management_ready",return_value=True)
        self.management.start()
        self.control=patch("app.main.user_management_ready",return_value=True)
        self.control.start()

    def tearDown(self):
        self.control.stop();self.management.stop();self.bundle.stop();self.env.stop()

    def post(self,path,body):
        return self.client.post(path,json=body,headers={"Origin":"https://radius.example.test"})

    def preview(self):
        return self.client.get("/api/guest-wifi/preview").json()

    def test_preview_only_exact_shared_wifi_identity(self):
        result=self.preview()
        self.assertEqual(result["plan"]["count"],2)
        self.assertEqual(result["guest"]["vlan"],30)
        self.assertTrue(result["guest"]["enabled"])
        self.assertEqual(result["plan"]["omada_unsupported"],1)
        self.assertEqual(result["plan"]["skipped_stale"],1)
        self.assertEqual(result["plan"]["skipped_roaming"],1)
        self.assertTrue(result["plan"]["portal_untouched"])
        self.assertEqual({x["nas_ip"] for x in result["plan"]["targets"]},
                         {"192.0.2.4","192.0.2.5"})
        self.assertNotIn("sid-Normal",str(result))
        self.assertNotIn("sid-Portal",str(result))
        guest=self.client.get("/api/users?category=guest_wifi").json()["items"][0]
        self.assertTrue(guest["editable"])

    def test_fingerprint_detects_session_changes(self):
        snap,users,sessions,_=fixture()
        one=build_guest_wifi_batch(sessions,snap["as_of"])
        two=build_guest_wifi_batch(sessions,snap["as_of"]+"-changed")
        self.assertNotEqual(one["fingerprint"],two["fingerprint"])
        sessions[0]["session_id"]="different"
        three=build_guest_wifi_batch(sessions,snap["as_of"])
        self.assertNotEqual(one["fingerprint"],three["fingerprint"])

    def test_guest_enable_then_disable_exact_action(self):
        body={"uuid":GUEST_UUID,"expected_enabled":True,"enabled":False}
        reply={"result":"applied","uuid":GUEST_UUID,"username":"guestwlan","enabled":False}
        proc=subprocess.CompletedProcess([],0,json.dumps(reply),"")
        with patch("app.main.subprocess.run",return_value=proc) as runner:
            result=self.post("/api/guest-wifi/set-enabled",body)
            self.assertEqual(result.status_code,200,result.text)
            self.assertEqual(json.loads(runner.call_args.kwargs["input"]),
                             {"action":"guest_enabled",**body,"username":"guestwlan"})
        new_snap,users,sessions,portals=fixture()
        for user in users:
            if user["username"]=="guestwlan":user["enabled"]=False
        with patch("app.main.bundle",return_value=(new_snap,users,sessions,portals)):
            body={"uuid":GUEST_UUID,"expected_enabled":False,"enabled":True}
            reply={"result":"applied","uuid":GUEST_UUID,"username":"guestwlan","enabled":True}
            with patch("app.main.subprocess.run",return_value=subprocess.CompletedProcess([],0,json.dumps(reply),"")):
                self.assertEqual(self.post("/api/guest-wifi/set-enabled",body).status_code,200)

    def test_guest_action_rejects_foreign_uuid_stale_or_noop(self):
        for body,status in [
            ({"uuid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb","expected_enabled":True,"enabled":False},409),
            ({"uuid":GUEST_UUID,"expected_enabled":False,"enabled":True},409),
            ({"uuid":GUEST_UUID,"expected_enabled":True,"enabled":True},400),
            ({"uuid":"not-a-uuid","expected_enabled":True,"enabled":False},422),
        ]:
            with self.subTest(body=body),patch("app.main.subprocess.run") as runner:
                self.assertEqual(self.post("/api/guest-wifi/set-enabled",body).status_code,status)
                runner.assert_not_called()

    def test_guest_disabled_channel_blocks_action(self):
        with patch("app.main.user_management_ready",return_value=False),patch("app.main.subprocess.run") as runner:
            self.assertEqual(self.post("/api/guest-wifi/set-enabled",
                {"uuid":GUEST_UUID,"expected_enabled":True,"enabled":False}).status_code,503)
            runner.assert_not_called()

    def test_batch_exact_consent_and_live_target_set(self):
        preview=self.preview()
        body={"uuid":GUEST_UUID,"expected_enabled":True,
              "fingerprint":preview["plan"]["fingerprint"],
              "expected_count":preview["plan"]["count"],
              "confirmation":"disconnect_guest_wifi"}
        def ack(target):
            return {"nas_ip":target["nas_ip"],"session_id":target["session_id"],
                    "mac":target["mac"],"result":"ack","reason":""}
        with patch("app.main.disconnect_one_guest_unifi",side_effect=ack) as runner:
            result=self.post("/api/guest-wifi/disconnect-all",body)
            self.assertEqual(result.status_code,200,result.text)
            self.assertEqual(result.json()["ack"],2)
            self.assertTrue(result.json()["portal_sessions_untouched"])
            self.assertTrue(all(x.args[0]["nas_ip"]!="127.0.0.1" for x in runner.call_args_list))
            self.assertEqual({x.args[0]["mac"] for x in runner.call_args_list},
                            {"02000000001b","02000000001c"})

    def test_batch_noop_invalid_fingerprint_and_count(self):
        preview=self.preview()
        body={"uuid":GUEST_UUID,"expected_enabled":True,
              "fingerprint":preview["plan"]["fingerprint"],
              "expected_count":2,"confirmation":"disconnect_guest_wifi"}
        variants=[
           ({**body,"fingerprint":"a"*64},409),
           ({**body,"expected_count":3},409),
           ({**body,"confirmation":"no"},400),
           ({**body,"uuid":"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},409),
           ({**body,"fingerprint":"xx"},422),
        ]
        for variant,status in variants:
            with self.subTest(variant=variant),patch("app.main.disconnect_one_guest_unifi") as runner:
                self.assertEqual(self.post("/api/guest-wifi/disconnect-all",variant).status_code,status)
                runner.assert_not_called()

    def test_partial_ack_is_reported_not_success(self):
        preview=self.preview()
        body={"uuid":GUEST_UUID,"expected_enabled":True,
              "fingerprint":preview["plan"]["fingerprint"],
              "expected_count":2,"confirmation":"disconnect_guest_wifi"}
        def conditional(t):
            return {**t,"result":"ack" if t["session_id"]=="sid-A" else "nak","reason":""}
        with patch("app.main.disconnect_one_guest_unifi",side_effect=conditional):
            result=self.post("/api/guest-wifi/disconnect-all",body)
            self.assertEqual(result.status_code,200)
            self.assertFalse(result.json()["ok"])
            self.assertEqual((result.json()["ack"],result.json()["nak"]),(1,1))

    def test_live_accounting_username_guard(self):
        src=(ROOT/"deploy/opnsense/bixcore-unifi-disconnect.py").read_text(encoding="utf8")
        tree=ast.parse(src)
        selected=[n for n in tree.body if isinstance(n,ast.FunctionDef)
                  and n.name in ("normmac","accounting")]
        self.assertEqual(len(selected),2)
        scope={"re":re,"sqlite3":sqlite3,"time":time,"ValueError":ValueError,"DB":""}
        exec(compile(ast.Module(body=selected,type_ignores=[]),"<helper>","exec"),scope)
        with tempfile.TemporaryDirectory() as temp:
            file=Path(temp)/"acct.sqlite"
            db=sqlite3.connect(file)
            db.execute("""CREATE TABLE radacct (radacctid INTEGER PRIMARY KEY,username TEXT,
                         nasipaddress TEXT,acctsessionid TEXT,callingstationid TEXT,
                         acctstarttime INTEGER,acctupdatetime INTEGER,acctstoptime INTEGER)""")
            db.execute("""INSERT INTO radacct(username,nasipaddress,acctsessionid,callingstationid,
                         acctstarttime,acctupdatetime,acctstoptime)
                         VALUES (?,?,?,?,?,?,NULL)""",
                         ("AnotherPhone","192.0.2.4","sid-A","02-00-00-00-00-1B",
                          int(time.time())-100,int(time.time())-30))
            db.commit();db.close()
            scope["DB"]=str(file)
            with self.assertRaisesRegex(ValueError,"ACCOUNTING_USERNAME_CHANGED"):
                scope["accounting"]("192.0.2.4","sid-A","02000000001b","guestwlan")
            scope["accounting"]("192.0.2.4","sid-A","02000000001b",None)

    def test_guest_vlan_locked_in_opnsense_model(self):
        php=(ROOT/"deploy/opnsense/bixcore-radius-user-toggle.php").read_text(encoding="utf8")
        helper=(ROOT/"deploy/opnsense/bixcore-radius-user-toggle.py").read_text(encoding="utf8")
        self.assertIn("$oldVlan!=='30'",php)
        self.assertIn("$name!=='guestwlan'",php)
        self.assertIn('vlan!="30"',helper)
        self.assertIn("execute_guest_enabled",helper)
        self.assertIn('render_check_hup("guestwlan",wanted,pid)',helper)
        self.assertNotIn("radiusd restart",helper)

if __name__=="__main__":unittest.main()
