"""Multi-port Omada 802.1X tests: no production traffic."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from subprocess import CompletedProcess
import os
import json

from app import omada_wired, main
from tests.test_omada_wired_pilot import helper, SESSION, ORIGIN
from fastapi.testclient import TestClient

MAC2 = "020000000011"
USER2 = "host/Another.ad.example.test"
T = 1795094000

class MultiPortTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "accounting.db")
        self.db = sqlite3.connect(self.path)
        self.db.execute("""CREATE TABLE radacct(
            radacctid INTEGER PRIMARY KEY, username TEXT,
            callingstationid TEXT, acctsessionid TEXT, nasportid TEXT,
            acctupdatetime INTEGER, acctstarttime INTEGER,
            nasipaddress TEXT, acctstoptime INTEGER, acctterminatecause TEXT)""")
        self.add(1, "0000002C", "02-00-00-00-00-10", helper.PILOT_USERNAME, 2, T-100)
        self.add(2, "0000002E", "02-00-00-00-00-11", USER2, 3, T-80)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def add(self, row, sid, mac, username, port, started, stopped=None):
        self.db.execute("INSERT INTO radacct VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (row,username,mac,sid,str(port),started,started,
                         "192.0.2.6",stopped,""))
        self.db.commit()

    def test_second_port_is_independently_selected(self):
        a=helper.verify_accounting("0000002C", now=T, db_path=self.path, mac=helper.PILOT_MAC)
        b=helper.verify_accounting("0000002E", now=T, db_path=self.path, mac=MAC2)
        self.assertEqual((a["port"],a["row_id"]),("2",1))
        self.assertEqual((b["port"],b["row_id"]),("3",2))
        self.assertEqual(b["username"],USER2)

    def test_packet_targets_correct_port_and_identity(self):
        packet,_=helper.build_request("0000002E",b"test-secret-xyz",8,
            port=3,mac=MAC2,username=USER2)
        offset=20; attrs={}
        while offset<len(packet):
            code,length=packet[offset:offset+2]
            attrs[code]=packet[offset+2:offset+length]
            offset+=length
        self.assertEqual(int.from_bytes(attrs[5],"big"),3)
        self.assertEqual(attrs[1].decode(),USER2)
        self.assertEqual(attrs[31].decode(),"02-00-00-00-00-11")
        self.assertNotIn(44,attrs)

    def test_second_port_cleanup_never_closes_first(self):
        before=helper.verify_accounting("0000002E",now=T,db_path=self.path,mac=MAC2)
        self.add(3,"0000002F","02-00-00-00-00-11",USER2,3,T+2)
        result=helper.close_acked_predecessor("0000002E",before,T,db_path=self.path)
        self.assertEqual(result["cleanup"],"closed")
        self.assertEqual(result["new_session_id"],"0000002F")
        rows=self.db.execute("SELECT radacctid,acctstoptime FROM radacct ORDER BY radacctid").fetchall()
        self.assertEqual(rows,[(1,None),(2,T+2),(3,None)])

    def test_cross_port_new_start_never_closes_old(self):
        before=helper.verify_accounting("0000002E",now=T,db_path=self.path,mac=MAC2)
        self.add(3,"0000002F","02-00-00-00-00-11",USER2,4,T+2)
        self.assertEqual(helper.close_acked_predecessor("0000002E",before,T,
            db_path=self.path)["cleanup"],"waiting_new_start")
        self.assertIsNone(self.db.execute("SELECT acctstoptime FROM radacct WHERE radacctid=2").fetchone()[0])

    def test_same_mac_on_other_fresh_port_is_rejected(self):
        self.add(3,"00000030","02-00-00-00-00-11",USER2,4,T-4)
        with self.assertRaisesRegex(ValueError,"CLIENT_MOVED_PORT"):
            helper.verify_accounting("0000002E",now=T,db_path=self.path,mac=MAC2)

    def test_other_client_reuses_target_port_is_rejected(self):
        self.add(3,"00000030","02-00-00-00-00-02","intruder",3,T-4)
        with self.assertRaisesRegex(ValueError,"PORT_NOT_EXCLUSIVELY_CLIENT"):
            helper.verify_accounting("0000002E",now=T,db_path=self.path,mac=MAC2)

    def test_same_sid_other_mac_and_port_still_unique(self):
        self.add(3,"0000002E","02-00-00-00-00-02","another",4,T-4)
        b=helper.verify_accounting("0000002E",now=T,db_path=self.path,mac=MAC2)
        self.assertEqual(b["port"],"3")

    def test_request_fails_closed_if_mac_does_not_match_session(self):
        a=helper.parse_request(json.dumps({"nas_ip":"192.0.2.6",
            "session_id":"0000002E","mac":"02-00-00-00-00-11"}).encode())
        self.assertEqual(a,("192.0.2.6","0000002E",MAC2))
        with self.assertRaisesRegex(ValueError,"SESSION_NOT_UNIQUE"):
            helper.verify_accounting("0000002E",now=T,db_path=self.path,mac=helper.PILOT_MAC)

    def test_per_client_latest_not_globally_latest(self):
        s1=dict(SESSION,mac="02-00-00-00-00-10",session_id="0000002C",
                started_at="2026-11-19T10:00:00Z")
        s2=dict(SESSION,mac="02-00-00-00-00-11",session_id="0000002E",
                username=USER2,started_at="2026-11-19T10:10:00Z")
        newest=omada_wired.latest_sessions([s1,s2])
        self.assertIs(newest[("192.0.2.6",helper.PILOT_MAC)],s1)
        self.assertIs(newest[("192.0.2.6",MAC2)],s2)

    def test_web_second_client_command_target(self):
        s=dict(SESSION,mac="02-00-00-00-00-11",session_id="0000002E",
               username=USER2,started_at="2026-11-19T10:10:00Z")
        main._OMADA_WIRED_LAST_ATTEMPT=0
        with TestClient(main.app) as client, \
            patch.dict(os.environ,{"BIX_OMADA_WIRED_ENABLED":"1"}), \
            patch.object(main.control_gateway,"available",return_value=True), \
            patch.object(main,"bundle",return_value=({"source":"sanitized_export"},[],[s],[])), \
            patch.object(main,"meta",return_value={"mode":"sanitized_export","snapshot_age_seconds":2}), \
            patch.object(main.control_gateway,"execute",
               return_value=CompletedProcess([],0,'{"result":"ack","cleanup":"no_new_start"}',"")) as sent:
            reply=client.post("/api/omada/disconnect",headers=ORIGIN,json={
                "nas_ip":"192.0.2.6","mac":"02-00-00-00-00-11","session_id":"0000002E"})
        self.assertEqual(reply.status_code,200)
        payload=json.loads(sent.call_args.args[1])
        self.assertEqual(payload["mac"],MAC2)
        self.assertEqual(payload["session_id"],"0000002E")

if __name__=="__main__":
    unittest.main()
