"""Strict Omada post-ACK Accounting cleanup tests. No production packets."""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import tempfile
import types
import unittest
from unittest.mock import patch
from subprocess import CompletedProcess

from fastapi.testclient import TestClient
from app import main, audit
from tests.test_omada_wired_pilot import helper, BODY, SESSION, ORIGIN


NOW = 1795090000
OLD = "0000002C"
NEW = "0000002D"
USER = "host/LAB-WORKSTATION.ad.example.test"
MAC = "02-00-00-00-00-10"


class DbFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "accounting.sqlite")
        db = sqlite3.connect(self.path)
        db.execute("""CREATE TABLE radacct (
            radacctid INTEGER PRIMARY KEY,
            username TEXT, callingstationid TEXT, acctsessionid TEXT,
            nasportid TEXT, acctupdatetime INTEGER, acctstarttime INTEGER,
            nasipaddress TEXT, acctstoptime INTEGER, acctterminatecause TEXT)""")
        db.execute(
            "INSERT INTO radacct VALUES (?,?,?,?,?,?,?,?,?,?)",
            (1, USER, MAC, OLD, "2", NOW-60, NOW-500,
             "192.0.2.6", None, ""),
        )
        db.commit()
        db.close()
        self.before = {
            "row_id": 1, "sid": OLD, "started": NOW-500,
            "updated": NOW-60, "max_before": 1,
        }

    def tearDown(self):
        self.temp.cleanup()

    def add(self, idx=2, sid=NEW, *, user=USER, mac=MAC,
            port="2", nas="192.0.2.6", start=NOW+7, stop=None):
        db = sqlite3.connect(self.path)
        db.execute(
            "INSERT INTO radacct VALUES (?,?,?,?,?,?,?,?,?,?)",
            (idx, user, mac, sid, port, start, start, nas, stop, ""),
        )
        db.commit()
        db.close()

    def row(self, idx):
        db = sqlite3.connect(self.path)
        try:
            return db.execute(
                "SELECT acctsessionid,acctstoptime,acctterminatecause FROM radacct "
                "WHERE radacctid=?", (idx,),
            ).fetchone()
        finally:
            db.close()

    def once(self):
        return helper.close_acked_predecessor(OLD, self.before, NOW,
                                               db_path=self.path)

    def test_all_three_conditions_close_only_old_session(self):
        self.add()
        out = self.once()
        self.assertEqual(out["cleanup"], "closed")
        self.assertEqual(out["new_session_id"], NEW)
        self.assertEqual(out["closed_at"], NOW+7)
        self.assertEqual(self.row(1),
                         (OLD, NOW+7, "Admin-Omada-Disconnect-Cleanup"))
        self.assertEqual(self.row(2), (NEW, None, ""))

    def test_new_start_absent_never_closes(self):
        self.assertEqual(self.once()["cleanup"], "waiting_new_start")
        self.assertIsNone(self.row(1)[1])

    def test_wrong_mac_on_same_port_is_fail_closed(self):
        self.add(mac="02-00-00-00-00-11", user="other")
        self.assertEqual(self.once()["cleanup"], "port_identity_changed")
        self.assertIsNone(self.row(1)[1])

    def test_new_start_different_port_is_insufficient(self):
        self.add(port="3")
        self.assertEqual(self.once()["cleanup"], "waiting_new_start")
        self.assertIsNone(self.row(1)[1])
        self.assertIsNone(self.row(2)[1])

    def test_new_start_different_nas_is_insufficient(self):
        self.add(nas="192.0.2.5")
        self.assertEqual(self.once()["cleanup"], "waiting_new_start")
        self.assertIsNone(self.row(1)[1])

    def test_preexisting_new_start_is_not_proof(self):
        self.add(start=NOW-10)
        self.before["max_before"] = 2
        self.assertEqual(self.once()["cleanup"], "waiting_new_start")
        self.assertIsNone(self.row(1)[1])

    def test_second_session_must_have_different_sid(self):
        self.add(sid=OLD)
        self.assertEqual(self.once()["cleanup"], "waiting_new_start")
        self.assertIsNone(self.row(1)[1])

    def test_nonmeaningful_zero_sid_cannot_be_successor(self):
        self.add(sid="00000000")
        self.assertEqual(self.once()["cleanup"], "waiting_new_start")
        self.assertIsNone(self.row(1)[1])

    def test_old_already_stopped_is_not_overwritten(self):
        db = sqlite3.connect(self.path)
        db.execute("UPDATE radacct SET acctstoptime=?,acctterminatecause=? "
                   "WHERE radacctid=1", (NOW+1, "NAS-Request"))
        db.commit()
        db.close()
        self.add()
        self.assertEqual(self.once()["cleanup"], "already_ended")
        self.assertEqual(self.row(1)[1:], (NOW+1, "NAS-Request"))

    def test_old_interim_update_change_blocks_cleanup(self):
        db = sqlite3.connect(self.path)
        db.execute("UPDATE radacct SET acctupdatetime=? WHERE radacctid=1",
                   (NOW+3,))
        db.commit()
        db.close()
        self.add()
        self.assertEqual(self.once()["cleanup"], "old_interim_changed")
        self.assertIsNone(self.row(1)[1])

    def test_foreign_open_client_blocks_even_with_valid_successor(self):
        self.add()
        self.add(idx=3, sid="0000002E", user="unauthorized", mac="02-00-00-00-00-11")
        self.assertEqual(self.once()["cleanup"], "port_identity_changed")
        self.assertIsNone(self.row(1)[1])

    def test_ambiguous_successor_blocks_cleanup(self):
        self.add()
        self.add(idx=3, sid="0000002E", start=NOW+8)
        self.assertEqual(self.once()["cleanup"], "ambiguous_successor")
        self.assertIsNone(self.row(1)[1])

    def test_accounting_old_row_identity_changed_blocks_cleanup(self):
        self.add()
        db = sqlite3.connect(self.path)
        db.execute("UPDATE radacct SET callingstationid=? WHERE radacctid=1",
                   ("02-00-00-00-00-11",))
        db.commit()
        db.close()
        self.assertEqual(self.once()["cleanup"], "old_session_changed")
        self.assertIsNone(self.row(1)[1])

    def test_verify_accounting_records_high_water_mark(self):
        initial = helper.verify_accounting(OLD, now=NOW,
                                            db_path=self.path)
        self.assertEqual(initial["row_id"],1)
        self.assertEqual(initial["max_before"],1)

    def test_bounded_wait_absent_start_returns_no_mutation(self):
        out = helper.wait_for_accounting_successor(
            OLD,self.before,NOW,max_wait=0,poll=0.01,db_path=self.path)
        self.assertEqual(out["cleanup"],"no_new_start")
        self.assertIsNone(self.row(1)[1])

    def test_bounded_wait_late_new_start(self):
        self.add()
        with patch.object(helper, "close_acked_predecessor",side_effect=[
            {"cleanup":"waiting_new_start"},
            {"cleanup":"closed","new_session_id":NEW},
        ]) as close:
            out=helper.wait_for_accounting_successor(
                OLD,self.before,NOW,max_wait=1,poll=0.01,db_path=self.path)
        self.assertEqual(out["cleanup"],"closed")
        self.assertEqual(close.call_count,2)


class NoCleanupWithoutAckTests(unittest.TestCase):
    def test_no_cleanup_for_nak_unknown_or_error(self):
        for reply in [
            {"result":"nak","reason":"DISCONNECT_REJECTED","error_cause":503},
            {"result":"unknown","reason":"NO_AUTHENTICATED_RESPONSE"},
            {"result":"error","reason":"LOCAL_UDP_3799_UNAVAILABLE"},
        ]:
            with self.subTest(result=reply["result"]):
                with tempfile.TemporaryDirectory() as td, \
                     patch.object(helper,"LOCK",str(Path(td)/"pilot.lock")), \
                     patch.object(helper,"verify_accounting",
                                  return_value={"row_id":1,"max_before":1,"port":"2","mac":MAC,"username":USER}), \
                     patch.object(helper,"read_secret",return_value=b"dummy"), \
                     patch.object(helper,"send_once",return_value=reply), \
                     patch.object(helper,"wait_for_accounting_successor") as cleanup, \
                     patch.object(helper,"fcntl",types.SimpleNamespace(
                         flock=lambda fd, flags:None, LOCK_EX=2, LOCK_NB=4)), \
                     patch.object(helper.stat, "S_IMODE", return_value=0o600), \
                     patch.object(helper.os, "fstat", return_value=types.SimpleNamespace(st_uid=0, st_mode=0o600)):
                    returned=helper.locked_execute(OLD)
                    self.assertEqual(returned["result"],reply["result"])
                    cleanup.assert_not_called()

    def test_cleanup_called_once_only_after_ack(self):
        with tempfile.TemporaryDirectory() as td, \
             patch.object(helper,"LOCK",str(Path(td)/"pilot.lock")), \
             patch.object(helper,"verify_accounting",
                          return_value={"row_id":1,"max_before":1,"port":"2","mac":MAC,"username":USER}), \
             patch.object(helper,"read_secret",return_value=b"dummy"), \
             patch.object(helper,"send_once",return_value={
                 "result":"ack","reason":"AUTHENTICATED_DISCONNECT_ACK"}), \
             patch.object(helper,"wait_for_accounting_successor",
                          return_value={"cleanup":"closed","new_session_id":NEW}) as close, \
             patch.object(helper,"fcntl",types.SimpleNamespace(
                 flock=lambda fd, flags:None, LOCK_EX=2, LOCK_NB=4)), \
             patch.object(helper.stat, "S_IMODE", return_value=0o600), \
                     patch.object(helper.os, "fstat", return_value=types.SimpleNamespace(st_uid=0, st_mode=0o600)):
            out=helper.locked_execute(OLD)
        self.assertEqual(out["result"],"ack")
        self.assertEqual(out["cleanup"],"closed")
        close.assert_called_once()


class WebAutoCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client=TestClient(main.app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_ack_propagates_closure_and_qualified_audit_fields(self):
        s=dict(SESSION,session_id=OLD)
        main._OMADA_WIRED_LAST_ATTEMPT=0
        with patch.dict(os.environ,{"BIX_OMADA_WIRED_ENABLED":"1"}), \
             patch.object(main.control_gateway,"available",return_value=True), \
             patch.object(main,"bundle",return_value=(
                 {"source":"sanitized_export"},[],[s],[])), \
             patch.object(main,"meta",return_value={
                 "mode":"sanitized_export","snapshot_age_seconds":2}), \
             patch.object(main.control_gateway,"execute",return_value=CompletedProcess(
                 [],0,'{"result":"ack","reason":"AUTHENTICATED_DISCONNECT_ACK",'
                      '"cleanup":"closed","new_session_id":"'+NEW+'"}',"")):
            response=self.client.post(
                "/api/omada/disconnect",headers=ORIGIN,
                json=dict(BODY,session_id=OLD))
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()["cleanup"],"closed")
        self.assertEqual(response.json()["new_session_id"],NEW)
        state,info=audit._outcome(response.content,200)
        self.assertEqual(state,"success")
        self.assertEqual(info["cleanup"],"closed")
        self.assertEqual(info["new_session_id"],NEW)

    def test_ack_but_no_new_start_remains_ack_not_cleanup(self):
        s=dict(SESSION,session_id=OLD)
        main._OMADA_WIRED_LAST_ATTEMPT=0
        with patch.dict(os.environ,{"BIX_OMADA_WIRED_ENABLED":"1"}), \
             patch.object(main.control_gateway,"available",return_value=True), \
             patch.object(main,"bundle",return_value=(
                 {"source":"sanitized_export"},[],[s],[])), \
             patch.object(main,"meta",return_value={
                 "mode":"sanitized_export","snapshot_age_seconds":2}), \
             patch.object(main.control_gateway,"execute",return_value=CompletedProcess(
                 [],0,'{"result":"ack","reason":"AUTHENTICATED_DISCONNECT_ACK",'
                      '"cleanup":"no_new_start"}',"")):
            response=self.client.post(
                "/api/omada/disconnect",headers=ORIGIN,
                json=dict(BODY,session_id=OLD))
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()["cleanup"],"no_new_start")
        self.assertIsNone(response.json()["new_session_id"])


if __name__=="__main__":
    unittest.main()
