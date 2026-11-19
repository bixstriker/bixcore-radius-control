"""Offline regression tests: no packets are sent to a production NAS."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from subprocess import CompletedProcess

from fastapi.testclient import TestClient
from app import main, omada_wired
from sync import compose_control


SCRIPT = Path(__file__).parents[1] / "deploy" / "opnsense" / "bixcore-omada-disconnect.py"
# fcntl is only used on FreeBSD/Linux; a local shim lets Windows test the
# pure packet builder and policy without ever executing the production helper.
try:
    import fcntl  # available on FreeBSD/Linux production hosts
except ImportError:
    sys.modules["fcntl"] = types.SimpleNamespace()
spec = importlib.util.spec_from_file_location("bixcore_omada_pilot", SCRIPT)
assert spec is not None and spec.loader is not None
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

SESSION = {
    "nas_ip": "192.0.2.6", "nas_family": "omada",
    "session_id": "00000026", "mac": "02-00-00-00-00-10",
    "username": "host/LAB-WORKSTATION.ad.example.test",
    "identity_kind": "other_local", "state": "fresh", "age_minutes": 1.0,
}
ORIGIN = {"Origin": "https://radius.example.test"}
BODY = {"nas_ip": "192.0.2.6", "session_id": "00000026",
        "mac": "02-00-00-00-00-10"}


def response(code, request_auth, identifier, secret, attrs=b""):
    header = struct.pack("!BBH", code, identifier, 20 + len(attrs))
    authenticator = hashlib.md5(header + request_auth + attrs + secret).digest()
    return header + authenticator + attrs


class PacketAndPolicyTests(unittest.TestCase):
    def test_only_explicit_pilot_accepted(self):
        self.assertEqual(helper.parse_request(json.dumps(BODY).encode()),
                         ("192.0.2.6", "00000026", "020000000010"))
        self.assertIsNone(helper.parse_request(b'{"probe":true}'))
        for invalid in [
            dict(BODY, nas_ip="192.0.2.4"),
            dict(BODY, session_id="00000026;rm"),
            dict(BODY, port=3),
        ]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                helper.parse_request(json.dumps(invalid).encode())

    def test_packet_only_supported_attributes_and_valid_authenticator(self):
        secret = b"offline-dummy-for-tests"
        packet, authenticator = helper.build_request("00000026", secret, 71)
        self.assertEqual((packet[0], packet[1]), (40, 71))
        self.assertEqual(len(packet), int.from_bytes(packet[2:4], "big"))
        self.assertEqual(packet[4:20], authenticator)
        self.assertEqual(authenticator, hashlib.md5(
            packet[:4] + b"\x00"*16 + packet[20:] + secret).digest())
        attrs = []
        at = 20
        while at < len(packet):
            code, n = packet[at], packet[at + 1]
            self.assertGreaterEqual(n, 2)
            attrs.append(code)
            at += n
        self.assertEqual(attrs, [1, 5, 31])
        self.assertNotIn(44, attrs)  # Accounting SID is validated locally, omitted on the wire
        self.assertNotIn(b"00000026", packet)
        self.assertNotIn(87, attrs)
        self.assertNotIn(33, attrs)

    def test_ack_and_nak_require_verifiable_authenticator(self):
        secret = b"offline-dummy-for-tests"
        packet, request_auth = helper.build_request("00000026", secret, 42)
        ack = response(41, request_auth, 42, secret)
        self.assertEqual(helper.decode_reply(ack, ("192.0.2.6", 3799),
                                             42, request_auth, secret)["result"], "ack")
        nak = response(42, request_auth, 42, secret,
                       helper.attribute(101, struct.pack("!I", 503)))
        self.assertEqual(helper.decode_reply(nak, ("192.0.2.6", 3799),
                                             42, request_auth, secret)["error_cause"], 503)
        self.assertIsNone(helper.decode_reply(ack, ("192.0.2.5", 3799),
                                              42, request_auth, secret))
        self.assertIsNone(helper.decode_reply(ack, ("192.0.2.6", 60000),
                                              42, request_auth, secret))
        self.assertIsNone(helper.decode_reply(ack, ("192.0.2.6", 3799),
                                              43, request_auth, secret))
        self.assertIsNone(helper.decode_reply(ack[:-1] + b"X", ("192.0.2.6", 3799),
                                              42, request_auth, secret))

    def test_accounting_fails_closed_against_wrong_client_or_new_sid(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "radacct.sqlite")
            db = sqlite3.connect(path)
            db.execute("""CREATE TABLE radacct (radacctid INTEGER, username TEXT,
                        callingstationid TEXT, acctsessionid TEXT, nasportid TEXT,
                        acctupdatetime INTEGER, acctstarttime INTEGER,
                        nasipaddress TEXT, acctstoptime INTEGER)""")
            now = 1795078800
            row = (1, helper.PILOT_USERNAME, "02-00-00-00-00-10",
                   "00000026", "2", now-25, now-60, "192.0.2.6", None)
            db.execute("INSERT INTO radacct VALUES (?,?,?,?,?,?,?,?,?)", row)
            db.commit()
            helper.verify_accounting("00000026", now=now, db_path=path)
            with self.assertRaisesRegex(ValueError, "SESSION_NOT_UNIQUE"):
                helper.verify_accounting("00000025", now=now, db_path=path)
            db.execute("UPDATE radacct SET acctupdatetime=?",
                       (now-700,))
            db.commit()
            with self.assertRaisesRegex(ValueError, "ACCOUNTING_NOT_FRESH"):
                helper.verify_accounting("00000026", now=now, db_path=path)
            db.execute("UPDATE radacct SET acctupdatetime=?", (now-25,))
            db.execute("INSERT INTO radacct VALUES (?,?,?,?,?,?,?,?,?)",
                       (2, "another", "02-00-00-00-00-11", "00000027",
                        "2", now-10, now-10, "192.0.2.6", None))
            db.commit()
            with self.assertRaisesRegex(ValueError, "PORT_NOT_EXCLUSIVELY_CLIENT"):
                helper.verify_accounting("00000026", now=now, db_path=path)
            db.close()

    def test_response_loss_is_unknown_and_never_auto_retried(self):
        sends = []
        class FakeSocket:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def bind(self, addr): self.bound = addr
            def settimeout(self, timeout): pass
            def sendto(self, data, addr):
                sends.append((data, addr, self.bound))
                return len(data)
            def recvfrom(self, n):
                raise helper.socket.timeout
        with patch.object(helper.socket, "socket", return_value=FakeSocket()):
            result = helper.send_once("00000026", b"offline-dummy", timeout=0.01)
        self.assertEqual(result["result"], "unknown")
        self.assertEqual(len(sends), 1)
        self.assertEqual(sends[0][1], ("192.0.2.6", 3799))
        self.assertEqual(sends[0][2], ("192.0.2.1", 3799))

    def test_busy_local_3799_prevents_send(self):
        class BusySocket:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def bind(self, addr): raise OSError("occupied")
            def sendto(self, data, addr): self.fail("MUST_NOT_SEND")
        with patch.object(helper.socket, "socket", return_value=BusySocket()):
            result = helper.send_once("00000026", b"offline-dummy")
        self.assertEqual(result["result"], "error")
        self.assertEqual(result["reason"], "LOCAL_UDP_3799_UNAVAILABLE")


class ApiPilotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
    @classmethod
    def tearDownClass(cls):
        cls.client.close()
    def setUp(self):
        main._OMADA_WIRED_LAST_ATTEMPT = 0.0

    def test_disabled_by_default(self):
        with patch.dict(os.environ, {"BIX_OMADA_WIRED_ENABLED": "0"}):
            reply = self.client.post("/api/omada/disconnect", headers=ORIGIN, json=BODY)
        self.assertEqual(reply.status_code, 503)

    def test_wrong_pilot_is_refused_even_if_enabled(self):
        with patch.dict(os.environ, {"BIX_OMADA_WIRED_ENABLED": "1"}), \
             patch.object(main.control_gateway, "available", return_value=True):
            reply = self.client.post("/api/omada/disconnect", headers=ORIGIN,
                                     json=dict(BODY, mac="02-00-00-00-00-11"))
        self.assertEqual(reply.status_code, 409)

    def test_stale_snapshot_refused_without_command(self):
        with patch.dict(os.environ, {"BIX_OMADA_WIRED_ENABLED": "1"}), \
             patch.object(main.control_gateway, "available", return_value=True), \
             patch.object(main, "bundle", return_value=({"source":"sanitized_export"}, [], [dict(SESSION)], [])), \
             patch.object(main, "meta", return_value={"mode":"sanitized_export", "snapshot_age_seconds":300}), \
             patch.object(main.control_gateway, "execute") as command:
            reply = self.client.post("/api/omada/disconnect", headers=ORIGIN, json=BODY)
        self.assertEqual(reply.status_code, 409)
        command.assert_not_called()

    def test_ack_unknown_and_rate_limit(self):
        with patch.dict(os.environ, {"BIX_OMADA_WIRED_ENABLED": "1"}), \
             patch.object(main.control_gateway, "available", return_value=True), \
             patch.object(main, "bundle", return_value=({"source":"sanitized_export"}, [], [dict(SESSION)], [])), \
             patch.object(main, "meta", return_value={"mode":"sanitized_export", "snapshot_age_seconds":2}), \
             patch.object(main.control_gateway, "execute",
                          return_value=CompletedProcess([],0,'{"result":"ack","reason":"AUTHENTICATED_DISCONNECT_ACK"}',"")) as command:
            reply = self.client.post("/api/omada/disconnect", headers=ORIGIN, json=BODY)
            repeat = self.client.post("/api/omada/disconnect", headers=ORIGIN, json=BODY)
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.json()["result"], "ack")
        self.assertEqual(repeat.status_code, 429)
        command.assert_called_once()
        self.assertEqual(command.call_args.args[0], "omada_disconnect")

        main._OMADA_WIRED_LAST_ATTEMPT = 0
        with patch.dict(os.environ, {"BIX_OMADA_WIRED_ENABLED": "1"}), \
             patch.object(main.control_gateway, "available", return_value=True), \
             patch.object(main, "bundle", return_value=({"source":"sanitized_export"}, [], [dict(SESSION)], [])), \
             patch.object(main, "meta", return_value={"mode":"sanitized_export", "snapshot_age_seconds":2}), \
             patch.object(main.control_gateway, "execute",
                          return_value=CompletedProcess([],0,'{"result":"unknown","reason":"NO_AUTHENTICATED_RESPONSE"}',"")):
            reply = self.client.post("/api/omada/disconnect", headers=ORIGIN, json=BODY)
        self.assertEqual(reply.status_code, 202)
        self.assertFalse(reply.json()["ok"])

    def test_nak_503_has_meaningful_message(self):
        main._OMADA_WIRED_LAST_ATTEMPT = 0
        with patch.dict(os.environ, {"BIX_OMADA_WIRED_ENABLED": "1"}), \
             patch.object(main.control_gateway, "available", return_value=True), \
             patch.object(main, "bundle", return_value=(
                 {"source":"sanitized_export"}, [], [dict(SESSION)], [])), \
             patch.object(main, "meta", return_value={
                 "mode":"sanitized_export", "snapshot_age_seconds":2}), \
             patch.object(main.control_gateway, "execute", return_value=CompletedProcess(
                 [],0,'{"result":"nak","reason":"DISCONNECT_REJECTED","error_cause":503}',"")):
            result = self.client.post("/api/omada/disconnect",headers=ORIGIN,json=BODY)
        self.assertEqual(result.status_code,409)
        self.assertIn("Error-Cause 503",result.json()["detail"])
        self.assertIn("Omada",result.json()["detail"])

    def test_control_action_needs_dedicated_key(self):
        self.assertEqual(compose_control.ACTIONS["omada_disconnect"][:2],
                         ("bixcore-omada-disconnect", "omada_disconnect"))
        with patch.object(compose_control, "SECRETS", Path("missing-secrets-dir")):
            result = compose_control.opnsense("omada_disconnect", "{}")
        self.assertEqual(result["error"], "CREDENTIALS_UNAVAILABLE")

    def test_compose_release_is_disabled_and_keyless_web(self):
        config = (SCRIPT.parents[2] / "compose.v0107.release.yaml").read_text("utf8")
        web, other = config.split("\n  sync:\n", 1)
        self.assertIn('BIX_OMADA_WIRED_ENABLED: "0"', web)
        self.assertNotIn("omada_disconnect_ed25519", web)
        self.assertIn("omada_disconnect_ed25519", other)
        self.assertIn("bixcore-radius-control:0.10.7-worker", other)
        self.assertIn("bixcore-radius-control:0.10.4-worker", other)

    def test_latest_session_wins_over_stale_open_duplicate(self):
        old = dict(SESSION, session_id="00000029",
                   started_at="2026-11-19T10:00:00+00:00",
                   network_kind="wired", nas_name="Omada")
        current = dict(SESSION, started_at="2026-11-19T10:05:00+00:00",
                       network_kind="wired", nas_name="Omada")
        self.assertIs(omada_wired.latest_session([old, current]), current)
        with patch.object(main, "bundle", return_value=(
                {"source":"sanitized_export"}, [], [old, current], [])), \
             patch.object(main, "meta", return_value={
                "mode":"sanitized_export", "snapshot_age_seconds":2,
                "omada_wired_enabled":True}):
            result = self.client.get("/api/sessions?nas=192.0.2.6")
        self.assertEqual(result.status_code, 200)
        items = result.json()["items"]
        self.assertFalse(next(s for s in items if s["session_id"]=="00000029")["omada_wired_latest"])
        self.assertTrue(next(s for s in items if s["session_id"]=="00000026")["omada_wired_latest"])

    def test_api_old_session_rejected_before_any_disconnect(self):
        old = dict(SESSION, session_id="00000029",
                   started_at="2026-11-19T10:00:00+00:00")
        current = dict(SESSION, started_at="2026-11-19T10:05:00+00:00")
        with patch.dict(os.environ, {"BIX_OMADA_WIRED_ENABLED": "1"}), \
             patch.object(main.control_gateway, "available", return_value=True), \
             patch.object(main, "bundle", return_value=(
                 {"source":"sanitized_export"}, [], [old, current], [])), \
             patch.object(main, "meta", return_value={
                 "mode":"sanitized_export", "snapshot_age_seconds":2}), \
             patch.object(main.control_gateway, "execute") as command:
            resp = self.client.post("/api/omada/disconnect",
                                    headers=ORIGIN,
                                    json=dict(BODY,session_id="00000029"))
        self.assertEqual(resp.status_code,409)
        command.assert_not_called()

    def test_hotfix_release_flag_defaults_off(self):
        text=(SCRIPT.parents[2]/"compose.v0107_1.release.yaml").read_text("utf8")
        self.assertIn('BIX_OMADA_WIRED_ENABLED: "0"',text)
        self.assertIn("bixcore-radius-control:0.10.7.1-web",text)
        self.assertIn("bixcore-radius-control:0.10.7-worker",text)

    def test_ui_action_exists_but_remains_flagged(self):
        text = (SCRIPT.parents[2] / "app" / "static" / "app.js").read_text("utf8")
        self.assertIn("meta.omada_wired_enabled", text)
        self.assertIn("executeOmadaWiredDisconnect", text)
        tooltip=next(x for x in text.splitlines() if "disc.title=" in x and "Omada" in x)
        self.assertNotIn("????",tooltip)
        self.assertIn(r"\u043e",tooltip)
        self.assertTrue(omada_wired.permitted_session(dict(SESSION)))
        self.assertFalse(omada_wired.permitted_session(dict(SESSION, nas_ip="192.0.2.5")))


if __name__ == "__main__":
    unittest.main()
