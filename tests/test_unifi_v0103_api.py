"""API tests for reauthentication and guarded two-AP disconnect workflow."""
import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app import main

SESSION={
    "nas_family":"unifi","nas_ip":"192.0.2.4","session_id":"abc123",
    "username":"demo_phone15","mac":"02-00-00-00-00-18",
    "identity_kind":"wifi_device","state":"fresh","stopped_at":None,
    "age_minutes":1.1,
}
BODY={"nas_ip":"192.0.2.4","session_id":"abc123","mac":"02-00-00-00-00-18"}
ORIGIN={"Origin":"https://radius.example.test"}


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client=TestClient(main.app)
    @classmethod
    def tearDownClass(cls):
        cls.client.close()
    def setUp(self):
        main._UNIFI_LAST_REAUTH.clear()
        self.patches=[
            patch.object(main,'management_ready',return_value=True),
            patch.object(main.unifi_workflow,'pmksa_ready',return_value=True),
            patch.object(main,'bundle',return_value=(
                {"source":"sanitized_export"},[],[dict(SESSION)],[])),
            patch.object(main,'meta',return_value={"mode":"sanitized_export",
                      "snapshot_age_seconds":5}),
        ]
        for p in self.patches:p.start()
    def tearDown(self):
        for p in reversed(self.patches):p.stop()

    def test_online_reauth_success_requires_both_ap_scan(self):
        response={"ok":True,"scanned":2,"authorized":[{
            "nas_ip":"192.0.2.4","bss":"wifi1ap2","bssid":"02:00:00:00:00:14"}],"cache":[]}
        with patch.object(main.ap_control,'call',side_effect=[
            response,{"ok":True,"result":"requested","bss":"wifi1ap2"}]) as action:
            res=self.client.post("/api/unifi/reauth",json=BODY,headers=ORIGIN)
        self.assertEqual(res.status_code,200)
        self.assertEqual(res.json()["result"],"requested")
        self.assertEqual(action.call_count,2)

    def test_reauth_rejects_wrong_access_point(self):
        scan={"ok":True,"scanned":2,"authorized":[{
            "nas_ip":"192.0.2.5","bss":"wifi2ap5","bssid":"02:00:00:00:00:16"}],"cache":[]}
        with patch.object(main.ap_control,'call',return_value=scan) as action:
            r=self.client.post("/api/unifi/reauth",json=BODY,headers=ORIGIN)
        self.assertEqual(r.status_code,409)
        self.assertEqual(action.call_count,1)

    def test_reauth_cooldown_prevents_duplicate_dispatch(self):
        scan={"ok":True,"scanned":2,"authorized":[{
            "nas_ip":"192.0.2.4","bss":"wifi1ap2","bssid":"02:00:00:00:00:14"}]}
        with patch.object(main.ap_control,'call',side_effect=[
            scan,{"ok":True,"bss":"wifi1ap2"}]) as action:
            self.assertEqual(self.client.post('/api/unifi/reauth',json=BODY,headers=ORIGIN).status_code,200)
            self.assertEqual(self.client.post('/api/unifi/reauth',json=BODY,headers=ORIGIN).status_code,429)
        self.assertEqual(action.call_count,2)

    def test_active_disconnect_requires_ack_then_cleans_both_aps(self):
        scan={"ok":True,"scanned":2,"authorized":[{
            "nas_ip":"192.0.2.4","bss":"wifi1ap2","bssid":"02:00:00:00:00:14"}]}
        complete={"complete":True,"reason":"CACHE_VERIFIED_EMPTY_BOTH_APS","cache":[]}
        with patch.object(main.ap_control,'call',return_value=scan),\
             patch.object(main,'_active_disconnect_on_opnsense',return_value="ack") as active,\
             patch.object(main.unifi_workflow,'cleanup',return_value=complete) as clean:
            r=self.client.post('/api/unifi/disconnect',json=BODY,headers=ORIGIN)
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json()['result'],'complete')
        self.assertTrue(r.json()['disconnect_ack'])
        active.assert_called_once()
        clean.assert_called_once()

    def test_partial_cleanup_not_presented_as_success(self):
        scan={"ok":True,"scanned":2,"authorized":[{
            "nas_ip":"192.0.2.4","bss":"wifi1ap2","bssid":"02:00:00:00:00:14"}]}
        partial={"complete":False,"reason":"CLIENT_RECONNECTED","cache":[]}
        with patch.object(main.ap_control,'call',return_value=scan),\
             patch.object(main,'_active_disconnect_on_opnsense',return_value="ack"),\
             patch.object(main.unifi_workflow,'cleanup',return_value=partial):
            r=self.client.post('/api/unifi/disconnect',json=BODY,headers=ORIGIN)
        self.assertEqual(r.status_code,200)
        self.assertFalse(r.json()['ok'])
        self.assertEqual(r.json()['result'],'partial')

    def test_offline_never_calls_active_disconnection(self):
        ended={**SESSION,'state':'ended','age_minutes':None,'stopped_at':'2026-11-16T17:00:00Z'}
        with patch.object(main,'bundle',return_value=(
             {"source":"sanitized_export"},[],[ended],[])),\
             patch.object(main,'last_ended_per_device',return_value=[ended]),\
             patch.object(main.ap_control,'call',return_value={
                "ok":True,"scanned":2,"authorized":[],"cache":[]}),\
             patch.object(main,'_active_disconnect_on_opnsense') as active,\
             patch.object(main.unifi_workflow,'cleanup',return_value={
                "complete":True,"reason":"NO_PMKSA_FOUND","cache":[]}):
            r=self.client.post('/api/unifi/disconnect',
                json={**BODY,"offline":True},headers=ORIGIN)
        self.assertEqual(r.status_code,200)
        self.assertFalse(r.json()['disconnect_ack'])
        active.assert_not_called()

    def test_disallow_offline_mode_on_active_station(self):
        ended={**SESSION,'state':'ended','age_minutes':None,'stopped_at':'2026-11-16T17:00:00Z'}
        with patch.object(main,'bundle',return_value=(
             {"source":"sanitized_export"},[],[ended],[])),\
             patch.object(main,'last_ended_per_device',return_value=[ended]),\
             patch.object(main.ap_control,'call',return_value={
                "ok":True,"scanned":2,"authorized":[{
                 "nas_ip":"192.0.2.4","bss":"wifi1ap2","bssid":"02:00:00:00:00:14"}]}),\
             patch.object(main,'_active_disconnect_on_opnsense') as active:
            r=self.client.post('/api/unifi/disconnect',
                json={**BODY,"offline":True},headers=ORIGIN)
        self.assertEqual(r.status_code,409)
        active.assert_not_called()

    def test_disallow_origin(self):
        with patch.object(main.ap_control,'call') as ap:
            r=self.client.post('/api/unifi/reauth',json=BODY)
            self.assertEqual(r.status_code,403)
            ap.assert_not_called()

if __name__=='__main__':
    unittest.main()
