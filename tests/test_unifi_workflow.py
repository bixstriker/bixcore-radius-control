"""Orchestration never clears arbitrary PMKSA or when a client reconnects."""
import unittest
from unittest.mock import patch
from app import unifi_workflow as w

MAC='02:00:00:00:00:18'
TARGET={'nas_ip':'192.0.2.4','bss':'wifi2ap5','bssid':'02:00:00:00:00:15',
        'pmkid':'a'*32,'ttl':1000}

class Tests(unittest.TestCase):
    def scan(self,online=False,cache=True):
        return {'ok':True,'scanned':2,
                'authorized':[{'nas_ip':'192.0.2.4','bss':'wifi1ap2','bssid':'02:00:00:00:00:14'}] if online else [],
                'cache':[TARGET] if cache else []}
    def test_one_cache_entry_removed_after_ack_and_verification(self):
        scans=[self.scan(),self.scan(),self.scan(cache=False),self.scan(cache=False)]
        with patch.object(w,'pmksa_ready',return_value=True),patch.object(w.ap_control,'call',side_effect=scans) as scan,patch.object(w,'send_das',return_value={'ok':True,'result':'ack'}) as send:
            result=w.cleanup(MAC,'demo_phone15','192.0.2.4','old-sid')
        self.assertTrue(result['complete'])
        self.assertEqual(result['cache'][0]['status'],'removed')
        self.assertEqual(send.call_count,1)
        self.assertEqual(scan.call_count,4)
        self.assertEqual(send.call_args.args[0]['pmkid'],TARGET['pmkid'])
    def test_never_disconnect_online_client_during_cache_cleanup(self):
        with patch.object(w,'pmksa_ready',return_value=True),patch.object(w.ap_control,'call',return_value=self.scan(online=True)),patch.object(w,'send_das') as send:
            result=w.cleanup(MAC,'demo_phone15','192.0.2.4','old-sid')
        self.assertFalse(result['complete'])
        self.assertEqual(result['reason'],'CLIENT_CONNECTED_OR_RECONNECTED')
        send.assert_not_called()
    def test_reconnection_race_prevents_das(self):
        with patch.object(w,'pmksa_ready',return_value=True),patch.object(w.ap_control,'call',side_effect=[self.scan(),self.scan(online=True)]),patch.object(w,'send_das') as send:
            result=w.cleanup(MAC,'demo_phone15','192.0.2.4','old-sid')
        self.assertFalse(result['complete'])
        send.assert_not_called()
    def test_sends_das_but_requires_pmkid_disappears(self):
        with patch.object(w,'pmksa_ready',return_value=True),patch.object(w.ap_control,'call',side_effect=[self.scan(),self.scan(),self.scan()]),patch.object(w,'send_das') as send:
            result=w.cleanup(MAC,'demo_phone15','192.0.2.4','old-sid')
        self.assertFalse(result['complete'])
        self.assertIn('PMKID',result['reason'])
        self.assertEqual(send.call_count,1)
    def test_no_cache_success_requires_both_aps(self):
        with patch.object(w,'pmksa_ready',return_value=True),patch.object(w.ap_control,'call',return_value=self.scan(cache=False)),patch.object(w,'send_das') as send:
            result=w.cleanup(MAC,'demo_phone15','192.0.2.4','old-sid')
        self.assertTrue(result['complete'])
        self.assertEqual(result['cache'],[])
        send.assert_not_called()
    def test_partial_ack_not_claim_full_success(self):
        with patch.object(w,'pmksa_ready',return_value=True),patch.object(w.ap_control,'call',side_effect=[self.scan(),self.scan()]),patch.object(w,'send_das',side_effect=w.WorkflowError('AP_NAK')):
            result=w.cleanup(MAC,'demo_phone15','192.0.2.4','old-sid')
        self.assertFalse(result['complete'])
        self.assertEqual(result['cache'][0]['status'],'not_verified')

if __name__=='__main__':
    unittest.main()
