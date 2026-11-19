"""Pure local tests of the root host's restricted AP scan and reauth."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

f=Path(__file__).parents[1]/'sync/unifi_host.py'
spec=importlib.util.spec_from_file_location('bixcore_unifi_host',f)
host=importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
MAC='02:00:00:00:00:18'
BSSID='02:00:00:00:00:14'
SAMPLE='BSS\twifi1ap2\t'+BSSID+'\t1\nCACHE\twifi1ap2\t'+BSSID+'\t'+'a'*32+'\t32000\n'

class Tests(unittest.TestCase):
    def test_valid_scan_from_two_aps(self):
        with patch.object(host,'ssh',side_effect=[SAMPLE,'BSS\twifi2ap5\t02:00:00:00:00:16\t0\n']):
            result=host.scan(MAC)
        self.assertEqual(result['scanned'],2)
        self.assertEqual(result['authorized'][0]['bss'],'wifi1ap2')
        self.assertEqual(result['cache'][0]['pmkid'],'a'*32)
    def test_duplicate_online_sta_rejected(self):
        with patch.object(host,'ssh',side_effect=[SAMPLE,SAMPLE]):
            with self.assertRaisesRegex(host.Reject,'AMBIGUOUS'):
                host.scan(MAC)
    def test_unknown_output_rejected(self):
        with patch.object(host,'ssh',return_value='UNKNOWN COMMAND\n'):
            with self.assertRaises(host.Reject):
                host.scan(MAC)
    def test_bad_bssid_rejected(self):
        with patch.object(host,'ssh',return_value='BSS\twifi1ap2\tinjection\t1\n'):
            with self.assertRaisesRegex(host.Reject,'BAD_BSS'):
                host.scan(MAC)
    def test_reauth_bound_to_scanned_bss_and_mac(self):
        observed=[]
        def fake_ssh(ap,script,timeout=22):
            observed.append((ap,script))
            if '__TARGET_MAC__' in script:raise AssertionError('MAC_PLACEHOLDER_NOT_REPLACED')
            if 'EAPOL_REAUTH' in script:
                self.assertIn('wifi1ap2',script)
                self.assertIn(MAC,script)
                return 'OK\n'
            return SAMPLE if ap=='192.0.2.4' else 'BSS\twifi2ap5\t02:00:00:00:00:16\t0\n'
        with patch.object(host,'ssh',side_effect=fake_ssh):
            result=host.reauth(MAC,'192.0.2.4',BSSID)
        self.assertEqual(result['result'],'requested')
        self.assertEqual(len(observed),3)
    def test_implicit_wrong_bss_does_not_reauth(self):
        with patch.object(host,'ssh',return_value=SAMPLE) as run:
            with self.assertRaises(host.Reject):
                host.reauth(MAC,'192.0.2.5',BSSID)
        self.assertEqual(run.call_count,2)
    def test_protect_from_arbitrary_shell_and_bad_mac(self):
        for req in [
            {'op':'scan','mac':'aa;reboot'},
            {'op':'flush','mac':MAC},
            {'op':'reauth','mac':MAC,'nas_ip':'192.0.2.4','bssid':'evil'},
        ]:
            with self.assertRaises(host.Reject):
                host.handle(req)

if __name__=='__main__':
    unittest.main()
