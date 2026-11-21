"""UniFi RadSec/UDP detail matching must fail closed. No network actions."""
import datetime
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "deploy/opnsense/bixcore-unifi-disconnect.py"
spec = importlib.util.spec_from_file_location("unifi_radsec_v102", SRC)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

NAS1="192.0.2.4"
NAS2="192.0.2.5"
PROXY="192.0.2.1"
SID="REAL_SID_0123"
MAC="021122334455"
BSSID="020000000004"

class TestRadSecDetail(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.patcher=patch.object(helper,"DETAIL_ROOT",self.root)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def record(self,sender, *, nas=NAS1,sid=SID,mac=MAC,identifier=BSSID,day=0):
        folder=self.root/sender
        folder.mkdir(parents=True, exist_ok=True)
        f=folder/(datetime.datetime.now()-datetime.timedelta(days=day)).strftime("detail-%Y%m%d")
        payload=(
            "Sat Nov 21 17:00:00 2026\n"
            f"\tNAS-IP-Address = {nas}\n"
            f'\tNAS-Identifier = "{identifier}"\n'
            f'\tAcct-Session-Id = "{sid}"\n'
            f"\tCalling-Station-Id = 02-11-22-33-44-55\n\n"
        )
        with f.open("a",encoding="utf8") as o:o.write(payload)
        return f

    def test_direct_udp_only(self):
        self.record(NAS1)
        self.assertEqual(helper.identifier(NAS1,SID,MAC),BSSID)

    def test_radsec_proxy_only(self):
        self.record(PROXY)
        self.assertEqual(helper.identifier(NAS1,SID,MAC),BSSID)

    def test_radsec_multiple_aps_separated(self):
        self.record(PROXY,nas=NAS2,identifier="020000000006")
        self.record(PROXY,nas=NAS1)
        self.assertEqual(helper.identifier(NAS1,SID,MAC),BSSID)
        self.assertEqual(helper.identifier(NAS2,SID,MAC),"020000000006")

    def test_consistent_both_sources(self):
        self.record(NAS1)
        self.record(PROXY)
        self.assertEqual(helper.identifier(NAS1,SID,MAC),BSSID)

    def test_conflict_between_direct_and_radsec_fails(self):
        self.record(NAS1,identifier=BSSID)
        self.record(PROXY,identifier="020000000005")
        with self.assertRaisesRegex(ValueError,"AMBIGUOUS"):
            helper.identifier(NAS1,SID,MAC)

    def test_conflicting_identifiers_same_radsec_file_fails(self):
        self.record(PROXY,identifier=BSSID)
        self.record(PROXY,identifier="020000000005")
        with self.assertRaisesRegex(ValueError,"AMBIGUOUS"):
            helper.identifier(NAS1,SID,MAC)

    def test_no_match_fails(self):
        self.record(PROXY,sid="UNRELATED")
        with self.assertRaisesRegex(ValueError,"NOT_FOUND"):
            helper.identifier(NAS1,SID,MAC)

    def test_mac_mismatch_fails(self):
        self.record(PROXY)
        with self.assertRaisesRegex(ValueError,"NOT_FOUND"):
            helper.identifier(NAS1,SID,"021122334456")

    def test_nas_mismatch_fails(self):
        self.record(PROXY,nas=NAS2)
        with self.assertRaisesRegex(ValueError,"NOT_FOUND"):
            helper.identifier(NAS1,SID,MAC)

    def test_prior_day_fallback(self):
        self.record(PROXY,day=1)
        self.assertEqual(helper.identifier(NAS1,SID,MAC),BSSID)

    def test_no_arbitrary_sender_directory(self):
        self.record("192.0.2.77")
        with self.assertRaisesRegex(ValueError,"MISSING"):
            helper.identifier(NAS1,SID,MAC)

    def test_reject_unknown_nas_and_invalid_sid(self):
        self.record(PROXY)
        with self.assertRaisesRegex(ValueError,"INVALID_NAS"):
            helper.identifier("192.0.2.77",SID,MAC)
        with self.assertRaisesRegex(ValueError,"INVALID_NAS"):
            helper.identifier(NAS1,"bad?sid",MAC)

    def test_reject_symlink_directory(self):
        outside=self.root/"outside"
        self.record("outside")
        try:(self.root/NAS1).symlink_to(outside,target_is_directory=True)
        except (OSError,NotImplementedError):self.skipTest("symlink privilege unavailable")
        with self.assertRaisesRegex(ValueError,"UNTRUSTED_PATH"):
            helper.identifier(NAS1,SID,MAC)

    def test_invalid_identifier_on_matching_record_fails(self):
        self.record(PROXY,identifier="../../root")
        with self.assertRaisesRegex(ValueError,"INVALID"):
            helper.identifier(NAS1,SID,MAC)

    def test_empty_identifier_fails(self):
        self.record(PROXY,identifier="")
        with self.assertRaisesRegex(ValueError,"INVALID"):
            helper.identifier(NAS1,SID,MAC)

if __name__ == "__main__":unittest.main()
