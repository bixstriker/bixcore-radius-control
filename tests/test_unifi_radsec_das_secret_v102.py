"""Unit-test exact RadSec client mapping; no secrets, packets or network changes."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

FILES=("bixcore-unifi-disconnect.py","bixcore-unifi-pmksa-clean.py")
BASE=Path(__file__).resolve().parents[1]/"deploy/opnsense"
CONFIG="""# RadSec client definitions
tls example_radsec_tls {
    CACertificateFile /example/ca.pem
    CertificateFile /example/leaf.pem
    CertificateKeyFile /example/key.pem
}
client UniFi_AP1 {
    Host 192.0.2.4/32
    Type tls
    Tls example_radsec_tls
    MatchCertificateAttribute CN:/^example$/
}
client UniFi_AP2 {
    Host 192.0.2.5/32
    Type tls
    Tls example_radsec_tls
}
# These backend UDP secrets MUST never be used for UniFi DAS:
server Example_Backend_Auth {
    Host 192.0.2.1
    Type udp
    Secret irrelevant_backend_value
}
"""
AP1="192.0.2.4"
AP2="192.0.2.5"

def load(name):
 spec=importlib.util.spec_from_file_location("bix_test_"+name.replace("-","_").replace(".","_"),BASE/name)
 module=importlib.util.module_from_spec(spec)
 spec.loader.exec_module(module)
 return module

class TestRadSecDAS(unittest.TestCase):
 def setUp(self):
    self.tmp=tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.path=Path(self.tmp.name)/"radsecproxy.conf"
    self.path.write_text(CONFIG,encoding="utf8")
    self.modules=[load(name) for name in FILES]
    for module in self.modules:
       patcher=patch.object(module,"RADSEC_CONFIG",self.path)
       patcher.start();self.addCleanup(patcher.stop)
       # A synthetic trusted OS fixture; production root/permissions guard remains intact.
       os_patch=patch.object(module,"os",SimpleNamespace(name="nt"))
       os_patch.start();self.addCleanup(os_patch.stop)
 def assert_error(self,configuration,error="RADSEC_"):
    self.path.write_text(configuration,encoding="utf8")
    for module in self.modules:
       with self.subTest(module=module.__name__),self.assertRaisesRegex(ValueError,error):
          module.secret_for(AP1)
 def test_both_aps_tls_use_fixed_radsec_secret(self):
    for module in self.modules:
       self.assertEqual(module.secret_for(AP1),"radsec")
       self.assertEqual(module.secret_for(AP2),"radsec")
 def test_backend_udp_secret_is_ignored(self):
    self.path.write_text(CONFIG.replace("irrelevant_backend_value","EVEN_ANOTHER_VALUE"),encoding="utf8")
    for module in self.modules:self.assertEqual(module.secret_for(AP1),"radsec")
 def test_unknown_nas_fails(self):
    for module in self.modules:
       with self.assertRaisesRegex(ValueError,"INVALID_NAS"):
          module.secret_for("192.0.2.99")
 def test_missing_client_fails(self):
    self.assert_error(CONFIG.replace("client UniFi_AP1", "client Another_AP"),"CLIENT_MISSING")
 def test_duplicate_client_fails(self):
    self.assert_error(CONFIG+CONFIG.split("client UniFi_AP1")[1].join(["client UniFi_AP1",""]),"CLIENT_MISSING")
 def test_wrong_host_fails(self):
    self.assert_error(CONFIG.replace("192.0.2.4/32","192.0.2.5/32"),"CONFIG_MISMATCH")
 def test_broad_host_fails(self):
    self.assert_error(CONFIG.replace("192.0.2.4/32","192.0.2.0/24"),"CONFIG_MISMATCH")
 def test_client_switched_to_udp_fails(self):
    self.assert_error(CONFIG.replace("Type tls","Type udp",1),"CONFIG_MISMATCH")
 def test_wrong_tls_profile_fails(self):
    self.assert_error(CONFIG.replace("    Tls example_radsec_tls","    Tls unexpected",1),"CONFIG_MISMATCH")
 def test_missing_tls_profile_fails(self):
    self.assert_error(CONFIG.replace("tls example_radsec_tls {","tls unused {"),"TLS_PROFILE")
 def test_explicit_client_secret_fails(self):
    self.assert_error(CONFIG.replace("client UniFi_AP1 {","client UniFi_AP1 {\n    Secret unexpected"),"CONFIG_MISMATCH")
 def test_config_symlink_fails(self):
    dest=Path(self.tmp.name)/"actual";dest.write_text(CONFIG,encoding="utf8")
    self.path.unlink()
    try:self.path.symlink_to(dest)
    except (OSError,NotImplementedError):self.skipTest("Symlink privileges unavailable")
    for module in self.modules:
       with self.assertRaisesRegex(ValueError,"UNTRUSTED"):
          module.secret_for(AP1)
 def test_missing_config_fails(self):
    self.path.unlink()
    for module in self.modules:
       with self.assertRaises(OSError):module.secret_for(AP1)
 def test_comment_does_not_create_client(self):
    self.assert_error(CONFIG.replace("client UniFi_AP1 {","# client UniFi_AP1 {"),"CLIENT_MISSING")
 def test_duplicate_tls_profile_fails(self):
    self.assert_error(CONFIG+'\ntls example_radsec_tls {\n}\n',"TLS_PROFILE")

if __name__=="__main__":unittest.main()
