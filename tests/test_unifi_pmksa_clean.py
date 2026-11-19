"""Fail-closed targeted UniFi PMKSA DAS executor tests; no AP commands."""
import importlib.util
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

PATH = Path(__file__).parents[1] / "deploy/opnsense/bixcore-unifi-pmksa-clean.py"
spec = importlib.util.spec_from_file_location("bixcore_pmksa_clean", PATH)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
NOW = 1_900_000_000


class TestPMKSAClean(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dbfile = str(Path(self.tmp.name) / "db.sqlite")
        with closing(sqlite3.connect(self.dbfile)) as conn, conn:
            conn.executescript("""CREATE TABLE radacct(
                radacctid INTEGER PRIMARY KEY,
                acctsessionid TEXT, username TEXT, callingstationid TEXT,
                nasipaddress TEXT, calledstationid TEXT,
                acctupdatetime INTEGER, acctstoptime INTEGER
            );""")
            conn.executemany(
                "INSERT INTO radacct VALUES(?,?,?,?,?,?,?,?)", [
                    (1,"fresh-old","demo_phone15","02-00-00-00-00-18","192.0.2.4",
                     "02-00-00-00-00-15:BiX",NOW-5000,NOW-4900),
                    (2,"other","Other","02-00-00-00-00-22","192.0.2.5",
                     "02-00-00-00-00-16:BiX",NOW-4000,NOW-3900),
                ],
            )
        self.body={"op":"cache_pmk","nas_ip":"192.0.2.5",
                   "source_nas":"192.0.2.4","session_id":"fresh-old",
                   "username":"demo_phone15","mac":"02:00:00:00:00:18",
                   "bssid":"02:00:00:00:00:16",
                   "pmkid":"a"*32}
        self.sent=[]

    def tearDown(self):
        self.tmp.cleanup()

    def transmit(self, ap, attrs):
        self.sent.append((ap, attrs))
        return {"ok":True,"result":"ack"}

    def test_das_uses_exact_nas_identifier_no_session_id(self):
        r=helper.execute(self.body,db_path=self.dbfile,now=NOW,send=self.transmit)
        self.assertTrue(r["ok"])
        self.assertEqual(len(self.sent),1)
        ip,attrs=self.sent[0]
        self.assertEqual(ip,"192.0.2.5")
        self.assertIn('NAS-Identifier = "020000000016"',attrs)
        self.assertIn('Calling-Station-Id = "02-00-00-00-00-18"',attrs)
        self.assertIn('Message-Authenticator = 0x00',attrs)
        self.assertNotIn("Acct-Session-Id",attrs)

    def test_wrong_source_session_is_rejected(self):
        with self.assertRaises(helper.Rejected):
            helper.execute({**self.body,"session_id":"other"},db_path=self.dbfile,now=NOW,send=self.transmit)
        self.assertEqual(self.sent,[])

    def test_reject_unknown_bssid(self):
        with self.assertRaisesRegex(helper.Rejected,"TARGET_BSSID"):
            helper.execute({**self.body,"bssid":"02:00:00:00:00:02"},db_path=self.dbfile,now=NOW,send=self.transmit)

    def test_reject_fresh_open_accounting_even_on_other_ap(self):
        with closing(sqlite3.connect(self.dbfile)) as db, db:
            db.execute("INSERT INTO radacct VALUES(3,?,?,?,?,?,?,?)",
                ("new","demo_phone15","02-00-00-00-00-18","192.0.2.4",
                 "02-00-00-00-00-15:BiX",NOW-35,None))
        with self.assertRaisesRegex(helper.Rejected,"CLIENT_RECENTLY_ONLINE"):
            helper.execute(self.body,db_path=self.dbfile,now=NOW,send=self.transmit)
        self.assertEqual(self.sent,[])

    def test_reject_invalid_inputs(self):
        examples=({"mac":"bad"},{"nas_ip":"127.0.0.1"},{"pmkid":"0"},{"bssid":"zzz"},
                  {"username":"host/LAB-DC01.ad.example.test"},
                  {"operation":"PMKSA_FLUSH"})
        for change in examples:
            with self.subTest(change=change),self.assertRaises(helper.Rejected):
                helper.execute({**self.body,**change},db_path=self.dbfile,now=NOW,send=self.transmit)
        self.assertEqual(self.sent,[])

    def test_secret_is_not_needed_for_test_or_accepted_without_validation(self):
        self.assertEqual(helper.validate(self.body)["username"],"demo_phone15")
        with self.assertRaises(helper.Rejected):
            helper.validate({"probe":True})

if __name__ == "__main__":
    unittest.main()
