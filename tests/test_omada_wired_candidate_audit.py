"""Offline-only tests for the Omada read-only candidate inventory."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from tools.omada_wired_candidate_audit import inventory


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.temp.name) / "fixture.db")
        db = sqlite3.connect(self.db)
        try:
            db.execute("""CREATE TABLE radacct (
                nasportid TEXT, nasipaddress TEXT, acctstarttime INTEGER,
                acctupdatetime INTEGER, acctstoptime INTEGER,
                callingstationid TEXT, username TEXT)""")
            db.executemany("INSERT INTO radacct VALUES (?,?,?,?,?,?,?)", [
                ("2","192.0.2.6",100,150,None,"02-00-00-00-00-22","u1"),
                ("2","192.0.2.6",101,160,180,"02:00:00:00:00:22","u1"),
                ("3","192.0.2.6",100,150,None,"02-00-00-00-00-0D","u2"),
                ("4","192.0.2.7",100,150,None,"02-00-00-00-00-0E","u3"),
                ("5","192.0.2.6",1,1,None,"02-00-00-00-00-0F","u4"),
            ])
            db.commit()
        finally:
            db.close()

    def tearDown(self):
        self.temp.cleanup()

    def test_distinct_clients_and_nas_and_time_scoping(self):
        data = inventory(self.db, "192.0.2.6", now=200, window_seconds=150)
        self.assertEqual([p["port_id"] for p in data["ports"]], ["2", "3"])
        self.assertEqual(data["ports"][0]["distinct_macs"], 1)
        self.assertEqual(data["ports"][0]["records"], 2)
        self.assertEqual(data["ports"][0]["open_rows"], 1)
        self.assertTrue(all(p["decision"] == "manual_review_required"
                            for p in data["ports"]))
        self.assertEqual(data["authorization"], "none; observation is not permission")
        self.assertNotIn("AA-BB", str(data))
        self.assertNotIn("u1", str(data))

    def test_read_only_db(self):
        before = Path(self.db).read_bytes()
        inventory(self.db,"192.0.2.6",now=200)
        self.assertEqual(before, Path(self.db).read_bytes())

    def test_invalid_window_rejected(self):
        for window in (0, -1, 2678401):
            with self.assertRaises(ValueError):
                inventory(self.db,"192.0.2.6",now=200,window_seconds=window)


if __name__ == "__main__":
    unittest.main()
