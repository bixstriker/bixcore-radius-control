"""Accounting cleanup must never terminate a newly active or changed session."""
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest

PATH = Path(__file__).parents[1] / "deploy" / "opnsense" / "bixcore-accounting-close-stale.py"
spec = importlib.util.spec_from_file_location("bix_stale_close", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

NOW = 1_900_000_000
OLD = NOW - 9600
START = OLD - 2400


class StaleAccountingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "accounting.sqlite"
        with sqlite3.connect(self.db) as db:
            db.execute("""CREATE TABLE radacct (
                radacctid INTEGER PRIMARY KEY, username TEXT, nasipaddress TEXT,
                callingstationid TEXT, acctsessionid TEXT, acctstarttime INTEGER,
                acctupdatetime INTEGER, acctstoptime INTEGER,
                acctterminatecause TEXT
            )""")
            db.execute("""INSERT INTO radacct VALUES
            (1,'Secondary_15TPro','192.0.2.5','02-00-00-00-00-12',
             'old-sid',?,?,NULL,NULL)""", (START, OLD))
            db.execute("""INSERT INTO radacct VALUES
            (2,'Secondary_15TPro','192.0.2.4','02-00-00-00-00-12',
             'new-sid',?,?,NULL,NULL)""", (NOW-220, NOW-30))
        self.body = dict(nas_ip="192.0.2.5", session_id="old-sid",
                         mac="02-00-00-00-00-12", username="Secondary_15TPro",
                         started=START, updated=OLD)

    def tearDown(self):
        import gc
        gc.collect()  # Windows keeps sqlite files open until connections are finalized.
        self.temp.cleanup()

    def rows(self):
        with sqlite3.connect(self.db) as db:
            return db.execute(
                "SELECT acctstoptime, acctterminatecause FROM radacct ORDER BY radacctid"
            ).fetchall()

    def call(self, data=None, now=NOW):
        return module.close_stale(data or self.body, db_path=str(self.db), now=now)

    def test_closes_only_exact_old_row_and_preserves_fresh(self):
        self.assertEqual(self.call()["result"], "closed")
        self.assertEqual(self.rows()[0], (OLD, "Admin-Stale-Cleanup"))
        self.assertEqual(self.rows()[1], (None, None))

    def test_cannot_reclose_row(self):
        self.call()
        with self.assertRaisesRegex(module.StaleCloseError, "SESSION_CHANGED"):
            self.call()

    def test_rejects_mismatch_and_preserves_both(self):
        for field, value in (
            ("nas_ip", "192.0.2.4"),
            ("session_id", "new-sid"),
            ("mac", "02-00-00-00-00-1A"),
            ("username", "someone_else"),
            ("started", START-1),
            ("updated", OLD-1),
        ):
            with self.subTest(field=field):
                with self.assertRaises(module.StaleCloseError):
                    self.call({**self.body, field: value})
                self.assertEqual(self.rows(), [(None, None), (None, None)])

    def test_rejects_recent_stale_or_future(self):
        with self.assertRaisesRegex(module.StaleCloseError, "SESSION_NOT_STALE"):
            self.call(now=OLD + 30)
        with self.assertRaisesRegex(module.StaleCloseError, "SESSION_NOT_STALE"):
            self.call(now=OLD - 30)

    def test_updates_blocked_when_row_changes_since_export(self):
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE radacct SET acctupdatetime=? WHERE radacctid=1", (NOW-20,))
        with self.assertRaisesRegex(module.StaleCloseError, "SESSION_CHANGED"):
            self.call()
        self.assertEqual(self.rows(), [(None, None), (None, None)])

    def test_rejects_duplicate_ambiguous_rows(self):
        with sqlite3.connect(self.db) as db:
            db.execute("""INSERT INTO radacct VALUES
            (3,'Secondary_15TPro','192.0.2.5','02-00-00-00-00-12',
             'old-sid',?,?,NULL,NULL)""", (START, OLD))
        with self.assertRaisesRegex(module.StaleCloseError, "AMBIGUOUS"):
            self.call()
        self.assertTrue(all(v[0] is None for v in self.rows()))

    def test_validation_rejects_unauthorized_nas_and_types(self):
        for sample in (
            {**self.body, "nas_ip": "127.0.0.1"},
            {**self.body, "updated": "1900000000"},
            {**self.body, "updated": True},
            {**self.body, "session_id": "x\nrm -rf /"},
            {**self.body, "mac": "bad"},
        ):
            with self.subTest(sample=sample):
                with self.assertRaises(module.StaleCloseError):
                    self.call(sample)


if __name__ == "__main__":
    unittest.main()
