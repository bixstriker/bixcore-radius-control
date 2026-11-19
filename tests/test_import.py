import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient
from app.main import app
from app.source import validate_snapshot
from tools.import_snapshot import install_payload
from tools.pull_restricted import pull
from tools.export_snapshot import export


def utc(dt):
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / 'private').mkdir()
        self.file = self.root / 'private/current.json'
        self.allowlist = Path(__file__).resolve().parent.parent / 'data/empty_allowlist.json'
        self.now = datetime.now(timezone.utc)

    def tearDown(self):
        self.tmp.cleanup()

    def snapshot(self, delta=90, stopped=None, users=None):
        date = self.now - timedelta(seconds=delta)
        return {
            'source':'sanitized_export', 'as_of':utc(self.now),
            'sessions':[{
                'username':'demo_phone15','nasipaddress':'192.0.2.4',
                'callingstationid':'02-00-00-00-00-18','acctsessionid':'test-2026',
                'acctstarttime':int((date-timedelta(minutes=5)).timestamp()),
                'acctupdatetime':int(date.timestamp()),'acctstoptime':stopped,
            }], 'local_users': users or [],
        }

    def load_api(self):
        with patch.dict(os.environ, {'BIX_RADIUS_SNAPSHOT':str(self.file),
                                     'BIX_RADIUS_ALLOWLIST':str(self.allowlist)}):
            with TestClient(app) as client:
                return client.get('/api/overview'), client.get('/api/sessions'), client.get('/api/phones')

    def test_real_import_fresh_and_dc_protected(self):
        s=self.snapshot(users=[{'uuid':'dc1','username':'host/LAB-DC01.ad.example.test',
                                'enabled':True,'vlan':10}])
        s['sessions'].append({'username':'host/LAB-DC01.ad.example.test','nasipaddress':'192.0.2.6',
                              'callingstationid':'02-00-00-00-00-11','acctsessionid':'00000020',
                              'acctstarttime':int((self.now-timedelta(hours=1)).timestamp()),
                              'acctupdatetime':int((self.now-timedelta(seconds=100)).timestamp()),
                              'acctstoptime':None})
        install_payload(json.dumps(s).encode(),self.file)
        overview,sessions,phones=self.load_api()
        self.assertEqual((overview.status_code,sessions.status_code,phones.status_code),(200,200,200))
        self.assertFalse(overview.json()['meta']['live'])
        self.assertFalse(overview.json()['meta']['snapshot_stale'])
        self.assertEqual(overview.json()['sessions']['fresh'],2)
        dc=next(x for x in sessions.json()['items'] if x['nas_ip']=='192.0.2.6')
        self.assertEqual(dc['identity_kind'],'infrastructure')
        self.assertEqual(phones.json()['total'],0)  # No verified SCEP provenance yet
        if os.name != 'nt':
            self.assertEqual(self.file.stat().st_mode & 0o777,0o600)

    def test_old_export_not_false_fresh(self):
        s=self.snapshot(delta=60)
        s['as_of']=utc(self.now-timedelta(hours=2))
        s['sessions'][0]['acctupdatetime']=int((self.now-timedelta(hours=2)).timestamp())
        install_payload(json.dumps(s).encode(),self.file)
        overview,sessions,_=self.load_api()
        self.assertTrue(overview.json()['meta']['snapshot_stale'])
        self.assertEqual(overview.json()['sessions']['stale'],1)
        self.assertEqual(sessions.json()['items'][0]['state'],'stale')

    def test_invalid_fields_rejected_without_overwrite(self):
        initial=json.dumps(self.snapshot()).encode()
        install_payload(initial,self.file)
        previous=self.file.read_bytes()
        malicious=self.snapshot()
        malicious['sessions'][0]['shared_secret']='oops'
        with self.assertRaises(ValueError):
            install_payload(json.dumps(malicious).encode(),self.file)
        self.assertEqual(self.file.read_bytes(),previous)
        malicious=self.snapshot(users=[{'uuid':'one','username':'phone','password':'should never pass'}])
        with self.assertRaises(ValueError):
            validate_snapshot(malicious)

    def test_demo_rejected_for_import(self):
        s=self.snapshot(); s['source']='demo'
        with self.assertRaises(ValueError): install_payload(json.dumps(s).encode(),self.file)

    def test_readonly_local_sqlite_export_then_import(self):
        db=self.root/'source.db'
        with sqlite3.connect(db) as conn:
            conn.execute('CREATE TABLE radacct (username text,nasipaddress text,callingstationid text,acctsessionid text,acctstarttime int,acctupdatetime int,acctstoptime int)')
            rec=self.snapshot()['sessions'][0]
            conn.execute('INSERT INTO radacct VALUES (?,?,?,?,?,?,?)',tuple(rec[k] for k in (
                'username','nasipaddress','callingstationid','acctsessionid','acctstarttime','acctupdatetime','acctstoptime')))
        conn.close()  # Commit context does not close SQLite handle on Windows
        self.assertEqual(export(db,None,self.file,100),1)
        resp,_,_=self.load_api()
        self.assertEqual(resp.status_code,200)
        self.assertEqual(resp.json()['sessions']['fresh'],1)

    def test_restricted_transport_constructs_safe_command(self):
        known=self.root/'known_hosts'; known.write_text('pinned-placeholder')
        identity=self.root/'readonly_ed25519'; identity.write_text('placeholder-key')
        s=self.snapshot()
        class Result:
            returncode=0
            stdout=json.dumps(s).encode()
            stderr=b''
        with patch('tools.pull_restricted.subprocess.run',return_value=Result()) as invoke:
            pull('RadiusGateway.example.test','radius-ro',known,identity,self.file)
        cmd=invoke.call_args.args[0]
        self.assertIn('BatchMode=yes',cmd)
        self.assertIn('StrictHostKeyChecking=yes',cmd)
        self.assertNotIn('root@RadiusGateway.example.test',cmd)
        self.assertNotIn('-pw',cmd)
        self.assertEqual(json.loads(self.file.read_text())['source'],'sanitized_export')


if __name__=='__main__':unittest.main()
