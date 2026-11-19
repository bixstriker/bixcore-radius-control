import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.export_opnsense_snapshot import read_local_users, sanitize_portal, export, read_accounting
from app.source import validate_snapshot
from tools.import_snapshot import install_payload


class ExporterTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.config=self.root/'config.xml'
        self.database=self.root/'radius.db'
        self.portal=self.root/'portal.json'
        self.private=self.root/'snapshot.json'
        self.secret='SECRET_PASSWORD_DO_NOT_EXPOSE'
        self.config.write_text('''<?xml version="1.0"?>
<opnsense><OPNsense><freeradius><user><users>
  <user uuid="u1"><username>guestwlan</username><enabled>1</enabled><vlan>30</vlan><password>SECRET_PASSWORD_DO_NOT_EXPOSE</password><tunnel_password>OTHER_SECRET</tunnel_password></user>
  <user uuid="u2"><username>guest</username><enabled>1</enabled><vlan></vlan><password>SECRET_PASSWORD_DO_NOT_EXPOSE</password></user>
  <user uuid="u3"><username>Visitor2026</username><enabled>0</enabled><password>SECRET_PASSWORD_DO_NOT_EXPOSE</password></user>
  <user uuid="u4"><username>host/LAB-DC01.ad.example.test</username><enabled>1</enabled><vlan>10</vlan><password>SECRET_PASSWORD_DO_NOT_EXPOSE</password></user>
</users></user></freeradius></OPNsense><system><password>SECRET_PASSWORD_DO_NOT_EXPOSE</password></system></opnsense>''')
        with sqlite3.connect(self.database) as c:
            c.execute('CREATE TABLE radacct (username text,nasipaddress text,callingstationid text,acctsessionid text,acctstarttime int,acctupdatetime int,acctstoptime int)')
            c.execute('INSERT INTO radacct VALUES (?,?,?,?,?,?,?)',('guestwlan','192.0.2.4','aa:bb','session-1',1794550000,1794559000,None))
        c.close()  # Explicit close needed on Windows
        self.portal.write_text(json.dumps([{'sessionId':'portal-1','zoneid':1,'userName':'Visitor2026','ipAddress':'203.0.113.20',
            'macAddress':'aa:bb:cc','startTime':1794550000.1,'last_accessed':1794559000,
            'authenticated_via':'Local FreeRADIUS','shared_secret':'SECRET_PASSWORD_DO_NOT_EXPOSE'}]))

    def tearDown(self): self.tmp.cleanup()

    def test_local_user_projection_never_emits_password(self):
        users=read_local_users(self.config)
        self.assertEqual(len(users),4)
        self.assertEqual(set(users[0]),{'uuid','username','enabled','vlan'})
        self.assertEqual(users[1]['vlan'],None)
        self.assertEqual(users[2]['enabled'],False)
        self.assertNotIn(self.secret,json.dumps(users))

    def test_portal_projection_only_approved_fields(self):
        raw=json.loads(self.portal.read_text())
        proj=sanitize_portal(raw)
        self.assertEqual(proj[0]['username'] if 'username' in proj[0] else proj[0]['userName'],'Visitor2026')
        self.assertNotIn(self.secret,json.dumps(proj))
        self.assertEqual(proj[0]['zoneid'],'1')

    def test_full_export_is_valid_and_contains_no_secret(self):
        snap=export(self.database,self.config,self.portal)
        validate_snapshot(snap)
        self.assertTrue(snap['users_collected'])
        self.assertTrue(snap['portal_collected'])
        self.assertEqual(snap['portal_sessions'][0]['userName'],'Visitor2026')
        self.assertEqual(snap['sessions'][0]['nasipaddress'],'192.0.2.4')
        self.assertNotIn('SECRET_PASSWORD',json.dumps(snap))
        install_payload(json.dumps(snap).encode(),self.private)
        if os.name != 'nt':
            self.assertEqual(self.private.stat().st_mode&0o777,0o600)

    def test_skip_portal_explicitly_marks_unavailable(self):
        snap=export(self.database,self.config,skip_portal=True)
        self.assertFalse(snap['portal_collected'])
        self.assertEqual(snap['portal_sessions'],[])

    def test_missing_user_model_fails_closed(self):
        self.config.write_text('<opnsense><system/></opnsense>')
        with self.assertRaises(ValueError):read_local_users(self.config)

    def test_reject_raw_captive_portal_api_data_with_secrets(self):
        snap=export(self.database,self.config,self.portal)
        snap['portal_sessions'][0]['password']='secret'
        with self.assertRaises(ValueError):validate_snapshot(snap)
        snap['portal_sessions'][0].pop('password')
        snap['local_users'][0]['password']='secret'
        with self.assertRaises(ValueError):validate_snapshot(snap)

    def test_readonly_sqlite_query(self):
        self.assertEqual(read_accounting(self.database,100)[0]['username'],'guestwlan')


if __name__=='__main__':unittest.main()
