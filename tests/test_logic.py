import unittest
from datetime import datetime, timezone
from app.logic import prepare_sessions, prepare_users, prepare_portal_sessions, summarize, timestamp, guest_disconnect_plan, last_ended_per_device, user_kind

AS_OF=datetime(2026,11,13,9,42,41,tzinfo=timezone.utc)


class LogicTests(unittest.TestCase):
    def setUp(self):
        self.users=prepare_users([
            {'uuid':'p1','username':'demo_phone11','enabled':1,'vlan':10},
            {'uuid':'dc','username':'host/LAB-DC01.ad.example.test','enabled':'1','vlan':10},
            {'uuid':'mab','username':'020000000022','enabled':1,'vlan':20},
            {'uuid':'guest','username':'guestwlan','enabled':1,'vlan':30},
            {'uuid':'visitor','username':'MyArbitraryPortalName','enabled':1,'vlan':None},
        ])

    def record(self,user='demo_phone11',nas='192.0.2.4',session='s1',updated='2026-11-13T09:39:47Z',stop=None):
        return {'username':user,'nasipaddress':nas,'acctsessionid':session,
                'callingstationid':'02-00-00-00-00-03','acctstarttime':'2026-11-13T09:00:00Z',
                'acctupdatetime':updated,'acctstoptime':stop}

    def test_categories_match_user_policy(self):
        by_name={u['username']:u for u in self.users}
        self.assertEqual(by_name['demo_phone11']['kind'],'wifi_device')
        self.assertEqual(by_name['guestwlan']['kind'],'guest_wifi')
        self.assertNotIn('schedule',by_name['guestwlan']['permitted_actions'])
        self.assertNotIn('set_vlan',by_name['guestwlan']['permitted_actions'])
        self.assertEqual(by_name['MyArbitraryPortalName']['kind'],'portal_user')
        self.assertNotIn('set_vlan',by_name['MyArbitraryPortalName']['permitted_actions'])
        self.assertEqual(by_name['host/LAB-DC01.ad.example.test']['kind'],'infrastructure')
        self.assertEqual(by_name['020000000022']['kind'],'wifi_device')
        self.assertFalse(any(u['editable'] for u in self.users))

    def test_protected_bootstrap_even_unexpected_vlan_or_missing_vlan(self):
        self.assertEqual(user_kind('host/LAB-DC02.ad.example.test',None),'infrastructure')
        self.assertEqual(user_kind('HOST/LAB-DC01.ad.example.test',30),'infrastructure')
        self.assertEqual(user_kind('guestwlan',None),'other_local')

    def test_unknown_identity_not_asserted_ldap(self):
        sessions=prepare_sessions([self.record(user='host/Secondary.ad.example.test')],self.users,AS_OF)
        self.assertEqual(sessions[0]['identity_kind'],'unknown')

    def test_fresh_and_stale_and_ended(self):
        recs=[self.record(),self.record(session='s2',updated='2026-11-09T14:00:00Z'),
              self.record(session='s3',stop='2026-11-13T09:41:00Z')]
        self.assertEqual(summarize(prepare_sessions(recs,self.users,AS_OF)),dict(total=3,fresh=1,stale=1,ended=1))

    def test_capped_history_for_dedicated_radius_account_across_macs_and_aps(self):
        recs=[]
        for i,mac in enumerate(('02-00-00-00-00-22','02:00:00:00:00:22','02-00-00-00-00-22','02-00-00-00-00-02')):
            entry=self.record(nas='192.0.2.4' if i%2==0 else '192.0.2.5',
                              session='h'+str(i),stop='2026-11-13T09:1'+str(i)+':00Z')
            entry['callingstationid']=mac
            recs.append(entry)
        hist=last_ended_per_device(prepare_sessions(recs,self.users,AS_OF))
        self.assertEqual(len(hist),2)
        self.assertEqual([s['session_id'] for s in hist],['h3','h2'])

    def test_shared_guestwlan_history_remains_two_per_mac_across_aps(self):
        recs=[]
        for i,mac in enumerate(('02-00-00-00-00-22','02-00-00-00-00-0D',
                                '02:00:00:00:00:22','02:00:00:00:00:0D',
                                '02-00-00-00-00-22','02-00-00-00-00-0D')):
            entry=self.record(user='guestwlan', nas='192.0.2.4' if i%2==0 else '192.0.2.5',
                              session='g'+str(i),stop='2026-11-13T09:1'+str(i)+':00Z')
            entry['callingstationid']=mac
            recs.append(entry)
        hist=last_ended_per_device(prepare_sessions(recs,self.users,AS_OF))
        self.assertEqual([s['session_id'] for s in hist],['g5','g4','g3','g2'])

    def test_distinct_dedicated_users_with_same_mac_keep_separate_histories(self):
        users=prepare_users([
            {'uuid':'one','username':'demo_phone2','enabled':1,'vlan':10},
            {'uuid':'two','username':'demo_phone11','enabled':1,'vlan':10}])
        recs=[]
        for i in range(3):
            for username in ('demo_phone2','demo_phone11'):
                entry=self.record(user=username, session=f'{username}-{i}',
                                  stop=f'2026-11-13T09:1{i}:00Z')
                recs.append(entry)
        hist=last_ended_per_device(prepare_sessions(recs,users,AS_OF))
        self.assertEqual(len(hist),4)
        self.assertEqual({s['session_id'] for s in hist},
                         {'demo_phone2-1','demo_phone2-2','demo_phone11-1','demo_phone11-2'})

    def test_unknown_accounts_stay_per_mac_to_avoid_merging_shared_users(self):
        recs=[]
        for i,mac in enumerate(('02-00-00-00-00-22','02-00-00-00-00-0D',
                                '02-00-00-00-00-22','02-00-00-00-00-0D')):
            entry=self.record(user='unclassified', session='u'+str(i),
                              stop=f'2026-11-13T09:1{i}:00Z')
            entry['callingstationid']=mac
            recs.append(entry)
        hist=last_ended_per_device(prepare_sessions(recs,self.users,AS_OF))
        self.assertEqual(len(hist),4)

    def test_no_stop_does_not_prove_fresh(self):
        obj=prepare_sessions([self.record(updated=None)],self.users,AS_OF)[0]
        self.assertEqual(obj['state'],'stale')

    def test_session_id_not_globally_unique(self):
        result=prepare_sessions([self.record(),self.record(nas='192.0.2.5')],self.users,AS_OF)
        self.assertEqual(len(result),2)

    def test_duplicate_records_not_double_counted(self):
        r=self.record()
        self.assertEqual(len(prepare_sessions([r,r],self.users,AS_OF)),1)

    def test_future_timestamp_marked_stale(self):
        item=prepare_sessions([self.record(updated='2026-11-13T10:43:00Z')],self.users,AS_OF)[0]
        self.assertEqual(item['state'],'stale')
        self.assertTrue(item['clock_skew'])

    def test_unknown_current_vlan_not_inferred(self):
        self.assertIsNone(prepare_sessions([self.record()],self.users,AS_OF)[0]['current_vlan'])

    def test_unzoned_iso_not_accepted(self):
        self.assertIsNone(timestamp('2026-11-13 09:42:41'))
        self.assertEqual(timestamp('1794559361').tzinfo,timezone.utc)

    def test_guest_disconnection_plan_scopes_exact_username_and_zone(self):
        rows=[self.record(user='guestwlan',session='guest-wifi'),
              self.record(user='guestwlan',session='old',updated='2026-10-13T09:00:00Z'),
              self.record(user='demo_phone11',session='normal'),
              self.record(user='guestwlan',nas='192.0.2.6',session='not-unifi')]
        sessions=prepare_sessions(rows,self.users,AS_OF)
        portal=prepare_portal_sessions([
            {'sessionId':'a','zoneid':1,'userName':'anything','ipAddress':'203.0.113.8','macAddress':'aa',
             'startTime':1794550000,'last_accessed':1794550200,'authenticated_via':'radius'},
            {'sessionId':'b','zoneid':2,'userName':'not-guest','ipAddress':'198.18.40.9','macAddress':'bb',
             'startTime':1794550000,'last_accessed':1794550200,'authenticated_via':'radius'},
        ],AS_OF)
        plan=guest_disconnect_plan(sessions,portal,['1'])
        self.assertEqual((plan['wifi_count'],plan['portal_count']),(1,1))
        self.assertFalse(plan['execution_enabled'])
        self.assertEqual(plan['wifi_targets'][0]['session_id'],'guest-wifi')
        self.assertEqual(plan['portal_targets'][0]['username'],'anything')
        unscoped=guest_disconnect_plan(sessions,portal,[])
        self.assertFalse(unscoped['zone_scope_verified'])
        self.assertEqual(unscoped['portal_count'],0)


if __name__=='__main__':unittest.main()
