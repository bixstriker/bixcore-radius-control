import unittest
from fastapi.testclient import TestClient
from app.main import app


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client=TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_overview_demo(self):
        response=self.client.get('/api/overview')
        self.assertEqual(response.status_code,200)
        data=response.json()
        self.assertEqual(data['sessions'],{'total':9,'fresh':7,'stale':2,'ended':3})
        self.assertEqual(data['users']['guest_wifi'],1)
        self.assertEqual(data['users']['portal_user'],6)
        self.assertEqual(data['users']['infrastructure'],2)
        self.assertEqual(data['portal'],2)
        self.assertFalse(data['meta']['live'])
        self.assertFalse(data['meta']['management_enabled'])

    def test_sessions_include_omada_and_guestwlan_but_not_portal_radius(self):
        data=self.client.get('/api/sessions').json()
        self.assertEqual(data['total'],9)
        self.assertTrue(all(s['state']!='ended' for s in data['items']))
        self.assertTrue(any(s['nas_ip']=='192.0.2.6' for s in data['items']))
        self.assertTrue(any(s['username']=='guestwlan' for s in data['items']))
        self.assertFalse(any(s['nas_ip']=='127.0.0.1' for s in data['items']))
        self.assertEqual(self.client.get('/api/sessions?include_portal=true').json()['total'],9)

    def test_session_status_filters(self):
        self.assertEqual(self.client.get('/api/sessions?state=fresh').json()['total'],7)
        self.assertEqual(self.client.get('/api/sessions?state=stale').json()['total'],2)

    def test_users_category_and_protected_dc(self):
        users=self.client.get('/api/users').json()['items']
        names={u['username']:u for u in users}
        self.assertNotIn('guestwlan',names)
        self.assertEqual(self.client.get('/api/users?category=guest_wifi').json()['items'][0]['permitted_actions'],['enable','disable','disconnect_all_guests'])
        self.assertNotIn('Visitor_2026',names)
        self.assertTrue(all(u['configured_vlan'] is not None for u in users))
        self.assertIn('set_vlan',names['OnyxBoox']['permitted_actions'])
        self.assertNotIn('schedule',names['Lenovo']['permitted_actions'])
        for name in ('host/LAB-DC01.ad.example.test','host/LAB-DC02.ad.example.test'):
            self.assertEqual(names[name]['kind'],'infrastructure')
            self.assertEqual(names[name]['permitted_actions'],['disconnect_session'])
            self.assertTrue(names[name]['protected'])
        self.assertTrue(all(not u['editable'] and not u['management_available'] for u in users))
        self.assertEqual(self.client.get('/api/users?category=portal_user').json()['total'],0)
        self.assertEqual(self.client.get('/api/users?query=visitor').json()['total'],0)

    def test_portal_live_sessions_are_separate_from_radius_accounting(self):
        portal=self.client.get('/api/portal-sessions').json()
        self.assertEqual(portal['total'],2)
        self.assertTrue(portal['meta']['portal_available'])
        self.assertEqual({p['username'] for p in portal['items']},{'guest1','Visitor_2026'})
        self.assertTrue(all(p['state']=='authorized' for p in portal['items']))

    def test_guest_disconnect_preview_is_scoped_and_not_executable(self):
        data=self.client.get('/api/guest-disconnect-preview').json()
        self.assertFalse(data['plan']['execution_enabled'])
        self.assertTrue(data['plan']['zone_scope_verified'])
        self.assertEqual(data['plan']['wifi_count'],2)
        self.assertEqual(data['plan']['portal_count'],2)
        self.assertEqual({p['username'] for p in data['plan']['portal_targets']},{'guest1','Visitor_2026'})
        self.assertEqual({x['nas'] for x in data['plan']['wifi_targets']},{'192.0.2.4','192.0.2.5'})

    def test_history_limit_is_two_per_personal_account_but_per_mac_for_guest(self):
        from datetime import datetime, timezone
        from unittest.mock import patch
        from app import main as main_module
        from app.logic import prepare_sessions, prepare_users
        snap, _, _, _ = main_module.bundle()
        users = prepare_users([
            {"uuid": "phone", "username": "demo_phone15", "enabled": True, "vlan": 10},
            {"uuid": "guest", "username": "guestwlan", "enabled": True, "vlan": 30},
        ])
        records = []
        for username, macs in (
            ("demo_phone15", ["02-00-00-00-00-18", "02-00-00-00-00-17",
                            "02-00-00-00-00-18", "02-00-00-00-00-17"]),
            ("guestwlan", ["02-00-00-00-00-0C", "02-00-00-00-00-19",
                           "02-00-00-00-00-0C", "02-00-00-00-00-19",
                           "02-00-00-00-00-0C", "02-00-00-00-00-19"]),
        ):
            for i, mac in enumerate(macs):
                records.append({
                    "username": username, "callingstationid": mac,
                    "nasipaddress": "192.0.2.4" if i % 2 else "192.0.2.5",
                    "acctsessionid": f"{username}-{i}",
                    "acctstarttime": "2026-11-18T11:00:00Z",
                    "acctupdatetime": "2026-11-18T11:30:00Z",
                    "acctstoptime": f"2026-11-18T12:0{i}:00Z",
                })
        sessions = prepare_sessions(
            records, users, datetime(2026, 11, 18, 13, tzinfo=timezone.utc))
        with patch.object(main_module, "bundle", return_value=(snap, users, sessions, [])):
            result = self.client.get("/api/sessions?state=ended").json()
            overview = self.client.get("/api/overview").json()
            personal = self.client.get(
                "/api/sessions?state=ended&query=demo_phone15").json()
        self.assertEqual(result["total"], 6)
        self.assertEqual(overview["sessions"]["ended"], 6)
        self.assertEqual(personal["total"], 2)
        self.assertEqual({x["session_id"] for x in personal["items"]},
                         {"demo_phone15-3", "demo_phone15-2"})
        self.assertEqual(len([x for x in result["items"] if x["username"] == "guestwlan"]), 4)

    def test_history_is_separate_and_guest_has_own_panel(self):
        current=self.client.get('/api/sessions').json()
        history=self.client.get('/api/sessions?state=ended').json()
        self.assertTrue(all(s['state']!='ended' for s in current['items']))
        self.assertTrue(all(s['state']=='ended' for s in history['items']))
        self.assertEqual(history['total'],3)
        self.assertEqual(self.client.get('/api/users').json()['total'],11)
        self.assertEqual(self.client.get('/api/users?category=guest_wifi').json()['total'],1)
        self.assertNotIn('guestwlan',[u['username'] for u in self.client.get('/api/users').json()['items']])
        html=self.client.get('/').text
        self.assertIn('data-session-view="history"',html)
        self.assertNotIn('data-state="ended"',html)

    def test_no_vlan_users_join_portal_and_not_radius(self):
        radius=self.client.get('/api/users').json()
        self.assertTrue(all(u['configured_vlan'] is not None for u in radius['items']))
        self.assertNotIn('guestwlan',[u['username'] for u in radius['items']])
        portal=self.client.get('/api/portal-users').json()
        self.assertEqual(portal['total'],6)
        self.assertEqual(portal['active_session_count'],2)
        self.assertTrue(all(u['configured_vlan'] is None for u in portal['items']))
        self.assertEqual(self.client.get('/api/portal-users?query=visitor').json()['total'],1)
        self.assertEqual(self.client.get('/api/portal-users?limit=2').json()['total'],6)
        self.assertEqual(len(self.client.get('/api/portal-users?limit=2').json()['items']),2)
        names={u['username']:u for u in portal['items']}
        self.assertEqual(names['guest1']['session_count'],1)
        self.assertEqual(names['Visitor_2026']['authorization_status'],'authorized')
        self.assertEqual(names['guest']['authorization_status'],'not_authorized')
        self.assertTrue(all('set_vlan' not in u['permitted_actions'] for u in portal['items']))
        self.assertTrue(all(u['management_available'] is False for u in portal['items']))
        self.assertEqual(portal['unmatched_count'],0)
        self.assertIn('Пользователи RADIUS',self.client.get('/').text)

    def test_new_arbitrary_users_are_grouped_by_vlan(self):
        from app.logic import prepare_users,prepare_portal_accounts
        users=prepare_users([{'uuid':'a','username':'A_new_portal','enabled':1,'vlan':None},
                             {'uuid':'b','username':'guest_named_but_vlan10','enabled':1,'vlan':10},
                             {'uuid':'c','username':'host/LAB-DC01.ad.example.test','enabled':1,'vlan':10}])
        portal,_=prepare_portal_accounts(users,[],True,False)
        self.assertEqual([x['username'] for x in portal],['A_new_portal'])
        self.assertEqual([x['username'] for x in users if x['kind']=='wifi_device'],['guest_named_but_vlan10'])
        self.assertEqual([x['username'] for x in users if x['kind']=='infrastructure'],['host/LAB-DC01.ad.example.test'])

    def test_portal_stale_status_is_separate_from_enabled(self):
        from app.logic import prepare_users,prepare_portal_accounts
        users=prepare_users([{'uuid':'a','username':'guest','enabled':0,'vlan':None},
                             {'uuid':'b','username':'other','enabled':1,'vlan':None}])
        sessions=[{'username':'guest','zone_id':'0','session_id':'a'},{'username':'external','zone_id':'0','session_id':'b'}]
        view,orphan=prepare_portal_accounts(users,sessions,True,True)
        by={u['username']:u for u in view}
        self.assertFalse(by['guest']['enabled'])
        self.assertEqual(by['guest']['authorization_status'],'previously_authorized')
        self.assertEqual(by['other']['authorization_status'],'not_confirmed')
        self.assertEqual(len(orphan),1)
        unknown,_=prepare_portal_accounts(users,sessions,False,False)
        self.assertTrue(all(u['authorization_status']=='unknown' for u in unknown))

    def test_no_mutation_routes(self):
        for url in ('/api/sessions','/api/phones','/api/users','/api/portal-sessions',
                    '/api/guest-disconnect-preview','/api/overview','/api/portal-users'):
            self.assertEqual(self.client.post(url,json={'action':'disconnect'}).status_code,405)
        self.assertEqual(self.client.post('/api/disconnect',json={}).status_code,404)

    def test_headers_and_private_data(self):
        response=self.client.get('/api/users')
        self.assertIn('default-src',response.headers['Content-Security-Policy'])
        self.assertEqual(response.headers['cache-control'],'no-store')
        self.assertNotIn('password',response.text.lower())
        self.assertNotIn('shared_secret',response.text.lower())

    def test_pagination(self):
        first=self.client.get('/api/sessions?limit=2&offset=0').json()
        second=self.client.get('/api/sessions?limit=2&offset=2').json()
        self.assertEqual(first['total'],9)
        self.assertEqual(len(first['items']),2)
        self.assertNotEqual(first['items'][0]['session_id'],second['items'][0]['session_id'])
        self.assertEqual(len(self.client.get('/api/users?limit=3&offset=0').json()['items']),3)

    def test_limits_and_filter_validation(self):
        self.assertEqual(self.client.get('/api/sessions?limit=99999').status_code,422)
        self.assertEqual(self.client.get('/api/sessions?state=active').status_code,422)
        self.assertEqual(self.client.get('/api/users?category=arbitrary').status_code,422)


if __name__=='__main__': unittest.main()
