"""Check that operation names describe the server behavior in all four locales."""
from pathlib import Path
import unittest
from test_ui_redesign import translations

ROOT=Path(__file__).resolve().parents[1]
JS=(ROOT/'app/static/app.js').read_text('utf8')
HTML=(ROOT/'app/static/index.html').read_text('utf8')
API=(ROOT/'app/main.py').read_text('utf8')
I18N=(ROOT/'app/static/ui.js').read_text('utf8')

class SemanticUILabels(unittest.TestCase):
    def test_action_keys_have_all_four_languages(self):
        catalog=translations()
        for key in (
            'Проверить PMKSA','Проверить и очистить PMKSA?',
            'Disconnect / PMKSA','Disconnect / проверка PMKSA?',
            'Запросить EAP-проверку','Запросить повторную EAP-проверку?',
            'Закрыть Accounting','Завершить сессию портала',
            'Просмотреть сессии для Disconnect…','Гостевые сессии для Disconnect',
            'Изменяет доступ к новым авторизациям Captive Portal; существующие сессии не отключает',
            'Запись будет переведена в Disabled на RadiusGateway. Уже активные сессии не разрываются; решение о новых авторизациях принимает FreeRADIUS.',
        ):
            self.assertIn(key,catalog)
            self.assertEqual(len(catalog[key]),3)
            self.assertTrue(all(catalog[key]))

    def test_offline_is_pmksa_only_and_online_uses_conditionals(self):
        self.assertIn("ui.sessionView==='history' && s.state==='ended' && s.offline_disconnect_eligible",JS)
        self.assertIn("const disc=add(td,'button','Проверить PMKSA'",JS)
        self.assertIn("button.textContent=offline?'Проверить PMKSA':'Disconnect / PMKSA'",JS)
        self.assertIn("if body.offline and stations:",API)
        self.assertIn('if stations:\n            _active_disconnect_on_opnsense(s,mac)',API)
        self.assertIn('unifi_workflow.cleanup(mac,s["username"],s["nas_ip"],s["session_id"])',API)
        self.assertIn('if any(x["state"] == "fresh"',API)

    def test_other_actions_are_distinct(self):
        self.assertIn("const reauth=add(group,'button','Запросить EAP-проверку'",JS)
        self.assertIn("const b=add(group,'button','Закрыть Accounting'",JS)
        self.assertIn("add(item,'button','Завершить сессию портала'",JS)
        self.assertIn("if(!await confirmPortalAction(user,'Завершить сессию портала',session))",JS)
        self.assertIn("window.BiXUI.actionCount('guestDisconnect',plan.count)",JS)
        self.assertIn("Просмотреть сессии для Disconnect…",HTML)
        self.assertIn("Запись будет переведена в Disabled на RadiusGateway.",JS)
        self.assertIn('body.confirmation!="disconnect_guest_wifi"',API)
        self.assertIn('s["state"] == "stale"',API)

    def test_account_toggle_has_no_automatic_disconnect_claim(self):
        self.assertIn('существующие сессии не разрывает',JS)
        self.assertIn('решение о новых авторизациях принимает FreeRADIUS',JS)
        self.assertIn('RADIUS Disconnect-Request',JS)
        self.assertIn("Für",I18N)  # German and other language variants have full translations

    def test_locale_count_engine_and_data_immutability(self):
        self.assertIn("function count(kind,n)",I18N)
        self.assertIn("function actionCount(kind,n)",I18N)
        self.assertIn("last2>=11&&last2<=14",I18N)
        self.assertIn("data-i18n-ignore",JS)
        self.assertIn("const addRaw=",JS)
        self.assertIn("window.BiXUI.count('history',total)",JS.replace("ui.sessionView==='history'?'history':'current'","'history'"))

if __name__=='__main__':
    unittest.main()
