"""Deterministic static regression checks; browser viewport smoke is separate."""
import re
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
STATIC=ROOT/'app'/'static'


class ResponsiveUITests(unittest.TestCase):
    def test_responsive_stylesheet_loaded_after_theme_both_pages(self):
        for page in ('index.html','login.html'):
            text=(STATIC/page).read_text(encoding='utf-8')
            self.assertLess(text.index('/static/ui-theme.css'),text.index('/static/responsive.css'))
            self.assertIn('name="viewport"',text)

    def test_tablet_and_phone_routes_and_motion_reduction(self):
        css=(STATIC/'responsive.css').read_text(encoding='utf-8')
        for rule in ('max-width: 1100px','max-width: 760px','max-width: 390px',
                     'grid-template-columns:repeat(2,minmax(0,1fr))',
                     'min-height:44px','prefers-reduced-motion:reduce',
                     'overscroll-behavior-x:contain','100dvh'):
            self.assertIn(rule,css)
        self.assertIn('.table-scroll table { min-width:0; }',css)

    def test_all_four_omada_confirmation_locales_and_no_pilot_language(self):
        js=(STATIC/'app.js').read_text(encoding='utf-8')
        fragment=js[js.index('function confirmOmadaWired(s){'):
                    js.index('async function executeOmadaWiredDisconnect')]
        for locale in ('ru:','en:','de:','uk:'):
            self.assertIn(locale,fragment)
        self.assertNotIn('802.1X-сессии BiX',fragment)
        self.assertIn('window.BiXUI?.locale',fragment)
        self.assertIn('dialog.showModal()',fragment)
        self.assertIn("dialog.returnValue==='confirm'",fragment)

    def test_navigation_and_assets_linked_to_real_routes(self):
        index=(STATIC/'index.html').read_text('utf-8')
        for view in ('sessions','users','portal','audit'):
            self.assertRegex(index,r'data-tab="'+view+'"')
        for asset in ('app.js','ui.js','responsive.css','style.css','ui-theme.css','favicon.svg'):
            self.assertTrue((STATIC/asset).is_file())
            self.assertIn('/static/'+asset,index)
        login=(STATIC/'login.html').read_text('utf-8')
        self.assertIn('/static/login.js',login)
        self.assertIn('href="/"',index)

if __name__=='__main__':
    unittest.main()
