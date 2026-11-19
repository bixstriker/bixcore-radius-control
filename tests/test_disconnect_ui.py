"""Static regression tests for the integrated Disconnect confirmation."""
from html.parser import HTMLParser
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
class DialogParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags=[]
        self.ids={}
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        self.tags.append((tag,a))
        if "id" in a:
            self.ids[a["id"]]=(tag,a)

class TestConfirmDialog(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html=(ROOT/"app/static/index.html").read_text(encoding="utf8")
        cls.js=(ROOT/"app/static/app.js").read_text(encoding="utf8")
        cls.css=(ROOT/"app/static/style.css").read_text(encoding="utf8")
        cls.doc=DialogParser()
        cls.doc.feed(cls.html)

    def test_native_modal_and_accessible_title(self):
        tag,attrs=self.doc.ids["disconnect-dialog"]
        self.assertEqual(tag,"dialog")
        self.assertEqual(attrs["aria-labelledby"],"disconnect-dialog-title")
        self.assertEqual(attrs["aria-describedby"],"disconnect-dialog-hint")
        self.assertIn("dialog.showModal()",self.js)

    def test_explicit_confirm_and_cancel_actions(self):
        forms=[a for tag,a in self.doc.tags if tag=="form" and a.get("method")=="dialog"]
        self.assertGreaterEqual(len(forms),2)
        buttons=[a for tag,a in self.doc.tags if tag=="button" and a.get("value") in ("cancel","confirm")]
        self.assertEqual({a["value"] for a in buttons},{"cancel","confirm"})
        self.assertIn("autofocus",next(a for a in buttons if a["value"]=="cancel"))
        self.assertIn("dialog.returnValue==='confirm'",self.js)

    def test_device_identity_is_escaped_using_textcontent(self):
        for key in ("user","nas","mac"):
            self.assertIn("disconnect-dialog-"+key,self.doc.ids)
            self.assertIn("$('disconnect-dialog-"+key+"').textContent=",self.js)
        self.assertNotIn("window.confirm(",self.js)
        self.assertNotIn("window.prompt(",self.js)

    def test_original_disconnect_request_is_not_changed(self):
        self.assertIn('fetch("/api/unifi/disconnect"',self.js)
        self.assertIn("disconnectBusy=true",self.js)
        self.assertIn("disconnectBusy=false",self.js)
        self.assertIn(".disconnect-dialog::backdrop",self.css)

if __name__=="__main__":
    unittest.main()
