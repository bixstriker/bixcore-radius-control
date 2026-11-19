"""UI-only regression checks. No production credentials or AP commands."""
from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import json
import re
import unittest

STATIC = Path(__file__).resolve().parents[1] / "app" / "static"
APP = Path(__file__).resolve().parents[1] / "app" / "main.py"
CYRILLIC = re.compile(r"[\u0400-\u052f]")


class Labels(HTMLParser):
    def __init__(self):
        super().__init__()
        self.labels = []
        self.ignored_depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "style") or "data-i18n-ignore" in attrs:
            self.ignored_depth += 1
        if self.ignored_depth:
            return
        for name in ("title", "aria-label", "placeholder", "data-label"):
            if attrs.get(name):
                self.labels.append(attrs[name].strip())

    def handle_endtag(self, tag):
        if self.ignored_depth:
            self.ignored_depth -= 1

    def handle_data(self, data):
        if not self.ignored_depth and data.strip():
            self.labels.append(data.strip())


def translations():
    source = (STATIC / "ui.js").read_text("utf8")
    initial = json.loads(source.split("const entries=", 1)[1].split(";\n", 1)[0])
    later = [json.loads(v.split(");\n", 1)[0]) for v in source.split("entries.push(...")[1:]]
    entries = initial + [entry for group in later for entry in group]
    return {row[0]: row[1:] for row in entries}


class DesignAndLocalesTests(unittest.TestCase):
    def test_version_and_real_home_navigation(self):
        index = (STATIC / "index.html").read_text("utf8")
        login = (STATIC / "login.html").read_text("utf8")
        server = APP.read_text("utf8")
        for value in (index, login, server):
            self.assertIn("1.0.1", value)
        self.assertIn('<a class="brand" href="/"', index)
        self.assertIn("brand-mark", index)
        self.assertIn("<svg", index)
        self.assertNotIn('<div class="brand-icon">B</div>', index)
        self.assertNotIn("0.10.1", index)

    def test_shared_theme_and_locale_controls_on_both_pages(self):
        for filename, script in (("index.html", "app.js"), ("login.html", "login.js")):
            source = (STATIC / filename).read_text("utf8")
            self.assertLess(source.index('/static/ui.js'), source.index('/static/' + script))
            self.assertIn('/static/ui-theme.css', source)
            self.assertIn('class="bix-language"', source)
            self.assertIn('class="bix-theme"', source)
            for language in ("ru", "en", "de", "uk"):
                self.assertIn('value="' + language + '"', source)
        css = (STATIC / "ui-theme.css").read_text("utf8")
        for needle in ('data-theme="light"', 'data-theme="dark"',
                       '@media(max-width:760px)', 'prefers-reduced-motion',
                       'bix-dialog-open', 'top-actions'):
            self.assertIn(needle, css)

    def test_full_static_markup_localization(self):
        localized = translations()
        self.assertGreaterEqual(len(localized), 250)
        for key, values in localized.items():
            self.assertEqual(len(values), 3, key)
            self.assertTrue(all(isinstance(x, str) and x for x in values), key)
        tokens = sorted((k for k in localized if len(k.strip()) >= 2),
                        key=len, reverse=True)
        pattern = re.compile("|".join(re.escape(k) for k in tokens))
        for filename in ("index.html", "login.html"):
            labels = Labels()
            labels.feed((STATIC / filename).read_text("utf8"))
            untranslated = []
            for raw in labels.labels:
                if not CYRILLIC.search(raw):
                    continue
                normalized = " ".join(raw.split())
                if normalized in localized:
                    continue
                english = pattern.sub(lambda m: localized[m.group(0)][0], raw)
                if CYRILLIC.search(english):
                    untranslated.append(raw[:100])
            self.assertEqual(untranslated, [], filename)

    def test_preferences_do_not_store_secrets(self):
        source = (STATIC / "ui.js").read_text("utf8")
        self.assertIn("bixcore-ui-language", source)
        self.assertIn("bixcore-ui-theme", source)
        self.assertIn("localStorage.setItem", source)
        self.assertNotIn("document.cookie", source)
        self.assertNotIn("innerHTML", source)
        runtime = source.split("const languageKey=", 1)[1]
        self.assertNotIn("password", runtime.casefold())


if __name__ == "__main__":
    unittest.main()
