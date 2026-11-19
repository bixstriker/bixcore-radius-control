"""Regression: history hotfix changes only the web image tag in Compose."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
HEADER = "# v0.10.4.1: bounded history per dedicated RADIUS identity; worker images unchanged.\n"


class HistoryFixComposeTests(unittest.TestCase):
    def check(self, older, fixed, old_tag, new_tag):
        previous = (ROOT / older).read_text(encoding="utf-8")
        new = (ROOT / fixed).read_text(encoding="utf-8")
        self.assertTrue(new.startswith(HEADER))
        self.assertEqual(previous.count(old_tag), 1)
        self.assertEqual(new.count(new_tag), 1)
        self.assertEqual(new[len(HEADER):], previous.replace(old_tag, new_tag, 1))
        self.assertIn("bixcore-radius-control:0.10.4", previous)

    def test_stage_hotfix_web_only(self):
        self.check(
            "compose.v0104.stage.yaml", "compose.v0104.1.stage.yaml",
            "bixcore-radius-control:0.10.4-stage-web",
            "bixcore-radius-control:0.10.4.1-stage-web")

    def test_production_hotfix_web_only(self):
        self.check(
            "compose.v0104.release.yaml", "compose.v0104.1.release.yaml",
            "bixcore-radius-control:0.10.4-web",
            "bixcore-radius-control:0.10.4.1-web")


if __name__ == "__main__":
    unittest.main()
