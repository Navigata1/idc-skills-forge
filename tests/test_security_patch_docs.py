"""Scope-specific documentation regressions, not independent acceptance."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SecurityPatchDocsTests(unittest.TestCase):
    def test_staging_commit_citations_are_explicitly_historical(self):
        for name in ("CHANGELOG.md", "docs/STATE-2.0.3-hardening.md"):
            content = (ROOT / name).read_text()
            for match in re.finditer(r"`(?:d0fac44|04a5bd4|e98cfac6)`", content):
                with self.subTest(file=name, position=match.start()):
                    self.assertIn("staging-only; not in public history", content[match.end():match.end()+80])

    def test_full_profile_instructions_do_not_pin_a_construction_tag(self):
        content = (ROOT / "docs/release-acceptance-evidence.md").read_text()
        self.assertNotIn("Run only after an annotated 2.0.4 tag", content)
        self.assertIn("registry release", content)
