from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import verify_gauntlet_records as gauntlet


GIT = Path(shutil.which("git") or "").resolve()
STAGING = "staging-only; not in public history"


class GauntletRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="idc-gauntlet-test-")
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name) / "repo"
        self.repo.mkdir()
        self.reviews = self.repo / "reviews"
        self.reviews.mkdir()
        subprocess.run([str(GIT), "-C", str(self.repo), "init", "-q"], check=True)
        subprocess.run([str(GIT), "-C", str(self.repo), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty",
                        "-qm", "fixture"], check=True)
        self.head = subprocess.check_output(
            [str(GIT), "-C", str(self.repo), "rev-parse", "HEAD"], text=True
        ).strip()
        self.filename = "fixture.json"
        self.record = {
            "taskId": "fixture", "reviewedCommit": self.head,
            "criticSeat": "fixture critic",
            "independence": "same-family; not a cross-family verdict",
            "disposition": "changes-requested",
            "findings": [{"severity": "medium", "title": "Fixture finding",
                          "evidence": "Fixture evidence", "recompute": "Fixture check"}],
        }

    def verify_record(self, record: dict, *, historical: bool = False) -> list[str]:
        (self.reviews / self.filename).write_text(json.dumps(record), encoding="utf-8")
        expected = {self.filename: (record["taskId"], record["reviewedCommit"])}
        with patch.object(gauntlet, "REPO_ROOT", self.repo), \
             patch.object(gauntlet, "REVIEWS_DIR", self.reviews), \
             patch.object(gauntlet, "EXPECTED", expected):
            if historical:
                return gauntlet.verify(allow_historical=True)
            return gauntlet.verify()

    def test_absent_valid_hex_commit_fails_closed(self) -> None:
        self.record["reviewedCommit"] = "0" * 40
        self.assertTrue(self.verify_record(self.record))

    def test_resolvable_commit_with_structured_findings_passes(self) -> None:
        self.assertEqual(self.verify_record(self.record), [])

    def test_non_commit_object_is_rejected(self) -> None:
        self.record["reviewedCommit"] = subprocess.check_output(
            [str(GIT), "-C", str(self.repo), "rev-parse", "HEAD^{tree}"], text=True
        ).strip()
        self.assertTrue(self.verify_record(self.record))

    def test_gutted_finding_text_is_rejected(self) -> None:
        for field in ("title", "evidence", "recompute"):
            for value in (None, [], {}, True, 7, "", "   "):
                with self.subTest(field=field, value=value):
                    record = copy.deepcopy(self.record)
                    record["findings"][0][field] = value
                    self.assertTrue(self.verify_record(record))

    def test_arbitrary_absent_pin_cannot_self_declare_historical(self) -> None:
        self.record.update(reviewedCommit="0" * 40, provenance=STAGING)
        self.assertTrue(self.verify_record(self.record, historical=True))

    def test_known_legacy_records_require_explicit_mode_and_provenance(self) -> None:
        originals = dict(gauntlet.EXPECTED)
        for filename, (task, commit) in originals.items():
            record = copy.deepcopy(self.record)
            record.update(taskId=task, reviewedCommit=commit, provenance=STAGING)
            (self.reviews / filename).write_text(json.dumps(record), encoding="utf-8")
        with patch.object(gauntlet, "REPO_ROOT", self.repo), \
             patch.object(gauntlet, "REVIEWS_DIR", self.reviews):
            self.assertTrue(gauntlet.verify())
            self.assertEqual(gauntlet.verify(allow_historical=True), [])
            path = self.reviews / next(iter(originals))
            record = json.loads(path.read_text(encoding="utf-8"))
            del record["provenance"]
            path.write_text(json.dumps(record), encoding="utf-8")
            self.assertTrue(gauntlet.verify(allow_historical=True))


if __name__ == "__main__":
    unittest.main()
