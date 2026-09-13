from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts import verify_platform_evidence as platform


HEAD = "a" * 40


def capture_fixture(root: Path) -> dict:
    records = []
    for name, filesystem in (("macos", "APFS"), ("windows", "NTFS")):
        record = {
            "platform": name, "status": "passed", "runner": "synthetic-test-fixture",
            "osVersion": "fixture", "filesystem": filesystem, "python": "3.12 fixture",
            "bash": "3.2 fixture" if name == "macos" else "n/a",
            "sshKeygen": "OpenSSH fixture", "command": "fixture-check --candidate " + HEAD,
        }
        capture = {"schema": "idc-platform-capture/v1", "candidateHead": HEAD,
                   **record, "exitCode": 0, "output": "synthetic fixture check passed\n"}
        path = root / f"{name}.capture.json"
        data = json.dumps(capture).encode("utf-8")
        path.write_bytes(data)
        records.append({**record, "outputArtifact": str(path),
                        "outputSHA256": "sha256:" + hashlib.sha256(data).hexdigest()})
    return {"schema": "idc-platform-evidence/v1", "candidateHead": HEAD, "records": records}


class PlatformCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="idc-platform-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.value = capture_fixture(self.root)

    def rewrite_capture(self, **changes) -> None:
        record = self.value["records"][0]
        path = Path(record["outputArtifact"])
        capture = json.loads(path.read_text(encoding="utf-8"))
        capture.update(changes)
        data = json.dumps(capture).encode("utf-8")
        path.write_bytes(data)
        record["outputSHA256"] = "sha256:" + hashlib.sha256(data).hexdigest()

    def test_fabricated_pass_without_artifact_fails(self) -> None:
        for record in self.value["records"]:
            del record["outputArtifact"]
        with self.assertRaises(platform.PlatformEvidenceError):
            platform.validate(self.value, HEAD)

    def test_consistent_capture_passes_without_claiming_host_authenticity(self) -> None:
        platform.validate(self.value, HEAD)

    def test_matching_hash_with_wrong_candidate_head_fails(self) -> None:
        self.rewrite_capture(candidateHead="b" * 40)
        with self.assertRaises(platform.PlatformEvidenceError):
            platform.validate(self.value, HEAD)

    def test_capture_must_bind_command_environment_status_and_success(self) -> None:
        original = copy.deepcopy(self.value)
        path = Path(original["records"][0]["outputArtifact"])
        data = path.read_bytes()
        for field, value in (("command", "another-command"), ("platform", "windows"),
                             ("runner", "another-host"), ("osVersion", "another-os"),
                             ("filesystem", "NTFS"), ("python", "different-python"),
                             ("bash", "different-bash"), ("sshKeygen", "different-ssh"),
                             ("status", "failed"), ("exitCode", 1), ("exitCode", False),
                             ("output", ""), ("output", [])):
            with self.subTest(field=field, value=value):
                path.write_bytes(data)
                self.value = copy.deepcopy(original)
                self.rewrite_capture(**{field: value})
                with self.assertRaises(platform.PlatformEvidenceError):
                    platform.validate(self.value, HEAD)

    def test_artifact_hash_mismatch_fails(self) -> None:
        self.value["records"][0]["outputSHA256"] = "sha256:" + "0" * 64
        with self.assertRaises(platform.PlatformEvidenceError):
            platform.validate(self.value, HEAD)

    def test_duplicate_capture_keys_fail_even_with_matching_digest(self) -> None:
        record = self.value["records"][0]
        path = Path(record["outputArtifact"])
        data = path.read_bytes()[:-1] + b', "candidateHead": "' + HEAD.encode() + b'"}'
        path.write_bytes(data)
        record["outputSHA256"] = "sha256:" + hashlib.sha256(data).hexdigest()
        with self.assertRaises(platform.PlatformEvidenceError):
            platform.validate(self.value, HEAD)

    def test_missing_relative_directory_and_oversized_artifacts_fail(self) -> None:
        oversized = self.root / "oversized.json"
        with oversized.open("wb") as stream:
            stream.truncate(8 * 1024 * 1024 + 1)
        for path in (self.root / "missing", Path("relative.json"), self.root, oversized):
            with self.subTest(path=path):
                self.value["records"][0]["outputArtifact"] = str(path)
                with self.assertRaises(platform.PlatformEvidenceError):
                    platform.validate(self.value, HEAD)

    @unittest.skipIf(os.name == "nt", "POSIX symlink fixture")
    def test_symlink_artifact_fails(self) -> None:
        target = Path(self.value["records"][0]["outputArtifact"])
        link = self.root / "capture-link"
        link.symlink_to(target)
        self.value["records"][0]["outputArtifact"] = str(link)
        with self.assertRaises(platform.PlatformEvidenceError):
            platform.validate(self.value, HEAD)


if __name__ == "__main__":
    unittest.main()
