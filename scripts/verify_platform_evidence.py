#!/usr/bin/env python3
"""Check captured platform evidence consistency, not runner or host authenticity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


HEAD_RE = re.compile(r"[0-9a-f]{40}\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SCHEMA = "idc-platform-evidence/v1"
CAPTURE_SCHEMA = "idc-platform-capture/v1"
MAX_CAPTURE_BYTES = 8 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
CAPTURE_FIELDS = {
    "platform", "status", "runner", "osVersion", "filesystem", "python",
    "bash", "sshKeygen", "command",
}


class PlatformEvidenceError(RuntimeError):
    pass


def _exact(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PlatformEvidenceError(f"{label} keys differ")
    return value


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PlatformEvidenceError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _snapshot(path: Path, ceiling: int, label: str) -> bytes:
    if not path.is_absolute():
        raise PlatformEvidenceError(f"{label} must be an absolute regular file")
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                             item.st_mtime_ns, item.st_ctime_ns)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= ceiling:
            raise PlatformEvidenceError(f"{label} must be a bounded non-symlink regular file")
        flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_BINARY", 0))
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if identity(before) != identity(opened):
                raise PlatformEvidenceError(f"{label} changed during capture")
            chunks: list[bytes] = []
            length = 0
            while length <= ceiling:
                chunk = os.read(descriptor, min(65536, ceiling + 1 - length))
                if not chunk:
                    break
                chunks.append(chunk)
                length += len(chunk)
            data = b"".join(chunks)
            final = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
        if (identity(before) != identity(final) or identity(final) != identity(after)
                or len(data) != before.st_size):
            raise PlatformEvidenceError(f"{label} changed during capture")
        return data
    except OSError as exc:
        raise PlatformEvidenceError(f"{label} could not be captured: {exc}") from exc


def _json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlatformEvidenceError(f"{label} is not valid JSON") from exc


def validate(value: Any, expected_head: str) -> None:
    root = _exact(value, {"schema", "candidateHead", "records"}, "platform evidence")
    if root["schema"] != SCHEMA:
        raise PlatformEvidenceError("platform evidence schema differs")
    if not isinstance(expected_head, str) or HEAD_RE.fullmatch(expected_head) is None or root["candidateHead"] != expected_head:
        raise PlatformEvidenceError("platform evidence does not bind the exact candidate head")
    records = root["records"]
    if not isinstance(records, list) or len(records) != 2:
        raise PlatformEvidenceError("exactly two platform records are required")
    expected_keys = CAPTURE_FIELDS | {"outputSHA256", "outputArtifact"}
    seen: set[str] = set()
    for index, item in enumerate(records):
        record = _exact(item, expected_keys, f"records[{index}]")
        platform = record["platform"]
        if not isinstance(platform, str) or platform not in {"macos", "windows"} or platform in seen:
            raise PlatformEvidenceError("platform records must uniquely cover macos and windows")
        seen.add(platform)
        if record["status"] != "passed":
            raise PlatformEvidenceError(f"{platform} platform evidence is not passed")
        for key in ("runner", "osVersion", "filesystem", "python", "bash", "sshKeygen", "command"):
            if not isinstance(record[key], str) or not record[key].strip():
                raise PlatformEvidenceError(f"{platform}.{key} must be non-empty")
        if platform == "windows" and record["filesystem"].casefold() != "ntfs":
            raise PlatformEvidenceError("Windows release evidence must come from NTFS")
        if not isinstance(record["outputSHA256"], str) or DIGEST_RE.fullmatch(record["outputSHA256"]) is None:
            raise PlatformEvidenceError(f"{platform}.outputSHA256 is invalid")
        artifact = record["outputArtifact"]
        if not isinstance(artifact, str) or not artifact.strip():
            raise PlatformEvidenceError(f"{platform}.outputArtifact must name a captured file")
        data = _snapshot(Path(artifact), MAX_CAPTURE_BYTES, f"{platform} output artifact")
        if "sha256:" + hashlib.sha256(data).hexdigest() != record["outputSHA256"]:
            raise PlatformEvidenceError(f"{platform} output artifact SHA-256 differs")
        capture = _exact(
            _json(data, f"{platform} output artifact"),
            CAPTURE_FIELDS | {"schema", "candidateHead", "exitCode", "output"},
            f"{platform} output capture",
        )
        if capture["schema"] != CAPTURE_SCHEMA or capture["candidateHead"] != expected_head:
            raise PlatformEvidenceError(f"{platform} output capture schema or candidate head differs")
        if any(capture[field] != record[field] for field in CAPTURE_FIELDS):
            raise PlatformEvidenceError(f"{platform} output capture command, environment, or status differs")
        if type(capture["exitCode"]) is not int or capture["exitCode"] != 0:
            raise PlatformEvidenceError(f"{platform} output capture must record successful exit 0")
        if not isinstance(capture["output"], str) or not capture["output"].strip():
            raise PlatformEvidenceError(f"{platform} output capture must contain non-empty output")
    if seen != {"macos", "windows"}:
        raise PlatformEvidenceError("macos and windows evidence are both required")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--candidate-head", required=True)
    args = parser.parse_args(argv)
    try:
        validate(_json(_snapshot(args.evidence.absolute(), MAX_RECORD_BYTES, "platform evidence"),
                       "platform evidence"), args.candidate_head)
    except (OSError, json.JSONDecodeError, PlatformEvidenceError) as exc:
        print(f"PLATFORM EVIDENCE REFUSED - {exc}", file=sys.stderr)
        return 2
    print(f"PLATFORM CAPTURE CONSISTENCY OK - macos+windows head={args.candidate_head}; "
          "runner authenticity and actual platform execution are not attested")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
