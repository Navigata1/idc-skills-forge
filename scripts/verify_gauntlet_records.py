#!/usr/bin/env python3
"""Check critique records; distinguish resolved commits from staging-only history."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Sequence


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))

from trust_root import TrustError, _git_bytes


REPO_ROOT = Path(__file__).resolve().parents[1]
REVIEWS_DIR = REPO_ROOT / "ops" / "gauntlet" / "reviews"
EXPECTED = {
    "P0-T1-contract-critique.json": (
        "P0-T1",
        "ca4257bb2790ddfea59175e850c6438fee3445e7",
    ),
    "P0-T2-validator-critique.json": (
        "P0-T2",
        "a083552def772489ae238bf6931cd275d471b263",
    ),
    "P0-T3-installer-critique.json": (
        "P0-T3",
        "b1ab04c31015b11a086020fa3a4d0d01654127e6",
    ),
}
HISTORICAL_EXPECTED = dict(EXPECTED)
HISTORICAL_PROVENANCE = "staging-only; not in public history"
SEVERITIES = {"critical", "high", "medium", "low"}


def _require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def verify(*, allow_historical: bool = False, git: Path | None = None) -> list[str]:
    errors: list[str] = []
    try:
        if git is None:
            discovered = shutil.which("git")
            if discovered is None:
                return ["Git executable is unavailable"]
            git = Path(discovered).resolve(strict=True)
        if not git.is_absolute() or not git.is_file() or not os.access(git, os.X_OK):
            return ["Git must be an absolute regular executable"]
        _git_bytes(git, REPO_ROOT, "rev-parse", "--git-dir")
    except (OSError, TrustError) as exc:
        return [f"Git repository could not be checked: {exc}"]
    found = {path.name for path in REVIEWS_DIR.glob("*.json")}
    _require(found == set(EXPECTED), f"review set mismatch: {sorted(found)}", errors)

    seen_tasks: set[str] = set()
    seen_commits: set[str] = set()
    for filename, (task_id, commit) in EXPECTED.items():
        path = REVIEWS_DIR / filename
        if not path.is_file():
            errors.append(f"missing review: {filename}")
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{filename}: invalid JSON: {exc}")
            continue
        if not isinstance(record, dict):
            errors.append(f"{filename}: record must be an object")
            continue

        actual_task = record.get("taskId")
        actual_commit = record.get("reviewedCommit")
        _require(actual_task == task_id, f"{filename}: taskId drift", errors)
        _require(actual_commit == commit, f"{filename}: reviewedCommit drift", errors)
        full_sha = isinstance(actual_commit, str) and re.fullmatch(r"[0-9a-f]{40}", actual_commit) is not None
        _require(
            full_sha,
            f"{filename}: reviewedCommit is not a full SHA",
            errors,
        )
        if isinstance(actual_task, str):
            _require(actual_task not in seen_tasks, f"{filename}: duplicate taskId", errors)
            seen_tasks.add(actual_task)
        if isinstance(actual_commit, str):
            _require(actual_commit not in seen_commits, f"{filename}: duplicate reviewedCommit", errors)
            seen_commits.add(actual_commit)
        if full_sha:
            try:
                object_type = _git_bytes(git, REPO_ROOT, "cat-file", "-t", actual_commit).strip()
            except TrustError:
                object_type = None
            known_historical = (
                HISTORICAL_EXPECTED.get(filename) == (actual_task, actual_commit)
                and record.get("provenance") == HISTORICAL_PROVENANCE
            )
            if allow_historical:
                _require(known_historical, f"{filename}: historical mode requires a known staging record and provenance", errors)
            _require(
                object_type == b"commit" or (object_type is None and allow_historical and known_historical),
                f"{filename}: reviewedCommit does not resolve to a commit object",
                errors,
            )

        independence = str(record.get("independence", "")).lower()
        _require("same-family" in independence, f"{filename}: family not disclosed", errors)
        _require(
            "not a cross-family" in independence,
            f"{filename}: cross-family limitation not disclosed",
            errors,
        )
        _require(bool(record.get("criticSeat")), f"{filename}: critic seat missing", errors)
        _require(
            record.get("disposition") == "changes-requested",
            f"{filename}: critique did not force a repair disposition",
            errors,
        )

        findings = record.get("findings")
        _require(isinstance(findings, list) and bool(findings), f"{filename}: findings missing", errors)
        for index, finding in enumerate(findings if isinstance(findings, list) else [], start=1):
            prefix = f"{filename}: finding {index}"
            _require(isinstance(finding, dict), f"{prefix} is not an object", errors)
            if not isinstance(finding, dict):
                continue
            _require(finding.get("severity") in SEVERITIES, f"{prefix} severity invalid", errors)
            for field in ("title", "evidence", "recompute"):
                text = finding.get(field)
                _require(isinstance(text, str) and bool(text.strip()), f"{prefix} {field} must be non-empty text", errors)

    return errors


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--git", type=Path, help="absolute Git executable (otherwise resolve installed Git)")
    parser.add_argument("--historical-records", action="store_true",
                        help="validate only the three declared staging records; not exact-commit acceptance")
    args = parser.parse_args(argv)
    errors = verify(allow_historical=args.historical_records, git=args.git)
    if errors:
        for error in errors:
            print(f"ERROR {error}", file=sys.stderr)
        return 1
    if args.historical_records:
        print("gauntlet historical records checked: 3 staging-only; not in public history; "
              "exact-commit acceptance and independent authorship not verified")
    else:
        print("gauntlet records checked: 3 resolved builder commit objects and structured "
              "same-family critiques; independent authorship and cross-family verdict not verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
