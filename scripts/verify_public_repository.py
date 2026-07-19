#!/usr/bin/env python3
"""Fail closed when the publishable snapshot contains private release material."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_PATHS = (
    "design-qa.md",
    "docs/DEMO_SCRIPT.md",
    "docs/DEVPOST_CHECKLIST.md",
    "docs/DEVPOST_DRAFT.md",
    "docs/DEVPOST_PRIVATE_TESTING_TEMPLATE.md",
    "docs/GALLERY_RUNBOOK.md",
    "docs/SECURITY_REMEDIATION.md",
    "docs/superpowers",
    "output/final-submission-2026-07-18",
)
PRIVATE_REFERENCES = (
    "docs/DEMO_SCRIPT.md",
    "docs/DEVPOST_CHECKLIST.md",
    "docs/DEVPOST_DRAFT.md",
    "docs/DEVPOST_PRIVATE_TESTING_TEMPLATE.md",
    "docs/GALLERY_RUNBOOK.md",
    "docs/SECURITY_REMEDIATION.md",
    "docs/superpowers/",
    "design-qa.md",
)
SCAN_EXCLUSIONS = (
    ":!scripts/verify_public_repository.py",
    ":!backend/tests/contract/test_public_repository.py",
)


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _grep_tracked(needle: str) -> tuple[str, ...]:
    result = _git("grep", "-n", "--fixed-strings", needle, "--", ".", *SCAN_EXCLUSIONS)
    if result.returncode not in {0, 1}:
        raise RuntimeError(result.stderr.strip() or "git grep failed")
    return tuple(line for line in result.stdout.splitlines() if line)


def verify() -> dict[str, object]:
    violations: list[str] = []
    for relative in PRIVATE_PATHS:
        if (ROOT / relative).exists():
            violations.append(f"private path exists: {relative}")
    for reference in PRIVATE_REFERENCES:
        violations.extend(
            f"private reference: {match}" for match in _grep_tracked(reference)
        )
    machine_home = "/" + "Users/"
    violations.extend(
        f"machine-local path: {match}" for match in _grep_tracked(machine_home)
    )
    tracked_environment = _git("ls-files", "--", ".env", ".env.local")
    if tracked_environment.returncode != 0:
        raise RuntimeError(tracked_environment.stderr.strip() or "git ls-files failed")
    violations.extend(
        f"tracked environment file: {relative}"
        for relative in tracked_environment.stdout.splitlines()
        if relative
    )
    return {
        "status": "FAIL" if violations else "PASS",
        "private_path_count": len(PRIVATE_PATHS),
        "private_reference_count": len(PRIVATE_REFERENCES),
        "violations": violations,
    }


def main() -> int:
    try:
        result = verify()
    except RuntimeError as error:
        print(f"public repository verification FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
