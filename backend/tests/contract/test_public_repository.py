from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PRIVATE_SUBMISSION_PATHS = (
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


def test_public_repository_excludes_private_submission_material() -> None:
    present = [
        relative
        for relative in PRIVATE_SUBMISSION_PATHS
        if (ROOT / relative).exists()
    ]

    assert present == []


def test_public_repository_contains_no_machine_specific_home_paths() -> None:
    result = subprocess.run(
        [
            "git",
            "grep",
            "-l",
            "/Users/",
            "--",
            ":!backend/tests/contract/test_public_repository.py",
            ":!artifacts/verification/**",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1, result.stdout


def test_generated_command_evidence_redacts_repository_and_home_paths() -> None:
    script = ROOT / "scripts" / "verification_lib.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_public_path_redaction",
        script,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)

    result = module.command_result(
        [
            sys.executable,
            "-c",
            (
                "import pathlib,sys; "
                f"print({str(ROOT)!r}); "
                f"print({str(Path.home())!r}, file=sys.stderr)"
            ),
        ]
    )

    serialized = str(result)
    assert str(ROOT) not in serialized
    assert str(Path.home()) not in serialized
    assert "[REPOSITORY_ROOT]" in serialized
    assert "[USER_HOME]" in serialized


def test_generated_command_evidence_redacts_truncated_machine_home_paths() -> None:
    script = ROOT / "scripts" / "verification_lib.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_public_truncated_path_redaction",
        script,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)

    result = module.command_result(
        [
            sys.executable,
            "-c",
            (
                "print(r'/Users/private-builder\\\\u2026/repository'); "
                "print('/home/private-builder/worktree')"
            ),
        ]
    )

    serialized = str(result)
    assert "/Users/" not in serialized
    assert "/home/private-builder" not in serialized
    assert serialized.count("[USER_HOME]") >= 2
