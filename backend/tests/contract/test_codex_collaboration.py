from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
DOSSIER = ROOT / "docs" / "codex-sessions.json"
NARRATIVE = ROOT / "docs" / "CODEX_COLLABORATION.md"
SESSION_ID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_SLICES = {
    "domain-state-machine",
    "hostile-evidence-sanitizer",
    "warrant-broker",
    "candidate-isolation",
    "agents-sdk",
    "mcp-zones",
    "web-ui",
    "release-verification",
}
REQUIRED_ROLES = {"plan", "implement", "adversarial_review"}


def _payload() -> dict[str, Any]:
    assert DOSSIER.is_file(), "B1 must ship docs/codex-sessions.json"
    payload = json.loads(DOSSIER.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _utc(value: object) -> datetime:
    assert isinstance(value, str) and value.endswith("Z")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert parsed.utcoffset() == UTC.utcoffset(parsed)
    return parsed


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_codex_dossier_has_real_id_shaped_privacy_minimized_session_provenance() -> None:
    payload = _payload()

    assert payload["schema_version"] == 2
    assert payload["generator"] == "scripts/verify_codex_collaboration.py"
    assert payload["continuous_build_session_id"] == (
        "019f5cdf-55ad-74f3-9a6c-af64f2478847"
    )
    assert payload["planning_session_id"] == "019f5c65-f787-7e63-b523-b8f4065a7819"
    assert payload["source"] == (
        "privacy-minimized local Codex session metadata and current repository test receipts"
    )
    assert payload["role_method"] == (
        "Conservative classification from the recorded task path and bounded task brief; "
        "role is not a native session_meta field."
    )

    sessions = payload["sessions"]
    assert isinstance(sessions, list) and sessions
    ids = [session["session_id"] for session in sessions]
    assert len(ids) == len(set(ids))
    assert all(SESSION_ID.fullmatch(session_id) for session_id in ids)
    for session in sessions:
        assert session["role"] in REQUIRED_ROLES
        assert "status" not in session, "session lifecycle is not proven by session_meta"
        assert isinstance(session["task_path"], str) and session["task_path"].startswith("/root")
        assert session["originator"] == "Codex Desktop"
        assert re.fullmatch(r"\d+\.\d+\.\d+", session["cli_version"])
        parent = session["parent_session_id"]
        assert parent is None or SESSION_ID.fullmatch(parent)
        assert session["repository_cwd_verified"] is True
        assert "recorded_git_commit" not in session
        assert "recorded_git_branch" not in session
        assert SHA256.fullmatch(session["session_meta_sha256"])
        started = _utc(session["started_at"])
        observed = _utc(session["observed_through"])
        assert started <= observed

    serialized = DOSSIER.read_text(encoding="utf-8")
    assert "/" + "Users/" not in serialized
    assert ".codex/sessions" not in serialized
    assert "OPENAI_API_KEY" not in serialized
    assert "raw_transcript" not in serialized
    assert "fixing_commits" not in serialized


def test_every_required_repository_slice_has_plan_implementation_and_review_receipts() -> None:
    payload = _payload()
    sessions = {session["session_id"]: session for session in payload["sessions"]}
    slices = payload["slices"]

    assert {item["slice_id"] for item in slices} == REQUIRED_SLICES
    for item in slices:
        assert isinstance(item["repository_paths"], list) and item["repository_paths"]
        for relative in item["repository_paths"]:
            path = Path(relative)
            assert not path.is_absolute() and ".." not in path.parts
            assert (ROOT / path).exists(), f"missing slice path: {relative}"
        by_role = item["session_ids"]
        assert set(by_role) == REQUIRED_ROLES
        for role in REQUIRED_ROLES:
            assert isinstance(by_role[role], list) and by_role[role]
            for session_id in by_role[role]:
                assert session_id in sessions
                assert sessions[session_id]["role"] == role


def test_named_review_receipts_resolve_to_exact_current_regression_sources() -> None:
    payload = _payload()
    receipts = {receipt["receipt_id"]: receipt for receipt in payload["receipts"]}
    assert set(receipts) == {"warrant-status-ui", "candidate-exit-code-spoof"}

    expected = {
        "warrant-status-ui": {
            "finding_session_id": "019f5d69-b112-7492-88bf-a9649615e307",
            "tests": {
                (
                    "web/tests/components/api.test.ts",
                    "discovers and decodes the exact pending warrant bindings",
                ),
                (
                    "web/tests/components/incident-room.test.tsx",
                    (
                        "refetches the room after approval and displays the authoritative "
                        "warrant status"
                    ),
                ),
            },
        },
        "candidate-exit-code-spoof": {
            "finding_session_id": "019f5d4e-1010-7580-a06b-d53593c1c29b",
            "tests": {
                (
                    "backend/tests/security/test_candidate_spoof.py",
                    "test_import_time_zero_exit_and_forged_stdout_cannot_spoof_success",
                ),
            },
        },
    }

    for receipt_id, contract in expected.items():
        receipt = receipts[receipt_id]
        assert receipt["finding_session_id"] == contract["finding_session_id"]
        actual_tests = {
            (test["path"], test["test_name"])
            for test in receipt["regression_tests"]
        }
        assert actual_tests == contract["tests"]
        assert "fixing_commits" not in receipt

        for test in receipt["regression_tests"]:
            source_path = ROOT / test["path"]
            source = source_path.read_text(encoding="utf-8")
            assert test["test_name"] in source
            assert test["source_sha256"] == hashlib.sha256(
                source_path.read_bytes()
            ).hexdigest()


def test_collaboration_narrative_explains_plan_provenance_and_execution_ownership() -> None:
    assert NARRATIVE.is_file(), "B1 must ship docs/CODEX_COLLABORATION.md"
    narrative = NARRATIVE.read_text(encoding="utf-8")

    assert "019f5c65-f787-7e63-b523-b8f4065a7819" in narrative
    assert "019f5cdf-55ad-74f3-9a6c-af64f2478847" in narrative
    assert "curated Superpowers plugin" in narrative
    assert "planning output, not independent execution evidence" in narrative
    assert "warrant-status-ui" in narrative
    assert "candidate-exit-code-spoof" in narrative
    for slice_id in REQUIRED_SLICES:
        assert f"`{slice_id}`" in narrative

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "[Codex collaboration dossier](docs/CODEX_COLLABORATION.md)" in readme
    assert "`collaboration.codex-provenance`" in readme


def test_codex_dossier_claim_is_registered_to_a_generated_artifact() -> None:
    path = ROOT / "scripts" / "verification_lib.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_codex_dossier_claim", path
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    mapping = {claim_id: filename for claim_id, filename, _description in module.CLAIMS}

    assert mapping["collaboration.codex-provenance"] == "codex-collaboration.json"


def test_dossier_validator_is_keyless_offline_and_strong_mode_fails_without_metadata(
    tmp_path: Path,
) -> None:
    validator = ROOT / "scripts" / "verify_codex_collaboration.py"
    assert validator.is_file() and validator.stat().st_mode & 0o111
    empty_codex_home = tmp_path / "empty-codex-home"
    empty_codex_home.mkdir()
    offline_environment = {**os.environ, "CODEX_HOME": str(empty_codex_home)}

    verified = subprocess.run(
        [
            sys.executable,
            str(validator),
            "--check",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=offline_environment,
    )
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert json.loads(verified.stdout)["local_session_metadata_checked"] == 0

    strong = subprocess.run(
        [
            sys.executable,
            str(validator),
            "--check",
            "--require-local-metadata",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=offline_environment,
    )
    assert strong.returncode != 0
    assert "local session metadata missing" in strong.stderr.lower()


def test_dossier_validator_rejects_a_forged_session_id(tmp_path: Path) -> None:
    validator = ROOT / "scripts" / "verify_codex_collaboration.py"

    forged = _payload()
    real_id = "019f5c9e-1d1c-73e2-8228-2c236dce5765"
    forged_id = "00000000-0000-0000-0000-000000000000"
    forged_session = next(
        session for session in forged["sessions"] if session["session_id"] == real_id
    )
    forged_session["session_id"] = forged_id
    for item in forged["slices"]:
        for session_ids in item["session_ids"].values():
            for index, session_id in enumerate(session_ids):
                if session_id == real_id:
                    session_ids[index] = forged_id
    forged_path = tmp_path / "forged-dossier.json"
    forged_path.write_text(json.dumps(forged), encoding="utf-8")
    rejected = subprocess.run(
        [
            sys.executable,
            str(validator),
            "--check",
            "--dossier",
            str(forged_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "CODEX_HOME": str(tmp_path / "empty-codex-home")},
    )
    assert rejected.returncode != 0
    assert "session selection does not match" in rejected.stderr.lower()


def test_session_projection_rejects_metadata_from_another_repository(
    tmp_path: Path,
) -> None:
    scripts = ROOT / "scripts"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_codex_repository_binding",
        scripts / "verify_codex_collaboration.py",
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.path.insert(0, str(scripts))
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.remove(str(scripts))

    foreign = {
        "id": "019f5c65-f787-7e63-b523-b8f4065a7819",
        "timestamp": "2026-07-01T00:00:00Z",
        "source": "cli",
        "originator": "Codex Desktop",
        "cli_version": "0.1.0",
        "cwd": str(tmp_path),
        "git": {},
    }
    with pytest.raises(module.DossierError, match="different repository cwd"):
        module._safe_session_projection(foreign)


def test_dossier_validator_rejects_coordinated_slice_and_receipt_rewrites(
    tmp_path: Path,
) -> None:
    validator = ROOT / "scripts" / "verify_codex_collaboration.py"
    payload = _payload()

    remapped = json.loads(json.dumps(payload))
    sanitizer = next(
        item
        for item in remapped["slices"]
        if item["slice_id"] == "hostile-evidence-sanitizer"
    )
    sanitizer["session_ids"]["plan"] = [
        "019f5c65-f787-7e63-b523-b8f4065a7819"
    ]
    remapped_path = tmp_path / "remapped-slice.json"
    remapped_path.write_text(json.dumps(remapped), encoding="utf-8")
    slice_result = subprocess.run(
        [sys.executable, str(validator), "--check", "--dossier", str(remapped_path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert slice_result.returncode != 0
    assert "slice mapping does not match" in slice_result.stderr.lower()

    rebound = json.loads(json.dumps(payload))
    rebound["receipts"][0]["finding_session_id"] = (
        "019f5d4e-1010-7580-a06b-d53593c1c29b"
    )
    rebound_path = tmp_path / "rebound-receipt.json"
    rebound_path.write_text(json.dumps(rebound), encoding="utf-8")
    receipt_result = subprocess.run(
        [sys.executable, str(validator), "--check", "--dossier", str(rebound_path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert receipt_result.returncode != 0
    assert "receipt mapping does not match" in receipt_result.stderr.lower()


def test_refresh_does_not_publish_a_dossier_before_all_validation_passes(
    tmp_path: Path,
) -> None:
    validator = ROOT / "scripts" / "verify_codex_collaboration.py"
    output = tmp_path / "codex-sessions.json"
    original = b'{"sentinel":"keep"}\n'
    output.write_bytes(original)

    result = subprocess.run(
        [
            sys.executable,
            str(validator),
            "--refresh",
            "--require-local-metadata",
            "--dossier",
            str(output),
            "--narrative",
            str(tmp_path / "missing.md"),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert output.read_bytes() == original
