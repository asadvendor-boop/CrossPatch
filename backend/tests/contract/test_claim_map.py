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
CLAIM_MAP = ROOT / "docs" / "CLAIM_MAP.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MATERIAL_CLAIM_IDS = {
    "product.effort-escalation",
    "product.fail-closed-abstain",
    "product.specialist-contract",
    "release.claim-provenance",
    "release.compose",
    "release.github-license",
    "readiness.demo",
    "readiness.hosted",
    "runtime.agents-sdk",
    "runtime.candidate-isolation",
    "runtime.cli-control-plane",
    "runtime.human-approval",
    "runtime.mcp-zones",
    "runtime.warrant-boundary",
    "runtime.webhook-race",
    "security.evidence-boundary",
    "ui.incident-room",
}


def _load_claim_map() -> dict[str, Any]:
    assert CLAIM_MAP.is_file(), "Task 10 must ship docs/CLAIM_MAP.json"
    payload = json.loads(CLAIM_MAP.read_text(encoding="utf-8"))
    assert isinstance(payload, dict), "claim map must be a JSON object"
    assert payload.get("schema_version") == 1, "claim map schema_version must be 1"
    claims = payload.get("claims")
    assert isinstance(claims, list) and claims, "claim map must contain material claims"
    assert all(isinstance(claim, dict) for claim in claims), "claims must be JSON objects"
    return payload


def _resolve_repo_file(relative: str, *, label: str) -> Path:
    path = Path(relative)
    assert not path.is_absolute() and ".." not in path.parts, f"unsafe {label}: {relative}"
    candidate = ROOT / path
    assert candidate.exists(), f"missing {label}: {relative}"
    assert not candidate.is_symlink(), f"{label} must not be a symlink: {relative}"
    resolved = candidate.resolve(strict=True)
    assert resolved.is_relative_to(ROOT.resolve()), f"{label} escapes the repository: {relative}"
    assert resolved.is_file(), f"missing {label}: {relative}"
    return resolved


def _parse_generated_at(value: object) -> datetime:
    assert isinstance(value, str) and value, "provenance.generated_at is required"
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert parsed.utcoffset() == UTC.utcoffset(parsed), "generated_at must be UTC"
    return parsed


def _registered_claim_ids() -> set[str]:
    path = ROOT / "scripts" / "verification_lib.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_verification_lib_contract", path
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return {claim_id for claim_id, _filename, _description in module.CLAIMS}


def test_checked_in_claim_map_matches_the_current_release_registry() -> None:
    path = ROOT / "scripts" / "verification_lib.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_checked_in_claim_registry_contract",
        path,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)

    loaded = json.loads(module._checked_in_claim_map_bytes())
    expected = {
        claim_id: f"artifacts/verification/{filename}"
        for claim_id, filename, _description in module.CLAIMS
    }
    observed = {
        claim["claim_id"]: claim["artifact_path"] for claim in loaded["claims"]
    }

    assert observed == expected


def _provisional_claim_fixture(
    tmp_path: Path,
    monkeypatch: Any,
) -> tuple[Any, dict[str, Any], tuple[str, ...]]:
    path = ROOT / "scripts" / "verification_lib.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_provisional_claim_map_contract",
        path,
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)

    artifact_directory = tmp_path / "artifacts" / "verification"
    artifact_directory.mkdir(parents=True)
    claim_map = tmp_path / "docs" / "CLAIM_MAP.json"
    claim_map.parent.mkdir()
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "ARTIFACT_DIR", artifact_directory)
    monkeypatch.setattr(module, "CLAIM_MAP", claim_map)
    monkeypatch.setattr(module, "current_git_sha", lambda: "a" * 40)
    monkeypatch.setattr(module, "release_source_sha256", lambda: "b" * 64)

    scripts = tmp_path / "scripts"
    scripts.mkdir()
    external_generators = {
        "demo-readiness.json": "scripts/evaluate-demo-readiness.sh",
        "github-license.json": "scripts/verify-github-license.sh",
        "hosted-acceptance.json": "scripts/verify-hosted.sh",
    }
    for generator in {"scripts/verify-release.sh", *external_generators.values()}:
        path = tmp_path / generator
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)

    statuses = {
        "demo-readiness.json": "DEMO_READINESS_BLOCKED",
        "github-license.json": "BLOCKED",
        "hosted-acceptance.json": "BLOCKED",
    }
    artifact_payloads: dict[str, dict[str, Any]] = {}
    for _claim_id, filename, _description in module.CLAIMS:
        if filename in artifact_payloads:
            continue
        generator = external_generators.get(filename, "scripts/verify-release.sh")
        artifact_payloads[filename] = {
            "checked_at": "2026-07-15T00:00:00Z",
            "command": f"generate {filename}",
            "generator": generator,
            "git_sha": "a" * 40,
            "machine_generated": True,
            "source": f"checked-in {filename}",
            "source_sha256": "b" * 64,
            "status": statuses.get(filename, "PASS"),
        }
        (artifact_directory / filename).write_text(
            json.dumps(artifact_payloads[filename], sort_keys=True) + "\n",
            encoding="utf-8",
        )

    claims = [
        {
            "artifact_path": f"artifacts/verification/{filename}",
            "artifact_sha256": hashlib.sha256(
                (artifact_directory / filename).read_bytes()
            ).hexdigest(),
            "artifact_status": artifact_payloads[filename]["status"],
            "claim_id": claim_id,
            "description": f"checked-in {claim_id}",
            "generator": artifact_payloads[filename]["generator"],
            "provenance": {
                "command": artifact_payloads[filename]["command"],
                "generated_at": artifact_payloads[filename]["checked_at"],
                "generator": artifact_payloads[filename]["generator"],
                "kind": "machine-generated",
                "retained_marker": claim_id,
                "source": artifact_payloads[filename]["source"],
            },
        }
        for claim_id, filename, _description in module.CLAIMS
        if claim_id != "collaboration.codex-provenance"
    ]
    checked_in = {
        "claims": claims,
        "generated_at": "2026-07-15T00:00:00Z",
        "generator": "scripts/verify-release.sh",
        "schema_version": 1,
    }
    claim_map.write_text(
        json.dumps(checked_in, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    checked_in_bytes = claim_map.read_bytes()
    monkeypatch.setattr(
        module,
        "_checked_in_claim_map_bytes",
        lambda: checked_in_bytes,
        raising=False,
    )

    refreshed = (
        "demo-readiness.json",
        "github-license.json",
        "hosted-acceptance.json",
    )
    return module, checked_in, refreshed


def _write_refreshed_artifacts(module: Any, refreshed: tuple[str, ...]) -> None:
    generators = {
        "demo-readiness.json": "scripts/evaluate-demo-readiness.sh",
        "github-license.json": "scripts/verify-github-license.sh",
        "hosted-acceptance.json": "scripts/verify-hosted.sh",
    }
    statuses = {
        "demo-readiness.json": "DEMO_READINESS_BLOCKED",
        "github-license.json": "BLOCKED",
        "hosted-acceptance.json": "BLOCKED",
    }
    for filename in refreshed:
        (module.ARTIFACT_DIR / filename).write_text(
            json.dumps(
                {
                    "checked_at": "2026-07-16T00:00:00Z",
                    "command": f"refresh {filename}",
                    "generator": generators[filename],
                    "git_sha": "a" * 40,
                    "machine_generated": True,
                    "source": f"fresh {filename}",
                    "source_sha256": "b" * 64,
                    "status": statuses[filename],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


def _canonical_entry_bytes(entry: dict[str, Any]) -> bytes:
    return json.dumps(
        entry,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def test_provisional_claim_rebind_preserves_every_material_claim(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    module, _checked_in, refreshed = _provisional_claim_fixture(tmp_path, monkeypatch)

    base = module.load_claim_map_base()
    _write_refreshed_artifacts(module, refreshed)
    provisional = module.rebind_refreshed_claims(base, refreshed)

    claim_ids = {claim["claim_id"] for claim in provisional["claims"]}
    assert claim_ids == {claim["claim_id"] for claim in _checked_in["claims"]}
    assert MATERIAL_CLAIM_IDS <= claim_ids


def test_provisional_claim_rebind_retains_nonrefreshed_entries_byte_identical(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    module, checked_in, refreshed = _provisional_claim_fixture(tmp_path, monkeypatch)
    refreshed_paths = {f"artifacts/verification/{filename}" for filename in refreshed}
    original = {
        claim["claim_id"]: _canonical_entry_bytes(claim)
        for claim in checked_in["claims"]
        if claim["artifact_path"] not in refreshed_paths
    }

    base = module.load_claim_map_base()
    _write_refreshed_artifacts(module, refreshed)
    provisional = module.rebind_refreshed_claims(base, refreshed)
    retained = {
        claim["claim_id"]: _canonical_entry_bytes(claim)
        for claim in provisional["claims"]
        if claim["artifact_path"] not in refreshed_paths
    }

    assert retained == original


def test_provisional_claim_rebind_updates_refreshed_artifact_hashes(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    module, _checked_in, refreshed = _provisional_claim_fixture(tmp_path, monkeypatch)

    base = module.load_claim_map_base()
    _write_refreshed_artifacts(module, refreshed)
    provisional = module.rebind_refreshed_claims(base, refreshed)
    by_id = {claim["claim_id"]: claim for claim in provisional["claims"]}
    registry = {
        claim_id: filename for claim_id, filename, _description in module.CLAIMS
    }
    refreshed_ids = {
        claim_id for claim_id, filename in registry.items() if filename in refreshed
    }

    for claim_id in refreshed_ids:
        artifact = module.ARTIFACT_DIR / registry[claim_id]
        assert by_id[claim_id]["artifact_sha256"] == hashlib.sha256(
            artifact.read_bytes()
        ).hexdigest()
        assert by_id[claim_id]["artifact_sha256"] != "0" * 64


@pytest.mark.parametrize(
    "invalid",
    [
        "missing",
        "invalid-json",
        "incomplete",
        "stale-hash",
        "status-drift",
        "generator-drift",
        "provenance-drift",
    ],
)
def test_provisional_claim_rebind_rejects_invalid_checked_in_map(
    tmp_path: Path,
    monkeypatch: Any,
    invalid: str,
) -> None:
    module, _checked_in, _refreshed = _provisional_claim_fixture(tmp_path, monkeypatch)
    if invalid == "missing":
        module.CLAIM_MAP.unlink()
    elif invalid == "invalid-json":
        module.CLAIM_MAP.write_text("{", encoding="utf-8")
    elif invalid == "incomplete":
        payload = json.loads(module.CLAIM_MAP.read_bytes())
        payload["claims"] = payload["claims"][1:]
        module.CLAIM_MAP.write_text(json.dumps(payload), encoding="utf-8")
    else:
        payload = json.loads(module.CLAIM_MAP.read_bytes())
        claim = payload["claims"][0]
        if invalid == "stale-hash":
            claim["artifact_sha256"] = "0" * 64
        elif invalid == "status-drift":
            claim["artifact_status"] = "BLOCKED"
        elif invalid == "generator-drift":
            claim["generator"] = "scripts/verify-hosted.sh"
        else:
            claim["provenance"]["source"] = "operator-authored replacement"
        module.CLAIM_MAP.write_text(
            json.dumps(payload),
            encoding="utf-8",
        )

    if module.CLAIM_MAP.is_file():
        invalid_bytes = module.CLAIM_MAP.read_bytes()
        monkeypatch.setattr(
            module,
            "_checked_in_claim_map_bytes",
            lambda: invalid_bytes,
            raising=False,
        )

    with pytest.raises(ValueError, match="checked-in claim map"):
        module.load_claim_map_base()


def test_provisional_claim_base_rejects_working_copy_map_drift(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    module, _checked_in, _refreshed = _provisional_claim_fixture(tmp_path, monkeypatch)
    payload = json.loads(module.CLAIM_MAP.read_bytes())
    payload["generated_at"] = "2026-07-16T00:00:00Z"
    module.CLAIM_MAP.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="checked-in claim map bytes"):
        module.load_claim_map_base()


def test_claim_ids_are_stable_and_unique() -> None:
    claims = _load_claim_map()["claims"]
    claim_ids = [claim.get("claim_id") for claim in claims]

    assert all(
        isinstance(claim_id, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,63}", claim_id)
        for claim_id in claim_ids
    ), "every claim_id must be a stable, whitespace-free identifier"
    assert len(claim_ids) == len(set(claim_ids)), "claim_id values must be unique"


def test_generator_omits_failed_positive_evidence_but_keeps_explicit_blocked_state(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    path = ROOT / "scripts" / "verification_lib.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_verification_status_contract", path
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    artifact_directory = tmp_path / "artifacts" / "verification"
    claim_map = tmp_path / "claim-map.json"
    artifact_directory.mkdir(parents=True)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "ARTIFACT_DIR", artifact_directory)
    monkeypatch.setattr(module, "current_git_sha", lambda: "a" * 40, raising=False)
    monkeypatch.setattr(module, "release_source_sha256", lambda: "b" * 64, raising=False)
    monkeypatch.setattr(module, "CLAIM_MAP", claim_map)

    state_statuses = {
        "demo-readiness.json": "DEMO_READINESS_BLOCKED",
        "hosted-acceptance.json": "BLOCKED",
        "github-license.json": "BLOCKED",
    }
    for _claim_id, filename, _description in module.CLAIMS:
        artifact = artifact_directory / filename
        if artifact.exists():
            continue
        status = state_statuses.get(filename, "PASS")
        if filename == "backend-tests.json":
            status = "FAIL"
        artifact.write_text(
            json.dumps(
                {
                    "checked_at": "2026-07-14T00:00:00Z",
                    "command": "machine-check",
                    "generator": "scripts/verify-release.sh",
                    "git_sha": "a" * 40,
                    "machine_generated": True,
                    "source": "fresh machine check",
                    "source_sha256": "b" * 64,
                    "status": status,
                }
            ),
            encoding="utf-8",
        )

    generated = module.generate_claim_map()["claims"]
    by_id = {claim["claim_id"]: claim for claim in generated}
    assert "release.backend" not in by_id
    assert "product.specialist-contract" not in by_id
    assert by_id["readiness.demo"]["artifact_status"] == "DEMO_READINESS_BLOCKED"
    assert by_id["readiness.hosted"]["artifact_status"] == "BLOCKED"
    assert by_id["release.github-license"]["artifact_status"] == "BLOCKED"


def test_claim_provenance_uses_a_dedicated_validation_artifact() -> None:
    path = ROOT / "scripts" / "verification_lib.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_claim_provenance_mapping", path
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    mapping = {claim_id: filename for claim_id, filename, _description in module.CLAIMS}

    assert mapping["release.claim-provenance"] == "claim-provenance.json"
    assert mapping["release.claim-provenance"] != mapping["release.backend"]


def test_incident_room_claim_names_the_selected_tracepaper_signal_identity() -> None:
    path = ROOT / "scripts" / "verification_lib.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_incident_room_claim_copy", path
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    descriptions = {
        claim_id: description
        for claim_id, _filename, description in module.CLAIMS
    }

    incident_room = descriptions["ui.incident-room"]
    assert "Tracepaper Signal Room" in incident_room
    assert "industrial" not in incident_room.lower()


def test_claim_input_validator_fails_closed_on_untrusted_artifact(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    path = ROOT / "scripts" / "verification_lib.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_claim_input_validation", path
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    artifact_directory = tmp_path / "artifacts" / "verification"
    generator = tmp_path / "scripts" / "verify-release.sh"
    artifact_directory.mkdir(parents=True)
    generator.parent.mkdir()
    generator.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    generator.chmod(0o755)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "ARTIFACT_DIR", artifact_directory)
    monkeypatch.setattr(module, "current_git_sha", lambda: "a" * 40, raising=False)
    monkeypatch.setattr(module, "release_source_sha256", lambda: "b" * 64, raising=False)

    state_statuses = {
        "demo-readiness.json": "DEMO_READINESS_BLOCKED",
        "hosted-acceptance.json": "BLOCKED",
        "github-license.json": "BLOCKED",
    }
    for claim_id, filename, _description in module.CLAIMS:
        if claim_id == "release.claim-provenance":
            continue
        artifact = artifact_directory / filename
        if artifact.exists():
            continue
        artifact.write_text(
            json.dumps(
                {
                    "checked_at": "2026-07-14T00:00:00Z",
                    "command": "machine-check",
                    "generator": "scripts/verify-release.sh",
                    "git_sha": "a" * 40,
                    "machine_generated": True,
                    "source": "fresh machine check",
                    "source_sha256": "b" * 64,
                    "status": state_statuses.get(filename, "PASS"),
                }
            ),
            encoding="utf-8",
        )

    assert module.validate_claim_inputs()["status"] == "PASS"

    backend = artifact_directory / "backend-tests.json"
    payload = json.loads(backend.read_text(encoding="utf-8"))
    payload["machine_generated"] = False
    backend.write_text(json.dumps(payload), encoding="utf-8")

    result = module.validate_claim_inputs()
    assert result["status"] == "FAIL"
    assert any(
        check["artifact_path"] == "artifacts/verification/backend-tests.json"
        and check["status"] == "FAIL"
        for check in result["checks"]
    )

    payload["machine_generated"] = True
    payload["git_sha"] = "c" * 40
    backend.write_text(json.dumps(payload), encoding="utf-8")
    stale_result = module.validate_claim_inputs()
    assert stale_result["status"] == "FAIL"
    assert "artifact git_sha does not match current HEAD" in next(
        check["errors"]
        for check in stale_result["checks"]
        if check["artifact_path"].endswith("backend-tests.json")
    )

    payload["git_sha"] = "a" * 40
    payload["source_sha256"] = "d" * 64
    backend.write_text(json.dumps(payload), encoding="utf-8")
    source_result = module.validate_claim_inputs()
    assert source_result["status"] == "FAIL"
    assert "artifact source_sha256 does not match the release source tree" in next(
        check["errors"]
        for check in source_result["checks"]
        if check["artifact_path"].endswith("backend-tests.json")
    )


def test_claim_binding_accepts_only_evidence_only_descendant_commits(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    path = ROOT / "scripts" / "verification_lib.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_claim_commit_binding", path
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)

    def git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    git("init", "--quiet")
    git("config", "user.email", "release-contract@crosspatch.invalid")
    git("config", "user.name", "CrossPatch release contract")
    (tmp_path / "README.md").write_text("source\n", encoding="utf-8")
    git("add", "README.md")
    git("commit", "--quiet", "-m", "source")
    source_commit = git("rev-parse", "HEAD")

    evidence = tmp_path / "artifacts" / "verification" / "backend-tests.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}\n", encoding="utf-8")
    claim_map = tmp_path / "docs" / "CLAIM_MAP.json"
    claim_map.parent.mkdir()
    claim_map.write_text("{}\n", encoding="utf-8")
    git("add", "artifacts/verification/backend-tests.json", "docs/CLAIM_MAP.json")
    git("commit", "--quiet", "-m", "evidence")
    evidence_commit = git("rev-parse", "HEAD")

    monkeypatch.setattr(module, "ROOT", tmp_path)
    assert module._artifact_git_sha_matches_current(source_commit, source_commit)
    assert module._artifact_git_sha_matches_current(source_commit, evidence_commit)
    assert not module._artifact_git_sha_matches_current(evidence_commit, source_commit)
    assert not module._artifact_git_sha_matches_current("f" * 40, evidence_commit)

    (tmp_path / "README.md").write_text("changed source\n", encoding="utf-8")
    git("add", "README.md")
    git("commit", "--quiet", "-m", "source change")
    changed_source_commit = git("rev-parse", "HEAD")
    assert not module._artifact_git_sha_matches_current(
        source_commit,
        changed_source_commit,
    )


def test_material_readme_claims_have_stable_registered_ids() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    registered = _registered_claim_ids()
    generated = {
        claim["claim_id"]
        for claim in _load_claim_map()["claims"]
        if isinstance(claim.get("claim_id"), str)
    }

    missing_registry = MATERIAL_CLAIM_IDS - registered
    assert not missing_registry, (
        f"material claims are absent from the generator: {missing_registry}"
    )
    missing_map = MATERIAL_CLAIM_IDS - generated
    assert not missing_map, f"material claims are absent from the claim map: {missing_map}"
    for claim_id in MATERIAL_CLAIM_IDS:
        assert f"`{claim_id}`" in readme, f"README does not map material claim {claim_id}"


def test_release_verifier_defers_claim_hash_validation_until_after_regeneration(
    monkeypatch: Any,
) -> None:
    scripts = ROOT / "scripts"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_release_verifier_contract", scripts / "release_verifier.py"
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.path.insert(0, str(scripts))
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.remove(str(scripts))

    events: list[object] = []
    command_groups: dict[str, list[list[str]]] = {}

    def fake_run_group(
        filename: str,
        _source: str,
        commands: list[list[str]],
        **_options: Any,
    ) -> dict[str, str]:
        events.append(("group", filename))
        command_groups[filename] = commands
        return {"status": "PASS"}

    def fake_generate_claim_map() -> dict[str, list[object]]:
        events.append("claim_map_generated")
        return {"claims": []}

    def fake_load_claim_map_base() -> dict[str, list[object]]:
        events.append("claim_map_base_loaded")
        return {"claims": []}

    def fake_rebind_refreshed_claims(
        base: dict[str, list[object]],
        refreshed: tuple[str, ...],
    ) -> dict[str, list[object]]:
        if refreshed == (
            "demo-readiness.json",
            "github-license.json",
            "hosted-acceptance.json",
        ):
            assert base == {"claims": []}
            events.append("external_claims_rebound")
            return {"claims": [], "rebound_stages": ["external"]}
        assert refreshed == ("codex-collaboration.json",)
        assert base == {"claims": [], "rebound_stages": ["external"]}
        events.append("codex_claim_rebound")
        return {"claims": [], "rebound_stages": ["external", "codex"]}

    def fake_command_result(argv: list[str]) -> dict[str, str]:
        events.append(("command", tuple(argv)))
        return {"status": "PASS"}

    monkeypatch.setattr(module, "run_group", fake_run_group)

    def fake_ensure_external_artifacts() -> tuple[str, ...]:
        events.append("external_artifacts_generated")
        return (
            "demo-readiness.json",
            "github-license.json",
            "hosted-acceptance.json",
        )

    monkeypatch.setattr(module, "ensure_external_artifacts", fake_ensure_external_artifacts)
    monkeypatch.setattr(
        module,
        "load_claim_map_base",
        fake_load_claim_map_base,
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "rebind_refreshed_claims",
        fake_rebind_refreshed_claims,
        raising=False,
    )
    monkeypatch.setattr(module, "generate_claim_map", fake_generate_claim_map)
    monkeypatch.setattr(
        module,
        "validate_claim_inputs",
        lambda: {"status": "PASS", "checks": []},
    )
    monkeypatch.setattr(module, "command_result", fake_command_result)
    monkeypatch.setattr(module, "atomic_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "git_sha", lambda: "a" * 40)
    monkeypatch.setattr(sys, "argv", ["release_verifier.py"])

    assert module.main() == 0

    assert events.index("claim_map_base_loaded") < events.index(
        "external_artifacts_generated"
    ), "the complete checked-in map must be loaded before external evidence mutates"
    assert events.index("external_artifacts_generated") < events.index(
        "external_claims_rebound"
    ), "every refreshed external artifact must be rebound before validation"
    assert events.index("external_claims_rebound") < events.index(
        ("group", "backend-tests.json")
    ), "the complete provisional map must exist before artifact contract tests run"
    assert events.index(("group", "codex-collaboration.json")) < events.index(
        "codex_claim_rebound"
    ) < events.index(("group", "backend-tests.json")), (
        "every generated claim artifact must be rebound before claim-map contracts run"
    )

    claim_map_generations = [
        index for index, event in enumerate(events) if event == "claim_map_generated"
    ]
    assert len(claim_map_generations) == 1

    backend_pytest = next(
        command for command in command_groups["backend-tests.json"] if "pytest" in command
    )
    assert "--ignore=backend/tests/contract/test_claim_map.py" in backend_pytest, (
        "the pre-generation backend suite must not validate stale claim hashes"
    )
    assert command_groups["codex-collaboration.json"] == [
        [
            "uv",
            "run",
            "--frozen",
            "--extra",
            "dev",
            "python",
            "scripts/verify_codex_collaboration.py",
            "--check",
        ]
    ], (
        "a positive public claim artifact must validate the privacy-minimized dossier"
    )
    final_validation = (
        "command",
        (
            "uv",
            "run",
            "--frozen",
            "--extra",
            "dev",
            "python",
            "-m",
            "pytest",
            "backend/tests/contract/test_claim_map.py",
            "-q",
        ),
    )
    assert claim_map_generations[-1] < events.index(final_validation)
    public_snapshot_validation = (
        "command",
        (
            "uv",
            "run",
            "--frozen",
            "--extra",
            "dev",
            "python",
            "scripts/verify_public_repository.py",
        ),
    )
    assert events.index(final_validation) < events.index(public_snapshot_validation), (
        "the public snapshot scan must run after every evidence artifact is regenerated"
    )


def test_release_verifier_rejects_invalid_base_before_external_mutation(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    scripts = ROOT / "scripts"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_release_invalid_base_contract",
        scripts / "release_verifier.py",
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.path.insert(0, str(scripts))
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.remove(str(scripts))

    external_mutation_attempted = False

    def fake_external_refresh() -> tuple[str, ...]:
        nonlocal external_mutation_attempted
        external_mutation_attempted = True
        return ()

    def fake_load_claim_map_base() -> dict[str, Any]:
        raise ValueError("checked-in claim map is invalid")

    monkeypatch.setattr(module, "ARTIFACT_DIR", tmp_path / "artifacts")
    monkeypatch.setattr(module, "load_claim_map_base", fake_load_claim_map_base)
    monkeypatch.setattr(module, "ensure_external_artifacts", fake_external_refresh)
    monkeypatch.setattr(sys, "argv", ["release_verifier.py"])

    assert module.main() == 1
    assert external_mutation_attempted is False


def test_public_bootstrap_accepts_only_a_clean_one_root_structural_claim_map(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    scripts = ROOT / "scripts"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_public_bootstrap_contract",
        scripts / "release_verifier.py",
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.path.insert(0, str(scripts))
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.remove(str(scripts))

    artifact_dir = tmp_path / "artifacts" / "verification"
    artifact_dir.mkdir(parents=True)
    claims: list[dict[str, Any]] = []
    for claim_id, filename, description in module.CLAIMS:
        generator = (
            "scripts/reproducible_adversarial_eval.py"
            if claim_id == "security.evidence-boundary"
            else "scripts/verify-release.sh"
        )
        artifact = artifact_dir / filename
        if filename not in module.PUBLIC_BOOTSTRAP_MISSING_ARTIFACTS:
            artifact.write_text('{"machine_generated":true}\n', encoding="utf-8")
        claims.append(
            {
                "claim_id": claim_id,
                "description": description,
                "artifact_path": f"artifacts/verification/{filename}",
                "artifact_sha256": (
                    hashlib.sha256(artifact.read_bytes()).hexdigest()
                    if artifact.exists()
                    else "0" * 64
                ),
                "artifact_status": "PASS",
                "generator": generator,
                "provenance": {
                    "kind": "machine-generated",
                    "generator": generator,
                    "source": "bootstrap fixture",
                    "command": "fixture",
                    "generated_at": "2026-07-20T00:00:00Z",
                },
            }
        )
    claim_map = tmp_path / "docs" / "CLAIM_MAP.json"
    claim_map.parent.mkdir()
    claim_map.write_text(
        json.dumps({"schema_version": 1, "claims": claims}) + "\n",
        encoding="utf-8",
    )

    def git(*arguments: str) -> None:
        subprocess.run(["git", *arguments], cwd=tmp_path, check=True, capture_output=True)

    git("init", "--quiet", "--initial-branch=main")
    git("config", "user.email", "release-contract@crosspatch.invalid")
    git("config", "user.name", "CrossPatch release contract")
    git("add", ".")
    git("commit", "--quiet", "-m", "public source root")

    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "CLAIM_MAP", claim_map)
    monkeypatch.setattr(module, "ARTIFACT_DIR", artifact_dir)
    payload = module.load_public_bootstrap_claim_map()
    assert len(payload["claims"]) == len(module.CLAIMS)

    provisional = module.write_public_bootstrap_provisional_claim_map(payload)
    expected_claim_ids = {
        claim_id
        for claim_id, filename, _description in module.CLAIMS
        if filename not in module.PUBLIC_BOOTSTRAP_MISSING_ARTIFACTS
    }
    assert {claim["claim_id"] for claim in provisional["claims"]} == expected_claim_ids
    assert all(
        (tmp_path / claim["artifact_path"]).is_file()
        for claim in provisional["claims"]
    )

    git("commit", "--quiet", "--allow-empty", "-m", "unexpected second commit")
    with pytest.raises(RuntimeError, match="exactly one root source commit"):
        module.load_public_bootstrap_claim_map()


def test_public_bootstrap_restores_the_prebuild_structural_map_byte_identity(
    monkeypatch: Any,
) -> None:
    scripts = ROOT / "scripts"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_public_bootstrap_restore_contract",
        scripts / "release_verifier.py",
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.path.insert(0, str(scripts))
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.remove(str(scripts))

    payload: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": "2026-07-20T00:00:00Z",
        "claims": [
            {"claim_id": claim_id}
            for claim_id, _filename, _description in module.CLAIMS
        ],
    }
    written: list[dict[str, Any]] = []
    monkeypatch.setattr(
        module,
        "atomic_json",
        lambda _path, candidate: written.append(candidate),
    )

    restored = module.restore_public_bootstrap_structural_claim_map(payload)

    assert restored == payload
    assert restored["generated_at"] == "2026-07-20T00:00:00Z"
    assert written == [payload]


def test_strict_race_verification_uses_the_profile_scoped_victim_verifier(
    monkeypatch: Any,
) -> None:
    scripts = ROOT / "scripts"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_strict_race_verifier_contract", scripts / "release_verifier.py"
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.path.insert(0, str(scripts))
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.remove(str(scripts))

    command_groups: dict[str, list[list[str]]] = {}

    def fake_run_group(
        filename: str,
        _source: str,
        commands: list[list[str]],
        **_options: Any,
    ) -> dict[str, str]:
        command_groups[filename] = commands
        return {"status": "PASS"}

    monkeypatch.setattr(module, "run_group", fake_run_group)
    monkeypatch.setattr(module, "ensure_external_artifacts", lambda: ())
    monkeypatch.setattr(module, "load_claim_map_base", lambda: {"claims": []}, raising=False)
    monkeypatch.setattr(
        module,
        "rebind_refreshed_claims",
        lambda base, _refreshed: base,
        raising=False,
    )
    monkeypatch.setattr(module, "generate_claim_map", lambda: {"claims": []})
    monkeypatch.setattr(
        module,
        "validate_claim_inputs",
        lambda: {"status": "PASS", "checks": []},
    )
    monkeypatch.setattr(module, "command_result", lambda _argv: {"status": "PASS"})
    monkeypatch.setattr(module, "atomic_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "git_sha", lambda: "a" * 40)
    monkeypatch.setattr(module, "require_clean_release_source", lambda **_kwargs: None)
    monkeypatch.setenv(
        "CROSSPATCH_VICTIM_WEBHOOK_SECRET",
        "release-test-victim-secret-A1b2C3d4E5f6",
    )
    monkeypatch.setattr(sys, "argv", ["release_verifier.py", "--strict"])

    assert module.main() == 0

    assert command_groups["codex-collaboration.json"][0][-1:] == ["--check"], (
        "strict public release evidence must validate without private local metadata"
    )
    strict_race = command_groups["race-reproduction.json"][1]
    assert strict_race[:8] == [
        "docker",
        "compose",
        "--profile",
        "verification",
        "run",
        "--rm",
        "-T",
        "victim-postgres-verifier",
    ]
    assert "/opt/crosspatch/tests/victim/test_race.py" in strict_race
    assert "/opt/crosspatch/tests/victim/test_worker_retry.py" in strict_race
    assert not any(
        command[:4] == ["docker", "compose", "exec", "-T"]
        for command in command_groups["race-reproduction.json"]
    ), "the production runner must never receive victim bootstrap DDL authority"


def test_every_claim_resolves_to_hash_verified_machine_generated_evidence() -> None:
    required = {
        "claim_id",
        "artifact_path",
        "artifact_sha256",
        "artifact_status",
        "generator",
        "provenance",
    }

    for claim in _load_claim_map()["claims"]:
        assert required <= set(claim), f"claim is missing required fields: {claim}"
        artifact_relative = claim["artifact_path"]
        assert isinstance(artifact_relative, str)
        assert Path(artifact_relative).parts[:2] == ("artifacts", "verification"), (
            "material claims must point to generated verification artifacts, not prose"
        )
        artifact = _resolve_repo_file(artifact_relative, label="claim artifact")
        artifact_bytes = artifact.read_bytes()
        assert artifact_bytes, f"claim artifact is empty: {artifact_relative}"
        expected_hash = claim["artifact_sha256"]
        assert isinstance(expected_hash, str) and SHA256.fullmatch(expected_hash), (
            f"invalid artifact_sha256 for {claim['claim_id']}"
        )
        assert hashlib.sha256(artifact_bytes).hexdigest() == expected_hash, (
            f"artifact bytes do not match claim hash for {claim['claim_id']}"
        )
        artifact_payload = json.loads(artifact_bytes)
        assert artifact_payload.get("status") == claim["artifact_status"]
        state_claim_statuses = {
            "readiness.demo": {"DEMO_READY", "DEMO_READINESS_BLOCKED"},
            "readiness.hosted": {"VERIFIED", "BLOCKED"},
            "release.github-license": {"API_VERIFIED", "BLOCKED"},
        }
        allowed_statuses = state_claim_statuses.get(claim["claim_id"], {"PASS"})
        assert claim["artifact_status"] in allowed_statuses, (
            f"{claim['claim_id']} cannot rely on failed or ambiguous evidence"
        )

        generator_relative = claim["generator"]
        assert isinstance(generator_relative, str) and generator_relative.startswith("scripts/"), (
            "generator must name the checked-in executable that produced the artifact"
        )
        generator = _resolve_repo_file(generator_relative, label="claim generator")
        assert os.access(generator, os.X_OK), (
            f"claim generator is not executable: {generator_relative}"
        )

        provenance = claim["provenance"]
        assert isinstance(provenance, dict), "provenance must be a structured object"
        assert provenance.get("kind") == "machine-generated"
        assert provenance.get("generator") == generator_relative
        command = provenance.get("command")
        assert isinstance(command, str) and command.strip(), "provenance.command is required"
        source = provenance.get("source")
        assert isinstance(source, str) and source.strip(), "provenance.source is required"
        assert source.lower() not in {"manual", "hand-authored", "seeded"}
        _parse_generated_at(provenance.get("generated_at"))


def test_demo_readiness_claim_binds_the_sealed_paced_cohort() -> None:
    claims = {claim["claim_id"]: claim for claim in _load_claim_map()["claims"]}
    demo_claim = claims["readiness.demo"]
    demo_artifact = json.loads(
        _resolve_repo_file(demo_claim["artifact_path"], label="demo readiness artifact").read_text(
            encoding="utf-8"
        )
    )
    cohort = demo_claim["provenance"].get("sealed_cohort")
    assert isinstance(cohort, dict), "demo claim must explicitly bind its sealed cohort"
    assert cohort["batch_id"] == demo_artifact["batch_id"]
    assert cohort["git_sha"] == "8a19ef1115bc1d665665a972f94d7c708a9dcbf5"
    assert cohort["disposition"] == "SEALED_HISTORICAL_ARTIFACT"

    manifest = _resolve_repo_file(cohort["batch_manifest_path"], label="paced batch manifest")
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == cohort["batch_manifest_sha256"]
    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert manifest_payload["git_sha"] == cohort["git_sha"]
    assert manifest_payload["status"] == "DEMO_READY"
    assert manifest_payload["completed_runs"] == 10
    assert manifest_payload["requested_runs"] == 10


def test_claim_artifacts_cannot_self_identify_as_seeded_or_hand_authored() -> None:
    forbidden = {"seeded", "hand-authored", "hand_authored", "fabricated"}
    for claim in _load_claim_map()["claims"]:
        artifact = _resolve_repo_file(claim["artifact_path"], label="claim artifact")
        if artifact.suffix != ".json":
            continue
        payload = json.loads(artifact.read_text(encoding="utf-8"))
        assert isinstance(payload, dict), "JSON claim artifacts must be objects"
        if "machine_generated" in payload:
            assert payload["machine_generated"] is True
        if "generator" in payload:
            assert payload["generator"] == claim["generator"]
        encoded = json.dumps(payload, sort_keys=True).lower()
        for marker in forbidden:
            assert f'"source": "{marker}"' not in encoded
            assert f'"{marker}": true' not in encoded
