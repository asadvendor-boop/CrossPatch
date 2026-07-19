from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"


def _load_script() -> ModuleType:
    path = SCRIPTS / "github_license_verifier.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_github_license_verifier", path
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    sys.path.insert(0, str(SCRIPTS))
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPTS))
    return module


def _expectations(module: ModuleType) -> Any:
    return module.Expectations(
        default_branch="main",
        description=(
            "Failure-first SRE incident review with deterministic, warrant-bound execution."
        ),
        topics=(
            "agents-sdk",
            "incident-response",
            "mcp",
            "openai",
            "site-reliability-engineering",
        ),
    )


def _api_payloads() -> dict[str, dict[str, Any]]:
    return {
        "repos/asadvendor-boop/CrossPatch": {
            "default_branch": "main",
            "description": (
                "Failure-first SRE incident review with deterministic, warrant-bound execution."
            ),
            "full_name": "asadvendor-boop/CrossPatch",
            "html_url": "https://github.com/asadvendor-boop/CrossPatch",
            "topics": [
                "agents-sdk",
                "incident-response",
                "mcp",
                "openai",
                "site-reliability-engineering",
            ],
            "visibility": "public",
        },
        "repos/asadvendor-boop/CrossPatch/commits/main": {"sha": "a" * 40},
        "repos/asadvendor-boop/CrossPatch/license": {
            "license": {"spdx_id": "MIT"},
            "path": "LICENSE",
            "sha": "b" * 40,
        },
    }


def test_authenticated_api_verification_is_explicitly_api_only() -> None:
    module = _load_script()
    payloads = _api_payloads()

    result = module.verify_repository(
        "asadvendor-boop/CrossPatch",
        _expectations(module),
        api_reader=lambda endpoint: (payloads[endpoint], None),
        local_head_reader=lambda: ("a" * 40, None),
    )

    assert result["status"] == "API_VERIFIED"
    assert result["verification_scope"] == "authenticated GitHub API and local git only"
    assert result["git_sha"] == "a" * 40
    assert result["blockers"] == []
    assert set(result["checks"]) == {
        "about_metadata",
        "default_branch",
        "repository_visibility",
        "remote_head_matches_local_head",
        "repository_readback",
        "root_license_detected",
    }
    assert all(check["status"] == "PASS" for check in result["checks"].values())
    assert result["authenticated_ui_about_visual_readback"] == {
        "api_inference_allowed": False,
        "claim": "GitHub About visibly renders MIT",
        "required_before_submission": True,
        "status": "NOT_PERFORMED",
    }


def test_verification_fails_closed_on_metadata_head_and_license_mismatches() -> None:
    module = _load_script()
    payloads = _api_payloads()
    payloads["repos/asadvendor-boop/CrossPatch"].update(
        {
            "default_branch": "release",
            "description": "wrong",
            "topics": ["openai"],
            "visibility": "private",
        }
    )
    payloads["repos/asadvendor-boop/CrossPatch/commits/main"]["sha"] = "c" * 40
    payloads["repos/asadvendor-boop/CrossPatch/license"]["license"]["spdx_id"] = "NOASSERTION"

    result = module.verify_repository(
        "asadvendor-boop/CrossPatch",
        _expectations(module),
        api_reader=lambda endpoint: (payloads[endpoint], None),
        local_head_reader=lambda: ("a" * 40, None),
    )

    assert result["status"] == "BLOCKED"
    assert result["checks"]["repository_visibility"]["status"] == "FAIL"
    assert result["checks"]["default_branch"]["status"] == "FAIL"
    assert result["checks"]["about_metadata"]["status"] == "FAIL"
    assert result["checks"]["remote_head_matches_local_head"]["status"] == "FAIL"
    assert result["checks"]["root_license_detected"]["status"] == "FAIL"
    assert len(result["blockers"]) == 5


def test_expectations_are_explicitly_configurable_without_weakening_public_visibility(
    monkeypatch: Any,
) -> None:
    module = _load_script()
    monkeypatch.setenv("CROSSPATCH_GITHUB_EXPECTED_DEFAULT_BRANCH", "release")
    monkeypatch.setenv("CROSSPATCH_GITHUB_EXPECTED_DESCRIPTION", "Release description")
    monkeypatch.setenv("CROSSPATCH_GITHUB_EXPECTED_TOPICS", "sre,openai,sre,incident-response")

    expected = module.Expectations.from_environment()

    assert expected.default_branch == "release"
    assert expected.description == "Release description"
    assert expected.topics == ("incident-response", "openai", "sre")
    assert expected.visibility == "public"


def test_api_or_local_git_errors_are_blockers_and_do_not_run_network_in_tests() -> None:
    module = _load_script()

    result = module.verify_repository(
        "asadvendor-boop/CrossPatch",
        _expectations(module),
        api_reader=lambda endpoint: (None, f"unavailable: {endpoint}"),
        local_head_reader=lambda: (None, "git HEAD unavailable"),
    )

    assert result["status"] == "BLOCKED"
    assert all(check["status"] in {"BLOCKED", "FAIL"} for check in result["checks"].values())
    assert any("git HEAD unavailable" in blocker for blocker in result["blockers"])
    assert any("/license" in blocker for blocker in result["blockers"])
