from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
VERIFIER = ROOT / "scripts" / "verify-hosted.sh"
ARTIFACT = ROOT / "artifacts" / "verification" / "hosted-acceptance.json"
MINIMUM_JUDGE_WINDOW = datetime(2026, 8, 13, 7, tzinfo=UTC)


def _load_script() -> ModuleType:
    path = ROOT / "scripts" / "hosted_verifier.py"
    specification = importlib.util.spec_from_file_location("crosspatch_hosted_verifier", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.remove(str(ROOT / "scripts"))
    return module


def _parse_utc(value: object, *, field: str) -> datetime:
    assert isinstance(value, str) and value, f"{field} must be a timestamp"
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert parsed.utcoffset() == UTC.utcoffset(parsed), f"{field} must be UTC"
    return parsed


def _load_artifact() -> dict[str, Any]:
    assert ARTIFACT.is_file(), (
        "the canonical machine-generated hosted-acceptance artifact must be checked in"
    )
    payload = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert isinstance(payload, dict), "hosted acceptance artifact must be a JSON object"
    return payload


def test_hosted_verifier_is_executable_and_writes_the_canonical_artifact() -> None:
    assert VERIFIER.is_file(), "Task 10 must ship scripts/verify-hosted.sh"
    assert os.access(VERIFIER, os.X_OK), "scripts/verify-hosted.sh must be executable"
    source = VERIFIER.read_text(encoding="utf-8")

    assert "set -euo pipefail" in source
    assert "hosted-acceptance.json" in source
    assert "CROSSPATCH_PUBLIC_URL" in source
    assert "CROSSPATCH_JUDGE_TOKEN" in source
    assert "2026-08-13T07:00:00Z" in source


def test_canonical_hosted_acceptance_state_is_internally_consistent() -> None:
    artifact = _load_artifact()

    assert artifact.get("schema_version") == 1
    assert artifact.get("machine_generated") is True
    assert artifact.get("generator") == "scripts/verify-hosted.sh"
    assert artifact.get("status") in {"BLOCKED", "VERIFIED"}
    public_url = artifact.get("public_url")
    assert public_url in (None, "") or (
        isinstance(public_url, str) and public_url.startswith("https://")
    )
    _parse_utc(artifact.get("checked_at"), field="checked_at")
    assert (
        _parse_utc(artifact.get("required_through"), field="required_through")
        >= MINIMUM_JUDGE_WINDOW
    )

    blockers = artifact.get("blockers")
    assert isinstance(blockers, list)
    if artifact["status"] == "BLOCKED":
        assert artifact.get("deployment_claimed") is False
        assert blockers, "BLOCKED artifact must record blockers"
    else:
        assert artifact.get("deployment_claimed") is True
        assert blockers == [], "VERIFIED artifact cannot retain blockers"
        assert isinstance(public_url, str) and public_url.startswith("https://")
        deployment_git_sha = artifact.get("deployment_git_sha")
        assert isinstance(deployment_git_sha, str) and len(deployment_git_sha) == 40
        assert all(character in "0123456789abcdef" for character in deployment_git_sha)
    if artifact["status"] == "BLOCKED" and public_url in (None, ""):
        blocker_text = json.dumps(blockers, sort_keys=True).lower()
        for required in ("credential", "dns", "reachable", "url"):
            assert required in blocker_text, f"hosted blocker evidence must mention {required}"


def test_canonical_hosted_artifact_preserves_every_required_external_result() -> None:
    artifact = _load_artifact()
    checks = artifact.get("checks")
    assert isinstance(checks, dict) and checks, "hosted artifact must enumerate attempted checks"
    required_external_checks = {
        "authenticated_judge_mcp",
        "backup_restore",
        "dns",
        "github_mit_metadata",
        "github_about_visual",
        "persistent_token",
        "private_service_ports_unreachable",
        "public_health",
        "reachable_url",
        "restart_policy",
        "tls",
        "tls_renewal",
        "uptime_monitor",
    }
    assert required_external_checks <= set(checks), (
        "hosted artifact omits required external checks: "
        f"{sorted(required_external_checks - set(checks))}"
    )
    github_artifact = json.loads(
        (ROOT / "artifacts" / "verification" / "github-license.json").read_text(encoding="utf-8")
    )
    expected_github_status = (
        "PASS" if github_artifact.get("status") == "API_VERIFIED" else "BLOCKED"
    )
    assert checks["github_mit_metadata"]["status"] == expected_github_status
    if artifact["status"] == "BLOCKED":
        blocked_checks = {
            name
            for name, result in checks.items()
            if isinstance(result, dict) and result.get("status") == "BLOCKED"
        }
        assert blocked_checks, "aggregate BLOCKED status requires at least one blocked check"
        blockers = artifact.get("blockers")
        assert isinstance(blockers, list) and blockers
        assert checks["github_about_visual"]["status"] == "BLOCKED", (
            "API metadata must never substitute for authenticated About-panel proof"
        )
    else:
        assert all(checks[name]["status"] == "PASS" for name in required_external_checks)


def test_generic_machine_generated_pass_is_not_operational_evidence(tmp_path: Path) -> None:
    module = _load_script()
    artifact = tmp_path / "restart-policy.json"
    artifact.write_text(
        json.dumps(
            {
                "machine_generated": True,
                "generator": "anything",
                "status": "PASS",
            }
        ),
        encoding="utf-8",
    )

    result = module.generated_evidence_check(
        artifact,
        label="live restart-policy readback",
    )

    assert result["status"] == "BLOCKED"


def _bound_operational_artifact(
    module: ModuleType,
    *,
    checked_at: datetime,
    check_id: str = "restart_policy",
) -> dict[str, Any]:
    contract = (
        module.GITHUB_VISUAL_EVIDENCE_CONTRACT
        if check_id == "github_about_visual"
        else module.OPERATIONAL_EVIDENCE_CONTRACTS[check_id]
    )
    observations_by_check: dict[str, dict[str, Any]] = {
        "restart_policy": {
            "services": {
                service: "unless-stopped"
                for service in (
                    "api",
                    "broker-mcp",
                    "caddy",
                    "candidate-executor",
                    "evidence-mcp",
                    "judge-mcp",
                    "postgres",
                    "runner",
                    "victim",
                    "victim-postgres",
                    "victim-worker",
                    "web",
                )
            }
        },
        "persistent_token": {
            "after_restart_authenticated": True,
            "before_restart_authenticated": True,
            "restarted_services": ["caddy", "judge-mcp"],
            "token_sha256": "b" * 64,
        },
        "tls_renewal": {
            "automation_enabled": True,
            "certificate_not_after": "2026-09-01T07:00:00Z",
            "hostname": "crosspatch.example",
            "renewal_probe_status": "PASS",
        },
        "backup_restore": {
            "backup_sha256": "c" * 64,
            "integrity_checks_passed": True,
            "isolated_project": "crosspatch-restore-drill-20260714",
            "restore_completed": True,
        },
    }
    return {
        "schema_version": module.EVIDENCE_SCHEMA_VERSION,
        "machine_generated": True,
        "check_id": check_id,
        "generator": contract.generator,
        "generator_action": contract.generator_action,
        "status": "PASS",
        "checked_at": checked_at.isoformat().replace("+00:00", "Z"),
        "deployment": {
            "public_url": "https://crosspatch.example",
            "git_sha": "a" * 40,
        },
        "source": "live deployment observation",
        "command": "capture live restart policy",
        "observations": observations_by_check.get(check_id, {"pending": True}),
    }


def test_bound_fresh_operational_evidence_cannot_substitute_for_missing_capture_action(
    tmp_path: Path,
) -> None:
    module = _load_script()
    assert hasattr(module, "OPERATIONAL_EVIDENCE_CONTRACTS"), (
        "hosted verifier must expose strict per-check evidence contracts"
    )
    now = datetime(2026, 7, 14, 8, tzinfo=UTC)
    artifact = tmp_path / "restart-policy.json"
    artifact.write_text(
        json.dumps(_bound_operational_artifact(module, checked_at=now)),
        encoding="utf-8",
    )

    result = module.generated_evidence_check(
        artifact,
        label="live restart-policy readback",
        contract=module.OPERATIONAL_EVIDENCE_CONTRACTS["restart_policy"],
        public_url="https://crosspatch.example",
        git_sha="a" * 40,
        now=now,
    )

    assert result["status"] == "BLOCKED"
    assert result["evidence"]["check_id"] == "restart_policy"
    assert result["evidence"]["git_sha"] == "a" * 40
    assert (
        "artifact was not captured by this verifier invocation"
        in result["evidence"]["validation_errors"]
    )


def test_all_operational_actions_exist_but_operator_json_remains_untrusted(
    tmp_path: Path,
) -> None:
    module = _load_script()
    assert module.IMPLEMENTED_OPERATIONAL_CAPTURE_ACTIONS == frozenset(
        contract.generator_action for contract in module.OPERATIONAL_EVIDENCE_CONTRACTS.values()
    )
    now = datetime(2026, 7, 14, 8, tzinfo=UTC)
    artifact = tmp_path / "restart-policy.json"
    artifact.write_text(
        json.dumps(_bound_operational_artifact(module, checked_at=now)),
        encoding="utf-8",
    )

    untrusted = module.generated_evidence_check(
        artifact,
        label="live restart-policy readback",
        contract=module.OPERATIONAL_EVIDENCE_CONTRACTS["restart_policy"],
        public_url="https://crosspatch.example",
        git_sha="a" * 40,
        now=now,
    )
    receipt = module.CapturedOperationalEvidence(
        check_id="restart_policy",
        path=artifact.resolve(),
        sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
    )
    trusted = module.generated_evidence_check(
        artifact,
        label="live restart-policy readback",
        contract=module.OPERATIONAL_EVIDENCE_CONTRACTS["restart_policy"],
        public_url="https://crosspatch.example",
        git_sha="a" * 40,
        now=now,
        captured=receipt,
    )

    assert untrusted["status"] == "BLOCKED"
    assert trusted["status"] == "PASS"
    artifact.write_text("{}", encoding="utf-8")
    assert (
        module.generated_evidence_check(
            artifact,
            label="live restart-policy readback",
            contract=module.OPERATIONAL_EVIDENCE_CONTRACTS["restart_policy"],
            public_url="https://crosspatch.example",
            git_sha="a" * 40,
            now=now,
            captured=receipt,
        )["status"]
        == "BLOCKED"
    )


def test_restart_policy_capture_requires_live_healthy_compose_containers(tmp_path: Path) -> None:
    module = _load_script()
    seen: list[str] = []

    def inspect(service: str) -> dict[str, Any]:
        seen.append(service)
        return {
            "project": "crosspatch",
            "service": service,
            "running": True,
            "healthy": True,
            "restart_policy": "unless-stopped",
        }

    receipt = module.capture_restart_policy(
        output_dir=tmp_path,
        public_url="https://crosspatch.example",
        git_sha="a" * 40,
        compose_project="crosspatch",
        inspector=inspect,
    )
    payload = json.loads(receipt.path.read_text(encoding="utf-8"))
    assert set(seen) == module.REQUIRED_RESTART_SERVICES
    assert payload["status"] == "PASS"

    def unhealthy(service: str) -> dict[str, Any]:
        value = inspect(service)
        if service == "api":
            value["healthy"] = False
        return value

    with pytest.raises(module.CaptureBlocked):
        module.capture_restart_policy(
            output_dir=tmp_path,
            public_url="https://crosspatch.example",
            git_sha="a" * 40,
            compose_project="crosspatch",
            inspector=unhealthy,
        )


def test_token_tls_and_backup_captures_fail_closed_on_unobserved_controls(
    tmp_path: Path,
) -> None:
    module = _load_script()
    token = "judge-token-never-written-to-artifact"
    receipt = module.capture_persistent_token(
        output_dir=tmp_path,
        public_url="https://crosspatch.example",
        git_sha="a" * 40,
        judge_token=token,
        compose_project="crosspatch",
        authenticator=lambda: True,
        restarter=lambda: {
            "caddy": ("id-caddy", "before", "after"),
            "judge-mcp": ("id-judge", "before", "after"),
        },
    )
    assert token not in receipt.path.read_text(encoding="utf-8")
    with pytest.raises(module.CaptureBlocked):
        module.capture_persistent_token(
            output_dir=tmp_path,
            public_url="https://crosspatch.example",
            git_sha="a" * 40,
            judge_token=token,
            compose_project="crosspatch",
            authenticator=lambda: False,
            restarter=lambda: {},
        )

    tls = module.capture_tls_renewal(
        output_dir=tmp_path,
        public_url="https://crosspatch.example",
        git_sha="a" * 40,
        compose_project="crosspatch",
        observer=lambda: {
            "automation_enabled": True,
            "certificate_not_after": "2026-09-01T07:00:00Z",
            "hostname": "crosspatch.example",
            "renewal_probe_status": "PASS",
        },
    )
    assert tls.check_id == "tls_renewal"

    backup = module.capture_backup_restore(
        output_dir=tmp_path,
        public_url="https://crosspatch.example",
        git_sha="a" * 40,
        compose_project="crosspatch",
        drill=lambda: {
            "backup_sha256": "c" * 64,
            "integrity_checks_passed": True,
            "isolated_project": "crosspatch-restore-0123456789ab",
            "restore_completed": True,
        },
    )
    assert backup.check_id == "backup_restore"
    with pytest.raises(module.CaptureBlocked):
        module.capture_backup_restore(
            output_dir=tmp_path,
            public_url="https://crosspatch.example",
            git_sha="a" * 40,
            compose_project="crosspatch",
            drill=lambda: {
                "backup_sha256": "c" * 64,
                "integrity_checks_passed": False,
                "isolated_project": "crosspatch-restore-0123456789ab",
                "restore_completed": True,
            },
        )


def test_operational_evidence_rejects_identity_deployment_and_freshness_tampering(
    tmp_path: Path,
) -> None:
    module = _load_script()
    now = datetime(2026, 7, 14, 8, tzinfo=UTC)
    baseline = _bound_operational_artifact(module, checked_at=now)
    mutations = {
        "schema": lambda value: value.update(schema_version="invented"),
        "check": lambda value: value.update(check_id="backup_restore"),
        "generator": lambda value: value.update(generator="scripts/backup.sh"),
        "action": lambda value: value.update(generator_action="capture:anything"),
        "host": lambda value: value["deployment"].update(public_url="https://other.example"),
        "commit": lambda value: value["deployment"].update(git_sha="b" * 40),
        "stale": lambda value: value.update(checked_at=(now - timedelta(days=8)).isoformat()),
        "future": lambda value: value.update(checked_at=(now + timedelta(hours=1)).isoformat()),
        "naive-time": lambda value: value.update(checked_at="2026-07-14T08:00:00"),
    }

    for name, mutate in mutations.items():
        payload = deepcopy(baseline)
        mutate(payload)
        artifact = tmp_path / f"{name}.json"
        artifact.write_text(json.dumps(payload), encoding="utf-8")
        result = module.generated_evidence_check(
            artifact,
            label="live restart-policy readback",
            contract=module.OPERATIONAL_EVIDENCE_CONTRACTS["restart_policy"],
            public_url="https://crosspatch.example",
            git_sha="a" * 40,
            now=now,
        )
        assert result["status"] == "BLOCKED", name


def test_operational_evidence_rejects_content_free_observations(tmp_path: Path) -> None:
    module = _load_script()
    now = datetime(2026, 7, 14, 8, tzinfo=UTC)
    for check_id, contract in module.OPERATIONAL_EVIDENCE_CONTRACTS.items():
        payload = _bound_operational_artifact(
            module,
            checked_at=now,
            check_id=check_id,
        )
        payload["observations"] = {"claimed": True}
        artifact = tmp_path / f"{check_id}-content-free.json"
        artifact.write_text(json.dumps(payload), encoding="utf-8")
        result = module.generated_evidence_check(
            artifact,
            label=check_id,
            contract=contract,
            public_url="https://crosspatch.example",
            git_sha="a" * 40,
            now=now,
        )
        assert result["status"] == "BLOCKED", check_id


def test_private_port_probe_passes_only_when_every_api_and_mcp_port_is_closed() -> None:
    module = _load_script()
    assert hasattr(module, "private_service_ports_check"), (
        "hosted verifier must actively probe private API/MCP ports"
    )
    attempted: list[tuple[str, int]] = []

    def refused(address: tuple[str, int], *, timeout: float) -> None:
        assert timeout > 0
        attempted.append(address)
        raise ConnectionRefusedError(address)

    closed = module.private_service_ports_check(
        "crosspatch.example",
        connector=refused,
    )

    assert closed["status"] == "PASS"
    assert attempted == [
        ("crosspatch.example", 8000),
        ("crosspatch.example", 8011),
        ("crosspatch.example", 8012),
        ("crosspatch.example", 8013),
    ]

    class OpenConnection:
        def close(self) -> None:
            return None

    def judge_exposed(address: tuple[str, int], *, timeout: float) -> Any:
        if address[1] == 8013:
            return OpenConnection()
        raise ConnectionRefusedError(address)

    exposed = module.private_service_ports_check(
        "crosspatch.example",
        connector=judge_exposed,
    )

    assert exposed["status"] == "FAIL"
    assert exposed["evidence"]["exposed_ports"] == [8013]


def _github_api_artifact(*, checked_at: datetime) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "machine_generated": True,
        "generator": "scripts/verify-github-license.sh",
        "source": "authenticated GitHub REST metadata, root license endpoint, and local git",
        "command": "./scripts/verify-github-license.sh",
        "checked_at": checked_at.isoformat().replace("+00:00", "Z"),
        "repository": "asadvendor-boop/CrossPatch",
        "git_sha": "a" * 40,
        "status": "API_VERIFIED",
        "verification_scope": "authenticated GitHub API and local git only",
        "blockers": [],
        "checks": {
            name: {"status": "PASS"}
            for name in (
                "about_metadata",
                "default_branch",
                "repository_visibility",
                "remote_head_matches_local_head",
                "repository_readback",
                "root_license_detected",
            )
        },
        "authenticated_ui_about_visual_readback": {
            "api_inference_allowed": False,
            "claim": "GitHub About visibly renders MIT",
            "required_before_submission": True,
            "status": "NOT_PERFORMED",
        },
    }


def test_github_api_and_visual_evidence_are_independent_required_facts(
    tmp_path: Path,
) -> None:
    module = _load_script()
    assert hasattr(module, "github_api_evidence_check")
    assert hasattr(module, "github_about_visual_evidence_check")
    now = datetime(2026, 7, 14, 8, tzinfo=UTC)
    api_path = tmp_path / "github-license.json"
    api_path.write_text(json.dumps(_github_api_artifact(checked_at=now)), encoding="utf-8")

    api_result = module.github_api_evidence_check(
        api_path,
        git_sha="a" * 40,
        now=now,
    )

    assert api_result["status"] == "PASS"
    assert api_result["evidence"]["repository"] == "asadvendor-boop/CrossPatch"

    screenshot = tmp_path / "github-about.png"
    screenshot.write_bytes(b"authenticated browser capture")
    visual = _bound_operational_artifact(
        module,
        checked_at=now,
        check_id="github_about_visual",
    )
    visual["observations"] = {
        "about_license_text": "MIT",
        "authenticated_session": True,
        "repository": "asadvendor-boop/CrossPatch",
        "screenshot_path": str(screenshot),
        "screenshot_sha256": hashlib.sha256(screenshot.read_bytes()).hexdigest(),
    }
    visual_path = tmp_path / "github-about-visual.json"
    visual_path.write_text(json.dumps(visual), encoding="utf-8")

    visual_result = module.github_about_visual_evidence_check(
        visual_path,
        public_url="https://crosspatch.example",
        git_sha="a" * 40,
        repository="asadvendor-boop/CrossPatch",
        now=now,
    )

    assert visual_result["status"] == "PASS"


def test_github_evidence_rejects_api_overclaim_and_visual_spoofing(tmp_path: Path) -> None:
    module = _load_script()
    assert hasattr(module, "github_api_evidence_check")
    assert hasattr(module, "github_about_visual_evidence_check")
    now = datetime(2026, 7, 14, 8, tzinfo=UTC)
    api_payload = _github_api_artifact(checked_at=now)
    api_payload["status"] = "VERIFIED"
    api_path = tmp_path / "github-api-overclaim.json"
    api_path.write_text(json.dumps(api_payload), encoding="utf-8")
    assert (
        module.github_api_evidence_check(
            api_path,
            git_sha="a" * 40,
            now=now,
        )["status"]
        == "BLOCKED"
    )

    screenshot = tmp_path / "github-about.png"
    screenshot.write_bytes(b"authenticated browser capture")
    baseline = _bound_operational_artifact(
        module,
        checked_at=now,
        check_id="github_about_visual",
    )
    baseline["observations"] = {
        "about_license_text": "MIT",
        "authenticated_session": True,
        "repository": "asadvendor-boop/CrossPatch",
        "screenshot_path": str(screenshot),
        "screenshot_sha256": hashlib.sha256(screenshot.read_bytes()).hexdigest(),
    }
    mutations = {
        "anonymous": lambda value: value["observations"].update(authenticated_session=False),
        "wrong-license": lambda value: value["observations"].update(
            about_license_text="NOASSERTION"
        ),
        "wrong-repository": lambda value: value["observations"].update(
            repository="attacker/repository"
        ),
        "forged-screenshot": lambda value: value["observations"].update(screenshot_sha256="0" * 64),
    }
    for name, mutate in mutations.items():
        payload = deepcopy(baseline)
        mutate(payload)
        path = tmp_path / f"visual-{name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        result = module.github_about_visual_evidence_check(
            path,
            public_url="https://crosspatch.example",
            git_sha="a" * 40,
            repository="asadvendor-boop/CrossPatch",
            now=now,
        )
        assert result["status"] == "BLOCKED", name


def test_hosted_stays_blocked_when_operational_inputs_are_only_self_asserted(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    module = _load_script()
    assert hasattr(module, "local_git_sha"), (
        "hosted evidence must bind to the current repository commit"
    )
    now = datetime.now(UTC)
    public_url = "https://crosspatch.example"

    async def passing_public_checks(_public_url: str, _judge_token: str) -> dict[str, dict]:
        return {
            name: {"status": "PASS", "detail": "verified"}
            for name in (
                "authenticated_judge_mcp",
                "dns",
                "private_service_ports_unreachable",
                "public_health",
                "reachable_url",
                "tls",
            )
        }

    monkeypatch.setattr(module, "ARTIFACT_DIR", tmp_path)
    source_git_sha = "a" * 40
    deployment_git_sha = "b" * 40
    monkeypatch.setattr(module, "local_git_sha", lambda: source_git_sha)
    monkeypatch.setattr(module, "public_checks", passing_public_checks)
    monkeypatch.setattr(sys, "argv", ["hosted_verifier.py", "--output", str(tmp_path / "out.json")])
    monkeypatch.setenv("CROSSPATCH_PUBLIC_URL", public_url)
    monkeypatch.setenv("CROSSPATCH_JUDGE_TOKEN", "judge-token")
    monkeypatch.setenv("CROSSPATCH_UPTIME_MONITOR_ID", "monitor-1")
    monkeypatch.setenv("CROSSPATCH_UPTIME_MONITOR_ACTIVE_THROUGH", "2026-09-01T07:00:00Z")

    for check_id, environment_name in {
        "restart_policy": "CROSSPATCH_RESTART_POLICY_EVIDENCE",
        "persistent_token": "CROSSPATCH_TOKEN_PERSISTENCE_EVIDENCE",
        "tls_renewal": "CROSSPATCH_TLS_RENEWAL_EVIDENCE",
        "backup_restore": "CROSSPATCH_BACKUP_RESTORE_EVIDENCE",
    }.items():
        artifact = tmp_path / f"{check_id}.json"
        artifact.write_text(
            json.dumps(
                _bound_operational_artifact(module, checked_at=now, check_id=check_id)
                | {"deployment": {"public_url": public_url, "git_sha": deployment_git_sha}}
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv(environment_name, str(artifact))

    (tmp_path / "github-license.json").write_text(
        json.dumps(_github_api_artifact(checked_at=now)),
        encoding="utf-8",
    )
    screenshot = tmp_path / "github-about.png"
    screenshot.write_bytes(b"authenticated browser capture")
    visual = _bound_operational_artifact(
        module,
        checked_at=now,
        check_id="github_about_visual",
    )
    visual["observations"] = {
        "about_license_text": "MIT",
        "authenticated_session": True,
        "repository": "asadvendor-boop/CrossPatch",
        "screenshot_path": str(screenshot),
        "screenshot_sha256": hashlib.sha256(screenshot.read_bytes()).hexdigest(),
    }
    visual_path = tmp_path / "github-about-visual.json"
    visual_path.write_text(json.dumps(visual), encoding="utf-8")
    monkeypatch.setenv("CROSSPATCH_GITHUB_ABOUT_VISUAL_EVIDENCE", str(visual_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hosted_verifier.py",
            "--output",
            str(tmp_path / "out.json"),
            "--deployment-git-sha",
            deployment_git_sha,
        ],
    )

    return_code = module.main()
    result = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))

    assert return_code == 2
    assert result["status"] == "BLOCKED"
    assert result["deployment_claimed"] is False
    assert result["git_sha"] == source_git_sha
    assert result["deployment_git_sha"] == deployment_git_sha
    assert result["checks"]["github_mit_metadata"]["status"] == "PASS"
    assert result["checks"]["github_about_visual"]["status"] == "PASS"
    assert {
        result["checks"][check_id]["status"] for check_id in module.OPERATIONAL_EVIDENCE_CONTRACTS
    } == {"BLOCKED"}

    blocked_output = tmp_path / "without-visual.json"
    monkeypatch.delenv("CROSSPATCH_GITHUB_ABOUT_VISUAL_EVIDENCE")
    monkeypatch.setattr(
        sys,
        "argv",
        ["hosted_verifier.py", "--output", str(blocked_output)],
    )

    blocked_return_code = module.main()
    blocked = json.loads(blocked_output.read_text(encoding="utf-8"))

    assert blocked_return_code == 2
    assert blocked["status"] == "BLOCKED"
    assert blocked["deployment_claimed"] is False
    assert blocked["checks"]["github_mit_metadata"]["status"] == "PASS"
    assert blocked["checks"]["github_about_visual"]["status"] == "BLOCKED"
