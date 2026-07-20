from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REQUIRED_DOCUMENTS = (
    "README.md",
    "SECURITY.md",
    "docs/EXTENDING.md",
    "docs/THREAT_MODEL.md",
    "docs/DEPLOYMENT.md",
    "docs/JUDGE_GUIDE.md",
    "docs/CLAIM_MAP.json",
)
REQUIRED_SCRIPTS = (
    "scripts/setup-sample-incident.sh",
    "scripts/verify-release.sh",
    "scripts/verify-hosted.sh",
    "scripts/verify-github-license.sh",
    "scripts/verify_public_repository.py",
    "scripts/backup.sh",
    "scripts/restore.sh",
)
SERVICE_DEADLINE = "2026-08-13T07:00:00Z"


def _read(relative: str) -> str:
    path = ROOT / relative
    assert path.is_file(), f"Task 10 must ship {relative}"
    return path.read_text(encoding="utf-8")


def test_release_documentation_and_operational_scripts_are_complete() -> None:
    missing = [
        relative
        for relative in (*REQUIRED_DOCUMENTS, *REQUIRED_SCRIPTS)
        if not (ROOT / relative).is_file()
    ]
    assert not missing, f"Task 10 release artifacts are missing: {missing}"
    not_executable = [
        relative
        for relative in REQUIRED_SCRIPTS
        if not os.access(ROOT / relative, os.X_OK)
    ]
    assert not not_executable, f"operational scripts must be executable: {not_executable}"


def test_docs_distribute_production_and_sealed_export_keys_without_rotation() -> None:
    deployment = _read("docs/DEPLOYMENT.md")
    judge_guide = _read("docs/JUDGE_GUIDE.md")

    for document in (deployment, judge_guide):
        for phrase in (
            "/verification/production-export-public-key.json",
            "/verification/sealed-cohort-export-public-key.json",
            "/verification/export-public-keys.json",
            "9fc05d3c32c1b276a3e59f699ad73b8f9f332cc608ece3c8f5fd2cb2b665bc7d",
            "949bed254068654a5d5c125079c4631055709fafcac92e097b02a08cd87f9875",
        ):
            assert phrase in document
    normalized_deployment = " ".join(deployment.lower().split())
    assert "does not rotate" in normalized_deployment
    assert "runtime proof" in normalized_deployment


def test_readme_declares_one_command_startup_and_mit_github_about_action() -> None:
    readme = _read("README.md")
    lowered = readme.lower()

    assert "docker compose up --build" in lowered
    assert "mit" in lowered
    assert "github about" in lowered
    assert "visible" in lowered, "README must say MIT remains visible in GitHub About"

    license_text = _read("LICENSE")
    assert "MIT License" in license_text
    assert "Permission is hereby granted" in license_text


def test_readme_documents_caddy_only_local_operator_and_approver_access() -> None:
    readme = _read("README.md")

    for phrase in (
        "CROSSPATCH_API_URL=https://localhost",
        "CROSSPATCH_ORIGIN=https://localhost",
        "CROSSPATCH_TOKEN",
        "CROSSPATCH_CSRF_TOKEN",
        "CROSSPATCH_STEP_UP_TOKEN",
        "crosspatch judge-token rotate",
        "local-only",
        "hosted deployments must override",
    ):
        assert phrase.lower() in readme.lower()


def test_readme_defines_the_warrant_gated_agent_execution_pattern() -> None:
    readme = _read("README.md")
    heading = "## Warrant-gated execution: due process for AI agents"

    assert heading in readme
    section = readme.split(heading, 1)[1].split("\n## ", 1)[0]
    normalized = " ".join(section.replace("**", "").split()).lower()
    for phrase in (
        "provenance-gated dialogue",
        "record-derived headlines",
        "reasoning-effort escalation ladder",
        "Auto-remediation acts without auditable authority",
        "Runbooks execute without reasoning",
        "reasons adversarially",
        "human-approved, hash-bound warrants",
    ):
        assert phrase.lower() in normalized


def test_extending_guide_describes_the_two_shipped_scenario_contracts() -> None:
    guide = _read("docs/EXTENDING.md")
    normalized = " ".join(guide.split())

    assert "Exactly two bundled scenarios ship" in guide
    assert "`webhook-race`" in guide
    assert "`webhook-payload-equivalence`" in guide
    assert "fully verified" in guide
    assert "no scenario plug-in registry" in guide
    assert "Live trials remain `webhook-race`-only" in guide
    for path in (
        "backend/src/crosspatch/api/routes/incidents.py",
        "backend/src/crosspatch/runtime/control.py",
        "backend/src/crosspatch/runtime/incidents.py",
        "backend/src/crosspatch/runner/catalog.py",
        "backend/src/crosspatch/runner/candidate_service.py",
        "backend/src/crosspatch/runner/supervisor.py",
    ):
        assert f"`{path}`" in guide
    for phrase in (
        "UNTRUSTED_EVIDENCE",
        "raw and sanitized artifact namespaces",
        "immutable execution plans",
        "human approval",
        "single-use warrant",
        "trusted black-box verifier",
        "1/2/2",
        "1/1/1",
        "202/409",
        "202/200/409",
    ):
        assert phrase in normalized
    assert "## Roadmap" not in guide


def test_readme_claims_exactly_two_record_proven_bundled_scenarios() -> None:
    readme = _read("README.md")
    normalized = " ".join(readme.split())

    assert "Exactly two bundled scenarios ship and are fully verified" in readme
    assert "`webhook-race`" in readme
    assert "`webhook-payload-equivalence`" in readme
    assert "Live trials remain `webhook-race`-only" in readme
    for phrase in ("1/2/2", "1/1/1", "202/409", "202/200/409"):
        assert phrase in normalized


def test_readme_reports_the_hostile_boundary_without_blending_denominators() -> None:
    readme = _read("README.md")
    normalized = " ".join(readme.split())

    for phrase in (
        "denied the hostile instruction authority",
        "CLEAR → human approval → VERIFIED",
        "1/1 held; 0 false approvals",
        "14/14 neutralized",
        "34/34 rejected before side effects",
        "1/1 expired warrant denied",
        "1/1 reused warrant denied",
        "1/1 duplicate failed-retry refused",
        "3/5 published repairs",
        "7/10 sealed-cohort runs",
        "zero false-approval events",
        "make eval",
        "35342f9f69bfb22fa8515870400e2c09b9747f2e163da338adee9632047ef789",
        "production-signed, read-only runtime",
    ):
        assert phrase in normalized
    assert "no equivalent measured no-sanitizer baseline exists" in normalized
    for forbidden in (
        "the release get denied",
        "the release was denied",
        "tampered inputs would ship",
        "n/n denied",
    ):
        assert forbidden not in normalized.lower()


def test_readme_opening_is_event_first_reproducible_and_transparently_attributed() -> None:
    readme = _read("README.md")
    event_first = (
        "The agent-release gate that survived a live tampered-evidence attack: "
        "the injected instruction lost authority, the legitimate repair still cleared, "
        "and the audit trail verifies both ways on a monitored public deployment."
    )
    category = "It is a due-process layer for agent-proposed changes."
    disclosure = (
        "The five personas are AI agents powered by GPT-5.6; portraits generated with "
        "ChatGPT Images; any resemblance to real persons is coincidental."
    )

    normalized = " ".join(readme.split())
    assert event_first in normalized
    assert category in normalized
    assert disclosure in normalized
    assert "https://stats.uptimerobot.com/9oxeuWMvvU" in readme
    for phrase in (
        "verify every claim yourself, in about a minute, on a fresh clone",
        "keyless OIDC CI",
        "golden snapshot",
        "35342f9f69bfb22fa8515870400e2c09b9747f2e163da338adee9632047ef789",
    ):
        assert phrase.lower() in normalized.lower()

    readme_lines = readme.splitlines()
    assert event_first in " ".join(readme_lines[1:6])
    assert not any("backend tests" in line for line in readme_lines[:30])


def test_readme_metrics_are_derived_from_the_computed_evaluation_summary() -> None:
    evaluation = json.loads(_read("artifacts/verification/adversarial-evaluation.json"))
    report = evaluation["report"]
    observed = report["observed"]
    canonical = report["canonical_reference"]
    expected = (
        f"{observed['sanitizer_vectors']['neutralized']}/{observed['sanitizer_vectors']['total']}",
        f"{observed['broker_authority_tamper']['rejected_before_side_effects']}/"
        f"{observed['broker_authority_tamper']['total']}",
        f"{observed['genuine_hostile_evidence']['boundary_held']}/"
        f"{observed['genuine_hostile_evidence']['total']}",
        f"{observed['published_repairs']['remand_then_clear']}/"
        f"{observed['published_repairs']['total']}",
        f"{observed['sealed_cohort']['runs_with_remand']}/"
        f"{observed['sealed_cohort']['total']}",
        f"{observed['false_approval_events']} false approvals",
        canonical["canonical_sha256"],
    )

    copy = " ".join(_read("README.md").split()).lower()
    for value in expected:
        assert str(value).lower() in copy, f"README.md is missing computed value {value}"


def test_judge_guide_has_exact_local_prerequisites_and_verified_platform_scope() -> None:
    guide = _read("docs/JUDGE_GUIDE.md")

    assert "cd CrossPatch" in guide
    assert "all ten explicitly published cases" not in guide
    assert "all explicitly published cases" in guide
    assert guide.count("export CROSSPATCH_API_URL=") == 1
    for phrase in (
        "Docker Desktop with Compose v2",
        "Git",
        "Node.js 22.12 or newer",
        "uv",
        "macOS on Apple Silicon",
        "Ubuntu Linux on x86-64",
        "Native Windows is unverified",
        "WSL2",
    ):
        assert phrase in guide


def test_readme_leads_with_the_live_product_and_share_image() -> None:
    readme = _read("README.md")
    normalized = " ".join(readme.split())
    first_section = readme.split("## Start locally", 1)[0]

    assert "https://crosspatch.repair" in first_section
    assert "web/public/crosspatch-share.png" in first_section
    external = readme.split("## Current external actions", 1)[1].split("\n## ", 1)[0]
    assert "The hosted app is live" in external
    assert "configure hosting and DNS" not in external
    assert "run `/feedback`" not in external
    assert (
        "The final CrossPatch logo was generated with ChatGPT Images and selected "
        "by the project owner"
    ) in normalized


def test_readme_reports_the_current_keyless_gate_counts() -> None:
    readme = " ".join(_read("README.md").split())

    assert (
        "899 Python test executions passed across the two gates—872 in the "
        "backend/victim suite (with claim-map validation excluded) and 27 in "
        "the dedicated claim-map validation—with 28 skips; 318 UI tests and "
        "5 browser E2E tests passed, with one capture-generator test skipped"
    ) in readme
    assert "898 backend tests" not in readme


def test_judge_cli_uses_a_distinct_api_reader_token_with_the_real_cli_variable() -> None:
    guide = _read("docs/JUDGE_GUIDE.md")
    normalized = " ".join(guide.split())

    assert "export CROSSPATCH_TOKEN=API_READER_TOKEN" in guide
    assert "CROSSPATCH_API_TOKEN" not in guide
    assert "API reader token" in normalized
    assert "Judge MCP bearer" in normalized
    assert "separate" in normalized.lower()


def test_hosted_runbook_requires_release_mode_and_disclaims_pre_lock_upgrades() -> None:
    deployment = _read("docs/DEPLOYMENT.md")

    assert "CROSSPATCH_RELEASE_MODE=1" in deployment
    assert "fresh PostgreSQL volume" in deployment
    assert "in-place schema upgrade" in deployment
    build = deployment.index("docker compose build --pull")
    identity = deployment.index("scripts/derive_release_identity.py")
    startup = deployment.index("docker compose up -d --wait")
    assert build < identity < startup, (
        "release image identities must be exported before release-mode services start"
    )


def test_product_tagline_keeps_courtroom_language_out_of_general_copy() -> None:
    readme = _read("README.md")

    assert "Every fix must survive adversarial review." in readme
    assert "Every fix faces cross-examination." not in readme


def test_readme_names_the_log_injection_surface_and_all_three_mcp_trust_zones() -> None:
    security_copy = (_read("README.md") + "\n" + _read("SECURITY.md")).lower()
    required_phrases = (
        "log-based prompt injection",
        "raw evidence",
        "sanitizer limitations",
        "evidence mcp",
        "broker mcp",
        "judge mcp",
    )
    missing = [phrase for phrase in required_phrases if phrase not in security_copy]
    assert not missing, f"README/security contract is missing: {missing}"
    assert "untrusted" in security_copy, "raw log lines must be documented as untrusted input"


def test_deployment_runbook_preserves_judge_access_through_august_12() -> None:
    deployment = _read("docs/DEPLOYMENT.md").lower()
    required = (
        SERVICE_DEADLINE.lower(),
        "hashed judge token",
        "persistent",
        "overlapping rotation",
        "immediate revocation",
        "restart",
        "tls renewal",
        "uptime monitor",
        "backup",
        "restore",
        "local verification",
        "hosted verification",
    )
    missing = [phrase for phrase in required if phrase not in deployment]
    assert not missing, f"deployment runbook is missing required operations: {missing}"


def test_judge_token_docs_distinguish_persistent_sessions_from_service_replay() -> None:
    joined = (
        _read("docs/DEPLOYMENT.md")
        + "\n"
        + _read("docs/JUDGE_GUIDE.md")
        + "\n"
        + _read("docs/THREAT_MODEL.md")
    ).lower()
    required = (
        "replacement mcp sessions",
        "registry revocation is checked on every request",
        "evidence and broker bearer tokens remain single-session",
        "stolen bearer",
    )
    missing = [phrase for phrase in required if phrase not in joined]
    assert not missing, f"judge persistent-session security contract is missing: {missing}"


def test_docs_define_operator_only_publication_and_global_live_trial_budget() -> None:
    joined = (
        _read("SECURITY.md")
        + "\n"
        + _read("docs/THREAT_MODEL.md")
        + "\n"
        + _read("docs/JUDGE_GUIDE.md")
        + "\n"
        + _read("docs/DEPLOYMENT.md")
    ).lower()
    normalized = " ".join(joined.replace("`", "").replace("-", " ").split())
    for phrase in (
        "live trial remains private",
        "verified is terminal",
        "one global",
        "per credential rate",
        "request_revision",
        "disposable sandbox",
    ):
        assert phrase in normalized


def test_readme_names_the_selected_editorial_tracepaper_identity() -> None:
    readme = _read("README.md")

    assert "editorial Tracepaper incident-room UI" in readme
    assert "industrial incident-room UI" not in readme


def test_readme_distinguishes_sealed_demo_readiness_from_hosted_key_provisioning() -> None:
    readme = _read("README.md")
    external_actions = readme.split("## Current external actions", 1)[1].split(
        "\n## ", 1
    )[0]

    assert "sealed ten-run demo gate is `DEMO_READY`" in external_actions
    assert "provide OpenAI credits/key" not in external_actions
    assert "The hosted app is live" in external_actions
    assert "provision the hosted deployment" not in external_actions


def test_docs_distinguish_local_completion_from_live_hosted_verification() -> None:
    joined = (
        _read("README.md")
        + "\n"
        + _read("docs/DEPLOYMENT.md")
        + "\n"
        + _read("docs/JUDGE_GUIDE.md")
    ).lower()
    assert "blocked" in joined
    assert "credentials" in joined
    assert "dns" in joined
    assert "reachable url" in joined
    assert "never" in joined and "claim" in joined and "hosted" in joined
