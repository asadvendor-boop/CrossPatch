from dataclasses import FrozenInstanceError, replace

import pytest
from crosspatch.runner.catalog import (
    APPROVED_PLAN_IDS,
    CANDIDATE_PLAN_IDS,
    ExecutionCatalog,
    ExecutionPlan,
    ModelSuppliedCommand,
    OracleProfile,
    UnknownExecutionPlan,
)

EXPECTED_PLAN_IDS = (
    "victim.single-delivery",
    "victim.sequential-duplicate",
    "victim.distinct-events",
    "victim.duplicate-race.affected",
    "victim.duplicate-race.candidate",
    "victim.payload-equivalence.affected",
    "victim.payload-equivalence.candidate",
    "victim.stress-duplicate-32",
    "victim.stress-distinct-32",
    "victim.hmac-rejection",
    "victim.payload-mismatch",
    "victim.worker-retry",
    "policy.protected-paths",
)


def test_catalog_contains_every_approved_plan_with_fixed_absolute_argv():
    catalog = ExecutionCatalog.default()

    assert APPROVED_PLAN_IDS == EXPECTED_PLAN_IDS
    assert catalog.plan_ids == EXPECTED_PLAN_IDS
    for plan_id in catalog.plan_ids:
        plan = catalog.resolve(plan_id)
        assert isinstance(plan.argv, tuple)
        if plan_id in CANDIDATE_PLAN_IDS:
            assert plan.argv == (
                "/opt/crosspatch/venv/bin/python",
                "/opt/crosspatch/candidate_service.py",
            )
            assert plan.expected_counts == (1, 1, 1)
            assert plan.working_directory == "/workspace"
            assert len(plan.sha256) == 64
            continue
        assert plan.argv[:4] == (
            "/opt/crosspatch/venv/bin/python",
            "-m",
            "pytest",
            "-q",
        )
        node_path, separator, test_name = plan.argv[4].partition("::")
        assert separator == "::"
        assert test_name.startswith("test_")
        assert node_path.startswith("/opt/crosspatch/tests/")
        assert "/workspace" not in node_path
        assert plan.working_directory == "/workspace"
        assert len(plan.sha256) == 64


def test_baseline_and_candidate_race_plans_are_separate_immutable_contracts():
    catalog = ExecutionCatalog.default()

    affected = catalog.resolve("victim.duplicate-race.affected")
    candidate = catalog.resolve("victim.duplicate-race.candidate")

    assert affected.expected_counts == (1, 2, 2)
    assert candidate.expected_counts == (1, 1, 1)
    assert affected.sha256 != candidate.sha256

    with pytest.raises(FrozenInstanceError):
        candidate.timeout_seconds = 1


def test_payload_equivalence_plans_bind_the_external_oracle_contract() -> None:
    catalog = ExecutionCatalog.default()
    affected = catalog.resolve("victim.payload-equivalence.affected")
    candidate = catalog.resolve("victim.payload-equivalence.candidate")

    assert affected.oracle_profile is OracleProfile.PAYLOAD_EQUIVALENCE
    assert affected.expected_statuses == (202, 409, 409)
    assert affected.expected_counts == (1, 1, 1)
    assert candidate.oracle_profile is OracleProfile.PAYLOAD_EQUIVALENCE
    assert candidate.expected_statuses == (202, 200, 409)
    assert candidate.expected_counts == (1, 1, 1)
    assert candidate.plan_id in CANDIDATE_PLAN_IDS
    assert affected.plan_id not in CANDIDATE_PLAN_IDS
    assert affected.sha256 != candidate.sha256

    changed_profile = replace(candidate, oracle_profile=OracleProfile.DUPLICATE_RACE)
    changed_statuses = replace(candidate, expected_statuses=(202, 409, 409))
    assert changed_profile.sha256 != candidate.sha256
    assert changed_statuses.sha256 != candidate.sha256


def test_race_candidate_declares_its_existing_external_oracle() -> None:
    candidate = ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")

    assert candidate.oracle_profile is OracleProfile.DUPLICATE_RACE
    assert candidate.expected_statuses is None


def test_catalog_rejects_unknown_and_model_supplied_argv():
    catalog = ExecutionCatalog.default()

    with pytest.raises(UnknownExecutionPlan):
        catalog.resolve("model-authored", (("sh", "-c", "anything"),))

    fixed = catalog.resolve("victim.single-delivery")
    with pytest.raises(ModelSuppliedCommand):
        catalog.resolve(fixed.plan_id, fixed.argv)

    with pytest.raises(ModelSuppliedCommand):
        catalog.resolve(fixed.plan_id, ())

    with pytest.raises(ModelSuppliedCommand):
        catalog.resolve(fixed.plan_id, None)


def test_production_catalog_constructor_rejects_injected_execution_plans():
    hostile = ExecutionPlan(
        plan_id="hostile.shell",
        argv=("/bin/sh", "-c", "id"),
    )

    with pytest.raises(TypeError):
        ExecutionCatalog((hostile,))

    with pytest.raises(TypeError):
        ExecutionCatalog(plans=(hostile,))


def test_catalog_mapping_and_plan_hashes_cannot_be_mutated():
    catalog = ExecutionCatalog.default()
    first = catalog.resolve("victim.hmac-rejection")

    with pytest.raises(TypeError):
        catalog.plans[first.plan_id] = first

    with pytest.raises(AttributeError):
        catalog._plans = {"hostile.shell": first}

    assert ExecutionCatalog.default().resolve(first.plan_id).sha256 == first.sha256
