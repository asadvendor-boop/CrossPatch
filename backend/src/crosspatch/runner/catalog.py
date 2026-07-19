"""Immutable, server-owned execution plans.

Models may select a plan by identifier.  They cannot provide or amend argv.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

RUNNER_PYTHON = "/opt/crosspatch/venv/bin/python"
TEST_ROOT = "/opt/crosspatch/tests"
WORKSPACE = "/workspace"
CANDIDATE_SERVICE = "/opt/crosspatch/candidate_service.py"
_MISSING = object()


class UnknownExecutionPlan(LookupError):
    """Raised when a caller selects an identifier outside the catalog."""


class ModelSuppliedCommand(ValueError):
    """Raised when a caller attempts to add command material to a selection."""


class OracleProfile(StrEnum):
    """Closed trusted exercises available outside the candidate process."""

    DUPLICATE_RACE = "duplicate-race"
    PAYLOAD_EQUIVALENCE = "payload-equivalence"


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """One fully resolved command contract owned by the deterministic runner."""

    plan_id: str
    argv: tuple[str, ...]
    working_directory: str = WORKSPACE
    timeout_seconds: int = 60
    expected_counts: tuple[int, int, int] | None = None
    expected_statuses: tuple[int, ...] | None = None
    oracle_profile: OracleProfile | None = None

    @property
    def sha256(self) -> str:
        document = {
            "argv": list(self.argv),
            "expected_counts": (
                list(self.expected_counts) if self.expected_counts is not None else None
            ),
            "plan_id": self.plan_id,
            "timeout_seconds": self.timeout_seconds,
            "working_directory": self.working_directory,
        }
        # Keep legacy plan digests stable when reading old canonical warrants.
        # Every newly catalogued candidate plan sets an explicit profile.
        if self.expected_statuses is not None:
            document["expected_statuses"] = list(self.expected_statuses)
        if self.oracle_profile is not None:
            document["oracle_profile"] = self.oracle_profile.value
        canonical = json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


def _pytest_plan(
    plan_id: str,
    test_file: str,
    test_name: str,
    *,
    timeout_seconds: int = 60,
    expected_counts: tuple[int, int, int] | None = None,
    expected_statuses: tuple[int, ...] | None = None,
    oracle_profile: OracleProfile | None = None,
) -> ExecutionPlan:
    return ExecutionPlan(
        plan_id=plan_id,
        argv=(
            RUNNER_PYTHON,
            "-m",
            "pytest",
            "-q",
            f"{test_file}::{test_name}",
        ),
        timeout_seconds=timeout_seconds,
        expected_counts=expected_counts,
        expected_statuses=expected_statuses,
        oracle_profile=oracle_profile,
    )


def _candidate_service_plan(
    plan_id: str,
    *,
    expected_counts: tuple[int, int, int],
    expected_statuses: tuple[int, ...] | None,
    oracle_profile: OracleProfile,
) -> ExecutionPlan:
    return ExecutionPlan(
        plan_id=plan_id,
        argv=(RUNNER_PYTHON, CANDIDATE_SERVICE),
        timeout_seconds=120,
        expected_counts=expected_counts,
        expected_statuses=expected_statuses,
        oracle_profile=oracle_profile,
    )


APPROVED_PLAN_IDS = (
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


_PLANS = (
    _pytest_plan(
        "victim.single-delivery",
        f"{TEST_ROOT}/victim/test_contract.py",
        "test_single_signed_delivery_is_processed_once",
    ),
    _pytest_plan(
        "victim.sequential-duplicate",
        f"{TEST_ROOT}/victim/test_contract.py",
        "test_sequential_duplicate_is_idempotent",
    ),
    _pytest_plan(
        "victim.distinct-events",
        f"{TEST_ROOT}/victim/test_contract.py",
        "test_distinct_event_ids_are_processed_independently",
    ),
    _pytest_plan(
        "victim.duplicate-race.affected",
        f"{TEST_ROOT}/backend/integration/test_reproduction.py",
        "test_affected_revision_reproduces_real_duplicate_delivery",
        expected_counts=(1, 2, 2),
        oracle_profile=OracleProfile.DUPLICATE_RACE,
    ),
    _candidate_service_plan(
        "victim.duplicate-race.candidate",
        expected_counts=(1, 1, 1),
        expected_statuses=None,
        oracle_profile=OracleProfile.DUPLICATE_RACE,
    ),
    _pytest_plan(
        "victim.payload-equivalence.affected",
        f"{TEST_ROOT}/backend/integration/test_payload_equivalence.py",
        "test_affected_revision_rejects_semantically_equivalent_retry",
        expected_counts=(1, 1, 1),
        expected_statuses=(202, 409, 409),
        oracle_profile=OracleProfile.PAYLOAD_EQUIVALENCE,
    ),
    _candidate_service_plan(
        "victim.payload-equivalence.candidate",
        expected_counts=(1, 1, 1),
        expected_statuses=(202, 200, 409),
        oracle_profile=OracleProfile.PAYLOAD_EQUIVALENCE,
    ),
    _pytest_plan(
        "victim.stress-duplicate-32",
        f"{TEST_ROOT}/victim/test_race.py",
        "test_thirty_two_duplicate_requests_obey_documented_baseline",
        timeout_seconds=120,
    ),
    _pytest_plan(
        "victim.stress-distinct-32",
        f"{TEST_ROOT}/victim/test_race.py",
        "test_thirty_two_distinct_events_are_not_coalesced",
        timeout_seconds=120,
    ),
    _pytest_plan(
        "victim.hmac-rejection",
        f"{TEST_ROOT}/victim/test_contract.py",
        "test_invalid_hmac_is_rejected_without_database_writes",
    ),
    _pytest_plan(
        "victim.payload-mismatch",
        f"{TEST_ROOT}/victim/test_contract.py",
        "test_reused_event_id_with_different_payload_is_rejected",
    ),
    _pytest_plan(
        "victim.worker-retry",
        f"{TEST_ROOT}/victim/test_worker_retry.py",
        "test_failed_delivery_is_retried_without_losing_the_job",
    ),
    _pytest_plan(
        "policy.protected-paths",
        f"{TEST_ROOT}/backend/security/test_broker_policy.py",
        "test_protected_or_escaping_paths_are_rejected",
    ),
)


if len(APPROVED_PLAN_IDS) != 13:
    raise RuntimeError("the production execution catalog must contain exactly 13 plans")
if tuple(plan.plan_id for plan in _PLANS) != APPROVED_PLAN_IDS:
    raise RuntimeError("production execution plans do not match the approved identifiers")

_PLAN_BY_ID = MappingProxyType({plan.plan_id: plan for plan in _PLANS})
if len(_PLAN_BY_ID) != len(_PLANS):
    raise RuntimeError("production execution plan identifiers must be unique")

CANDIDATE_PLAN_IDS = frozenset(
    {
        "victim.duplicate-race.candidate",
        "victim.payload-equivalence.candidate",
    }
)


class ExecutionCatalog:
    """Read-only lookup over the compile-time plan set."""

    __slots__ = ()

    @classmethod
    def default(cls) -> ExecutionCatalog:
        return cls()

    @property
    def plans(self) -> Mapping[str, ExecutionPlan]:
        return _PLAN_BY_ID

    @property
    def plan_ids(self) -> tuple[str, ...]:
        return APPROVED_PLAN_IDS

    def resolve(self, plan_id: str, supplied_argv: object = _MISSING) -> ExecutionPlan:
        try:
            plan = _PLAN_BY_ID[plan_id]
        except KeyError as error:
            raise UnknownExecutionPlan(plan_id) from error
        if supplied_argv is not _MISSING:
            raise ModelSuppliedCommand(
                f"argv is server-owned; select plan {plan_id!r} without command material"
            )
        return plan
