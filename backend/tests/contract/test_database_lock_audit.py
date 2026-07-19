"""Pin every database lock primitive to an explicitly reviewed role boundary."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from crosspatch.db.migrations import _API_UPDATE_COLUMNS

ROOT = Path(__file__).resolve().parents[3]
SCAN_ROOTS = (ROOT / "backend/src/crosspatch", ROOT / "victim/src")
API_ROLE_PATHS = frozenset(
    {
        "backend/src/crosspatch/db/repositories.py",
        "backend/src/crosspatch/runtime/auth.py",
        "backend/src/crosspatch/runtime/authority.py",
        "backend/src/crosspatch/runtime/database.py",
        "backend/src/crosspatch/runtime/control.py",
        "backend/src/crosspatch/runtime/live_trials.py",
    }
)
RECORD_TABLES = {
    "ControlWarrantRecord": "control_warrants",
    "IncidentRecord": "incidents",
    "JudgeTokenRecord": "judge_tokens",
    "LiveTrialBudgetRecord": "live_trial_budget",
    "LiveTrialCredentialRecord": "live_trial_credentials",
    "LiveTrialReservationRecord": "live_trial_reservations",
    "MutationAuthorityRecord": "mutation_authority",
    "RuntimeWorkRecord": "runtime_work",
    "WarrantRecord": "mutation_warrants",
}
SQL_LOCK = re.compile(
    r"\b(?:"
    r"FOR\s+(?:NO\s+KEY\s+)?UPDATE|"
    r"FOR\s+(?:KEY\s+)?SHARE|"
    r"LOCK\s+TABLE|"
    r"pg_advisory_(?:xact_)?lock"
    r")\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, order=True)
class LockUse:
    path: str
    function: str
    primitive: str
    target: str


EXPECTED_LOCKS = frozenset(
    {
        LockUse(
            "backend/src/crosspatch/broker/store.py",
            "_lock_authority",
            "sql-lock",
            "pg_advisory_xact_lock",
        ),
        LockUse(
            "backend/src/crosspatch/broker/store.py",
            "add_approved",
            "orm-row-lock",
            "MutationAuthorityRecord",
        ),
        LockUse(
            "backend/src/crosspatch/broker/store.py",
            "replace_authority",
            "orm-row-lock",
            "MutationAuthorityRecord",
        ),
        LockUse(
            "backend/src/crosspatch/broker/store.py",
            "claim_warrant",
            "orm-row-lock",
            "WarrantRecord",
        ),
        LockUse(
            "backend/src/crosspatch/broker/store.py",
            "finish",
            "orm-row-lock",
            "WarrantRecord",
        ),
        LockUse(
            "backend/src/crosspatch/runner/reproduction.py",
            "run",
            "sql-lock",
            "LOCK TABLE",
        ),
        LockUse(
            "backend/src/crosspatch/runtime/auth.py",
            "revoke",
            "orm-row-lock",
            "JudgeTokenRecord",
        ),
        LockUse(
            "backend/src/crosspatch/runtime/auth.py",
            "revoke_by_token_id",
            "orm-row-lock",
            "JudgeTokenRecord",
        ),
        LockUse(
            "backend/src/crosspatch/runtime/authority.py",
            "_expire_warrant_if_needed",
            "orm-row-lock",
            "ControlWarrantRecord",
        ),
        LockUse(
            "backend/src/crosspatch/runtime/authority.py",
            "_expire_warrant_if_needed",
            "orm-row-lock",
            "IncidentRecord",
        ),
        LockUse(
            "backend/src/crosspatch/runtime/authority.py",
            "decide_warrant",
            "sql-lock",
            "pg_advisory_xact_lock",
        ),
        LockUse(
            "backend/src/crosspatch/runtime/authority.py",
            "decide_warrant",
            "orm-row-lock",
            "ControlWarrantRecord",
        ),
        LockUse(
            "backend/src/crosspatch/runtime/authority.py",
            "decide_warrant",
            "orm-row-lock",
            "IncidentRecord",
        ),
        LockUse(
            "backend/src/crosspatch/runtime/authority.py",
            "decide_warrant",
            "orm-row-lock",
            "MutationAuthorityRecord",
        ),
        LockUse(
            "backend/src/crosspatch/runtime/authority.py",
            "request_revision",
            "orm-row-lock",
            "ControlWarrantRecord",
        ),
        LockUse(
            "backend/src/crosspatch/runtime/authority.py",
            "request_revision",
            "orm-row-lock",
            "IncidentRecord",
        ),
        LockUse(
            "backend/src/crosspatch/runtime/live_trials.py",
            "_budget_locked",
            "sql-lock",
            "pg_advisory_xact_lock",
        ),
        LockUse(
            "backend/src/crosspatch/runtime/live_trials.py",
            "_budget_locked",
            "orm-row-lock",
            "LiveTrialBudgetRecord",
        ),
        *(
            LockUse(
                "backend/src/crosspatch/runtime/live_trials.py",
                function,
                "orm-row-lock",
                target,
            )
            for function, target in (
                ("bind_incident", "LiveTrialReservationRecord"),
                ("reserve", "LiveTrialCredentialRecord"),
                ("revoke", "LiveTrialCredentialRecord"),
                ("settle", "LiveTrialReservationRecord"),
            )
        ),
        *(
            LockUse(
                "backend/src/crosspatch/runtime/authority.py",
                function,
                "orm-row-lock",
                "IncidentRecord",
            )
            for function in (
                "fail_closed_abstain",
                "open_approval",
                "record_verdict",
                "reject_duplicate_retry",
            )
        ),
        *(
            LockUse(
                "backend/src/crosspatch/runtime/database.py",
                function,
                "orm-row-lock",
                "IncidentRecord",
            )
            for function in (
                "append_event",
                "claim_runtime_work",
                "complete_repair_work",
                "fail_closed_interrupted_incidents",
                "fail_runtime_work",
                "prepare_seat",
                "project_broker_result",
                "record_execution_failure",
                "record_seat_output",
                "record_test_run",
                "requeue_interrupted_runtime_work",
            )
        ),
        *(
            LockUse(
                "backend/src/crosspatch/runtime/database.py",
                function,
                "orm-row-lock",
                "RuntimeWorkRecord",
            )
            for function in (
                "claim_runtime_work",
                "complete_repair_work",
                "fail_runtime_work",
                "record_execution_failure",
                "requeue_interrupted_runtime_work",
            )
        ),
        LockUse(
            "backend/src/crosspatch/db/repositories.py",
            "append",
            "orm-row-lock",
            "IncidentRecord",
        ),
        LockUse(
            "victim/src/victim/worker.py",
            "run_once",
            "sql-lock",
            "FOR UPDATE",
        ),
    }
)


def _function_name(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.AsyncFunctionDef, ast.FunctionDef)):
            return current.name
    return "<module>"


def _record_target(node: ast.AST) -> str:
    records = sorted(
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and child.id.endswith("Record")
    )
    assert len(set(records)) == 1, "row lock must name exactly one mapped record"
    return records[0]


def _sql_lock_target(value: str) -> str:
    match = SQL_LOCK.search(value)
    assert match is not None
    normalized = " ".join(match.group(0).split()).upper()
    if normalized.startswith("PG_ADVISORY"):
        return normalized.casefold()
    return normalized


def _discover_locks() -> frozenset[LockUse]:
    findings: set[LockUse] = set()
    for scan_root in SCAN_ROOTS:
        for path in scan_root.rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            parents = {
                child: node
                for node in ast.walk(tree)
                for child in ast.iter_child_nodes(node)
            }
            relative = path.relative_to(ROOT).as_posix()
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "with_for_update"
                ):
                    findings.add(
                        LockUse(
                            relative,
                            _function_name(node, parents),
                            "orm-row-lock",
                            _record_target(node.func.value),
                        )
                    )
                if isinstance(node, ast.Call):
                    for keyword in node.keywords:
                        if (
                            keyword.arg == "with_for_update"
                            and isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is True
                        ):
                            findings.add(
                                LockUse(
                                    relative,
                                    _function_name(node, parents),
                                    "orm-row-lock",
                                    _record_target(node),
                                )
                            )
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and SQL_LOCK.search(node.value)
                ):
                    findings.add(
                        LockUse(
                            relative,
                            _function_name(node, parents),
                            "sql-lock",
                            _sql_lock_target(node.value),
                        )
                    )
    return frozenset(findings)


def test_every_database_lock_primitive_is_explicitly_reviewed() -> None:
    assert _discover_locks() == EXPECTED_LOCKS


def test_api_role_row_locks_only_tables_it_can_update() -> None:
    api_locks = {
        finding for finding in EXPECTED_LOCKS if finding.path in API_ROLE_PATHS
    }
    assert api_locks, "API lock inventory must not silently disappear"
    advisory_locks = {
        finding for finding in api_locks if finding.primitive == "sql-lock"
    }
    assert advisory_locks == {
        LockUse(
            "backend/src/crosspatch/runtime/authority.py",
            "decide_warrant",
            "sql-lock",
            "pg_advisory_xact_lock",
        ),
        LockUse(
            "backend/src/crosspatch/runtime/live_trials.py",
            "_budget_locked",
            "sql-lock",
            "pg_advisory_xact_lock",
        ),
    }
    assert {
        RECORD_TABLES[finding.target]
        for finding in api_locks
        if finding.primitive == "orm-row-lock"
    }.issubset(_API_UPDATE_COLUMNS)
