from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def _method(path: Path, class_name: str, method_name: str) -> ast.FunctionDef:
    module = ast.parse(path.read_text(encoding="utf-8"))
    owner = next(
        node
        for node in module.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    return next(
        node
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name == method_name
    )


def _select_count_literals(method: ast.FunctionDef) -> set[str]:
    return {
        node.value.strip()
        for node in ast.walk(method)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.lstrip().startswith("SELECT count(*)")
    }


def test_victim_counts_uses_complete_constant_sql_literals() -> None:
    method = _method(ROOT / "victim/src/victim/db.py", "Database", "counts")

    assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(method))
    assert _select_count_literals(method) == {
        "SELECT count(*) AS count FROM webhook_receipts WHERE provider = %s",
        "SELECT count(*) AS count FROM webhook_receipts "
        "WHERE provider = %s AND event_id = %s",
        "SELECT count(*) AS count FROM outbox_jobs WHERE provider = %s",
        "SELECT count(*) AS count FROM outbox_jobs "
        "WHERE provider = %s AND event_id = %s",
        "SELECT count(*) AS count FROM deliveries WHERE provider = %s",
        "SELECT count(*) AS count FROM deliveries "
        "WHERE provider = %s AND event_id = %s",
    }


def test_supervisor_counts_uses_complete_constant_sql_literals() -> None:
    method = _method(
        ROOT / "backend/src/crosspatch/runner/supervisor.py",
        "PostgresCountBlackBoxVerifier",
        "_counts",
    )

    assert not any(isinstance(node, ast.JoinedStr) for node in ast.walk(method))
    assert _select_count_literals(method) == {
        "SELECT count(*) FROM webhook_receipts WHERE provider = %s AND event_id = %s",
        "SELECT count(*) FROM outbox_jobs WHERE provider = %s AND event_id = %s",
        "SELECT count(*) FROM deliveries WHERE provider = %s AND event_id = %s",
    }
