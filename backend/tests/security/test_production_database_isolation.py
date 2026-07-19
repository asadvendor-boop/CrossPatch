"""Live proof that candidate code cannot reach control-plane PostgreSQL."""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess

import pytest


def _compose(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker Compose is required for the production isolation proof")
    project = os.environ.get("CROSSPATCH_PRODUCTION_COMPOSE_PROJECT", "crosspatch-task5")
    return subprocess.run(
        [docker, "compose", "-p", project, *args],
        check=check,
        capture_output=True,
        text=True,
    )


def test_candidate_cannot_reach_or_change_control_database_sentinel() -> None:
    if os.environ.get("CROSSPATCH_PRODUCTION_COMPOSE_TEST") != "1":
        pytest.skip("requires a running production Compose topology")
    table = f"runner_isolation_{secrets.token_hex(8)}"
    create = (
        f"CREATE TABLE {table} (value text NOT NULL); "
        f"INSERT INTO {table} (value) VALUES ('unchanged');"
    )
    try:
        _compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "crosspatch",
            "-d",
            "crosspatch",
            "-c",
            create,
        )
        candidate_attempt = _compose(
            "exec",
            "-T",
            "candidate-executor",
            "/opt/crosspatch/venv/bin/python",
            "-c",
            (
                "import socket; "
                "connection=socket.create_connection(('postgres', 5432), 2); "
                "connection.close()"
            ),
            check=False,
        )
        assert candidate_attempt.returncode != 0, (
            "candidate container unexpectedly reached the control database"
        )
        value = _compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "crosspatch",
            "-d",
            "crosspatch",
            "-tAc",
            f"SELECT value FROM {table};",
        ).stdout.strip()
        assert value == "unchanged"
    finally:
        _compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            "crosspatch",
            "-d",
            "crosspatch",
            "-c",
            f"DROP TABLE IF EXISTS {table};",
            check=False,
        )
