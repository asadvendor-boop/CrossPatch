"""Host-side launcher for the real hardened Broker -> runner flow."""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest


def test_live_broker_creates_seals_executes_and_cleans_candidate_workspace() -> None:
    if os.environ.get("CROSSPATCH_PRODUCTION_COMPOSE_TEST") != "1":
        pytest.skip("requires a running production Compose topology")
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker Compose is required for the production broker proof")
    project = os.environ.get("CROSSPATCH_PRODUCTION_COMPOSE_PROJECT", "crosspatch-task5")
    result = subprocess.run(
        [
            docker,
            "compose",
            "-p",
            project,
            "exec",
            "-T",
            "broker-mcp",
            "/opt/crosspatch/venv/bin/python",
            "/app/backend/tests/security/production_broker_runner_probe.py",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload["status"] == "EXECUTED"
    for key, value in payload.items():
        if key != "status":
            assert isinstance(value, str) and len(value) == 64
