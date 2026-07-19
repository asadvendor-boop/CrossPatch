"""Static contracts for the immutable Task 4 runner image."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[3]
RUNNER_DOCKERFILE = REPOSITORY_ROOT / "infra" / "runner" / "Dockerfile"
COMPOSE_FILE = REPOSITORY_ROOT / "compose.yaml"


def _compose_config() -> dict[str, object]:
    completed = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "config", "--format", "json"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def test_runner_dockerfile_builds_frozen_external_test_environment() -> None:
    dockerfile = RUNNER_DOCKERFILE.read_text(encoding="utf-8")

    assert "python:3.13.7-slim-bookworm@sha256:" in dockerfile
    assert "ghcr.io/astral-sh/uv:0.10.12@sha256:" in dockerfile
    assert "UV_PROJECT_ENVIRONMENT=/opt/crosspatch/venv" in dockerfile
    assert "uv sync --frozen --extra dev --no-install-project" in dockerfile
    assert "COPY --chown=root:root backend/tests/ /opt/crosspatch/tests/backend/" in dockerfile
    assert "COPY --chown=root:root victim/tests/ /opt/crosspatch/tests/victim/" in dockerfile
    assert "chmod -R a-w /opt/crosspatch" in dockerfile
    assert "the production image must contain exactly 13 catalog nodes" in dockerfile
    assert "the production image must contain exactly two candidate plans" in dockerfile
    assert "missing immutable catalog test files" in dockerfile
    assert "missing immutable candidate sidecar driver" in dockerfile
    assert "useradd --uid 10002" in dockerfile
    assert "chown crosspatch:crosspatch /workspaces" in dockerfile
    assert "USER crosspatch" in dockerfile


def test_task4_compose_keeps_every_service_private_and_hardens_runner() -> None:
    config = _compose_config()
    services = config["services"]

    assert {"candidate-executor", "postgres", "victim", "runner"} <= services.keys()
    for service_name, service in services.items():
        if service_name != "caddy":
            assert not service.get("ports"), f"{service_name} must not publish host ports"

    runner = services["runner"]
    assert runner["read_only"] is True
    assert runner["user"] == "10001:10001"
    assert "ALL" in runner["cap_drop"]
    assert "no-new-privileges:true" in runner["security_opt"]
    assert all("docker.sock" not in str(volume) for volume in runner.get("volumes", ()))
    assert {"candidate-executor", "victim", "victim-postgres"} <= (
        runner["depends_on"].keys()
    )
    assert "postgres" not in runner["depends_on"]

    candidate = services["candidate-executor"]
    assert candidate["read_only"] is True
    assert candidate["user"] == "0:0"
    assert candidate["entrypoint"] == [
        "/usr/local/bin/crosspatch-candidate-executor-entrypoint"
    ]
    assert candidate["environment"]["CROSSPATCH_EXECUTOR_UID"] == "10003"
    assert candidate["environment"]["CROSSPATCH_CANDIDATE_UID"] == "10002"
    assert candidate["environment"]["CROSSPATCH_CANDIDATE_GID"] == "10002"
    assert set(candidate["cap_add"]) == {"KILL", "SETGID", "SETUID"}
    assert candidate["environment"]["CROSSPATCH_EXECUTOR_UID"] != (
        candidate["environment"]["CROSSPATCH_CANDIDATE_UID"]
    )
    assert "ALL" in candidate["cap_drop"]
    assert candidate.get("security_opt", []) == []
    assert candidate.get("pid") not in {"host", "service:runner"}
    assert all("docker.sock" not in str(volume) for volume in candidate.get("volumes", ()))

    runner_volumes = " ".join(str(volume) for volume in runner.get("volumes", ()))
    candidate_volumes = " ".join(str(volume) for volume in candidate.get("volumes", ()))
    assert "candidate-workspaces" in runner_volumes
    assert "candidate-handoff" in runner_volumes
    assert "candidate-handoff" in candidate_volumes
    assert "candidate-workspaces" not in candidate_volumes
    assert ":ro" in candidate_volumes or "read_only" in candidate_volumes
    assert "runner-jobs" in runner_volumes
    assert "runner-jobs" not in candidate_volumes
    assert "candidate-context" not in candidate_volumes
    assert not any(
        "CROSSPATCH_CANDIDATE_CONTEXT" in key
        for key in candidate.get("environment", {})
    )
    candidate_networks = set(candidate["networks"])
    runner_networks = set(runner["networks"])
    assert candidate_networks == {"candidate-data"}
    assert runner_networks == {"runner", "victim", "victim-data"}
    assert candidate_networks.isdisjoint(runner_networks)
    assert not candidate_networks & {"broker", "edge", "evidence", "judge"}
    assert not runner_networks & {"broker", "edge", "evidence", "judge"}
    for network_name in candidate_networks | runner_networks:
        assert config["networks"][network_name]["internal"] is True


def test_docker_build_context_excludes_local_secrets_and_worktrees() -> None:
    ignored = (REPOSITORY_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

    for required in (".crosspatch/", ".env", ".git/", ".venv/", "node_modules/"):
        assert required in ignored
