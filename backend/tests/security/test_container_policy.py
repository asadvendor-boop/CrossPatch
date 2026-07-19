from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from crosspatch.runner.catalog import ExecutionCatalog

ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = ROOT / "compose.yaml"
RUNNER_POLICY = ROOT / "infra" / "runner-policy.json"
HARDENED_SERVICES = {"broker-mcp", "evidence-mcp", "judge-mcp", "runner"}
FORBIDDEN_CONTEXT_MARKERS = (
    ".crosspatch",
    "candidate-context",
    "oracle-context",
    "supervisor-context",
    "trusted-context",
)


def _render_compose() -> dict[str, Any]:
    assert COMPOSE_FILE.is_file(), "Task 10 must ship compose.yaml"
    docker = shutil.which("docker")
    assert docker is not None, "Docker Compose is required to validate container policy"
    result = subprocess.run(
        [docker, "compose", "-f", str(COMPOSE_FILE), "config", "--format", "json"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"compose policy cannot be rendered:\n{result.stderr}"
    return json.loads(result.stdout)


def _load_policy() -> dict[str, Any]:
    assert RUNNER_POLICY.is_file(), "Task 10 must ship infra/runner-policy.json"
    policy = json.loads(RUNNER_POLICY.read_text(encoding="utf-8"))
    assert policy.get("schema_version") == 1
    for role in ("oracle", "executor"):
        role_policy = policy.get(role)
        assert isinstance(role_policy, dict), f"runner policy must define {role}"
        required = {"service", "uid", "pid_namespace", "read_only_rootfs"}
        assert required <= set(role_policy), (
            f"runner policy {role} is missing {required - set(role_policy)}"
        )
    assert "oracle_context_visible_to_candidate" in policy
    candidate = policy.get("candidate")
    assert isinstance(candidate, dict)
    assert {"parent_service", "uid", "pid_namespace", "read_only_rootfs"} <= set(
        candidate
    )
    return policy


def _service(compose: dict[str, Any], name: str) -> dict[str, Any]:
    services = compose.get("services", {})
    assert name in services, f"runner policy names missing Compose service {name!r}"
    return services[name]


def _uid(service: dict[str, Any]) -> int:
    user = str(service.get("user", ""))
    assert user and user.split(":", 1)[0].isdigit(), "service user must be a numeric UID"
    return int(user.split(":", 1)[0])


def _environment(service: dict[str, Any]) -> dict[str, str]:
    environment = service.get("environment", {})
    if isinstance(environment, dict):
        return {str(key): str(value) for key, value in environment.items()}
    return dict(item.split("=", 1) for item in environment if "=" in item)


def _mount_strings(service: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for mount in service.get("volumes", []):
        if isinstance(mount, dict):
            values.extend(str(mount.get(key, "")) for key in ("source", "target"))
        else:
            values.append(str(mount))
    return values


def test_no_service_mounts_docker_or_container_runtime_authority() -> None:
    compose = _render_compose()
    forbidden = (
        "docker.sock",
        "containerd.sock",
        "podman.sock",
        "/var/run/docker",
        "/run/docker",
    )

    for name, service in compose.get("services", {}).items():
        surface = json.dumps(
            {
                "volumes": service.get("volumes", []),
                "devices": service.get("devices", []),
                "environment": service.get("environment", {}),
            },
            sort_keys=True,
        ).lower()
        assert not any(marker in surface for marker in forbidden), (
            f"{name} mounts container-runtime authority; the broker must stay fail closed"
        )


def test_oracle_and_candidate_use_distinct_uids_and_private_pid_namespaces() -> None:
    compose = _render_compose()
    policy = _load_policy()
    oracle_policy = policy["oracle"]
    executor_policy = policy["executor"]
    candidate_policy = policy["candidate"]
    assert oracle_policy.get("service") != executor_policy.get("service")
    assert oracle_policy.get("uid") != candidate_policy.get("uid")
    assert executor_policy.get("uid") != candidate_policy.get("uid")

    for role, role_policy in (("oracle", oracle_policy), ("executor", executor_policy)):
        service_name = role_policy.get("service")
        assert isinstance(service_name, str) and service_name
        service = _service(compose, service_name)
        assert role_policy.get("pid_namespace") == "private"
        assert not service.get("pid"), f"{role} must not join another or host PID namespace"
        if role == "executor":
            assert _uid(service) == executor_policy["container_bootstrap_uid"] == 0
            assert int(_environment(service)["CROSSPATCH_EXECUTOR_UID"]) == (
                executor_policy["uid"]
            )
            assert service.get("entrypoint") == [
                "/usr/local/bin/crosspatch-candidate-executor-entrypoint"
            ]
        else:
            assert _uid(service) == role_policy.get("uid")
        assert service.get("read_only") is True
        assert role_policy.get("read_only_rootfs") is True

    executor = _service(compose, executor_policy["service"])
    executor_environment = _environment(executor)
    assert candidate_policy["parent_service"] == executor_policy["service"]
    assert candidate_policy["pid_namespace"] == (
        "shared-disposable-executor-container"
    )
    assert int(executor_environment["CROSSPATCH_CANDIDATE_UID"]) == candidate_policy["uid"]
    assert int(executor_environment["CROSSPATCH_EXECUTOR_UID"]) == executor_policy["uid"]
    assert candidate_policy["read_only_rootfs"] is True


def test_candidate_receives_no_oracle_or_trusted_context() -> None:
    compose = _render_compose()
    policy = _load_policy()
    assert policy.get("oracle_context_visible_to_candidate") is False
    candidate = _service(compose, policy["candidate"]["parent_service"])

    mounted = "\n".join(_mount_strings(candidate)).lower().replace("_", "-")
    assert not any(marker in mounted for marker in FORBIDDEN_CONTEXT_MARKERS), (
        "candidate service must not mount oracle state, secrets, or trusted context"
    )
    environment = "\n".join(
        f"{key}={value}" for key, value in sorted(_environment(candidate).items())
    ).lower().replace("_", "-")
    assert not any(marker in environment for marker in FORBIDDEN_CONTEXT_MARKERS), (
        "candidate service must not receive trusted context through its environment"
    )


def test_broker_calls_the_real_runner_service_for_trusted_receipts() -> None:
    compose = _render_compose()
    runner = _service(compose, "runner")
    broker = _service(compose, "broker-mcp")
    candidate = _service(compose, "candidate-executor")

    runner_command = " ".join(str(value) for value in (runner.get("command") or ()))
    assert "crosspatch.runner.runner_service:create_app" in runner_command
    runner_environment = _environment(runner)
    broker_environment = _environment(broker)
    assert runner_environment["CROSSPATCH_RUNNER_JOBS_ROOT"] == "/var/lib/crosspatch/jobs"
    assert runner_environment["CROSSPATCH_RUNNER_WORKSPACES_ROOT"] == (
        "/var/lib/crosspatch/candidate-workspaces"
    )
    assert broker_environment["CROSSPATCH_RUNNER_URL"] == "http://runner:9020"
    assert "CROSSPATCH_RUNNER_TOKEN" in broker_environment
    assert "runner" in broker.get("depends_on", {})
    assert "candidate-executor" in runner.get("depends_on", {})
    assert "candidate-executor" not in broker.get("depends_on", {})

    candidate_only = {
        "CROSSPATCH_CANDIDATE_EXECUTOR_URL",
        "CROSSPATCH_CANDIDATE_TARGET_URL",
        "CROSSPATCH_CANDIDATE_UID",
        "CROSSPATCH_SUPERVISOR_UID",
    }
    assert candidate_only.isdisjoint(broker_environment)
    assert candidate_only <= set(runner_environment)
    assert "CROSSPATCH_RUNNER_TOKEN" not in _environment(candidate)
    assert runner_environment["CROSSPATCH_RELEASE_MODE"] in {"0", "1"}
    assert broker_environment["CROSSPATCH_RELEASE_MODE"] in {"0", "1"}
    assert _environment(candidate)["CROSSPATCH_RELEASE_MODE"] in {"0", "1"}


def test_candidate_victim_database_is_disjoint_from_control_authority() -> None:
    compose = _render_compose()
    control_database = _service(compose, "postgres")
    victim_database = _service(compose, "victim-postgres")
    candidate = _service(compose, "candidate-executor")
    runner = _service(compose, "runner")
    victim = _service(compose, "victim")

    control_networks = set(control_database.get("networks", {}))
    candidate_networks = set(candidate.get("networks", {}))
    assert control_networks
    assert candidate_networks.isdisjoint(control_networks), (
        "candidate code must have no route to the control-plane PostgreSQL network"
    )
    victim_database_networks = set(victim_database.get("networks", {}))
    assert candidate_networks & victim_database_networks == {"candidate-data"}
    assert "victim-data" not in candidate_networks

    candidate_environment = _environment(candidate)
    assert {
        "CROSSPATCH_DATABASE_URL",
        "CROSSPATCH_SYNC_DATABASE_URL",
        "CROSSPATCH_TEST_DATABASE_URL",
    }.isdisjoint(candidate_environment)
    assert (
        urlparse(candidate_environment["CROSSPATCH_CANDIDATE_DATABASE_URL"]).hostname
        == "victim-postgres"
    )
    assert (
        urlparse(_environment(runner)["CROSSPATCH_TEST_DATABASE_URL"]).hostname
        == "victim-postgres"
    )
    assert urlparse(_environment(victim)["VICTIM_DATABASE_URL"]).hostname == "victim-postgres"


def test_broker_mcp_runner_and_mcp_readers_are_fail_closed_containers() -> None:
    compose = _render_compose()
    policy = _load_policy()
    service_names = HARDENED_SERVICES | {policy["executor"]["service"]}

    for name in sorted(service_names):
        service = _service(compose, name)
        assert service.get("privileged") not in (True, "true")
        assert service.get("read_only") is True, f"{name} root filesystem must be read-only"
        assert "ALL" in service.get("cap_drop", []), f"{name} must drop all capabilities"
        security_options = {str(value).lower() for value in service.get("security_opt", [])}
        if name == policy["executor"]["service"]:
            assert security_options == set()
            assert set(service.get("cap_add", [])) == {"KILL", "SETGID", "SETUID"}
            assert policy["executor"]["capability_source"] == (
                "root-bootstrap-in-process-demotion"
            )
            assert policy["executor"]["no_new_privileges"] is True
            assert policy["candidate"]["no_new_privileges"] is True
        else:
            assert "no-new-privileges:true" in security_options, (
                f"{name} must enforce no-new-privileges"
            )


def test_payload_equivalence_reuses_existing_runner_boundary_without_new_capability() -> None:
    compose = _render_compose()
    policy = _load_policy()
    services = compose.get("services", {})
    plan = ExecutionCatalog.default().resolve("victim.payload-equivalence.candidate")

    assert not any("equivalence" in str(name).casefold() for name in services)
    assert plan.argv == (
        "/opt/crosspatch/venv/bin/python",
        "/opt/crosspatch/candidate_service.py",
    )
    assert plan.oracle_profile.value == "payload-equivalence"
    assert plan.expected_statuses == (202, 200, 409)
    assert plan.expected_counts == (1, 1, 1)

    candidate = _service(compose, policy["candidate"]["parent_service"])
    runner = _service(compose, policy["oracle"]["service"])
    broker = _service(compose, "broker-mcp")
    for name, service in (("candidate", candidate), ("runner", runner), ("broker", broker)):
        surface = json.dumps(
            {
                "environment": service.get("environment", {}),
                "volumes": service.get("volumes", []),
                "cap_add": service.get("cap_add", []),
                "devices": service.get("devices", []),
            },
            sort_keys=True,
        ).casefold()
        assert "webhook_signing_secret" not in surface, f"{name} received signing authority"
        if name != "broker":
            assert "approval_mac_key" not in surface, (
                f"{name} received broker-only approval authority"
            )
        assert "candidate-context" not in surface.replace("_", "-"), (
            f"{name} received candidate-context capability"
        )

    assert set(broker.get("cap_add", [])) == set()
    assert set(runner.get("cap_add", [])) == set()
