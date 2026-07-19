from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from crosspatch.runner.secrets import INSECURE_VICTIM_DATABASE_PASSWORDS

ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = ROOT / "compose.yaml"
CADDY_FILE = ROOT / "infra" / "Caddyfile"
MINIMUM_JUDGE_WINDOW = datetime(2026, 8, 13, 7, tzinfo=UTC)
REQUIRED_SERVICES = {
    "api",
    "broker-mcp",
    "candidate-executor",
    "caddy",
    "control-migrate",
    "evidence-mcp",
    "judge-mcp",
    "postgres",
    "runner",
    "victim",
    "victim-role-bootstrap",
    "victim-postgres",
    "victim-worker",
    "web",
}


def _render_compose(
    *,
    profile: str | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    assert COMPOSE_FILE.is_file(), "Task 10 must ship compose.yaml"
    docker = shutil.which("docker")
    assert docker is not None, "Docker Compose is required to validate the release topology"
    command = [docker, "compose", "-f", str(COMPOSE_FILE)]
    if profile is not None:
        command.extend(["--profile", profile])
    command.extend(["config", "--format", "json"])
    result = subprocess.run(
        command,
        cwd=ROOT,
        env={**os.environ, **(environment or {})},
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "compose.yaml must render without interpolation or schema errors:\n"
        f"{result.stdout}\n{result.stderr}"
    )
    return json.loads(result.stdout)


def _service(compose: dict[str, Any], name: str) -> dict[str, Any]:
    services = compose.get("services", {})
    assert name in services, f"compose.yaml is missing the required {name!r} service"
    return services[name]


def _published_ports(service: dict[str, Any]) -> set[int]:
    published: set[int] = set()
    for port in service.get("ports", []):
        value: Any
        if isinstance(port, dict):
            value = port.get("published")
        else:
            value = str(port).split(":")[-2 if ":" in str(port) else -1]
        if value is not None:
            published.add(int(value))
    return published


def _service_networks(service: dict[str, Any]) -> set[str]:
    networks = service.get("networks", {})
    if isinstance(networks, dict):
        return set(networks)
    return set(networks)


def _environment(service: dict[str, Any]) -> dict[str, str]:
    environment = service.get("environment", {})
    if isinstance(environment, dict):
        return {str(key): str(value) for key, value in environment.items()}
    return dict(item.split("=", 1) for item in environment if "=" in item)


def _mounts(service: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    return tuple(
        mount if isinstance(mount, dict) else {"rendered": str(mount)}
        for mount in service.get("volumes", ())
    )


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert parsed.utcoffset() == UTC.utcoffset(parsed), f"timestamp must be UTC: {value}"
    return parsed


def test_compose_contains_the_complete_crosspatch_runtime() -> None:
    compose = _render_compose()
    services = set(compose.get("services", {}))

    assert REQUIRED_SERVICES <= services, (
        "the one-command judge stack is incomplete; missing services: "
        f"{sorted(REQUIRED_SERVICES - services)}"
    )


def test_only_caddy_publishes_ports_80_and_443() -> None:
    compose = _render_compose()
    public = {
        name: ports
        for name, service in compose["services"].items()
        if (ports := _published_ports(service))
    }

    assert public == {"caddy": {80, 443}}, (
        "only Caddy may be host-reachable, and it must publish exactly 80/443; "
        f"rendered public ports were {public}"
    )
    assert {port.get("host_ip") for port in _service(compose, "caddy")["ports"]} == {
        "127.0.0.1"
    }


def test_example_environment_preserves_the_loopback_development_default() -> None:
    example = (ROOT / ".env.example").read_text(encoding="utf-8")

    assert "CROSSPATCH_BIND_ADDRESS=127.0.0.1" in example
    assert "CROSSPATCH_BACKUP_AUTH_KEY_FILE=" in example


def test_release_candidate_network_contains_no_repository_known_role_credential() -> None:
    environment = {
        "CROSSPATCH_RELEASE_MODE": "1",
        "CROSSPATCH_CANDIDATE_EXECUTOR_TOKEN": "release-sidecar-A1b2C3d4E5f6G7h8I9j0K1l2",
        "CROSSPATCH_VICTIM_POSTGRES_ADMIN_PASSWORD": "release-admin-A1b2C3d4E5f6G7h8I9j0K1l2",
        "CROSSPATCH_VICTIM_APP_PASSWORD": "release-app-A1b2C3d4E5f6G7h8I9j0K1l2M3",
        "CROSSPATCH_VICTIM_CANDIDATE_PASSWORD": "release-candidate-A1b2C3d4E5f6G7h8I9j0K1",
        "CROSSPATCH_VICTIM_WORKER_PASSWORD": "release-worker-A1b2C3d4E5f6G7h8I9j0K1",
        "CROSSPATCH_VICTIM_ORACLE_PASSWORD": "release-oracle-A1b2C3d4E5f6G7h8I9j0K1",
        "CROSSPATCH_VICTIM_SCOPE_PASSWORD": "release-scope-A1b2C3d4E5f6G7h8I9j0K1L2",
    }
    compose = _render_compose(environment=environment)
    known = set(INSECURE_VICTIM_DATABASE_PASSWORDS) | {
        "crosspatch-victim-admin-local-only",
        "crosspatch-local-sidecar-token-32chars",
    }

    for service_name, service in compose["services"].items():
        if "candidate-data" not in _service_networks(service):
            continue
        rendered = json.dumps(_environment(service), sort_keys=True)
        assert all(secret not in rendered for secret in known), service_name


def test_strict_release_proof_uses_an_isolated_loopback_compose_project() -> None:
    project = "crosspatch-release-proof-contract"
    compose = _render_compose(
        environment={
            "COMPOSE_PROJECT_NAME": project,
            "CROSSPATCH_BIND_ADDRESS": "127.0.0.1",
            "CROSSPATCH_HTTP_PORT": "0",
            "CROSSPATCH_HTTPS_PORT": "0",
        }
    )
    public = {
        name: ports
        for name, service in compose["services"].items()
        if (ports := _published_ports(service))
    }

    assert compose["name"] == project
    assert public == {"caddy": {0}}
    rendered_ports = _service(compose, "caddy")["ports"]
    assert {(port["target"], port["published"]) for port in rendered_ports} == {
        (8080, "0"),
        (8443, "0"),
    }
    assert {port.get("host_ip") for port in rendered_ports} == {"127.0.0.1"}
    assert all(
        volume.get("name", "").startswith(f"{project}_")
        for volume in compose["volumes"].values()
    )


def test_postgres_verifiers_use_only_the_disposable_verification_database() -> None:
    compose = _render_compose(profile="verification")
    database = _service(compose, "verification-postgres")
    assert database.get("profiles") == ["verification"]
    assert database.get("restart") == "no"
    assert _published_ports(database) == set()
    assert not database.get("expose")
    assert _service_networks(database) == {"verification"}
    assert compose["networks"]["verification"].get("internal") is True
    assert not _mounts(database)
    assert any(
        str(tmpfs).startswith("/var/lib/postgresql/data:")
        for tmpfs in database.get("tmpfs", ())
    ), "verification PostgreSQL state must be disposable"
    database_environment = _environment(database)
    assert set(database_environment) == {
        "POSTGRES_DB",
        "POSTGRES_INITDB_ARGS",
        "POSTGRES_PASSWORD",
        "POSTGRES_USER",
    }
    assert database_environment["POSTGRES_DB"] == "crosspatch_verification"
    assert database_environment["POSTGRES_USER"] == "crosspatch_verifier"
    assert database_environment["POSTGRES_PASSWORD"]


def test_every_fresh_postgres_cluster_uses_deterministic_utf8() -> None:
    compose = _render_compose(profile="verification")

    for service_name in ("postgres", "verification-postgres", "victim-postgres"):
        assert _environment(_service(compose, service_name))["POSTGRES_INITDB_ARGS"] == (
            "--encoding=UTF8 --locale=C"
        )

    expected = {
        "postgres-verifier": (
            "CROSSPATCH_TEST_POSTGRES_DSN",
            "postgresql+asyncpg",
        ),
        "victim-postgres-verifier": (
            "CROSSPATCH_TEST_DATABASE_URL",
            "postgresql",
        ),
    }
    for service_name, (dsn_key, scheme) in expected.items():
        verifier = _service(compose, service_name)
        environment = _environment(verifier)
        assert verifier.get("profiles") == ["verification"]
        assert verifier.get("restart") == "no"
        assert _published_ports(verifier) == set()
        assert not verifier.get("expose")
        assert _service_networks(verifier) == {"verification"}
        assert set(verifier.get("depends_on", {})) == {"verification-postgres"}
        assert not _mounts(verifier), "database verifiers use immutable image contents"
        assert set(environment) == {dsn_key}
        verifier_database = urlparse(environment[dsn_key])
        assert verifier_database.scheme == scheme
        assert verifier_database.username == "crosspatch_verifier"
        assert verifier_database.password
        assert verifier_database.hostname == "verification-postgres"
        assert verifier_database.port == 5432
        assert verifier_database.path == "/crosspatch_verification"


def test_victim_bootstrap_authority_is_absent_from_runtime_services() -> None:
    compose = _render_compose(profile="verification")
    for service_name in ("runner", "candidate-executor"):
        runtime_environment = _environment(_service(compose, service_name))
        assert "CROSSPATCH_VICTIM_POSTGRES_ADMIN_PASSWORD" not in runtime_environment
        for value in runtime_environment.values():
            if value.startswith(("postgresql://", "postgresql+asyncpg://")):
                assert urlparse(value).username != "crosspatch_victim_bootstrap", (
                    f"{service_name} must never receive victim bootstrap authority"
                )


def test_control_plane_database_roles_are_distinct_and_readers_have_no_artifact_mount() -> None:
    compose = _render_compose()
    expected_roles = {
        "api": "crosspatch_api",
        "broker-mcp": "crosspatch_broker",
        "evidence-mcp": "crosspatch_evidence",
        "judge-mcp": "crosspatch_judge",
    }
    owner_url = urlparse(
        _environment(_service(compose, "control-migrate"))["CROSSPATCH_DATABASE_URL"]
    )
    assert owner_url.username == "crosspatch"
    assert set(_service(compose, "control-migrate").get("depends_on", {})) == {"postgres"}

    observed: set[str] = set()
    for service_name, expected_role in expected_roles.items():
        service = _service(compose, service_name)
        database_url = urlparse(_environment(service)["CROSSPATCH_DATABASE_URL"])
        assert database_url.username == expected_role
        assert database_url.password
        assert database_url.username != owner_url.username
        assert set(service.get("depends_on", {})) >= {"control-migrate"}
        observed.add(database_url.username)
    assert observed == set(expected_roles.values())

    for reader in ("evidence-mcp", "judge-mcp"):
        assert not _mounts(_service(compose, reader)), (
            f"{reader} consumes database projections and must have no raw artifact path"
        )


def test_victim_app_candidate_scope_worker_and_oracle_database_roles_are_disjoint() -> None:
    compose = _render_compose()
    services_and_urls = {
        "candidate-executor": "CROSSPATCH_CANDIDATE_DATABASE_URL",
        "candidate-scope": "CROSSPATCH_CANDIDATE_SCOPE_DATABASE_URL",
        "victim": "VICTIM_DATABASE_URL",
        "victim-worker": "VICTIM_DATABASE_URL",
        "runner-oracle": "CROSSPATCH_TEST_DATABASE_URL",
        "runner-worker": "CROSSPATCH_WORKER_DATABASE_URL",
    }
    parsed: dict[str, Any] = {}
    for label, environment_key in services_and_urls.items():
        service_name = (
            "candidate-executor"
            if label == "candidate-scope"
            else label.split("-", 1)[0]
            if label.startswith("runner-")
            else label
        )
        parsed[label] = urlparse(_environment(_service(compose, service_name))[environment_key])
        assert parsed[label].hostname == "victim-postgres"
        assert parsed[label].password

    assert parsed["candidate-executor"].username == "crosspatch_victim_candidate"
    assert parsed["candidate-scope"].username == "crosspatch_victim_scope"
    assert parsed["victim"].username == "crosspatch_victim_app"
    assert parsed["victim-worker"].username == "crosspatch_victim_worker"
    assert parsed["runner-worker"].username == "crosspatch_victim_worker"
    assert parsed["runner-oracle"].username == "crosspatch_victim_oracle"
    assert len(
        {
            parsed["candidate-executor"].username,
            parsed["candidate-scope"].username,
            parsed["victim"].username,
            parsed["victim-worker"].username,
            parsed["runner-oracle"].username,
        }
    ) == 5

    bootstrap = _service(compose, "victim-role-bootstrap")
    assert set(bootstrap.get("depends_on", {})) == {"victim-postgres"}
    for runtime in ("candidate-executor", "victim", "victim-worker", "runner"):
        assert set(_service(compose, runtime).get("depends_on", {})) >= {
            "victim-role-bootstrap"
        }


def test_victim_role_sql_denies_candidate_oracle_spoof_capabilities() -> None:
    sql = (ROOT / "infra/postgres/victim-roles.sql").read_text(encoding="utf-8").lower()
    assert "revoke all on all tables in schema public from crosspatch_victim," in sql
    assert "grant select on webhook_receipts to crosspatch_victim_candidate" in sql
    assert (
        "grant insert on webhook_receipts, outbox_jobs to crosspatch_victim_candidate" in sql
    )
    assert (
        "grant select on webhook_receipts, outbox_jobs, deliveries "
        "to crosspatch_victim_worker" in sql
    )
    assert "grant update on outbox_jobs to crosspatch_victim_worker" in sql
    assert "grant insert on deliveries to crosspatch_victim_worker" in sql
    assert (
        "grant select, delete on webhook_receipts, outbox_jobs, deliveries\n"
        "    to crosspatch_victim_oracle" in sql
    )
    assert "force row level security" in sql
    assert "crosspatch_candidate_scope_allows(provider, event_id)" in sql
    assert "grant execute on function crosspatch_bind_candidate_scope" in sql
    forbidden_candidate_grants = (
        "grant delete",
        "grant update",
        "grant insert on deliveries",
    )
    candidate_section = sql.split("-- candidate grants", 1)[1].split("-- worker grants", 1)[0]
    assert not any(grant in candidate_section for grant in forbidden_candidate_grants)


def test_candidate_sees_only_the_single_attempt_handoff_volume() -> None:
    compose = _render_compose()
    runner = _service(compose, "runner")
    candidate = _service(compose, "candidate-executor")
    runner_mounts = _mounts(runner)
    candidate_mounts = _mounts(candidate)

    assert any(
        mount.get("source") == "candidate-workspaces"
        and mount.get("target") == "/var/lib/crosspatch/candidate-workspaces"
        and mount.get("read_only") is not True
        for mount in runner_mounts
    )
    assert any(
        mount.get("source") == "candidate-handoff"
        and mount.get("target") == "/var/lib/crosspatch/candidate-handoff"
        and mount.get("read_only") is not True
        for mount in runner_mounts
    )
    assert any(
        mount.get("source") == "candidate-handoff"
        and mount.get("target") == "/workspaces"
        and mount.get("read_only") is True
        for mount in candidate_mounts
    )
    assert all(
        mount.get("source") != "candidate-workspaces" for mount in candidate_mounts
    )


def test_mcp_healthchecks_require_database_aware_healthz() -> None:
    compose = _render_compose()

    for name, port in (("evidence-mcp", 8011), ("broker-mcp", 8012), ("judge-mcp", 8013)):
        healthcheck = " ".join(
            str(value) for value in _service(compose, name)["healthcheck"]["test"]
        )
        assert f"http://127.0.0.1:{port}/healthz" in healthcheck
        assert "urlopen" in healthcheck


def test_caddy_retains_only_the_capability_required_by_its_pinned_binary() -> None:
    caddy = _service(_render_compose(), "caddy")

    assert "ALL" in caddy.get("cap_drop", [])
    assert set(caddy.get("cap_add", [])) == {"NET_BIND_SERVICE"}, (
        "the pinned Caddy binary carries cap_net_bind_service; Docker refuses to exec "
        "it under no-new-privileges unless that single capability remains bounded"
    )


def test_judge_mcp_has_no_host_mapping_and_only_uses_internal_networks() -> None:
    compose = _render_compose()
    judge = _service(compose, "judge-mcp")
    caddy = _service(compose, "caddy")

    assert _published_ports(judge) == set(), "Judge MCP must never publish a host port"
    judge_networks = _service_networks(judge)
    assert judge_networks, "Judge MCP must attach to a private Compose network"
    assert judge_networks & _service_networks(caddy), "Caddy must reach Judge MCP privately"
    for network in judge_networks:
        definition = compose.get("networks", {}).get(network, {}) or {}
        assert definition.get("internal") is True, (
            f"Judge MCP network {network!r} must be declared internal: true"
        )


def test_caddy_rewrites_public_judge_path_to_private_mcp_endpoint() -> None:
    assert CADDY_FILE.is_file(), "Task 10 must ship infra/Caddyfile"
    caddy = CADDY_FILE.read_text(encoding="utf-8")
    route_at = caddy.find("/mcp/judge")
    assert route_at >= 0, "Caddy must expose the authenticated /mcp/judge route"
    proxy_at = caddy.find("reverse_proxy judge-mcp:8013", route_at)
    assert proxy_at > route_at, "the judge route must proxy only to judge-mcp:8013"
    route = caddy[route_at : proxy_at + len("reverse_proxy judge-mcp:8013")]
    rewrite = re.compile(
        r"(?:\brewrite\s+\S+\s+/mcp(?:\s|\{|$)|"
        r"\buri\s+replace\s+/mcp/judge\s+/mcp(?:\s|$))",
        re.MULTILINE,
    )
    assert rewrite.search(route), (
        "Caddy must explicitly rewrite /mcp/judge to the server's /mcp endpoint; "
        "handle_path stripping to / is not equivalent"
    )
    assert 'header Authorization "Bearer *"' in caddy[:proxy_at]
    assert "handle @judgeUnauthorized" in caddy and "401" in caddy


def test_caddy_redirects_www_to_the_canonical_apex_without_proxying() -> None:
    caddy = CADDY_FILE.read_text(encoding="utf-8")

    redirect_site = "www.{$CROSSPATCH_SITE_ADDRESS:localhost}"
    assert redirect_site in caddy
    block = caddy.split(f"{redirect_site} {{", 1)[1].split("\n}", 1)[0]
    assert "redir https://{$CROSSPATCH_SITE_ADDRESS:localhost}{uri} permanent" in block
    assert "reverse_proxy" not in block


def test_long_running_services_restart_and_durable_state_uses_named_volumes() -> None:
    compose = _render_compose()

    one_shot_services = {"control-migrate", "victim-role-bootstrap"}
    for name in REQUIRED_SERVICES - one_shot_services:
        assert _service(compose, name).get("restart") == "unless-stopped", (
            f"{name} must recover after a host or daemon restart"
        )
    for name in one_shot_services:
        assert _service(compose, name).get("restart") == "no"

    durable_mounts = {
        "postgres": {"postgres-data"},
        "api": {"agent-sessions", "artifact-store", "judge-secrets"},
        "caddy": {"caddy-config", "caddy-data"},
    }
    declared = set(compose.get("volumes", {}))
    for service_name, expected in durable_mounts.items():
        mounted = {
            str(mount.get("source"))
            for mount in _mounts(_service(compose, service_name))
            if mount.get("type") == "volume"
        }
        assert expected <= mounted <= declared


def test_runtime_judge_token_expiry_cannot_end_before_august_13_utc() -> None:
    compose = _render_compose()
    for name in ("api", "judge-mcp"):
        environment = _environment(_service(compose, name))
        value = environment.get("CROSSPATCH_JUDGE_TOKEN_EXPIRES_AT")
        assert value, f"{name} must receive CROSSPATCH_JUDGE_TOKEN_EXPIRES_AT"
        assert _parse_utc(value) >= MINIMUM_JUDGE_WINDOW, (
            f"{name} shortens judge access below the inclusive August 12 window: {value}"
        )


def test_mcp_zones_share_only_their_explicit_keys_with_the_control_plane() -> None:
    compose = _render_compose()
    environments = {
        name: _environment(_service(compose, name))
        for name in ("api", "evidence-mcp", "broker-mcp", "judge-mcp")
    }
    zone_keys = {
        "evidence-mcp": "CROSSPATCH_EVIDENCE_MCP_SIGNING_SECRET",
        "broker-mcp": "CROSSPATCH_BROKER_MCP_SIGNING_SECRET",
        "judge-mcp": "CROSSPATCH_JUDGE_MCP_SIGNING_SECRET",
    }

    for service_name, key in zone_keys.items():
        assert environments[service_name][key] == environments["api"][key]
        assert len(environments[service_name][key].encode("utf-8")) >= 32
        unrelated = set(zone_keys.values()) - {key}
        assert unrelated.isdisjoint(environments[service_name])
    assert all(
        "CROSSPATCH_MCP_SIGNING_SECRET" not in environment
        for environment in environments.values()
    )
    assert environments["broker-mcp"]["CROSSPATCH_APPROVAL_MAC_KEY"] == (
        environments["api"]["CROSSPATCH_APPROVAL_MAC_KEY"]
    )


def test_read_only_mcp_zones_receive_no_unrelated_runtime_secrets() -> None:
    compose = _render_compose()
    forbidden = {
        "CROSSPATCH_APPROVER_TOKEN",
        "CROSSPATCH_OPERATOR_TOKEN",
        "CROSSPATCH_VICTIM_WEBHOOK_SECRET",
        "OPENAI_API_KEY",
    }
    for name in ("evidence-mcp", "judge-mcp"):
        assert forbidden.isdisjoint(_environment(_service(compose, name)))

    judge_mounts = json.dumps(_mounts(_service(compose, "judge-mcp")), sort_keys=True)
    assert "judge-secrets" not in judge_mounts


def test_api_receives_distinct_local_approval_credentials() -> None:
    environment = _environment(_service(_render_compose(), "api"))
    keys = (
        "CROSSPATCH_APPROVER_TOKEN",
        "CROSSPATCH_APPROVER_CSRF_TOKEN",
        "CROSSPATCH_APPROVER_STEP_UP_TOKEN",
    )
    values = [environment.get(key, "") for key in keys]

    assert all(len(value.encode("utf-8")) >= 32 for value in values)
    assert len(set(values)) == len(values), "approval credentials must be independent"


def test_all_credential_bearing_services_receive_the_release_mode_gate() -> None:
    compose = _render_compose()

    for name in (
        "api",
        "broker-mcp",
        "candidate-executor",
        "evidence-mcp",
        "judge-mcp",
        "runner",
        "victim",
        "victim-worker",
    ):
        environment = _environment(_service(compose, name))
        assert environment.get("CROSSPATCH_RELEASE_MODE") in {"0", "1"}, (
            f"{name} must receive the hosted fail-closed credential gate"
        )


def test_candidate_executor_is_a_distinct_trusted_uid_with_only_drop_and_kill_caps() -> None:
    candidate = _service(_render_compose(), "candidate-executor")
    environment = _environment(candidate)

    assert str(candidate.get("user")) == "0:0"
    assert candidate.get("entrypoint") == [
        "/usr/local/bin/crosspatch-candidate-executor-entrypoint"
    ]
    assert environment["CROSSPATCH_EXECUTOR_UID"] == "10003"
    assert environment["CROSSPATCH_CANDIDATE_UID"] == "10002"
    assert environment["CROSSPATCH_CANDIDATE_GID"] == "10002"
    assert environment["CROSSPATCH_EXECUTOR_UID"] != environment["CROSSPATCH_CANDIDATE_UID"]
    assert "ALL" in candidate.get("cap_drop", [])
    assert set(candidate.get("cap_add", [])) == {"KILL", "SETGID", "SETUID"}
    assert candidate.get("security_opt", []) == []
    healthcheck = " ".join(str(value) for value in candidate["healthcheck"]["test"])
    assert "os.setgroups([10004])" in healthcheck
    assert "os.setresgid(10003,10003,10003)" in healthcheck
    assert "os.setresuid(10003,10003,10003)" in healthcheck
    health_command = candidate["healthcheck"]["test"][-1]
    assert "\n" not in health_command
    assert "bytes((13, 10))" in health_command


def test_candidate_networks_do_not_overlap_api_broker_or_control_database() -> None:
    compose = _render_compose()
    candidate_networks = _service_networks(_service(compose, "candidate-executor"))
    runner_networks = _service_networks(_service(compose, "runner"))

    assert candidate_networks == {"candidate-data"}
    for forbidden in ("api", "broker-mcp", "postgres"):
        assert candidate_networks.isdisjoint(
            _service_networks(_service(compose, forbidden))
        ), f"candidate network still reaches {forbidden}"
    assert candidate_networks.isdisjoint(runner_networks)
    assert candidate_networks & _service_networks(
        _service(compose, "victim-postgres")
    ) == {"candidate-data"}
    for network in candidate_networks:
        assert compose["networks"][network].get("internal") is True


def test_runner_uses_group_protected_unix_sockets_for_all_candidate_control() -> None:
    compose = _render_compose()
    candidate = _service(compose, "candidate-executor")
    runner = _service(compose, "runner")
    broker = _service(compose, "broker-mcp")
    candidate_environment = _environment(candidate)
    runner_environment = _environment(runner)

    assert candidate_environment["CROSSPATCH_CANDIDATE_EXECUTOR_SOCKET"] == (
        "/run/crosspatch/control/executor.sock"
    )
    assert candidate_environment["CROSSPATCH_CANDIDATE_APP_SOCKET"] == (
        "/run/crosspatch/app/candidate.sock"
    )
    assert runner_environment["CROSSPATCH_CANDIDATE_EXECUTOR_SOCKET"] == (
        candidate_environment["CROSSPATCH_CANDIDATE_EXECUTOR_SOCKET"]
    )
    assert runner_environment["CROSSPATCH_CANDIDATE_TARGET_SOCKET"] == (
        candidate_environment["CROSSPATCH_CANDIDATE_APP_SOCKET"]
    )
    assert "CROSSPATCH_CANDIDATE_APP_SOCKET" not in runner_environment
    for service in (candidate, runner):
        assert any(
            mount.get("source") == "candidate-runtime"
            and mount.get("target") == "/run/crosspatch"
            for mount in _mounts(service)
        )
    assert all(
        mount.get("source") != "candidate-runtime" for mount in _mounts(broker)
    )


def test_victim_database_uses_a_separate_least_privilege_application_role() -> None:
    compose = _render_compose()
    database = _service(compose, "victim-postgres")
    database_environment = _environment(database)
    candidate_url = _environment(_service(compose, "candidate-executor"))[
        "CROSSPATCH_CANDIDATE_DATABASE_URL"
    ]
    init_sql = (ROOT / "infra/postgres/victim-bootstrap.sql").read_text(
        encoding="utf-8"
    )
    role_sql = (ROOT / "infra/postgres/victim-roles.sql").read_text(encoding="utf-8")

    assert database_environment["POSTGRES_USER"] == "crosspatch_victim_bootstrap"
    assert database_environment["POSTGRES_USER"] not in candidate_url
    assert "CROSSPATCH_VICTIM_POSTGRES_ADMIN_PASSWORD" in COMPOSE_FILE.read_text(
        encoding="utf-8"
    )
    assert "CREATE ROLE crosspatch_victim_owner NOLOGIN" in init_sql
    assert "victim-roles.sql" in init_sql
    before_role_creation = init_sql.split(r"\i /bootstrap/victim-roles.sql", 1)[0]
    assert "TO crosspatch_victim;" not in before_role_creation, (
        "fresh initialization must not grant to the legacy role before it exists"
    )
    assert "CREATE ROLE crosspatch_victim_candidate NOLOGIN" in role_sql
    assert "CREATE ROLE crosspatch_victim_app NOLOGIN" in role_sql
    assert "CREATE ROLE crosspatch_victim_scope NOLOGIN" in role_sql
    assert "CREATE ROLE crosspatch_victim_worker NOLOGIN" in role_sql
    assert "CREATE ROLE crosspatch_victim_oracle NOLOGIN" in role_sql
    for required in (
        "NOSUPERUSER",
        "NOCREATEDB",
        "NOCREATEROLE",
        "NOREPLICATION",
        "NOBYPASSRLS",
    ):
        assert required in init_sql or required in role_sql
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES" not in role_sql
    assert database_environment["CROSSPATCH_RELEASE_MODE"] in {"0", "1"}
    assert database.get("entrypoint") == [
        "/bin/sh",
        "/usr/local/bin/crosspatch-victim-postgres-entrypoint",
    ]
    assert database.get("command") == ["postgres"]
    assert any(
        mount.get("target")
        == "/usr/local/bin/crosspatch-victim-postgres-entrypoint"
        and mount.get("read_only") is True
        for mount in _mounts(database)
    )
    entrypoint = (ROOT / "infra/postgres/victim-entrypoint.sh").read_text(
        encoding="utf-8"
    )
    for required in (
        "CROSSPATCH_VICTIM_POSTGRES_ADMIN_PASSWORD",
        "CROSSPATCH_VICTIM_APP_PASSWORD",
        "CROSSPATCH_VICTIM_CANDIDATE_PASSWORD",
        "CROSSPATCH_VICTIM_WORKER_PASSWORD",
        "CROSSPATCH_VICTIM_ORACLE_PASSWORD",
        "CROSSPATCH_VICTIM_SCOPE_PASSWORD",
        "crosspatch-victim-admin-local-only",
        "/usr/local/bin/docker-entrypoint.sh",
    ):
        assert required in entrypoint


def test_api_model_sessions_use_a_dedicated_writable_volume() -> None:
    compose = _render_compose()
    api = _service(compose, "api")
    environment = _environment(api)

    assert environment["CROSSPATCH_AGENT_SESSION_DATABASE"] == (
        "/var/lib/crosspatch/agent-sessions/agents.sqlite"
    )
    assert any(
        mount.get("source") == "agent-sessions"
        and mount.get("target") == "/var/lib/crosspatch/agent-sessions"
        and mount.get("read_only") is not True
        for mount in _mounts(api)
    )
    for name, service in compose["services"].items():
        if name == "api":
            continue
        assert all(
            mount.get("source") != "agent-sessions" for mount in _mounts(service)
        )


def test_api_has_one_global_live_trial_budget_and_per_credential_rate_window() -> None:
    environment = _environment(_service(_render_compose(), "api"))

    assert environment["CROSSPATCH_LIVE_TRIAL_GLOBAL_BUDGET_USD"] == "20"
    assert environment["CROSSPATCH_LIVE_TRIAL_RUN_RESERVATION_USD"] == "4"
    assert environment["CROSSPATCH_LIVE_TRIAL_REQUESTS_PER_WINDOW"] == "3"
    assert environment["CROSSPATCH_LIVE_TRIAL_WINDOW_SECONDS"] == "3600"


def test_api_reader_token_is_distinct_from_mutating_credentials() -> None:
    environment = _environment(_service(_render_compose(), "api"))
    reader = environment.get("CROSSPATCH_READER_TOKEN", "")

    assert len(reader.encode("utf-8")) >= 32
    assert reader not in {
        environment["CROSSPATCH_OPERATOR_TOKEN"],
        environment["CROSSPATCH_APPROVER_TOKEN"],
        environment["CROSSPATCH_APPROVER_CSRF_TOKEN"],
        environment["CROSSPATCH_APPROVER_STEP_UP_TOKEN"],
    }
    assert len(environment.get("CROSSPATCH_EXPORT_SIGNING_SEED", "").encode("utf-8")) >= 32


def test_judge_mcp_allows_the_configured_public_site_host() -> None:
    source = COMPOSE_FILE.read_text(encoding="utf-8")

    assert "CROSSPATCH_JUDGE_ALLOWED_HOSTS" in source
    judge_block = source.split("  judge-mcp:", 1)[1].split("\n  web:", 1)[0]
    assert "${CROSSPATCH_SITE_ADDRESS:-localhost}" in judge_block


def test_api_raw_and_sanitized_artifacts_use_the_persistent_artifact_volume() -> None:
    compose = _render_compose()
    api = _service(compose, "api")
    environment = _environment(api)
    assert environment["CROSSPATCH_RAW_ARTIFACT_ROOT"] == (
        "/var/lib/crosspatch/artifacts/raw"
    )
    assert environment["CROSSPATCH_SANITIZED_ARTIFACT_ROOT"] == (
        "/var/lib/crosspatch/artifacts/sanitized"
    )
    mounts = _mounts(api)
    assert any(
        mount.get("source") == "artifact-store"
        and mount.get("target") == "/var/lib/crosspatch/artifacts"
        and mount.get("read_only") is not True
        for mount in mounts
    )
