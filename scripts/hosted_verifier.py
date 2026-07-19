#!/usr/bin/env python3
"""Verify externally reachable deployment facts without inventing unavailable proof."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography import x509
from verification_lib import ARTIFACT_DIR, ROOT, atomic_json, release_source_sha256, utc_now

GENERATOR = "scripts/verify-hosted.sh"
REQUIRED_THROUGH = "2026-08-13T07:00:00Z"
EVIDENCE_SCHEMA_VERSION = "crosspatch.hosted-evidence.v1"
MAX_EVIDENCE_FUTURE_SKEW = timedelta(minutes=5)
PRIVATE_SERVICE_PORTS = (8000, 8011, 8012, 8013)
REQUIRED_RESTART_SERVICES = frozenset(
    {
        "api",
        "broker-mcp",
        "caddy",
        "candidate-executor",
        "evidence-mcp",
        "judge-mcp",
        "postgres",
        "runner",
        "victim",
        "victim-postgres",
        "victim-worker",
        "web",
    }
)
EVIDENCE_TOP_LEVEL_KEYS = frozenset(
    {
        "checked_at",
        "check_id",
        "command",
        "deployment",
        "generator",
        "generator_action",
        "machine_generated",
        "observations",
        "schema_version",
        "source",
        "status",
    }
)


@dataclass(frozen=True)
class EvidenceContract:
    check_id: str
    generator: str
    generator_action: str
    max_age: timedelta = timedelta(days=7)
    require_checked_in_generator: bool = True


OPERATIONAL_EVIDENCE_CONTRACTS = {
    check_id: EvidenceContract(
        check_id=check_id,
        generator="scripts/hosted_verifier.py",
        generator_action=f"capture:{check_id}",
    )
    for check_id in (
        "backup_restore",
        "persistent_token",
        "restart_policy",
        "tls_renewal",
    )
}
GITHUB_VISUAL_EVIDENCE_CONTRACT = EvidenceContract(
    check_id="github_about_visual",
    generator="codex-browser/github-about-visual-v1",
    generator_action="authenticated-github-about-capture",
    require_checked_in_generator=False,
)
GITHUB_API_CHECKS = frozenset(
    {
        "about_metadata",
        "default_branch",
        "repository_visibility",
        "remote_head_matches_local_head",
        "repository_readback",
        "root_license_detected",
    }
)


class CaptureBlocked(RuntimeError):
    """The requested control could not be observed directly."""


@dataclass(frozen=True)
class CapturedOperationalEvidence:
    check_id: str
    path: Path
    sha256: str


IMPLEMENTED_OPERATIONAL_CAPTURE_ACTIONS = frozenset(
    contract.generator_action for contract in OPERATIONAL_EVIDENCE_CONTRACTS.values()
)


def _run(argv: list[str], *, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        argv,
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip()[-2000:]
        raise CaptureBlocked(f"live command failed ({result.returncode}): {detail}")
    return result.stdout


def _compose(compose_project: str, *arguments: str, env: dict[str, str] | None = None) -> str:
    return _run(
        ["docker", "compose", "--project-name", compose_project, *arguments],
        env=env,
    )


def _write_capture(
    *,
    check_id: str,
    output_dir: Path,
    public_url: str,
    git_sha: str,
    command: str,
    observations: dict[str, Any],
) -> CapturedOperationalEvidence:
    errors = _operational_observation_errors(
        check_id,
        observations,
        public_url=public_url,
        now=datetime.now(UTC),
    )
    if errors:
        raise CaptureBlocked("; ".join(errors))
    contract = OPERATIONAL_EVIDENCE_CONTRACTS[check_id]
    payload = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "machine_generated": True,
        "check_id": check_id,
        "generator": contract.generator,
        "generator_action": contract.generator_action,
        "status": "PASS",
        "checked_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "deployment": {"public_url": public_url.rstrip("/"), "git_sha": git_sha},
        "source": "live deployment observation by the checked-in hosted verifier",
        "command": command,
        "observations": observations,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{check_id}.json"
    atomic_json(path, payload)
    raw = path.read_bytes()
    return CapturedOperationalEvidence(
        check_id=check_id,
        path=path.resolve(),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _inspect_compose_service(compose_project: str, service: str) -> dict[str, Any]:
    container_id = _compose(compose_project, "ps", "-q", service).strip()
    if not container_id or "\n" in container_id:
        raise CaptureBlocked(f"service {service} does not resolve to one container")
    values = json.loads(_run(["docker", "inspect", container_id]))
    if not isinstance(values, list) or len(values) != 1:
        raise CaptureBlocked(f"service {service} inspection was ambiguous")
    value = values[0]
    labels = value.get("Config", {}).get("Labels", {})
    state = value.get("State", {})
    health = state.get("Health", {}).get("Status")
    return {
        "project": labels.get("com.docker.compose.project"),
        "service": labels.get("com.docker.compose.service"),
        "running": state.get("Running") is True,
        "healthy": health in (None, "healthy"),
        "restart_policy": value.get("HostConfig", {}).get("RestartPolicy", {}).get("Name"),
        "container_id": container_id,
        "started_at": state.get("StartedAt"),
    }


def capture_restart_policy(
    *,
    output_dir: Path,
    public_url: str,
    git_sha: str,
    compose_project: str,
    inspector: Callable[[str], dict[str, Any]] | None = None,
) -> CapturedOperationalEvidence:
    observe = inspector or (lambda service: _inspect_compose_service(compose_project, service))
    policies: dict[str, str] = {}
    for service in sorted(REQUIRED_RESTART_SERVICES):
        value = observe(service)
        if (
            value.get("project") != compose_project
            or value.get("service") != service
            or value.get("running") is not True
            or value.get("healthy") is not True
            or value.get("restart_policy") != "unless-stopped"
        ):
            raise CaptureBlocked(f"service {service} failed live restart-policy inspection")
        policies[service] = value["restart_policy"]
    return _write_capture(
        check_id="restart_policy",
        output_dir=output_dir,
        public_url=public_url,
        git_sha=git_sha,
        command="docker compose ps -q plus docker inspect for every service",
        observations={"services": policies},
    )


def _judge_authenticator(
    public_url: str, judge_token: str, *, allow_insecure_localhost: bool = False
) -> bool:
    host = urlparse(public_url).hostname
    if allow_insecure_localhost and host not in {"localhost", "127.0.0.1", "::1"}:
        raise CaptureBlocked("insecure Judge MCP observation is restricted to localhost")
    response = httpx.post(
        public_url.rstrip("/") + "/mcp/judge",
        headers={
            "Authorization": f"Bearer {judge_token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "crosspatch-token-persistence", "version": "1"},
            },
        },
        timeout=20,
        verify=not allow_insecure_localhost,
    )
    return response.status_code == 200 and "jsonrpc" in response.text


def capture_persistent_token(
    *,
    output_dir: Path,
    public_url: str,
    git_sha: str,
    judge_token: str,
    compose_project: str,
    authenticator: Callable[[], bool] | None = None,
    restarter: Callable[[], dict[str, tuple[str, str, str]]] | None = None,
    allow_insecure_localhost: bool = False,
) -> CapturedOperationalEvidence:
    authenticate = authenticator or (
        lambda: _judge_authenticator(
            public_url, judge_token, allow_insecure_localhost=allow_insecure_localhost
        )
    )
    if not judge_token or not authenticate():
        raise CaptureBlocked("judge token was not authenticated before restart")

    def live_restart() -> dict[str, tuple[str, str, str]]:
        before = {
            service: _inspect_compose_service(compose_project, service)
            for service in ("caddy", "judge-mcp")
        }
        _compose(compose_project, "restart", "judge-mcp", "caddy")
        deadline = time.monotonic() + 120
        after: dict[str, dict[str, Any]] = {}
        while time.monotonic() < deadline:
            try:
                after = {
                    service: _inspect_compose_service(compose_project, service)
                    for service in ("caddy", "judge-mcp")
                }
                if all(value["running"] and value["healthy"] for value in after.values()):
                    break
            except CaptureBlocked:
                pass
            time.sleep(1)
        return {
            service: (
                str(after.get(service, {}).get("container_id", "")),
                str(before[service].get("started_at", "")),
                str(after.get(service, {}).get("started_at", "")),
            )
            for service in ("caddy", "judge-mcp")
        }

    observations = (restarter or live_restart)()
    if set(observations) != {"caddy", "judge-mcp"} or any(
        not container_id or not before or not after or before == after
        for container_id, before, after in observations.values()
    ):
        raise CaptureBlocked("controlled restart was not independently observed")
    if not authenticate():
        raise CaptureBlocked("judge token did not authenticate after restart")
    return _write_capture(
        check_id="persistent_token",
        output_dir=output_dir,
        public_url=public_url,
        git_sha=git_sha,
        command="authenticated Judge MCP probe before and after controlled restart",
        observations={
            "after_restart_authenticated": True,
            "before_restart_authenticated": True,
            "restarted_services": sorted(observations),
            "token_sha256": hashlib.sha256(judge_token.encode()).hexdigest(),
        },
    )


def _live_tls_renewal_observation(
    public_url: str,
    compose_project: str,
    *,
    allow_insecure_localhost: bool = False,
) -> dict[str, Any]:
    parsed = urlparse(public_url)
    host = parsed.hostname
    if parsed.scheme != "https" or not host:
        raise CaptureBlocked("TLS capture requires an HTTPS public URL")
    caddy = _inspect_compose_service(compose_project, "caddy")
    container = json.loads(_run(["docker", "inspect", caddy["container_id"]]))[0]
    command = " ".join(container.get("Config", {}).get("Cmd", []))
    mounts = container.get("Mounts", [])
    if "caddy run" not in command or not any(
        mount.get("Destination") == "/data" and mount.get("RW") is True for mount in mounts
    ):
        raise CaptureBlocked("running Caddy lacks its live command or writable certificate storage")
    _compose(
        compose_project,
        "exec",
        "-T",
        "caddy",
        "caddy",
        "validate",
        "--config",
        "/etc/caddy/Caddyfile",
    )
    logs = _compose(compose_project, "logs", "--no-color", "caddy")
    if "certificate maintenance" not in logs and '"logger":"tls.renew"' not in logs:
        raise CaptureBlocked("running Caddy has no observed certificate-maintenance activity")
    local = host in {"localhost", "127.0.0.1", "::1"}
    if allow_insecure_localhost and not local:
        raise CaptureBlocked("insecure TLS observation is restricted to localhost")
    context = (
        ssl._create_unverified_context()
        if allow_insecure_localhost
        else ssl.create_default_context()
    )
    port = parsed.port or 443
    with socket.create_connection((host, port), timeout=10) as connection:
        with context.wrap_socket(connection, server_hostname=host) as wrapped:
            certificate = x509.load_der_x509_certificate(wrapped.getpeercert(binary_form=True))
    sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if host not in sans.get_values_for_type(x509.DNSName):
        raise CaptureBlocked("live certificate SAN does not include the deployment hostname")
    not_after = certificate.not_valid_after_utc
    if not_after <= datetime.now(UTC):
        raise CaptureBlocked("live certificate is expired")
    return {
        "automation_enabled": True,
        "certificate_not_after": not_after.isoformat().replace("+00:00", "Z"),
        "hostname": host,
        "renewal_probe_status": "PASS",
    }


def capture_tls_renewal(
    *,
    output_dir: Path,
    public_url: str,
    git_sha: str,
    compose_project: str,
    observer: Callable[[], dict[str, Any]] | None = None,
    allow_insecure_localhost: bool = False,
) -> CapturedOperationalEvidence:
    observations = (
        observer
        or (
            lambda: _live_tls_renewal_observation(
                public_url, compose_project, allow_insecure_localhost=allow_insecure_localhost
            )
        )
    )()
    return _write_capture(
        check_id="tls_renewal",
        output_dir=output_dir,
        public_url=public_url,
        git_sha=git_sha,
        command="inspect running Caddy, validate config, and read live certificate",
        observations=observations,
    )


_DATABASE_SNAPSHOT_SQL = """
SELECT json_object_agg(name, count) FROM (
 SELECT 'incidents' name, count(*) count FROM incidents UNION ALL
 SELECT 'timeline_events', count(*) FROM timeline_events UNION ALL
 SELECT 'evidence', count(*) FROM evidence UNION ALL
 SELECT 'published_cases', count(*) FROM published_cases UNION ALL
 SELECT 'judge_tokens', count(*) FROM judge_tokens
) snapshot;
"""


def _database_snapshot(compose_project: str) -> str:
    value = _compose(
        compose_project,
        "exec",
        "-T",
        "postgres",
        "psql",
        "--username=crosspatch",
        "--dbname=crosspatch",
        "--tuples-only",
        "--no-align",
        "--command",
        _DATABASE_SNAPSHOT_SQL,
    ).strip()
    if not value.startswith("{"):
        raise CaptureBlocked("database snapshot could not be observed")
    return hashlib.sha256(value.encode()).hexdigest()


def _live_backup_restore_drill(compose_project: str) -> dict[str, Any]:
    project = f"crosspatch-restore-{secrets.token_hex(6)}"
    with tempfile.TemporaryDirectory(prefix="crosspatch-restore-drill-") as temporary:
        root = Path(temporary)
        key = root / "backup-auth.key"
        key.write_text(
            __import__("base64").b64encode(secrets.token_bytes(32)).decode(), encoding="ascii"
        )
        key.chmod(0o600)
        env = os.environ.copy()
        env["COMPOSE_PROJECT_NAME"] = compose_project
        env["CROSSPATCH_BACKUP_AUTH_KEY_FILE"] = str(key)
        source_snapshot = _database_snapshot(compose_project)
        output = (
            _run(
                [
                    sys.executable,
                    str(ROOT / "scripts/backup_restore.py"),
                    "backup",
                    "--output-dir",
                    str(root),
                ],
                env=env,
            )
            .strip()
            .splitlines()[-1]
        )
        archive = Path(output)
        if not archive.is_file():
            raise CaptureBlocked("backup command did not produce an archive")
        restore_env = env | {
            "COMPOSE_PROJECT_NAME": project,
            "CROSSPATCH_RESTORE_PROJECT": project,
            "CROSSPATCH_RESTORE_TARGET": "isolated-nonproduction",
            "CROSSPATCH_RESTORE_CONFIRM": "RESTORE",
            "CROSSPATCH_RELEASE_MODE": "0",
        }
        try:
            _compose(project, "up", "-d", "--wait", "api", env=restore_env)
            _run(
                [sys.executable, str(ROOT / "scripts/backup_restore.py"), "restore", str(archive)],
                env=restore_env,
            )
            restored_snapshot = _database_snapshot(project)
            if restored_snapshot != source_snapshot:
                raise CaptureBlocked("restored database snapshot differs from the live source")
        finally:
            _compose(project, "down", "-v", "--remove-orphans", env=restore_env)
        return {
            "backup_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "integrity_checks_passed": restored_snapshot == source_snapshot,
            "isolated_project": project,
            "restore_completed": True,
        }


def capture_backup_restore(
    *,
    output_dir: Path,
    public_url: str,
    git_sha: str,
    compose_project: str,
    drill: Callable[[], dict[str, Any]] | None = None,
) -> CapturedOperationalEvidence:
    observations = (drill or (lambda: _live_backup_restore_drill(compose_project)))()
    return _write_capture(
        check_id="backup_restore",
        output_dir=output_dir,
        public_url=public_url,
        git_sha=git_sha,
        command="live backup followed by isolated Compose restore and snapshot comparison",
        observations=observations,
    )


def status(value: str, *, detail: str, evidence: dict | None = None) -> dict:
    result = {"status": value, "detail": detail}
    if evidence:
        result["evidence"] = evidence
    return result


def parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def local_git_sha(root: Path = ROOT) -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    value = result.stdout.strip().lower()
    if (
        result.returncode != 0
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        return None
    return value


def git_sha_argument(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 40 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise argparse.ArgumentTypeError("deployment git SHA must be 40 lowercase hex characters")
    return normalized


def _is_sha256(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _operational_observation_errors(
    check_id: str,
    observations: object,
    *,
    public_url: str | None,
    now: datetime,
) -> list[str]:
    if not isinstance(observations, dict):
        return ["observations are missing"]
    errors: list[str] = []
    if check_id == "restart_policy":
        if set(observations) != {"services"}:
            return ["restart-policy observations do not match the strict contract"]
        services = observations.get("services")
        if not isinstance(services, dict) or set(services) != REQUIRED_RESTART_SERVICES:
            errors.append("restart-policy service set is incomplete")
        elif any(policy != "unless-stopped" for policy in services.values()):
            errors.append("one or more production services lack the required restart policy")
    elif check_id == "persistent_token":
        expected = {
            "after_restart_authenticated",
            "before_restart_authenticated",
            "restarted_services",
            "token_sha256",
        }
        if set(observations) != expected:
            return ["token-persistence observations do not match the strict contract"]
        if observations.get("before_restart_authenticated") is not True:
            errors.append("judge token was not authenticated before restart")
        if observations.get("after_restart_authenticated") is not True:
            errors.append("judge token did not persist across restart")
        restarted = observations.get("restarted_services")
        if (
            not isinstance(restarted, list)
            or any(not isinstance(service, str) for service in restarted)
            or not {"caddy", "judge-mcp"} <= set(restarted)
        ):
            errors.append("required public and Judge MCP services were not restarted")
        if not _is_sha256(observations.get("token_sha256")):
            errors.append("token identity hash is invalid")
    elif check_id == "tls_renewal":
        expected = {
            "automation_enabled",
            "certificate_not_after",
            "hostname",
            "renewal_probe_status",
        }
        if set(observations) != expected:
            return ["TLS-renewal observations do not match the strict contract"]
        expected_hostname = urlparse(public_url or "").hostname
        if not expected_hostname or observations.get("hostname") != expected_hostname:
            errors.append("TLS hostname does not match the public deployment")
        if observations.get("automation_enabled") is not True:
            errors.append("TLS renewal automation is not enabled")
        if observations.get("renewal_probe_status") != "PASS":
            errors.append("TLS renewal probe did not pass")
        certificate_not_after = parse_timestamp(observations.get("certificate_not_after"))
        if certificate_not_after is None or certificate_not_after <= now:
            errors.append("TLS certificate expiry evidence is invalid")
    elif check_id == "backup_restore":
        expected = {
            "backup_sha256",
            "integrity_checks_passed",
            "isolated_project",
            "restore_completed",
        }
        if set(observations) != expected:
            return ["backup/restore observations do not match the strict contract"]
        if not _is_sha256(observations.get("backup_sha256")):
            errors.append("backup hash is invalid")
        if observations.get("restore_completed") is not True:
            errors.append("restore drill did not complete")
        if observations.get("integrity_checks_passed") is not True:
            errors.append("restored integrity checks did not pass")
        project = observations.get("isolated_project")
        if not isinstance(project, str) or not project.startswith("crosspatch-restore-"):
            errors.append("restore did not use an isolated project")
    else:
        errors.append("unknown operational evidence check")
    return errors


def generated_evidence_check(
    path_value: str | Path | None,
    *,
    label: str,
    contract: EvidenceContract | None = None,
    public_url: str | None = None,
    git_sha: str | None = None,
    now: datetime | None = None,
    root: Path = ROOT,
    captured: CapturedOperationalEvidence | None = None,
) -> dict:
    if not path_value:
        return status("BLOCKED", detail=f"machine-generated {label} evidence is missing")
    path = Path(path_value).expanduser()
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError("evidence path is not a regular file")
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return status("FAIL", detail=f"{label} evidence is invalid: {error}")
    validation_errors: list[str] = []
    if not isinstance(payload, dict):
        validation_errors.append("artifact must be an object")
        payload = {}
    if contract is None:
        validation_errors.append("an explicit evidence contract is required")
    if set(payload) != EVIDENCE_TOP_LEVEL_KEYS:
        validation_errors.append("artifact does not match the strict evidence schema")
    if payload.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
        validation_errors.append("schema version mismatch")
    if payload.get("machine_generated") is not True:
        validation_errors.append("artifact is not machine generated")
    if contract is not None:
        if payload.get("check_id") != contract.check_id:
            validation_errors.append("check identity mismatch")
        if payload.get("generator") != contract.generator:
            validation_errors.append("generator identity mismatch")
        if payload.get("generator_action") != contract.generator_action:
            validation_errors.append("generator action mismatch")
        if contract.require_checked_in_generator:
            generator = (root / contract.generator).resolve()
            resolved_root = root.resolve()
            if (
                generator == resolved_root
                or resolved_root not in generator.parents
                or generator.is_symlink()
                or not generator.is_file()
                or not os.access(generator, os.X_OK)
            ):
                validation_errors.append("expected generator is not checked-in executable code")
    if payload.get("status") != "PASS":
        validation_errors.append("artifact does not report PASS")
    checked_at = parse_timestamp(payload.get("checked_at"))
    checked_now = (now or datetime.now(UTC)).astimezone(UTC)
    if checked_at is None:
        validation_errors.append("checked_at must be timezone-aware")
    elif contract is not None and not (
        checked_now - contract.max_age <= checked_at <= checked_now + MAX_EVIDENCE_FUTURE_SKEW
    ):
        validation_errors.append("artifact is stale or from the future")
    deployment = payload.get("deployment")
    if not isinstance(deployment, dict) or set(deployment) != {"git_sha", "public_url"}:
        validation_errors.append("deployment binding is invalid")
        deployment = {}
    expected_url = public_url.rstrip("/") if isinstance(public_url, str) else None
    actual_url = deployment.get("public_url")
    if (
        not expected_url
        or not isinstance(actual_url, str)
        or actual_url.rstrip("/") != expected_url
    ):
        validation_errors.append("public URL binding mismatch")
    if not isinstance(git_sha, str) or len(git_sha) != 40 or deployment.get("git_sha") != git_sha:
        validation_errors.append("git SHA binding mismatch")
    for name in ("command", "source"):
        if not isinstance(payload.get(name), str) or not payload[name].strip():
            validation_errors.append(f"{name} provenance is missing")
    if contract is not None and contract.check_id in OPERATIONAL_EVIDENCE_CONTRACTS:
        actual_sha256 = hashlib.sha256(raw).hexdigest()
        if (
            captured is None
            or captured.check_id != contract.check_id
            or captured.path != path.resolve()
            or captured.sha256 != actual_sha256
        ):
            validation_errors.append("artifact was not captured by this verifier invocation")
        validation_errors.extend(
            _operational_observation_errors(
                contract.check_id,
                payload.get("observations"),
                public_url=public_url,
                now=checked_now,
            )
        )
    elif not isinstance(payload.get("observations"), dict) or not payload["observations"]:
        validation_errors.append("observations are missing")
    valid = not validation_errors
    try:
        rendered_path = str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        rendered_path = str(path.resolve())
    return status(
        "PASS" if valid else "BLOCKED",
        detail=(
            f"machine-generated {label} evidence verified"
            if valid
            else f"{label} evidence is not in a verified state"
        ),
        evidence={
            "artifact_path": rendered_path,
            "artifact_sha256": hashlib.sha256(raw).hexdigest(),
            "check_id": payload.get("check_id"),
            "generator": payload.get("generator"),
            "git_sha": deployment.get("git_sha"),
            "reported_status": payload.get("status"),
            "validation_errors": validation_errors,
        },
    )


def github_api_evidence_check(
    path_value: str | Path | None,
    *,
    git_sha: str | None,
    now: datetime | None = None,
    root: Path = ROOT,
) -> dict:
    """Validate API-only GitHub license evidence without inferring UI visibility."""

    if not path_value:
        return status("BLOCKED", detail="authenticated GitHub API evidence is missing")
    path = Path(path_value).expanduser()
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError("evidence path is not a regular file")
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return status("FAIL", detail=f"authenticated GitHub API evidence is invalid: {error}")

    errors: list[str] = []
    if not isinstance(payload, dict):
        errors.append("artifact must be an object")
        payload = {}
    generator = (root / "scripts/verify-github-license.sh").resolve()
    resolved_root = root.resolve()
    if (
        generator == resolved_root
        or resolved_root not in generator.parents
        or generator.is_symlink()
        or not generator.is_file()
        or not os.access(generator, os.X_OK)
    ):
        errors.append("GitHub evidence generator is not checked-in executable code")
    if payload.get("schema_version") != 1:
        errors.append("schema version mismatch")
    if payload.get("machine_generated") is not True:
        errors.append("artifact is not machine generated")
    if payload.get("generator") != "scripts/verify-github-license.sh":
        errors.append("generator identity mismatch")
    if payload.get("status") != "API_VERIFIED":
        errors.append("GitHub API evidence must report API_VERIFIED")
    if payload.get("verification_scope") != "authenticated GitHub API and local git only":
        errors.append("GitHub verification scope mismatch")
    if payload.get("git_sha") != git_sha or not isinstance(git_sha, str) or len(git_sha) != 40:
        errors.append("git SHA binding mismatch")
    repository = payload.get("repository")
    if not isinstance(repository, str) or repository.count("/") != 1:
        errors.append("repository identity is missing")
    checked_at = parse_timestamp(payload.get("checked_at"))
    checked_now = (now or datetime.now(UTC)).astimezone(UTC)
    if checked_at is None:
        errors.append("checked_at must be timezone-aware")
    elif not (
        checked_now - timedelta(days=7) <= checked_at <= checked_now + MAX_EVIDENCE_FUTURE_SKEW
    ):
        errors.append("GitHub API evidence is stale or from the future")
    checks = payload.get("checks")
    if not isinstance(checks, dict) or set(checks) != GITHUB_API_CHECKS:
        errors.append("GitHub API checks do not match the strict contract")
    elif any(
        not isinstance(check, dict) or check.get("status") != "PASS" for check in checks.values()
    ):
        errors.append("one or more GitHub API checks did not pass")
    visual = payload.get("authenticated_ui_about_visual_readback")
    if (
        not isinstance(visual, dict)
        or visual.get("status") != "NOT_PERFORMED"
        or visual.get("api_inference_allowed") is not False
        or visual.get("required_before_submission") is not True
    ):
        errors.append("API artifact must explicitly disclaim visual About verification")
    if payload.get("blockers") != []:
        errors.append("GitHub API artifact contains blockers")
    try:
        rendered_path = str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        rendered_path = str(path.resolve())
    return status(
        "PASS" if not errors else "BLOCKED",
        detail=(
            "authenticated GitHub API MIT metadata verified"
            if not errors
            else "authenticated GitHub API evidence is not in a verified state"
        ),
        evidence={
            "artifact_path": rendered_path,
            "artifact_sha256": hashlib.sha256(raw).hexdigest(),
            "generator": payload.get("generator"),
            "git_sha": payload.get("git_sha"),
            "repository": repository,
            "reported_status": payload.get("status"),
            "validation_errors": errors,
        },
    )


def github_about_visual_evidence_check(
    path_value: str | Path | None,
    *,
    public_url: str | None,
    git_sha: str | None,
    repository: str | None,
    now: datetime | None = None,
    root: Path = ROOT,
) -> dict:
    """Validate separate authenticated-browser proof of the visible GitHub About license."""

    result = generated_evidence_check(
        path_value,
        label="authenticated GitHub About visual readback",
        contract=GITHUB_VISUAL_EVIDENCE_CONTRACT,
        public_url=public_url,
        git_sha=git_sha,
        now=now,
        root=root,
    )
    if result["status"] != "PASS" or not path_value:
        return result
    path = Path(path_value).expanduser()
    payload = json.loads(path.read_bytes())
    observations = payload.get("observations")
    errors: list[str] = []
    expected_keys = {
        "about_license_text",
        "authenticated_session",
        "repository",
        "screenshot_path",
        "screenshot_sha256",
    }
    if not isinstance(observations, dict) or set(observations) != expected_keys:
        errors.append("visual observations do not match the strict contract")
        observations = {}
    if observations.get("authenticated_session") is not True:
        errors.append("visual capture was not authenticated")
    if observations.get("about_license_text") != "MIT":
        errors.append("GitHub About did not visibly show MIT")
    if not repository or observations.get("repository") != repository:
        errors.append("visual repository identity mismatch")
    screenshot_value = observations.get("screenshot_path")
    screenshot = Path(screenshot_value).expanduser() if isinstance(screenshot_value, str) else None
    if screenshot is not None and not screenshot.is_absolute():
        screenshot = path.parent / screenshot
    if screenshot is None or screenshot.is_symlink() or not screenshot.is_file():
        errors.append("visual screenshot is missing or unsafe")
    else:
        actual_screenshot_sha = hashlib.sha256(screenshot.read_bytes()).hexdigest()
        if observations.get("screenshot_sha256") != actual_screenshot_sha:
            errors.append("visual screenshot hash mismatch")
    if errors:
        result["status"] = "BLOCKED"
        result["detail"] = "authenticated GitHub About visual evidence is invalid"
        result["evidence"]["validation_errors"].extend(errors)
    return result


def tls_probe(host: str, port: int = 443) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as connection:
        with context.wrap_socket(connection, server_hostname=host) as wrapped:
            certificate = wrapped.getpeercert()
            return {
                "protocol": wrapped.version(),
                "cipher": wrapped.cipher()[0] if wrapped.cipher() else None,
                "not_after": certificate.get("notAfter"),
                "subject_alt_name": certificate.get("subjectAltName", []),
            }


def private_service_ports_check(
    host: str,
    *,
    connector: Callable[..., object] = socket.create_connection,
) -> dict:
    """Prove that private API and MCP listeners are not reachable on the public host."""

    exposed_ports: list[int] = []
    for port in PRIVATE_SERVICE_PORTS:
        try:
            connection = connector((host, port), timeout=3.0)
        except OSError:
            continue
        exposed_ports.append(port)
        close = getattr(connection, "close", None)
        if callable(close):
            close()
    return status(
        "FAIL" if exposed_ports else "PASS",
        detail=(
            f"private service ports are publicly reachable: {exposed_ports}"
            if exposed_ports
            else "private API and MCP ports are unreachable from the public host"
        ),
        evidence={
            "host": host,
            "probed_ports": list(PRIVATE_SERVICE_PORTS),
            "exposed_ports": exposed_ports,
        },
    )


async def public_checks(public_url: str, judge_token: str) -> dict[str, dict]:
    parsed = urlparse(public_url)
    checks: dict[str, dict] = {}
    if parsed.scheme != "https" or not parsed.hostname:
        reason = "CROSSPATCH_PUBLIC_URL must be an absolute HTTPS URL"
        for name in (
            "reachable_url",
            "dns",
            "tls",
            "public_health",
            "authenticated_judge_mcp",
            "private_service_ports_unreachable",
        ):
            checks[name] = status("BLOCKED", detail=reason)
        return checks

    checks["private_service_ports_unreachable"] = private_service_ports_check(parsed.hostname)

    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(parsed.hostname, 443)})
        checks["dns"] = status(
            "PASS", detail="hostname resolved", evidence={"addresses": addresses}
        )
    except OSError as error:
        checks["dns"] = status("FAIL", detail=f"DNS resolution failed: {error}")

    try:
        checks["tls"] = status(
            "PASS", detail="trusted TLS handshake succeeded", evidence=tls_probe(parsed.hostname)
        )
    except (OSError, ssl.SSLError) as error:
        checks["tls"] = status("FAIL", detail=f"trusted TLS handshake failed: {error}")

    headers = {"Authorization": f"Bearer {judge_token}"}
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            root = await client.get(public_url.rstrip("/") + "/")
            checks["reachable_url"] = status(
                "PASS" if root.status_code == 200 else "FAIL",
                detail=f"public root returned HTTP {root.status_code}",
            )
            health = await client.get(public_url.rstrip("/") + "/healthz")
            checks["public_health"] = status(
                "PASS" if health.status_code == 200 else "FAIL",
                detail=f"public health returned HTTP {health.status_code}",
            )
            initialize = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "crosspatch-hosted-verifier", "version": "0.1.0"},
                },
            }
            mcp = await client.post(
                public_url.rstrip("/") + "/mcp/judge",
                headers={
                    **headers,
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
                json=initialize,
            )
            mcp_pass = mcp.status_code == 200 and "jsonrpc" in mcp.text
            checks["authenticated_judge_mcp"] = status(
                "PASS" if mcp_pass else "FAIL",
                detail=f"authenticated MCP initialize returned HTTP {mcp.status_code}",
            )
    except httpx.HTTPError as error:
        for name in ("reachable_url", "public_health", "authenticated_judge_mcp"):
            checks.setdefault(name, status("FAIL", detail=f"HTTP verification failed: {error}"))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ARTIFACT_DIR / "hosted-acceptance.json")
    parser.add_argument("--capture-operational", action="store_true")
    parser.add_argument("--capture-dir", type=Path, default=ARTIFACT_DIR / "hosted-operational")
    parser.add_argument("--compose-project", default="crosspatch")
    parser.add_argument("--deployment-git-sha", type=git_sha_argument)
    parser.add_argument("--allow-insecure-localhost", action="store_true")
    arguments = parser.parse_args()
    public_url = os.environ.get("CROSSPATCH_PUBLIC_URL", "").strip()
    judge_token = os.environ.get("CROSSPATCH_JUDGE_TOKEN", "").strip()
    monitor_id = os.environ.get("CROSSPATCH_UPTIME_MONITOR_ID", "").strip()
    monitor_through = os.environ.get("CROSSPATCH_UPTIME_MONITOR_ACTIVE_THROUGH", "").strip()
    git_sha = local_git_sha()
    deployment_git_sha = arguments.deployment_git_sha or git_sha
    captured: dict[str, CapturedOperationalEvidence] = {}

    blockers: list[str] = []
    checks: dict[str, dict]
    if not public_url or not judge_token:
        missing = []
        if not public_url:
            missing.append("CROSSPATCH_PUBLIC_URL and a reachable hosted URL/DNS configuration")
        if not judge_token:
            missing.append("CROSSPATCH_JUDGE_TOKEN credential")
        blockers.extend(missing)
        detail = "hosted authority is unavailable: " + "; ".join(missing)
        checks = {
            name: status("BLOCKED", detail=detail)
            for name in (
                "authenticated_judge_mcp",
                "dns",
                "private_service_ports_unreachable",
                "public_health",
                "reachable_url",
                "tls",
            )
        }
    else:
        checks = asyncio.run(public_checks(public_url, judge_token))

    monitor_deadline = parse_timestamp(monitor_through)
    required_deadline = parse_timestamp(REQUIRED_THROUGH)
    monitor_ok = bool(
        monitor_id
        and monitor_deadline
        and required_deadline
        and monitor_deadline >= required_deadline
    )
    checks["uptime_monitor"] = status(
        "PASS" if monitor_ok else "BLOCKED",
        detail=(
            "external monitor is active through the required window"
            if monitor_ok
            else "uptime monitor credential/evidence through the required window is missing"
        ),
        evidence={"monitor_id": monitor_id or None, "active_through": monitor_through or None},
    )
    if not monitor_ok:
        blockers.append("uptime monitor evidence through 2026-08-13T07:00:00Z is missing")

    operational_evidence = {
        "restart_policy": (
            "CROSSPATCH_RESTART_POLICY_EVIDENCE",
            "live restart-policy readback",
        ),
        "persistent_token": (
            "CROSSPATCH_TOKEN_PERSISTENCE_EVIDENCE",
            "judge-token persistence across restart",
        ),
        "tls_renewal": (
            "CROSSPATCH_TLS_RENEWAL_EVIDENCE",
            "TLS renewal schedule/readback",
        ),
        "backup_restore": (
            "CROSSPATCH_BACKUP_RESTORE_EVIDENCE",
            "isolated backup/restore drill",
        ),
    }
    if arguments.capture_operational:
        if not public_url or not judge_token or not git_sha or not deployment_git_sha:
            blockers.append(
                "operational capture requires public URL, judge token, and local git SHA"
            )
        else:
            actions = (
                lambda: capture_restart_policy(
                    output_dir=arguments.capture_dir,
                    public_url=public_url,
                    git_sha=deployment_git_sha,
                    compose_project=arguments.compose_project,
                ),
                lambda: capture_persistent_token(
                    output_dir=arguments.capture_dir,
                    public_url=public_url,
                    git_sha=deployment_git_sha,
                    judge_token=judge_token,
                    compose_project=arguments.compose_project,
                    allow_insecure_localhost=arguments.allow_insecure_localhost,
                ),
                lambda: capture_tls_renewal(
                    output_dir=arguments.capture_dir,
                    public_url=public_url,
                    git_sha=deployment_git_sha,
                    compose_project=arguments.compose_project,
                    allow_insecure_localhost=arguments.allow_insecure_localhost,
                ),
                lambda: capture_backup_restore(
                    output_dir=arguments.capture_dir,
                    public_url=public_url,
                    git_sha=deployment_git_sha,
                    compose_project=arguments.compose_project,
                ),
            )
            for action in actions:
                try:
                    receipt = action()
                    captured[receipt.check_id] = receipt
                except (CaptureBlocked, OSError, ValueError, httpx.HTTPError) as error:
                    blockers.append(f"operational capture blocked: {error}")
    for check_name, (environment_name, label) in operational_evidence.items():
        receipt = captured.get(check_name)
        evidence_path = (
            receipt.path if receipt is not None else os.environ.get(environment_name, "").strip()
        )
        checks[check_name] = generated_evidence_check(
            evidence_path,
            label=label,
            contract=OPERATIONAL_EVIDENCE_CONTRACTS[check_name],
            public_url=public_url,
            git_sha=deployment_git_sha,
            captured=receipt,
        )
        if checks[check_name]["status"] != "PASS":
            blockers.append(f"{label} evidence is missing or unverified")

    checks["github_mit_metadata"] = github_api_evidence_check(
        ARTIFACT_DIR / "github-license.json",
        git_sha=git_sha,
    )
    if checks["github_mit_metadata"]["status"] != "PASS":
        blockers.append("authenticated GitHub MIT metadata readback is unverified")

    github_repository = checks["github_mit_metadata"].get("evidence", {}).get("repository")
    checks["github_about_visual"] = github_about_visual_evidence_check(
        os.environ.get("CROSSPATCH_GITHUB_ABOUT_VISUAL_EVIDENCE", "").strip(),
        public_url=public_url,
        git_sha=git_sha,
        repository=github_repository,
    )
    if checks["github_about_visual"]["status"] != "PASS":
        blockers.append("authenticated GitHub About visual readback is missing or unverified")

    required_names = {
        "authenticated_judge_mcp",
        "backup_restore",
        "dns",
        "github_mit_metadata",
        "github_about_visual",
        "persistent_token",
        "private_service_ports_unreachable",
        "public_health",
        "reachable_url",
        "restart_policy",
        "tls",
        "tls_renewal",
        "uptime_monitor",
    }
    verified = all(checks.get(name, {}).get("status") == "PASS" for name in required_names)
    for name, result in checks.items():
        if result.get("status") == "FAIL":
            blockers.append(f"{name}: {result.get('detail')}")
    payload = {
        "schema_version": 1,
        "machine_generated": True,
        "generator": GENERATOR,
        "source": "external DNS, TLS, HTTP, authenticated MCP, and monitor probes",
        "command": (
            "./scripts/verify-hosted.sh --output artifacts/verification/hosted-acceptance.json"
        ),
        "checked_at": utc_now(),
        "git_sha": git_sha,
        "deployment_git_sha": deployment_git_sha,
        "required_through": REQUIRED_THROUGH,
        "status": "VERIFIED" if verified else "BLOCKED",
        "deployment_claimed": verified,
        "public_url": public_url or None,
        "blockers": sorted(set(blockers)),
        "checks": checks,
        "source_sha256": release_source_sha256(),
    }
    atomic_json(arguments.output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if verified else 2


if __name__ == "__main__":
    sys.exit(main())
