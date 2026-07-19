#!/usr/bin/env python3
"""Run local release gates and produce hash-addressable evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

from verification_lib import (
    ARTIFACT_DIR,
    CLAIM_MAP,
    CLAIMS,
    ROOT,
    atomic_json,
    command_result,
    generate_claim_map,
    load_claim_map_base,
    rebind_refreshed_claims,
    sha256_file,
    utc_now,
    validate_claim_inputs,
    verification_artifact,
)

GENERATOR = "scripts/verify-release.sh"
_SIDECAR_TEST_SECRET = "CROSSPATCH_TEST_LIVE_VICTIM_SECRET"
_STRICT_PROJECT_PREFIX = "crosspatch-release-proof-"
_LOCAL_IMAGE_TAGS = (
    "crosspatch-app:local",
    "crosspatch-runner:local",
    "crosspatch-web:local",
)
PUBLIC_BOOTSTRAP_MISSING_ARTIFACTS = frozenset(
    {
        "backend-tests.json",
        "compose-policy.json",
        "frontend-tests.json",
    }
)
STRICT_SECRET_ENVIRONMENT_NAMES = (
    "CROSSPATCH_POSTGRES_PASSWORD",
    "CROSSPATCH_API_POSTGRES_PASSWORD",
    "CROSSPATCH_BROKER_POSTGRES_PASSWORD",
    "CROSSPATCH_EVIDENCE_POSTGRES_PASSWORD",
    "CROSSPATCH_JUDGE_POSTGRES_PASSWORD",
    "CROSSPATCH_VICTIM_POSTGRES_ADMIN_PASSWORD",
    "CROSSPATCH_VICTIM_APP_PASSWORD",
    "CROSSPATCH_VICTIM_CANDIDATE_PASSWORD",
    "CROSSPATCH_VICTIM_WORKER_PASSWORD",
    "CROSSPATCH_VICTIM_ORACLE_PASSWORD",
    "CROSSPATCH_VICTIM_SCOPE_PASSWORD",
    "CROSSPATCH_VERIFICATION_POSTGRES_PASSWORD",
    "CROSSPATCH_OPERATOR_TOKEN",
    "CROSSPATCH_READER_TOKEN",
    "CROSSPATCH_APPROVER_TOKEN",
    "CROSSPATCH_APPROVER_CSRF_TOKEN",
    "CROSSPATCH_APPROVER_STEP_UP_TOKEN",
    "CROSSPATCH_APPROVAL_MAC_KEY",
    "CROSSPATCH_EXPORT_SIGNING_SEED",
    "CROSSPATCH_EVIDENCE_MCP_SIGNING_SECRET",
    "CROSSPATCH_BROKER_MCP_SIGNING_SECRET",
    "CROSSPATCH_JUDGE_MCP_SIGNING_SECRET",
    "CROSSPATCH_RUNNER_TOKEN",
    "CROSSPATCH_CANDIDATE_EXECUTOR_TOKEN",
    "CROSSPATCH_VICTIM_WEBHOOK_SECRET",
)

EnvironmentProvider = Callable[[], dict[str, str]]


def _read_local_image_ids() -> dict[str, str]:
    result = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", *_LOCAL_IMAGE_TAGS],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    values = tuple(line.strip() for line in result.stdout.splitlines() if line.strip())
    if result.returncode != 0 or len(values) != len(_LOCAL_IMAGE_TAGS):
        raise RuntimeError("strict release image identity readback failed")
    image_ids = dict(zip(_LOCAL_IMAGE_TAGS, values, strict=True))
    if any(re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in values):
        raise RuntimeError("strict release image identity readback was invalid")
    return image_ids


def strict_compose_cleanup_command(project_name: str) -> list[str]:
    if re.fullmatch(r"crosspatch-release-proof-[0-9a-f]{12}", project_name) is None:
        raise ValueError("cleanup requires an isolated strict project identity")
    return [
        "docker",
        "compose",
        "--profile",
        "verification",
        "down",
        "--volumes",
        "--remove-orphans",
    ]


class StrictComposeEnvironment:
    """One release-mode Compose identity whose credentials never enter argv/evidence."""

    def __init__(
        self,
        *,
        image_id_reader: Callable[[], dict[str, str]] = _read_local_image_ids,
        project_suffix: str | None = None,
        token_factory: Callable[[int], str] = secrets.token_urlsafe,
    ) -> None:
        suffix = project_suffix or secrets.token_hex(6)
        if re.fullmatch(r"[0-9a-f]{12}", suffix) is None:
            raise ValueError("strict Compose project suffix must be 12 lowercase hex characters")
        self.project_name = f"{_STRICT_PROJECT_PREFIX}{suffix}"
        self._image_id_reader = image_id_reader
        generated: dict[str, str] = {}
        observed: set[str] = set()
        for name in STRICT_SECRET_ENVIRONMENT_NAMES:
            for _attempt in range(16):
                value = token_factory(48)
                if value not in observed:
                    break
            else:
                raise RuntimeError("strict release secret generator repeated values")
            if len(value.encode("utf-8")) < 32 or any(character.isspace() for character in value):
                raise RuntimeError("strict release secret generator returned unsafe material")
            observed.add(value)
            generated[name] = value
        self._redactions = tuple(generated[name] for name in STRICT_SECRET_ENVIRONMENT_NAMES)
        self._base_environment = os.environ.copy()
        self._base_environment.update(
            {
                **generated,
                "COMPOSE_PROFILES": "",
                "COMPOSE_PROJECT_NAME": self.project_name,
                "CROSSPATCH_ALLOWED_ORIGINS": "https://localhost",
                "CROSSPATCH_BIND_ADDRESS": "127.0.0.1",
                "CROSSPATCH_HTTP_PORT": "0",
                "CROSSPATCH_HTTPS_PORT": "0",
                "CROSSPATCH_JUDGE_TOKEN_EXPIRES_AT": "2026-09-01T07:00:00Z",
                "CROSSPATCH_RELEASE_MODE": "1",
                "CROSSPATCH_SITE_ADDRESS": "localhost",
                "OPENAI_API_KEY": "",
                _SIDECAR_TEST_SECRET: generated["CROSSPATCH_VICTIM_WEBHOOK_SECRET"],
            }
        )
        self._resolved_environment: dict[str, str] | None = None

    @property
    def redactions(self) -> tuple[str, ...]:
        return self._redactions

    def environment(self) -> dict[str, str]:
        if self._resolved_environment is None:
            image_ids = self._image_id_reader()
            if set(image_ids) != set(_LOCAL_IMAGE_TAGS):
                raise RuntimeError("strict release image inventory was incomplete")
            for image_id in image_ids.values():
                if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
                    raise RuntimeError("strict release image identity was invalid")
            runner_digest = image_ids["crosspatch-runner:local"].removeprefix("sha256:")
            identity = {
                "compose_sha256": hashlib.sha256((ROOT / "compose.yaml").read_bytes()).hexdigest(),
                "git_sha": git_sha(),
                "image_ids": {tag: image_ids[tag] for tag in sorted(image_ids)},
                "profile": "crosspatch-strict-release-proof-v1",
            }
            environment_digest = hashlib.sha256(
                json.dumps(identity, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ).hexdigest()
            self._resolved_environment = {
                **self._base_environment,
                "CROSSPATCH_ENVIRONMENT_DIGEST": environment_digest,
                "CROSSPATCH_RUNNER_DIGEST": runner_digest,
            }
        return self._resolved_environment.copy()

    def cleanup_environment(self) -> dict[str, str]:
        if self._resolved_environment is not None:
            return self._resolved_environment.copy()
        cleanup_digest = hashlib.sha256(
            f"{self.project_name}:cleanup-only".encode("ascii")
        ).hexdigest()
        return {
            **self._base_environment,
            "CROSSPATCH_ENVIRONMENT_DIGEST": cleanup_digest,
            "CROSSPATCH_RUNNER_DIGEST": cleanup_digest,
        }


def run_group(
    filename: str,
    source: str,
    commands: list[list[str]],
    *,
    command_environments: Mapping[
        int, dict[str, str] | EnvironmentProvider
    ] | None = None,
    redactions: tuple[str, ...] = (),
    stop_on_failure: bool = False,
) -> dict:
    checks: list[dict] = []
    environments = command_environments or {}
    for index, command in enumerate(commands):
        try:
            environment = environments.get(index)
            if callable(environment):
                environment = environment()
        except (OSError, RuntimeError, ValueError) as error:
            message = f"command environment setup failed: {type(error).__name__}"
            combined = f"STDOUT\n\nSTDERR\n{message}".encode()
            checks.append(
                {
                    "command": shlex.join(command),
                    "started_at": utc_now(),
                    "duration_ms": 0,
                    "exit_code": None,
                    "timed_out": False,
                    "status": "FAIL",
                    "stdout": "",
                    "stderr": message,
                    "output_sha256": hashlib.sha256(combined).hexdigest(),
                    "output_bytes": len(combined),
                    "output_truncated": False,
                }
            )
            if stop_on_failure:
                break
            continue
        check = command_result(
            command,
            environment=environment,
            redactions=redactions,
        )
        checks.append(check)
        if stop_on_failure and check.get("status") != "PASS":
            break
    artifact = verification_artifact(
        generator=GENERATOR,
        source=source,
        checks=checks,
        extra={"git_sha": git_sha()},
    )
    atomic_json(ARTIFACT_DIR / filename, artifact)
    return artifact


def git_sha() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=False, capture_output=True, text=True
    )
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else None


def _git_path_list(arguments: list[str]) -> tuple[str, ...]:
    if not arguments:
        raise ValueError("git path-list arguments are required")
    result = subprocess.run(
        ["git", arguments[0], "-z", *arguments[1:]],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError("strict release source identity readback failed")
    try:
        values = tuple(
            item.decode("utf-8")
            for item in result.stdout.split(b"\0")
            if item
        )
    except UnicodeDecodeError as error:
        raise RuntimeError("strict release source path was not UTF-8") from error
    return values


def release_source_changes() -> tuple[str, ...]:
    tracked = _git_path_list(["diff", "--name-only", "--no-renames", "HEAD", "--"])
    untracked = _git_path_list(["ls-files", "--others", "--exclude-standard"])
    return tuple(sorted(set(tracked + untracked)))


def require_clean_release_source(
    *, allowed_prefixes: tuple[str, ...] = ()
) -> None:
    normalized = tuple(prefix.rstrip("/") for prefix in allowed_prefixes)
    blocked = tuple(
        path
        for path in release_source_changes()
        if not any(path == prefix or path.startswith(f"{prefix}/") for prefix in normalized)
    )
    if blocked:
        rendered = ", ".join(blocked[:8])
        if len(blocked) > 8:
            rendered += f", ... ({len(blocked)} paths)"
        raise RuntimeError(
            "strict release requires a commit-bound clean source tree; changed paths: "
            + rendered
        )


def source_integrity_artifact(
    *, allowed_prefixes: tuple[str, ...]
) -> dict[str, object]:
    require_clean_release_source(allowed_prefixes=allowed_prefixes)
    changed = release_source_changes()
    changed_digest = hashlib.sha256(
        "\n".join(changed).encode("utf-8")
    ).hexdigest()
    check = {
        "command": "git source identity vs HEAD excluding generator-owned evidence",
        "duration_ms": 0,
        "exit_code": 0,
        "output_bytes": 0,
        "output_sha256": changed_digest,
        "output_truncated": False,
        "started_at": utc_now(),
        "status": "PASS",
        "stderr": "",
        "stdout": "",
        "timed_out": False,
    }
    return verification_artifact(
        generator=GENERATOR,
        source=(
            "tracked and untracked build source matched Git HEAD; only "
            "verifier-owned generated evidence differed"
        ),
        checks=[check],
        extra={
            "allowed_generated_prefixes": list(allowed_prefixes),
            "git_sha": git_sha(),
            "observed_generated_path_count": len(changed),
            "observed_generated_paths_sha256": changed_digest,
        },
    )


def blocked_supply_chain_provenance(reason_code: str) -> dict:
    checked_at = utc_now()
    common = {
        "checked_at": checked_at,
        "git_sha": git_sha(),
        "machine_generated": True,
        "reason_code": reason_code,
        "schema_version": 1,
        "status": "BLOCKED",
    }
    atomic_json(
        ARTIFACT_DIR / "image-provenance.json",
        {
            **common,
            "generator": "scripts/capture_image_provenance.py",
            "source": "strict image provenance preconditions were not satisfied",
        },
    )
    atomic_json(
        ARTIFACT_DIR / "export-public-key.json",
        {
            **common,
            "generator": "scripts/generate_export_public_key.py",
            "private_seed_included": False,
            "source": "running API signing-key proof preconditions were not satisfied",
        },
    )
    result = {
        **common,
        "generator": GENERATOR,
        "source": "strict supply-chain provenance stage was not executed",
    }
    atomic_json(ARTIFACT_DIR / "supply-chain-provenance.json", result)
    return result


def blocked_immutable_build(reason_code: str) -> dict:
    result = {
        "checked_at": utc_now(),
        "generator": "scripts/build_immutable_images.py",
        "git_sha": git_sha(),
        "machine_generated": True,
        "reason_code": reason_code,
        "schema_version": 1,
        "source": "immutable local image build was not completed",
        "status": "BLOCKED",
    }
    atomic_json(ARTIFACT_DIR / "immutable-build.json", result)
    return result


def demo_readiness_command() -> list[str]:
    evaluator = str(ROOT / "scripts" / "evaluate-demo-readiness.sh")
    current_path = ARTIFACT_DIR / "paced-batches" / "current.json"
    try:
        current = json.loads(current_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return [evaluator]
    batch_id = current.get("batch_id")
    if (
        current.get("status") == "DEMO_READY"
        and isinstance(batch_id, str)
        and batch_id.startswith("paced-")
        and os.path.basename(batch_id) == batch_id
    ):
        return [
            evaluator,
            "--verify-sealed-batch-dir",
            str(ARTIFACT_DIR / "paced-batches" / batch_id),
        ]
    return [evaluator]


def _external_artifact_identity(path: Path) -> tuple[str, int, int] | None:
    try:
        payload = path.read_bytes()
        metadata = path.stat()
    except OSError:
        return None
    return (
        hashlib.sha256(payload).hexdigest(),
        metadata.st_ino,
        metadata.st_mtime_ns,
    )


def _validated_external_artifact(
    filename: str,
    *,
    generator: str,
    allowed_statuses: frozenset[str],
) -> tuple[tuple[str, int, int], str]:
    path = ARTIFACT_DIR / filename
    if path.is_symlink():
        raise RuntimeError(f"external artifact did not produce or validate: {filename}")
    try:
        payload = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"external artifact did not produce or validate: {filename}"
        ) from error
    if (
        not isinstance(payload, dict)
        or payload.get("machine_generated") is not True
        or payload.get("generator") != generator
        or payload.get("status") not in allowed_statuses
        or not isinstance(payload.get("checked_at"), str)
        or not payload["checked_at"]
    ):
        raise RuntimeError(f"external artifact did not produce or validate: {filename}")
    identity = _external_artifact_identity(path)
    if identity is None:
        raise RuntimeError(f"external artifact did not produce or validate: {filename}")
    return identity, payload["status"]


def ensure_external_artifacts() -> tuple[str, ...]:
    environment = os.environ.copy()
    demo_command = demo_readiness_command()
    specifications = (
        (
            demo_command,
            "demo-readiness.json",
            "scripts/evaluate-demo-readiness.sh",
            {0: frozenset({"DEMO_READY"}), 2: frozenset({"DEMO_READINESS_BLOCKED"})},
            "--verify-sealed-batch-dir" in demo_command,
        ),
        (
            [str(ROOT / "scripts" / "verify-github-license.sh")],
            "github-license.json",
            "scripts/verify-github-license.sh",
            {0: frozenset({"API_VERIFIED"}), 2: frozenset({"BLOCKED"})},
            False,
        ),
        (
            [str(ROOT / "scripts" / "verify-hosted.sh")],
            "hosted-acceptance.json",
            "scripts/verify-hosted.sh",
            {0: frozenset({"VERIFIED"}), 2: frozenset({"BLOCKED"})},
            False,
        ),
    )
    refreshed: list[str] = []
    for command, filename, generator, statuses_by_returncode, allow_validated in specifications:
        path = ARTIFACT_DIR / filename
        before = _external_artifact_identity(path)
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            check=False,
        )
        allowed_statuses = statuses_by_returncode.get(result.returncode)
        if allowed_statuses is None:
            raise RuntimeError(f"external artifact generator failed: {filename}")
        after, _status = _validated_external_artifact(
            filename,
            generator=generator,
            allowed_statuses=allowed_statuses,
        )
        if before == after:
            if not allow_validated or result.returncode != 0:
                raise RuntimeError(
                    f"external artifact did not produce or validate: {filename}"
                )
            continue
        refreshed.append(filename)
    return tuple(refreshed)


def load_public_bootstrap_claim_map() -> dict[str, object]:
    commit_count = subprocess.run(
        ["git", "rev-list", "--count", "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if commit_count.returncode != 0 or commit_count.stdout.strip() != "1":
        raise RuntimeError("public bootstrap requires exactly one root source commit")
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if status.returncode != 0 or status.stdout:
        raise RuntimeError("public bootstrap requires a clean source tree")
    try:
        payload = json.loads(CLAIM_MAP.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("public bootstrap claim map is missing or invalid") from error
    claims = payload.get("claims") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != 1
        or not isinstance(claims, list)
    ):
        raise RuntimeError("public bootstrap claim map structure is invalid")
    expected = {
        claim_id: (filename, description)
        for claim_id, filename, description in CLAIMS
    }
    actual = {
        claim.get("claim_id"): claim
        for claim in claims
        if isinstance(claim, dict) and isinstance(claim.get("claim_id"), str)
    }
    if len(actual) != len(claims) or set(actual) != set(expected):
        raise RuntimeError("public bootstrap claim inventory is incomplete")
    missing: set[str] = set()
    for claim_id, (filename, description) in expected.items():
        claim = actual[claim_id]
        if claim.get("artifact_path") != f"artifacts/verification/{filename}":
            raise RuntimeError(f"public bootstrap artifact path mismatch: {claim_id}")
        if claim.get("description") != description:
            raise RuntimeError(f"public bootstrap claim description mismatch: {claim_id}")
        provenance = claim.get("provenance")
        generator = claim.get("generator")
        if (
            not isinstance(generator, str)
            or not generator
            or not isinstance(provenance, dict)
            or provenance.get("kind") != "machine-generated"
            or provenance.get("generator") != generator
        ):
            raise RuntimeError(f"public bootstrap provenance is invalid: {claim_id}")
        artifact = ARTIFACT_DIR / filename
        if not artifact.is_file():
            missing.add(filename)
            continue
        if claim.get("artifact_sha256") != sha256_file(artifact):
            raise RuntimeError(f"public bootstrap artifact hash mismatch: {filename}")
        try:
            artifact_payload = json.loads(artifact.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError(f"public bootstrap artifact is invalid: {filename}") from error
        if not isinstance(artifact_payload, dict) or artifact_payload.get(
            "machine_generated"
        ) is not True:
            raise RuntimeError(f"public bootstrap artifact is not generated: {filename}")
    if missing != set(PUBLIC_BOOTSTRAP_MISSING_ARTIFACTS):
        raise RuntimeError(
            "public bootstrap may omit only the three path-bearing regenerated artifacts"
        )
    return payload


def write_public_bootstrap_provisional_claim_map(
    payload: dict[str, object],
) -> dict[str, object]:
    """Publish a coherent map while bootstrap-only artifacts are absent."""

    claims = payload.get("claims")
    if not isinstance(claims, list):
        raise RuntimeError("public bootstrap claim inventory is invalid")
    retained: list[object] = []
    missing: set[str] = set()
    for claim in claims:
        if not isinstance(claim, dict):
            raise RuntimeError("public bootstrap claim entry is invalid")
        relative = claim.get("artifact_path")
        if not isinstance(relative, str):
            raise RuntimeError("public bootstrap claim artifact path is invalid")
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts:
            raise RuntimeError("public bootstrap claim artifact path is unsafe")
        artifact = ROOT / path
        if artifact.is_file():
            retained.append(claim)
        else:
            missing.add(path.name)
    if missing != set(PUBLIC_BOOTSTRAP_MISSING_ARTIFACTS):
        raise RuntimeError(
            "public bootstrap provisional map has an unexpected missing artifact set"
        )
    provisional = dict(payload)
    provisional["generated_at"] = utc_now()
    provisional["claims"] = retained
    atomic_json(CLAIM_MAP, provisional)
    return provisional


def restore_public_bootstrap_structural_claim_map(
    payload: dict[str, object],
) -> dict[str, object]:
    """Restore the validated full inventory after the keyless self-check."""

    claims = payload.get("claims")
    expected_ids = {claim_id for claim_id, _filename, _description in CLAIMS}
    actual_ids = {
        claim.get("claim_id")
        for claim in claims
        if isinstance(claim, dict) and isinstance(claim.get("claim_id"), str)
    } if isinstance(claims, list) else set()
    if len(actual_ids) != len(CLAIMS) or actual_ids != expected_ids:
        raise RuntimeError("public bootstrap structural claim inventory is incomplete")
    restored = dict(payload)
    atomic_json(CLAIM_MAP, restored)
    return restored


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--public-bootstrap", action="store_true")
    arguments = parser.parse_args()
    if arguments.public_bootstrap and not arguments.strict:
        print("release blocked: public bootstrap requires --strict", file=sys.stderr)
        return 1
    if arguments.strict:
        try:
            require_clean_release_source()
        except RuntimeError as error:
            print(f"strict release blocked: {error}", file=sys.stderr)
            return 1
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    try:
        claim_map_base = (
            load_public_bootstrap_claim_map()
            if arguments.public_bootstrap
            else load_claim_map_base()
        )
    except (RuntimeError, ValueError) as error:
        print(f"release blocked: {error}", file=sys.stderr)
        return 1

    # Contract tests inspect the checked-in external-state artifacts. Refresh
    # their honest BLOCKED/verified state before any suite reads them; strict
    # source integrity permits only this generator-owned evidence.
    try:
        refreshed_artifacts = ensure_external_artifacts()
        claim_map_base = rebind_refreshed_claims(claim_map_base, refreshed_artifacts)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"release blocked: {error}", file=sys.stderr)
        return 1

    results: dict[str, dict] = {}
    codex_dossier_command = [
        "uv",
        "run",
        "--frozen",
        "--extra",
        "dev",
        "python",
        "scripts/verify_codex_collaboration.py",
        "--check",
    ]
    results["codex_collaboration"] = run_group(
        "codex-collaboration.json",
        "privacy-minimized Codex task lineage and current test-receipt validation",
        [codex_dossier_command],
    )
    try:
        claim_map_base = rebind_refreshed_claims(
            claim_map_base,
            ("codex-collaboration.json",),
        )
    except (OSError, ValueError) as error:
        print(f"release blocked: {error}", file=sys.stderr)
        return 1
    results["supply_chain_preflight"] = run_group(
        "supply-chain-preflight.json",
        "deterministic lockfile SBOM and pre-build build-context secret scan",
        [
            [
                "uv",
                "run",
                "--frozen",
                "--extra",
                "dev",
                "python",
                "scripts/generate_sbom.py",
                "--output",
                "artifacts/verification/sbom.cdx.json",
            ],
            [
                "uv",
                "run",
                "--frozen",
                "--extra",
                "dev",
                "python",
                "scripts/scan_build_context.py",
                "--output",
                "artifacts/verification/build-context-secret-scan.json",
            ],
        ],
    )
    supply_chain_preflight_passed = (
        results["supply_chain_preflight"].get("status") == "PASS"
    )
    if arguments.strict and not supply_chain_preflight_passed:
        blocked_immutable_build("SUPPLY_CHAIN_PREFLIGHT_FAILED")
    if arguments.strict and supply_chain_preflight_passed:
        image_setup = command_result(
            [
                "uv",
                "run",
                "--frozen",
                "--extra",
                "dev",
                "python",
                "scripts/build_immutable_images.py",
                "--build-only",
            ]
        )
        if image_setup.get("status") != "PASS":
            blocked_immutable_build("PRECONSUMER_IMAGE_BUILD_FAILED")
            print("strict release blocked: pre-consumer image build failed", file=sys.stderr)
            return 1
    if arguments.public_bootstrap:
        try:
            write_public_bootstrap_provisional_claim_map(claim_map_base)
        except (OSError, RuntimeError, ValueError) as error:
            print(f"release blocked: {error}", file=sys.stderr)
            return 1
    strict_environment = (
        StrictComposeEnvironment()
        if arguments.strict and supply_chain_preflight_passed
        else None
    )
    results["backend"] = run_group(
        "backend-tests.json",
        "fresh locked backend, security, contract, victim, and integration verification",
        [
            [
                "uv",
                "run",
                "--frozen",
                "--extra",
                "dev",
                "ruff",
                "check",
                "backend",
                "victim",
                "scripts",
            ],
            [
                "uv",
                "run",
                "--frozen",
                "--extra",
                "dev",
                "python",
                "-m",
                "pytest",
                "-m",
                "not real_model",
                "--ignore=backend/tests/contract/test_claim_map.py",
                "--cov=backend/src/crosspatch",
                "--cov-report=term-missing",
            ],
            [
                "uv",
                "run",
                "--frozen",
                "--extra",
                "dev",
                "python",
                "scripts/reproducible_adversarial_eval.py",
                "--output",
                "artifacts/verification/adversarial-evaluation.json",
            ],
        ],
    )
    if arguments.public_bootstrap:
        try:
            claim_map_base = restore_public_bootstrap_structural_claim_map(
                claim_map_base
            )
        except (OSError, RuntimeError, ValueError) as error:
            print(f"release blocked: {error}", file=sys.stderr)
            return 1
    results["frontend"] = run_group(
        "frontend-tests.json",
        "fresh locked Next.js unit, static, production, and browser verification",
        [
            ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            ["npm", "--prefix", "web", "run", "lint"],
            ["npm", "--prefix", "web", "run", "typecheck"],
            ["npm", "--prefix", "web", "test", "--", "--run"],
            [
                "uv",
                "run",
                "--frozen",
                "--extra",
                "dev",
                "python",
                "scripts/verify_capture_integrity.py",
            ],
            ["npm", "--prefix", "web", "run", "build"],
            ["npm", "--prefix", "web", "run", "test:e2e"],
        ],
    )
    if arguments.strict:
        try:
            results["source_integrity"] = source_integrity_artifact(
                allowed_prefixes=("artifacts/verification", "docs/CLAIM_MAP.json")
            )
        except RuntimeError as error:
            print(f"strict release blocked: {error}", file=sys.stderr)
            return 1
        atomic_json(
            ARTIFACT_DIR / "source-integrity.json",
            results["source_integrity"],
        )
    compose_commands = [
        [
            "uv",
            "run",
            "--frozen",
            "--extra",
            "dev",
            "python",
            "-m",
            "pytest",
            "backend/tests/contract/test_compose.py",
            "backend/tests/contract/test_docs.py",
            "backend/tests/contract/test_hosted_acceptance.py",
            "backend/tests/security/test_container_policy.py",
            "backend/tests/contract/test_task4_container.py",
            "-q",
        ],
        ["docker", "compose", "config", "--quiet"],
    ]
    compose_environments: dict[int, dict[str, str] | EnvironmentProvider] = {}
    if strict_environment is not None:
        compose_commands.extend(
            [
                [
                    "uv",
                    "run",
                    "--frozen",
                    "--extra",
                    "dev",
                    "python",
                    "scripts/build_immutable_images.py",
                    "--verify-only",
                    "--output",
                    "artifacts/verification/immutable-build.json",
                ],
                ["docker", "compose", "up", "-d", "--wait", "--remove-orphans"],
                ["docker", "compose", "ps", "--format", "json"],
            ]
        )
        compose_environments[len(compose_commands) - 2] = strict_environment.environment
        compose_environments[len(compose_commands) - 1] = strict_environment.environment
    results["compose"] = run_group(
        "compose-policy.json",
        "rendered and optionally live one-command Docker Compose topology",
        compose_commands,
        command_environments=compose_environments,
        redactions=strict_environment.redactions if strict_environment else (),
        stop_on_failure=True,
    )
    compose_passed = results["compose"].get("status") == "PASS"
    results["package"] = run_group(
        "package-build.json",
        "frozen dependency graphs and distributable source/wheel build",
        [
            ["uv", "lock", "--check"],
            [
                "uv",
                "run",
                "--frozen",
                "--extra",
                "dev",
                "python",
                "scripts/verify_package_install.py",
            ],
        ],
    )
    if arguments.strict:
        if supply_chain_preflight_passed and compose_passed:
            blocked_supply_chain_provenance("PROVENANCE_STAGE_NOT_COMPLETED")
            results["supply_chain_provenance"] = run_group(
                "supply-chain-provenance.json",
                "strict deployed image and operational export public-key provenance",
                [
                    [
                        "uv",
                        "run",
                        "--frozen",
                        "--extra",
                        "dev",
                        "python",
                        "scripts/capture_image_provenance.py",
                        "--output",
                        "artifacts/verification/image-provenance.json",
                    ],
                    [
                        "uv",
                        "run",
                        "--frozen",
                        "--extra",
                        "dev",
                        "python",
                        "scripts/generate_export_public_key.py",
                        "--output",
                        "artifacts/verification/export-public-key.json",
                    ],
                ],
                command_environments={
                    0: strict_environment.environment,
                    1: strict_environment.environment,
                },
                redactions=strict_environment.redactions,
                stop_on_failure=True,
            )
        else:
            reason_code = (
                "SUPPLY_CHAIN_PREFLIGHT_FAILED"
                if not supply_chain_preflight_passed
                else "COMPOSE_STAGE_FAILED"
            )
            results["supply_chain_provenance"] = blocked_supply_chain_provenance(
                reason_code
            )
    race_commands = [
        [
            "uv",
            "run",
            "--frozen",
            "--extra",
            "dev",
            "python",
            "-m",
            "pytest",
            "victim/tests/test_race.py",
            "victim/tests/test_worker_retry.py",
            "backend/tests/integration/test_reproduction.py",
            "backend/tests/integration/test_payload_equivalence.py",
            "-q",
        ]
    ]
    if strict_environment is not None and compose_passed:
        race_commands.append(
            [
                "docker",
                "compose",
                "--profile",
                "verification",
                "run",
                "--rm",
                "-T",
                "victim-postgres-verifier",
                "-m",
                "pytest",
                "/opt/crosspatch/tests/victim/test_race.py",
                "/opt/crosspatch/tests/victim/test_worker_retry.py",
                (
                    "/opt/crosspatch/tests/backend/integration/test_reproduction.py"
                    "::test_affected_revision_reproduces_real_duplicate_delivery"
                ),
                (
                    "/opt/crosspatch/tests/backend/integration/"
                    "test_payload_equivalence.py"
                    "::test_affected_revision_rejects_semantically_equivalent_retry"
                ),
                "-q",
            ]
        )
    results["race"] = run_group(
        "race-reproduction.json",
        "real signed HTTP and PostgreSQL bundled-scenario reproduction",
        race_commands,
        command_environments=(
            {1: strict_environment.environment} if len(race_commands) > 1 else {}
        ),
        redactions=strict_environment.redactions if strict_environment else (),
        stop_on_failure=True,
    )
    warrant_commands = [
        [
            "uv",
            "run",
            "--frozen",
            "--extra",
            "dev",
            "python",
            "-m",
            "pytest",
            "backend/tests/unit/test_warrant.py",
            "backend/tests/integration/test_broker.py",
            "backend/tests/integration/test_broker_postgres.py",
            "backend/tests/security/test_broker_policy.py",
            "backend/tests/security/test_candidate_spoof.py",
            "backend/tests/security/test_mcp_boundaries.py",
            "backend/tests/security/test_production_sidecar.py",
            "-q",
        ]
    ]
    if strict_environment is not None and compose_passed:
        warrant_commands.append(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "-e",
                "CROSSPATCH_PRODUCTION_SIDECAR_TEST=1",
                "-e",
                _SIDECAR_TEST_SECRET,
                "runner",
                "/opt/crosspatch/venv/bin/python",
                "-m",
                "pytest",
                "/opt/crosspatch/tests/backend/security/test_production_sidecar.py",
                "-q",
            ]
        )
        warrant_commands.append(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "broker-mcp",
                "/opt/crosspatch/venv/bin/python",
                "/app/backend/tests/security/production_broker_runner_probe.py",
            ]
        )
        warrant_commands.append(
            [
                "docker",
                "compose",
                "--profile",
                "verification",
                "run",
                "--rm",
                "-T",
                "postgres-verifier",
                "-m",
                "pytest",
                "/opt/crosspatch/tests/backend/integration/test_event_store_postgres.py",
                (
                    "/opt/crosspatch/tests/backend/integration/"
                    "test_control_db_hardening_postgres.py"
                ),
                "/opt/crosspatch/tests/backend/integration/test_broker_postgres.py",
                "-q",
            ]
        )
    try:
        results["warrant"] = run_group(
            "warrant-boundary.json",
            (
                "canonical approval, deterministic broker, candidate UID/capability "
                "containment, disposable executor boot replacement, production "
                "Broker-to-runner execution and cleanup, and MCP boundaries"
            ),
            warrant_commands,
            command_environments=(
                {
                    index: strict_environment.environment
                    for index in range(1, len(warrant_commands))
                }
                if strict_environment is not None
                else {}
            ),
            redactions=strict_environment.redactions if strict_environment else (),
            stop_on_failure=True,
        )
    finally:
        if strict_environment is not None:
            results["strict_cleanup"] = run_group(
                "strict-compose-cleanup.json",
                "guarded removal of the isolated release-proof project and fresh volumes",
                [strict_compose_cleanup_command(strict_environment.project_name)],
                command_environments={0: strict_environment.cleanup_environment},
                redactions=strict_environment.redactions,
                stop_on_failure=True,
            )

    results["claim_provenance"] = validate_claim_inputs()
    results["claim_provenance"]["git_sha"] = git_sha()
    atomic_json(
        ARTIFACT_DIR / "claim-provenance.json",
        results["claim_provenance"],
    )
    claim_map = generate_claim_map()
    claim_map_validation = command_result(
        [
            "uv",
            "run",
            "--frozen",
            "--extra",
            "dev",
            "python",
            "-m",
            "pytest",
            "backend/tests/contract/test_claim_map.py",
            "-q",
        ]
    )
    results["public_repository"] = command_result(
        [
            "uv",
            "run",
            "--frozen",
            "--extra",
            "dev",
            "python",
            "scripts/verify_public_repository.py",
        ]
    )
    local_pass = all(
        artifact.get("status") == "PASS" for artifact in results.values()
    ) and claim_map_validation.get("status") == "PASS"
    summary = {
        "schema_version": 1,
        "machine_generated": True,
        "generator": GENERATOR,
        "source": "scripts/release_verifier.py executed local release commands",
        "command": "./scripts/verify-release.sh" + (" --strict" if arguments.strict else ""),
        "checked_at": utc_now(),
        "git_sha": git_sha(),
        "status": "PASS" if local_pass else "FAIL",
        "strict": arguments.strict,
        "local_checks": {
            **{name: value.get("status") for name, value in results.items()},
            "claim_map": claim_map_validation.get("status"),
        },
        "claim_map_validation": claim_map_validation,
        "external_readiness_is_independent": True,
        "claim_count": len(claim_map["claims"]),
    }
    atomic_json(ARTIFACT_DIR / "release-summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if local_pass else 1


if __name__ == "__main__":
    sys.exit(main())
