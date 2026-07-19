#!/usr/bin/env python3
"""Shared primitives for machine-generated CrossPatch release evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_DIR = ROOT / "artifacts" / "verification"
CLAIM_MAP = ROOT / "docs" / "CLAIM_MAP.json"
_MACHINE_HOME_TEXT = re.compile(
    r"(?<![A-Za-z0-9])/(?:Users|home)/[^/\\\s\"']+(?:\\u2026|…)?"
)
_MACHINE_HOME_BYTES = re.compile(_MACHINE_HOME_TEXT.pattern.encode("utf-8"))
_SOURCE_DIGEST_EXCLUDES = frozenset(
    {
        "docs/CLAIM_MAP.json",
    }
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def current_git_sha() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    value = result.stdout.strip().lower()
    if result.returncode != 0 or len(value) != 40 or any(
        character not in "0123456789abcdef" for character in value
    ):
        return None
    return value


def release_source_sha256() -> str | None:
    """Hash tracked release inputs while excluding generated claim evidence."""
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    digest = hashlib.sha256()
    try:
        paths = sorted(
            item.decode("utf-8")
            for item in result.stdout.split(b"\0")
            if item
        )
    except UnicodeDecodeError:
        return None
    for relative in paths:
        if relative in _SOURCE_DIGEST_EXCLUDES or relative.startswith(
            "artifacts/verification/"
        ):
            continue
        path = ROOT / relative
        try:
            content = path.read_bytes()
        except OSError:
            return None
        encoded_path = relative.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def command_result(
    argv: list[str],
    *,
    timeout: int = 1800,
    environment: dict[str, str] | None = None,
    redactions: Iterable[str] = (),
) -> dict[str, Any]:
    started_at = utc_now()
    monotonic_start = time.monotonic()
    try:
        result = subprocess.run(
            argv,
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=False,
            timeout=timeout,
        )
        stdout = result.stdout or b""
        stderr = result.stderr or b""
        exit_code: int | None = result.returncode
        timed_out = False
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        exit_code = None
        timed_out = True
    except OSError as error:
        stdout = b""
        stderr = f"command unavailable: {type(error).__name__}".encode("ascii")
        exit_code = None
        timed_out = False
    redaction_values = tuple(
        value for value in sorted(set(redactions), key=len, reverse=True) if value
    )
    for value in redaction_values:
        encoded = value.encode("utf-8")
        stdout = stdout.replace(encoded, b"[REDACTED]")
        stderr = stderr.replace(encoded, b"[REDACTED]")
    path_redactions = (
        (str(ROOT.resolve()), "[REPOSITORY_ROOT]"),
        (str(Path.home().resolve()), "[USER_HOME]"),
    )
    for value, marker in path_redactions:
        encoded = value.encode("utf-8")
        replacement = marker.encode("ascii")
        stdout = stdout.replace(encoded, replacement)
        stderr = stderr.replace(encoded, replacement)
    stdout = _MACHINE_HOME_BYTES.sub(b"[USER_HOME]", stdout)
    stderr = _MACHINE_HOME_BYTES.sub(b"[USER_HOME]", stderr)
    duration_ms = round((time.monotonic() - monotonic_start) * 1000)
    combined = b"STDOUT\n" + stdout + b"\nSTDERR\n" + stderr
    limit = 96 * 1024
    return {
        "command": _redact_paths(
            _redact_text(shlex.join(argv), redaction_values),
            path_redactions,
        ),
        "started_at": started_at,
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "status": "PASS" if exit_code == 0 and not timed_out else "FAIL",
        "stdout": stdout[-limit:].decode("utf-8", errors="replace"),
        "stderr": stderr[-limit:].decode("utf-8", errors="replace"),
        "output_sha256": sha256_bytes(combined),
        "output_bytes": len(combined),
        "output_truncated": len(stdout) > limit or len(stderr) > limit,
    }


def _redact_text(value: str, redactions: tuple[str, ...]) -> str:
    for secret in redactions:
        value = value.replace(secret, "[REDACTED]")
    return value


def _redact_paths(
    value: str,
    redactions: tuple[tuple[str, str], ...],
) -> str:
    for path, marker in redactions:
        value = value.replace(path, marker)
    return _MACHINE_HOME_TEXT.sub("[USER_HOME]", value)


def verification_artifact(
    *,
    generator: str,
    source: str,
    checks: list[dict[str, Any]],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    passed = bool(checks) and all(check.get("status") == "PASS" for check in checks)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "machine_generated": True,
        "generator": generator,
        "source": source,
        "checked_at": utc_now(),
        "git_sha": current_git_sha(),
        "source_sha256": release_source_sha256(),
        "status": "PASS" if passed else "FAIL",
        "checks": checks,
    }
    if extra:
        payload.update(extra)
    return payload


CLAIMS: tuple[tuple[str, str, str], ...] = (
    (
        "collaboration.codex-provenance",
        "codex-collaboration.json",
        "Real Codex task lineage, repository-slice ownership, and regression receipts",
    ),
    ("release.backend", "backend-tests.json", "Backend, security, contract, and integration suite"),
    (
        "product.specialist-contract",
        "backend-tests.json",
        "Exact five-seat order, models, output schemas, and tool boundaries",
    ),
    (
        "product.fail-closed-abstain",
        "backend-tests.json",
        "Complete Magistrate failure matrix maps to ABSTAIN without execution authority",
    ),
    (
        "product.effort-escalation",
        "backend-tests.json",
        "Bounded reasoning escalation and semantic duplicate rejection",
    ),
    (
        "security.evidence-boundary",
        "adversarial-evaluation.json",
        (
            "Genuine hostile-evidence boundary, sanitizer vectors, authority-tamper "
            "controls, duplicate refusal, and REMAND records"
        ),
    ),
    (
        "runtime.agents-sdk",
        "backend-tests.json",
        "Responses API Agents SDK orchestration, sessions, tracing, handoffs, and guardrails",
    ),
    (
        "runtime.cli-control-plane",
        "backend-tests.json",
        "CLI uses the authenticated API and SSE control plane",
    ),
    (
        "release.claim-provenance",
        "claim-provenance.json",
        "Claim IDs, artifact hashes, checked-in generators, and provenance contracts",
    ),
    (
        "release.frontend",
        "frontend-tests.json",
        "UI tests, lint, typecheck, build, and browser flow",
    ),
    (
        "ui.incident-room",
        "frontend-tests.json",
        (
            "Tracepaper Signal Room, exact specialist rail, recorded-moment feed, "
            "evidence, and approval UI"
        ),
    ),
    ("release.compose", "compose-policy.json", "Rendered service topology and container policy"),
    ("release.package", "package-build.json", "Frozen lock and package build checks"),
    ("runtime.webhook-race", "race-reproduction.json", "Real webhook race and controls"),
    (
        "runtime.warrant-boundary",
        "warrant-boundary.json",
        (
            "Approval, candidate UID/capability containment, disposable executor "
            "lifecycle, and runner checks"
        ),
    ),
    (
        "runtime.human-approval",
        "warrant-boundary.json",
        "Explicit byte-bound human approval precedes Bailiff and broker execution",
    ),
    (
        "runtime.candidate-isolation",
        "warrant-boundary.json",
        "Read-only candidate workspace and trusted external success oracle",
    ),
    (
        "runtime.mcp-zones",
        "warrant-boundary.json",
        "Evidence, Broker, and Judge MCP authority boundaries",
    ),
    (
        "readiness.demo",
        "demo-readiness.json",
        "Genuine fresh-output model-run readiness state with prompt-cache input reads allowed",
    ),
    ("readiness.hosted", "hosted-acceptance.json", "External hosted acceptance state"),
    ("release.github-license", "github-license.json", "GitHub MIT metadata readback state"),
)

_STATE_CLAIM_STATUSES = {
    "readiness.demo": frozenset({"DEMO_READY", "DEMO_READINESS_BLOCKED"}),
    "readiness.hosted": frozenset({"VERIFIED", "BLOCKED"}),
    "release.github-license": frozenset({"API_VERIFIED", "BLOCKED"}),
}

_PROVISIONAL_REQUIRED_CLAIM_IDS = frozenset(
    claim_id
    for claim_id, _filename, _description in CLAIMS
    if claim_id != "collaboration.codex-provenance"
)


def _sealed_demo_cohort(payload: dict[str, Any]) -> dict[str, str]:
    """Bind DEMO_READY evidence to the immutable code cohort that produced it."""

    batch_id = payload.get("batch_id")
    if (
        not isinstance(batch_id, str)
        or not batch_id.startswith("paced-")
        or Path(batch_id).name != batch_id
    ):
        raise ValueError("DEMO_READY artifact is missing a safe paced batch id")
    manifest = ARTIFACT_DIR / "paced-batches" / batch_id / "batch-manifest.json"
    try:
        manifest_bytes = manifest.read_bytes()
        manifest_payload = json.loads(manifest_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("sealed paced batch manifest is missing or invalid") from error
    if not isinstance(manifest_payload, dict):
        raise ValueError("sealed paced batch manifest is not an object")
    git_sha = manifest_payload.get("git_sha")
    if (
        manifest_payload.get("batch_id") != batch_id
        or manifest_payload.get("status") != "DEMO_READY"
        or manifest_payload.get("completed_runs") != 10
        or manifest_payload.get("requested_runs") != 10
        or not isinstance(git_sha, str)
        or len(git_sha) != 40
        or any(character not in "0123456789abcdef" for character in git_sha)
    ):
        raise ValueError("sealed paced batch manifest does not satisfy the gate contract")
    return {
        "batch_id": batch_id,
        "batch_manifest_path": str(manifest.relative_to(ROOT)),
        "batch_manifest_sha256": sha256_bytes(manifest_bytes),
        "disposition": "SEALED_HISTORICAL_ARTIFACT",
        "git_sha": git_sha,
    }


def _claim_binding_errors(
    filename: str,
    payload: dict[str, Any],
    *,
    git_sha: str | None,
    source_sha256: str | None,
) -> list[str]:
    if filename == "demo-readiness.json" and payload.get("status") == "DEMO_READY":
        try:
            _sealed_demo_cohort(payload)
        except ValueError as error:
            return [str(error)]
        return []

    errors: list[str] = []
    if not _artifact_git_sha_matches_current(payload.get("git_sha"), git_sha):
        errors.append("artifact git_sha does not match current HEAD")
    if source_sha256 is None or payload.get("source_sha256") != source_sha256:
        errors.append("artifact source_sha256 does not match the release source tree")
    return errors


def _artifact_git_sha_matches_current(
    artifact_git_sha: object,
    current_git_sha: object,
) -> bool:
    """Accept exact HEAD or a source-identical evidence-only ancestor."""

    def valid_sha(value: object) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 40
            and all(character in "0123456789abcdef" for character in value)
        )

    if not valid_sha(artifact_git_sha) or not valid_sha(current_git_sha):
        return False
    if artifact_git_sha == current_git_sha:
        return True

    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", artifact_git_sha, current_git_sha],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if ancestor.returncode != 0:
        return False
    changed = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            "--no-renames",
            f"{artifact_git_sha}..{current_git_sha}",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if changed.returncode != 0:
        return False
    paths = [path for path in changed.stdout.splitlines() if path]
    return bool(paths) and all(
        path == "docs/CLAIM_MAP.json"
        or path.startswith("artifacts/verification/")
        for path in paths
    )


def validate_claim_inputs() -> dict[str, Any]:
    """Validate every non-self claim artifact before publishing the claim map."""

    expected: dict[str, set[str]] = {}
    for claim_id, filename, _description in CLAIMS:
        if claim_id == "release.claim-provenance":
            continue
        expected.setdefault(filename, set()).update(
            _STATE_CLAIM_STATUSES.get(claim_id, frozenset({"PASS"}))
        )

    git_sha = current_git_sha()
    source_sha256 = release_source_sha256()
    checks: list[dict[str, Any]] = []
    for filename in sorted(expected):
        artifact = ARTIFACT_DIR / filename
        errors: list[str] = []
        payload: dict[str, Any] | None = None
        artifact_sha256: str | None = None
        try:
            artifact_bytes = artifact.read_bytes()
            artifact_sha256 = sha256_bytes(artifact_bytes)
            candidate = json.loads(artifact_bytes)
            if isinstance(candidate, dict):
                payload = candidate
            else:
                errors.append("artifact JSON is not an object")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            errors.append("artifact is missing or invalid JSON")

        if payload is not None:
            if payload.get("machine_generated") is not True:
                errors.append("artifact is not machine-generated")
            if payload.get("status") not in expected[filename]:
                errors.append("artifact status is not allowed for its registered claims")
            generator = payload.get("generator")
            if not isinstance(generator, str) or not generator.startswith("scripts/"):
                errors.append("artifact generator is not a checked-in script path")
            else:
                generator_path = Path(generator)
                if generator_path.is_absolute() or ".." in generator_path.parts:
                    errors.append("artifact generator path is unsafe")
                else:
                    resolved_generator = ROOT / generator_path
                    if not resolved_generator.is_file() or not os.access(
                        resolved_generator, os.X_OK
                    ):
                        errors.append("artifact generator is missing or not executable")
            for field in ("checked_at", "source"):
                value = payload.get(field)
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"artifact {field} is missing")
            errors.extend(
                _claim_binding_errors(
                    filename,
                    payload,
                    git_sha=git_sha,
                    source_sha256=source_sha256,
                )
            )

        checks.append(
            {
                "artifact_path": f"artifacts/verification/{filename}",
                "artifact_sha256": artifact_sha256,
                "command": f"validate registered claim input {filename}",
                "duration_ms": 0,
                "errors": errors,
                "exit_code": 0 if not errors else 1,
                "output_bytes": 0,
                "output_sha256": sha256_bytes("\n".join(errors).encode("utf-8")),
                "output_truncated": False,
                "started_at": utc_now(),
                "status": "PASS" if not errors else "FAIL",
                "stderr": "",
                "stdout": "",
                "timed_out": False,
            }
        )
    return verification_artifact(
        generator="scripts/verify-release.sh",
        source=(
            "registered claim inputs, allowed statuses, artifact hashes, and "
            "checked-in executable generators"
        ),
        checks=checks,
    )


def _claim_entry(
    claim_id: str,
    filename: str,
    description: str,
    *,
    git_sha: str | None,
    source_sha256: str | None,
) -> dict[str, Any] | None:
    artifact = ARTIFACT_DIR / filename
    try:
        artifact_bytes = artifact.read_bytes()
        payload = json.loads(artifact_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not artifact_bytes or not isinstance(payload, dict):
        return None
    if payload.get("machine_generated") is not True:
        return None
    artifact_status = payload.get("status")
    allowed_statuses = _STATE_CLAIM_STATUSES.get(claim_id, frozenset({"PASS"}))
    if artifact_status not in allowed_statuses:
        return None
    if _claim_binding_errors(
        filename,
        payload,
        git_sha=git_sha,
        source_sha256=source_sha256,
    ):
        return None
    generator = payload.get("generator")
    generated_at = payload.get("checked_at")
    source = payload.get("source")
    if not all(
        isinstance(value, str) and value
        for value in (generator, generated_at, source)
    ):
        return None
    command = payload.get("command")
    if not isinstance(command, str) or not command:
        checks = payload.get("checks")
        if isinstance(checks, list) and checks and isinstance(checks[0], dict):
            command = str(checks[0].get("command") or source)
        else:
            command = source
    provenance: dict[str, Any] = {
        "kind": "machine-generated",
        "generator": generator,
        "command": command,
        "source": source,
        "generated_at": generated_at,
    }
    if claim_id == "readiness.demo" and artifact_status == "DEMO_READY":
        provenance["sealed_cohort"] = _sealed_demo_cohort(payload)
    return {
        "claim_id": claim_id,
        "description": description,
        "artifact_path": str(artifact.relative_to(ROOT)),
        "artifact_sha256": sha256_bytes(artifact_bytes),
        "artifact_status": artifact_status,
        "generator": generator,
        "provenance": provenance,
    }


def _checked_in_claim_map_bytes() -> bytes:
    try:
        relative = CLAIM_MAP.relative_to(ROOT).as_posix()
    except ValueError as error:
        raise ValueError("checked-in claim map path escapes the repository") from error
    result = subprocess.run(
        ["git", "show", f"HEAD:{relative}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0 or not result.stdout:
        raise ValueError("checked-in claim map is absent from HEAD")
    return result.stdout


def load_claim_map_base() -> dict[str, Any]:
    try:
        claim_map_bytes = CLAIM_MAP.read_bytes()
        checked_in_bytes = _checked_in_claim_map_bytes()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("checked-in claim map is missing or invalid JSON") from error
    if CLAIM_MAP.is_symlink() or claim_map_bytes != checked_in_bytes:
        raise ValueError("checked-in claim map bytes do not match HEAD")
    try:
        candidate = json.loads(claim_map_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("checked-in claim map is missing or invalid JSON") from error
    if not isinstance(candidate, dict):
        raise ValueError("checked-in claim map is not an object")
    if candidate.get("schema_version") != 1:
        raise ValueError("checked-in claim map has an invalid schema version")
    if candidate.get("generator") != "scripts/verify-release.sh":
        raise ValueError("checked-in claim map has an invalid generator")
    generated_at = candidate.get("generated_at")
    if not isinstance(generated_at, str) or not generated_at:
        raise ValueError("checked-in claim map has no generation time")
    claims = candidate.get("claims")
    if not isinstance(claims, list) or not claims:
        raise ValueError("checked-in claim map has no claims")

    registry = {
        claim_id: (filename, description)
        for claim_id, filename, description in CLAIMS
    }
    observed: set[str] = set()
    for claim in claims:
        if not isinstance(claim, dict):
            raise ValueError("checked-in claim map contains a non-object claim")
        claim_id = claim.get("claim_id")
        if not isinstance(claim_id, str) or claim_id not in registry:
            raise ValueError("checked-in claim map contains an unknown claim")
        if claim_id in observed:
            raise ValueError("checked-in claim map contains a duplicate claim")
        observed.add(claim_id)
        filename, _description = registry[claim_id]
        expected_artifact_path = f"artifacts/verification/{filename}"
        if claim.get("artifact_path") != expected_artifact_path:
            raise ValueError("checked-in claim map contains an invalid artifact path")
        if not isinstance(claim.get("description"), str) or not claim["description"]:
            raise ValueError("checked-in claim map contains an invalid description")
        artifact_sha256 = claim.get("artifact_sha256")
        if (
            not isinstance(artifact_sha256, str)
            or len(artifact_sha256) != 64
            or any(character not in "0123456789abcdef" for character in artifact_sha256)
        ):
            raise ValueError("checked-in claim map contains an invalid artifact hash")
        if not isinstance(claim.get("artifact_status"), str):
            raise ValueError("checked-in claim map contains an invalid artifact status")
        if not isinstance(claim.get("generator"), str):
            raise ValueError("checked-in claim map contains an invalid claim generator")
        if not isinstance(claim.get("provenance"), dict):
            raise ValueError("checked-in claim map contains invalid provenance")

        artifact = ROOT / expected_artifact_path
        if artifact.is_symlink():
            raise ValueError("checked-in claim map artifact must not be a symlink")
        try:
            artifact_bytes = artifact.read_bytes()
            artifact_payload = json.loads(artifact_bytes)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("checked-in claim map artifact is missing or invalid") from error
        if not isinstance(artifact_payload, dict):
            raise ValueError("checked-in claim map artifact is not an object")
        if sha256_bytes(artifact_bytes) != artifact_sha256:
            raise ValueError("checked-in claim map contains an artifact hash drift")
        if artifact_payload.get("machine_generated") is not True:
            raise ValueError("checked-in claim map artifact is not machine-generated")
        if artifact_payload.get("status") != claim.get("artifact_status"):
            raise ValueError("checked-in claim map contains an artifact status drift")

        generator = claim["generator"]
        generator_path = Path(generator)
        if generator_path.is_absolute() or ".." in generator_path.parts:
            raise ValueError("checked-in claim map contains an unsafe generator")
        resolved_generator = ROOT / generator_path
        if (
            resolved_generator.is_symlink()
            or not resolved_generator.is_file()
            or not os.access(resolved_generator, os.X_OK)
        ):
            raise ValueError("checked-in claim map generator is missing or not executable")
        if artifact_payload.get("generator") != generator:
            raise ValueError("checked-in claim map contains an artifact generator drift")

        provenance = claim["provenance"]
        expected_provenance = {
            "generator": generator,
            "generated_at": artifact_payload.get("checked_at"),
            "source": artifact_payload.get("source"),
        }
        if provenance.get("kind") != "machine-generated" or any(
            provenance.get(field) != value
            for field, value in expected_provenance.items()
        ):
            raise ValueError("checked-in claim map contains provenance drift")
        if not isinstance(provenance.get("command"), str) or not provenance["command"]:
            raise ValueError("checked-in claim map contains invalid provenance command")
    missing = _PROVISIONAL_REQUIRED_CLAIM_IDS - observed
    if missing:
        raise ValueError(
            "checked-in claim map is incomplete: " + ", ".join(sorted(missing))
        )
    return candidate


def rebind_refreshed_claims(
    base: dict[str, Any],
    refreshed_filenames: Iterable[str],
) -> dict[str, Any]:
    refreshed = frozenset(refreshed_filenames)
    registered_filenames = {filename for _claim_id, filename, _description in CLAIMS}
    if not refreshed or not refreshed <= registered_filenames:
        raise ValueError("refreshed claim artifact inventory is empty or invalid")

    git_sha = current_git_sha()
    source_sha256 = release_source_sha256()
    registry = {
        claim_id: (filename, description)
        for claim_id, filename, description in CLAIMS
    }
    claims: list[dict[str, Any]] = []
    rebound_filenames: set[str] = set()
    for retained in base["claims"]:
        claim_id = retained["claim_id"]
        filename, description = registry[claim_id]
        if filename not in refreshed:
            claims.append(retained)
            continue
        rebound = _claim_entry(
            claim_id,
            filename,
            description,
            git_sha=git_sha,
            source_sha256=source_sha256,
        )
        if rebound is None:
            raise ValueError(f"refreshed claim artifact failed binding: {filename}")
        claims.append(rebound)
        rebound_filenames.add(filename)
    missing = refreshed - rebound_filenames
    if missing:
        raise ValueError(
            "refreshed claim artifacts are absent from the checked-in map: "
            + ", ".join(sorted(missing))
        )

    payload = dict(base)
    payload["generated_at"] = utc_now()
    payload["claims"] = claims
    atomic_json(CLAIM_MAP, payload)
    return payload


def generate_claim_map() -> dict[str, Any]:
    git_sha = current_git_sha()
    source_sha256 = release_source_sha256()
    claims = [
        entry
        for claim_id, filename, description in CLAIMS
        if (
            entry := _claim_entry(
                claim_id,
                filename,
                description,
                git_sha=git_sha,
                source_sha256=source_sha256,
            )
        )
        is not None
    ]
    payload = {
        "schema_version": 1,
        "generated_at": utc_now(),
        "generator": "scripts/verify-release.sh",
        "claims": claims,
    }
    atomic_json(CLAIM_MAP, payload)
    return payload
