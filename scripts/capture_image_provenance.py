#!/usr/bin/env python3
"""Capture deployed Compose container image identities without environment data."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from build_immutable_images import (
    BUILD_TARGETS,
    CONTEXT_MANIFEST_LABEL,
    CONTEXT_TAR_LABEL,
)
from build_immutable_images import GENERATOR as IMMUTABLE_BUILD_GENERATOR
from scan_build_context import GENERATOR as SCAN_GENERATOR
from scan_build_context import scan_context
from verification_lib import ROOT, atomic_json

GENERATOR = "scripts/capture_image_provenance.py"
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
REPO_DIGEST = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
LOCAL_IMAGE_TAGS = frozenset(tag for _dockerfile, _target, tag in BUILD_TARGETS)


class ProvenanceError(RuntimeError):
    pass


class _Result(Protocol):
    stdout: str
    stderr: str
    returncode: int


Run = Callable[..., _Result]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ProvenanceError("image provenance timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _run_checked(run: Run, argv: list[str], root: Path) -> str:
    result = run(
        argv,
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ProvenanceError(f"command failed without trusted readback: {' '.join(argv[:3])}")
    return result.stdout


def _json_list(value: str, *, label: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(value)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ProvenanceError(f"{label} was not JSON") from error
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise ProvenanceError(f"{label} must be a JSON array")
    return payload


def _git_sha(root: Path, run: Run) -> str:
    value = _run_checked(run, ["git", "rev-parse", "HEAD"], root).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ProvenanceError("Git SHA readback is invalid")
    return value


def _build_context_evidence(root: Path) -> tuple[str, str]:
    evidence_path = root / "artifacts" / "verification" / "build-context-secret-scan.json"
    try:
        evidence_bytes = evidence_path.read_bytes()
        evidence = json.loads(evidence_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvenanceError(
            "build-context secret-scan evidence is unavailable or invalid"
        ) from error
    if (
        not isinstance(evidence, dict)
        or evidence.get("status") != "PASS"
        or evidence.get("machine_generated") is not True
        or evidence.get("generator") != SCAN_GENERATOR
        or evidence.get("schema_version") != 1
    ):
        raise ProvenanceError("build-context secret-scan evidence is not a trusted pass")
    manifest = evidence.get("build_context_manifest_sha256")
    if not isinstance(manifest, str) or not SHA256_HEX.fullmatch(manifest):
        raise ProvenanceError("build-context manifest SHA-256 is invalid")
    current = scan_context(root)
    if current.get("status") != "PASS":
        raise ProvenanceError("current build context failed the secret scan")
    if current.get("build_context_manifest_sha256") != manifest:
        raise ProvenanceError("build context changed after the preflight scan")
    return manifest, hashlib.sha256(evidence_bytes).hexdigest()


def _immutable_build_evidence(root: Path, context_manifest: str) -> tuple[str, str]:
    path = root / "artifacts" / "verification" / "immutable-build.json"
    try:
        evidence_bytes = path.read_bytes()
        evidence = json.loads(evidence_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvenanceError("immutable build evidence is unavailable or invalid") from error
    expected_images = [
        {"dockerfile": dockerfile, "tag": tag, "target": target}
        for dockerfile, target, tag in BUILD_TARGETS
    ]
    if (
        not isinstance(evidence, dict)
        or evidence.get("status") != "PASS"
        or evidence.get("machine_generated") is not True
        or evidence.get("generator") != IMMUTABLE_BUILD_GENERATOR
        or evidence.get("schema_version") != 1
        or evidence.get("build_context_manifest_sha256") != context_manifest
        or evidence.get("images") != expected_images
    ):
        raise ProvenanceError("immutable build evidence is not a trusted matching pass")
    tar_sha256 = evidence.get("build_context_tar_sha256")
    if not isinstance(tar_sha256, str) or not SHA256_HEX.fullmatch(tar_sha256):
        raise ProvenanceError("immutable build evidence tar SHA-256 is invalid")
    return tar_sha256, hashlib.sha256(evidence_bytes).hexdigest()


def capture_image_provenance(
    root: Path = ROOT,
    *,
    run: Run = subprocess.run,
    checked_at: Callable[[], datetime] = _utc_now,
) -> dict[str, Any]:
    resolved = root.resolve(strict=True)
    compose_path = resolved / "compose.yaml"
    if not compose_path.is_file():
        raise ProvenanceError("compose.yaml is unavailable")
    context_manifest, context_evidence_sha256 = _build_context_evidence(resolved)

    services = tuple(
        line.strip()
        for line in _run_checked(
            run, ["docker", "compose", "ps", "--all", "--services"], resolved
        ).splitlines()
        if line.strip()
    )
    container_ids = tuple(
        line.strip()
        for line in _run_checked(
            run, ["docker", "compose", "ps", "--all", "-q"], resolved
        ).splitlines()
        if line.strip()
    )
    if not services or len(services) != len(set(services)):
        raise ProvenanceError("Compose service readback is empty or duplicated")
    if not container_ids or len(container_ids) != len(set(container_ids)):
        raise ProvenanceError("Compose container readback is empty or duplicated")

    containers = _json_list(
        _run_checked(
            run,
            ["docker", "inspect", "--type", "container", *container_ids],
            resolved,
        ),
        label="container inspection",
    )
    if len(containers) != len(container_ids):
        raise ProvenanceError("container inspection count changed during readback")

    by_service: dict[str, dict[str, Any]] = {}
    image_ids: set[str] = set()
    for container in containers:
        config = container.get("Config")
        state = container.get("State")
        if not isinstance(config, dict) or not isinstance(state, dict):
            raise ProvenanceError("container inspection omitted config or state")
        labels = config.get("Labels")
        service = labels.get("com.docker.compose.service") if isinstance(labels, dict) else None
        if not isinstance(service, str) or not service or service in by_service:
            raise ProvenanceError("container inspection has an invalid Compose service label")
        status = state.get("Status")
        exit_code = state.get("ExitCode")
        running = status == "running"
        successful_one_shot = status == "exited" and exit_code == 0
        if not running and not successful_one_shot:
            raise ProvenanceError(
                f"service {service} is not a healthy running or successful one-shot container"
            )
        health = state.get("Health")
        if running and isinstance(health, dict) and health.get("Status") != "healthy":
            raise ProvenanceError(f"service {service} has no healthy container readback")
        image_id = container.get("Image")
        if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
            raise ProvenanceError(f"service {service} image ID is invalid")
        container_id = container.get("Id")
        configured_image = config.get("Image")
        if not isinstance(container_id, str) or not container_id:
            raise ProvenanceError(f"service {service} container ID is invalid")
        if not isinstance(configured_image, str) or not configured_image:
            raise ProvenanceError(f"service {service} configured image is invalid")
        by_service[service] = {
            "configured_image": configured_image,
            "container_id": container_id,
            "exit_code": exit_code,
            "image_id": image_id,
            "state": status,
        }
        image_ids.add(image_id)

    if set(services) != set(by_service):
        raise ProvenanceError("Compose services and inspected containers do not match")

    images = _json_list(
        _run_checked(
            run,
            ["docker", "image", "inspect", *sorted(image_ids)],
            resolved,
        ),
        label="image inspection",
    )
    image_metadata: dict[str, dict[str, Any]] = {}
    for image in images:
        image_id = image.get("Id")
        digests = image.get("RepoDigests")
        if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
            raise ProvenanceError("image inspection returned an invalid image ID")
        if digests is None:
            digests = []
        if not isinstance(digests, list) or not all(
            isinstance(digest, str) and REPO_DIGEST.fullmatch(digest) for digest in digests
        ):
            raise ProvenanceError(f"image {image_id} repository digests are invalid")
        config = image.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        if labels is None:
            labels = {}
        if not isinstance(labels, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in labels.items()
        ):
            raise ProvenanceError(f"image {image_id} labels are invalid")
        image_metadata[image_id] = {
            "labels": labels,
            "repo_digests": tuple(sorted(set(digests))),
        }
    if set(image_metadata) != image_ids:
        raise ProvenanceError("deployed image IDs and image inspection do not match")

    expected_tar_sha256, immutable_evidence_sha256 = _immutable_build_evidence(
        resolved, context_manifest
    )
    local_tags: set[str] = set()
    context_tar_hashes: set[str] = set()
    records = []
    for service in sorted(by_service):
        record = by_service[service]
        metadata = image_metadata[record["image_id"]]
        if record["configured_image"] in LOCAL_IMAGE_TAGS:
            labels = metadata["labels"]
            tar_sha256 = labels.get(CONTEXT_TAR_LABEL)
            if labels.get(CONTEXT_MANIFEST_LABEL) != context_manifest:
                raise ProvenanceError(
                    f"service {service} image build-context labels are missing or invalid"
                )
            if tar_sha256 != expected_tar_sha256:
                raise ProvenanceError(
                    f"service {service} image does not match immutable build evidence"
                )
            local_tags.add(record["configured_image"])
            context_tar_hashes.add(tar_sha256)
            record = {
                **record,
                "build_context_manifest_sha256": context_manifest,
                "build_context_tar_sha256": tar_sha256,
            }
        records.append(
            {
                **record,
                "repo_digests": list(metadata["repo_digests"]),
                "service": service,
            }
        )
    if local_tags != LOCAL_IMAGE_TAGS or len(context_tar_hashes) != 1:
        raise ProvenanceError("deployed local images do not share one immutable build context")
    context_tar_sha256 = next(iter(context_tar_hashes))
    manifest_bytes = json.dumps(
        records,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return {
        "build_context_evidence_sha256": context_evidence_sha256,
        "build_context_manifest_sha256": context_manifest,
        "build_context_tar_sha256": context_tar_sha256,
        "checked_at": _timestamp(checked_at()),
        "compose_file_sha256": hashlib.sha256(compose_path.read_bytes()).hexdigest(),
        "deployment_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "generator": GENERATOR,
        "git_sha": _git_sha(resolved, run),
        "immutable_build_evidence_sha256": immutable_evidence_sha256,
        "machine_generated": True,
        "schema_version": 1,
        "services": records,
        "source": "docker inspect readback of the deployed Compose containers and images",
        "status": "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "verification" / "image-provenance.json",
    )
    arguments = parser.parse_args()
    try:
        result = capture_image_provenance(ROOT)
    except (OSError, ValueError, ProvenanceError, subprocess.SubprocessError) as error:
        result = {
            "checked_at": _timestamp(_utc_now()),
            "error": type(error).__name__,
            "generator": GENERATOR,
            "machine_generated": True,
            "schema_version": 1,
            "source": "Docker Compose image readback was unavailable or inconsistent",
            "status": "FAIL",
        }
        atomic_json(arguments.output, result)
        return 1
    atomic_json(arguments.output, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
