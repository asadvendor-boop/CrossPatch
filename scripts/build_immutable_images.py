#!/usr/bin/env python3
"""Build every local Compose image from one preflight-bound tar snapshot."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from scan_build_context import GENERATOR as SCAN_GENERATOR
from scan_build_context import _DockerIgnore, _included_files
from verification_lib import ROOT, atomic_json

GENERATOR = "scripts/build_immutable_images.py"
CONTEXT_MANIFEST_LABEL = "org.crosspatch.build.context-manifest-sha256"
CONTEXT_TAR_LABEL = "org.crosspatch.build.context-tar-sha256"
SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
BUILD_TARGETS = (
    ("Dockerfile", "python-runtime", "crosspatch-app:local"),
    ("infra/runner/Dockerfile", "runner", "crosspatch-runner:local"),
    ("Dockerfile", "web-runtime", "crosspatch-web:local"),
)


class ImmutableBuildError(RuntimeError):
    pass


class _Result(Protocol):
    returncode: int
    stdout: str


Run = Callable[..., _Result]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ImmutableBuildError("immutable-build timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _preflight_manifest(root: Path) -> str:
    path = root / "artifacts" / "verification" / "build-context-secret-scan.json"
    try:
        evidence = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ImmutableBuildError("preflight evidence is unavailable or invalid") from error
    if (
        not isinstance(evidence, dict)
        or evidence.get("status") != "PASS"
        or evidence.get("machine_generated") is not True
        or evidence.get("generator") != SCAN_GENERATOR
        or evidence.get("schema_version") != 1
    ):
        raise ImmutableBuildError("preflight evidence is not a trusted pass")
    manifest = evidence.get("build_context_manifest_sha256")
    if not isinstance(manifest, str) or not SHA256_HEX.fullmatch(manifest):
        raise ImmutableBuildError("preflight manifest SHA-256 is invalid")
    return manifest


def _snapshot_context(root: Path, destination: Path, expected_manifest: str) -> str:
    matcher = _DockerIgnore.load(root / ".dockerignore")
    manifest = hashlib.sha256()
    with tarfile.open(destination, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for path in _included_files(root, matcher):
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise ImmutableBuildError("immutable context contains a non-regular file")
            payload = path.read_bytes()
            digest = hashlib.sha256(payload).hexdigest()
            manifest.update(relative.encode("utf-8") + b"\0" + digest.encode("ascii") + b"\n")
            member = tarfile.TarInfo(relative)
            member.gid = 0
            member.gname = ""
            member.mode = stat.S_IMODE(metadata.st_mode)
            member.mtime = 0
            member.size = len(payload)
            member.uid = 0
            member.uname = ""
            archive.addfile(member, io.BytesIO(payload))
    if manifest.hexdigest() != expected_manifest:
        raise ImmutableBuildError("immutable context does not match the preflight manifest")
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def build_images(
    root: Path = ROOT,
    *,
    run: Run = subprocess.run,
    checked_at: Callable[[], datetime] = _utc_now,
) -> dict[str, Any]:
    resolved = root.resolve(strict=True)
    manifest = _preflight_manifest(resolved)
    with tempfile.TemporaryDirectory(prefix="crosspatch-build-context-") as directory:
        context_tar = Path(directory) / "context.tar"
        context_tar.touch(mode=0o600)
        tar_sha256 = _snapshot_context(resolved, context_tar, manifest)
        context_bytes = context_tar.read_bytes()
        if hashlib.sha256(context_bytes).hexdigest() != tar_sha256:
            raise ImmutableBuildError("immutable context changed before Docker build")
        for dockerfile, target, tag in BUILD_TARGETS:
            command = [
                "docker",
                "build",
                "--file",
                dockerfile,
                "--target",
                target,
                "--tag",
                tag,
                "--label",
                f"{CONTEXT_MANIFEST_LABEL}={manifest}",
                "--label",
                f"{CONTEXT_TAR_LABEL}={tar_sha256}",
                "-",
            ]
            result = run(command, cwd=resolved, check=False, input=context_bytes)
            if result.returncode != 0:
                raise ImmutableBuildError(f"immutable Docker build failed for {tag}")
    return {
        "build_context_manifest_sha256": manifest,
        "build_context_tar_sha256": tar_sha256,
        "checked_at": _timestamp(checked_at()),
        "generator": GENERATOR,
        "images": [
            {"dockerfile": dockerfile, "tag": tag, "target": target}
            for dockerfile, target, tag in BUILD_TARGETS
        ],
        "machine_generated": True,
        "schema_version": 1,
        "source": "one immutable tar snapshot supplied to every local Docker image build",
        "status": "PASS",
    }


def verify_images(
    root: Path = ROOT,
    *,
    run: Run = subprocess.run,
    snapshot: Callable[[Path, Path, str], str] = _snapshot_context,
    checked_at: Callable[[], datetime] = _utc_now,
) -> dict[str, Any]:
    resolved = root.resolve(strict=True)
    manifest = _preflight_manifest(resolved)
    with tempfile.TemporaryDirectory(prefix="crosspatch-build-context-") as directory:
        context_tar = Path(directory) / "context.tar"
        context_tar.touch(mode=0o600)
        tar_sha256 = snapshot(resolved, context_tar, manifest)
    for _dockerfile, _target, tag in BUILD_TARGETS:
        result = run(
            ["docker", "image", "inspect", tag],
            cwd=resolved,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ImmutableBuildError(f"prebuilt Docker image is unavailable: {tag}")
        try:
            images = json.loads(result.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ImmutableBuildError("prebuilt Docker image inspection was invalid") from error
        if not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], dict):
            raise ImmutableBuildError("prebuilt Docker image inspection was ambiguous")
        image = images[0]
        config = image.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        if (
            not isinstance(labels, dict)
            or labels.get(CONTEXT_MANIFEST_LABEL) != manifest
            or labels.get(CONTEXT_TAR_LABEL) != tar_sha256
        ):
            raise ImmutableBuildError("prebuilt Docker image has invalid immutable context labels")
        image_id = image.get("Id")
        if not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None:
            raise ImmutableBuildError("prebuilt Docker image identity was invalid")
    return {
        "build_context_manifest_sha256": manifest,
        "build_context_tar_sha256": tar_sha256,
        "checked_at": _timestamp(checked_at()),
        "generator": GENERATOR,
        "images": [
            {"dockerfile": dockerfile, "tag": tag, "target": target}
            for dockerfile, target, tag in BUILD_TARGETS
        ],
        "machine_generated": True,
        "schema_version": 1,
        "source": "preflight-bound label readback from every prebuilt local Docker image",
        "status": "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--build-only", action="store_true")
    mode.add_argument("--verify-only", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "verification" / "immutable-build.json",
    )
    arguments = parser.parse_args()
    try:
        result = verify_images(ROOT) if arguments.verify_only else build_images(ROOT)
    except (OSError, ValueError, ImmutableBuildError, subprocess.SubprocessError) as error:
        if arguments.build_only:
            print(f"immutable image setup failed: {type(error).__name__}", file=sys.stderr)
            return 1
        result = {
            "checked_at": _timestamp(_utc_now()),
            "error": type(error).__name__,
            "generator": GENERATOR,
            "machine_generated": True,
            "schema_version": 1,
            "source": "immutable local image build was unavailable or inconsistent",
            "status": "FAIL",
        }
        atomic_json(arguments.output, result)
        return 1
    if arguments.build_only:
        return 0
    atomic_json(arguments.output, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
