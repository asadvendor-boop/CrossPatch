#!/usr/bin/env python3
"""Derive warrant-bound release digests from the built local image identities."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from verification_lib import ROOT

IMAGE_TAGS = (
    "crosspatch-app:local",
    "crosspatch-runner:local",
    "crosspatch-web:local",
)
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
PROFILE = "crosspatch-hosted-release-v1"


class ReleaseIdentityError(RuntimeError):
    pass


def _command(argv: list[str], *, root: Path) -> str:
    result = subprocess.run(
        argv,
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ReleaseIdentityError(f"release identity readback failed: {argv[0]}")
    return result.stdout


def read_image_ids(root: Path) -> dict[str, str]:
    values = tuple(
        line.strip()
        for line in _command(
            ["docker", "image", "inspect", "--format", "{{.Id}}", *IMAGE_TAGS],
            root=root,
        ).splitlines()
        if line.strip()
    )
    if len(values) != len(IMAGE_TAGS):
        raise ReleaseIdentityError("release image identity inventory is incomplete")
    return dict(zip(IMAGE_TAGS, values, strict=True))


def read_commit_sha(root: Path) -> str:
    return _command(["git", "rev-parse", "HEAD"], root=root).strip()


def derive_release_identity(
    root: Path = ROOT,
    *,
    image_ids: Mapping[str, str] | None = None,
    commit_sha: str | None = None,
) -> dict[str, Any]:
    resolved = root.resolve(strict=True)
    observed = dict(image_ids) if image_ids is not None else read_image_ids(resolved)
    if set(observed) != set(IMAGE_TAGS):
        raise ReleaseIdentityError("release image identity inventory is incomplete")
    if any(IMAGE_ID.fullmatch(value) is None for value in observed.values()):
        raise ReleaseIdentityError("release image identity is not a lowercase SHA-256 ID")
    commit = commit_sha or read_commit_sha(resolved)
    if COMMIT_SHA.fullmatch(commit) is None:
        raise ReleaseIdentityError("release commit identity is invalid")
    compose = resolved / "compose.yaml"
    if not compose.is_file():
        raise ReleaseIdentityError("compose.yaml is unavailable")
    compose_sha256 = hashlib.sha256(compose.read_bytes()).hexdigest()
    canonical_identity = {
        "compose_sha256": compose_sha256,
        "git_sha": commit,
        "image_ids": {tag: observed[tag] for tag in sorted(observed)},
        "profile": PROFILE,
    }
    environment_digest = hashlib.sha256(
        json.dumps(
            canonical_identity,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()
    return {
        **canonical_identity,
        "environment_digest": environment_digest,
        "runner_digest": observed["crosspatch-runner:local"].removeprefix("sha256:"),
        "schema_version": 1,
        "status": "PASS",
    }


def dotenv(identity: Mapping[str, Any]) -> str:
    runner = identity.get("runner_digest")
    environment = identity.get("environment_digest")
    if not isinstance(runner, str) or re.fullmatch(r"[0-9a-f]{64}", runner) is None:
        raise ReleaseIdentityError("runner digest is invalid")
    if not isinstance(environment, str) or re.fullmatch(
        r"[0-9a-f]{64}", environment
    ) is None:
        raise ReleaseIdentityError("environment digest is invalid")
    return (
        f"CROSSPATCH_RUNNER_DIGEST={runner}\n"
        f"CROSSPATCH_ENVIRONMENT_DIGEST={environment}\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("dotenv", "json"), default="dotenv")
    arguments = parser.parse_args()
    try:
        identity = derive_release_identity()
        output = (
            dotenv(identity)
            if arguments.format == "dotenv"
            else json.dumps(identity, indent=2, sort_keys=True) + "\n"
        )
    except (OSError, ReleaseIdentityError, subprocess.SubprocessError) as error:
        print(f"release identity failed: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
