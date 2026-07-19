#!/usr/bin/env python3
"""Verify authenticated GitHub repository metadata without overstating UI evidence."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from verification_lib import ARTIFACT_DIR, ROOT, atomic_json, release_source_sha256, utc_now

GENERATOR = "scripts/verify-github-license.sh"
DEFAULT_BRANCH = "main"
DEFAULT_DESCRIPTION = (
    "Failure-first SRE incident review with deterministic, warrant-bound execution."
)
DEFAULT_TOPICS = (
    "agents-sdk",
    "incident-response",
    "mcp",
    "openai",
    "site-reliability-engineering",
)

ApiReader = Callable[[str], tuple[dict[str, Any] | None, str | None]]
HeadReader = Callable[[], tuple[str | None, str | None]]


@dataclass(frozen=True)
class Expectations:
    """Release metadata expected from the public GitHub repository."""

    default_branch: str = DEFAULT_BRANCH
    description: str = DEFAULT_DESCRIPTION
    topics: tuple[str, ...] = DEFAULT_TOPICS
    visibility: str = "public"

    @classmethod
    def from_environment(cls) -> Expectations:
        branch = (
            os.environ.get("CROSSPATCH_GITHUB_EXPECTED_DEFAULT_BRANCH", "").strip()
            or DEFAULT_BRANCH
        )
        description = (
            os.environ.get("CROSSPATCH_GITHUB_EXPECTED_DESCRIPTION", "").strip()
            or DEFAULT_DESCRIPTION
        )
        configured_topics = os.environ.get(
            "CROSSPATCH_GITHUB_EXPECTED_TOPICS", ",".join(DEFAULT_TOPICS)
        )
        topics = tuple(
            sorted(
                {topic.strip().lower() for topic in configured_topics.split(",") if topic.strip()}
            )
        )
        if not topics:
            topics = DEFAULT_TOPICS
        return cls(default_branch=branch, description=description, topics=topics)


def gh_json(endpoint: str) -> tuple[dict[str, Any] | None, str | None]:
    result = subprocess.run(
        ["gh", "api", endpoint], cwd=ROOT, check=False, capture_output=True, text=True
    )
    if result.returncode != 0:
        return None, result.stderr.strip() or "gh api failed"
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        return None, f"GitHub returned invalid JSON: {error}"
    if not isinstance(value, dict):
        return None, "GitHub returned a non-object JSON response"
    return value, None


def local_head() -> tuple[str | None, str | None]:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    value = result.stdout.strip()
    if result.returncode != 0 or not value:
        return None, result.stderr.strip() or "local git HEAD is unavailable"
    return value, None


def detect_repository() -> str | None:
    configured = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if configured:
        return configured
    result = subprocess.run(
        ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else None


def _check(status: bool, **details: Any) -> dict[str, Any]:
    return {"status": "PASS" if status else "FAIL", **details}


def verify_repository(
    repository: str,
    expected: Expectations,
    *,
    api_reader: ApiReader | None = None,
    local_head_reader: HeadReader | None = None,
) -> dict[str, Any]:
    """Compare authenticated API state and the pushed branch with release expectations."""

    api_reader = api_reader or gh_json
    local_head_reader = local_head_reader or local_head
    metadata, metadata_error = api_reader(f"repos/{repository}")
    remote_commit, commit_error = api_reader(
        f"repos/{repository}/commits/{expected.default_branch}"
    )
    license_payload, license_error = api_reader(f"repos/{repository}/license")
    local_sha, local_error = local_head_reader()
    blockers = [
        error for error in (metadata_error, commit_error, license_error, local_error) if error
    ]

    checks: dict[str, dict[str, Any]] = {}
    repository_matches = bool(metadata and metadata.get("full_name") == repository)
    checks["repository_readback"] = _check(
        repository_matches,
        expected=repository,
        actual=metadata.get("full_name") if metadata else None,
        html_url=metadata.get("html_url") if metadata else None,
    )
    if not repository_matches and not metadata_error:
        blockers.append("GitHub repository identity does not match the configured repository")

    actual_visibility = metadata.get("visibility") if metadata else None
    visibility_matches = actual_visibility == expected.visibility
    checks["repository_visibility"] = _check(
        visibility_matches,
        expected=expected.visibility,
        actual=actual_visibility,
    )
    if not visibility_matches and not metadata_error:
        blockers.append("GitHub repository visibility is not public")

    actual_branch = metadata.get("default_branch") if metadata else None
    branch_matches = actual_branch == expected.default_branch
    checks["default_branch"] = _check(
        branch_matches,
        expected=expected.default_branch,
        actual=actual_branch,
    )
    if not branch_matches and not metadata_error:
        blockers.append("GitHub default branch does not match the expected release branch")

    actual_description = metadata.get("description") if metadata else None
    raw_topics = metadata.get("topics") if metadata else None
    actual_topics = (
        tuple(sorted(topic for topic in raw_topics if isinstance(topic, str)))
        if isinstance(raw_topics, list)
        else ()
    )
    about_matches = actual_description == expected.description and actual_topics == expected.topics
    checks["about_metadata"] = _check(
        about_matches,
        expected_description=expected.description,
        actual_description=actual_description,
        expected_topics=list(expected.topics),
        actual_topics=list(actual_topics),
    )
    if not about_matches and not metadata_error:
        blockers.append("GitHub About description or topics do not match release metadata")

    remote_sha = remote_commit.get("sha") if remote_commit else None
    head_matches = bool(local_sha and remote_sha and local_sha == remote_sha)
    checks["remote_head_matches_local_head"] = _check(
        head_matches,
        branch=expected.default_branch,
        local_head=local_sha,
        remote_head=remote_sha,
    )
    if not head_matches and not commit_error and not local_error:
        blockers.append("GitHub release branch HEAD does not match local HEAD")

    license_metadata = license_payload.get("license") if license_payload else None
    spdx = license_metadata.get("spdx_id") if isinstance(license_metadata, dict) else None
    license_path = license_payload.get("path") if license_payload else None
    license_detected = spdx == "MIT" and license_path == "LICENSE"
    checks["root_license_detected"] = _check(
        license_detected,
        spdx_id=spdx,
        path=license_path,
        sha=license_payload.get("sha") if license_payload else None,
    )
    if not license_detected and not license_error:
        blockers.append("GitHub has not detected root LICENSE as MIT")

    verified = all(check["status"] == "PASS" for check in checks.values())
    return {
        "status": "API_VERIFIED" if verified else "BLOCKED",
        "git_sha": local_sha,
        "verification_scope": "authenticated GitHub API and local git only",
        "blockers": blockers,
        "checks": checks,
        "authenticated_ui_about_visual_readback": {
            "status": "NOT_PERFORMED",
            "claim": "GitHub About visibly renders MIT",
            "api_inference_allowed": False,
            "required_before_submission": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ARTIFACT_DIR / "github-license.json")
    arguments = parser.parse_args()
    repository = detect_repository()
    expected = Expectations.from_environment()
    local_sha, _local_error = local_head()

    if repository is None:
        verification = {
            "status": "BLOCKED",
            "git_sha": None,
            "verification_scope": "authenticated GitHub API and local git only",
            "blockers": ["GitHub repository identity or authenticated remote is unavailable"],
            "checks": {
                name: {"status": "BLOCKED"}
                for name in (
                    "repository_readback",
                    "repository_visibility",
                    "default_branch",
                    "about_metadata",
                    "remote_head_matches_local_head",
                    "root_license_detected",
                )
            },
            "authenticated_ui_about_visual_readback": {
                "status": "NOT_PERFORMED",
                "claim": "GitHub About visibly renders MIT",
                "api_inference_allowed": False,
                "required_before_submission": True,
            },
        }
    else:
        verification = verify_repository(repository, expected)

    payload = {
        "schema_version": 1,
        "machine_generated": True,
        "generator": GENERATOR,
        "source": "authenticated GitHub REST metadata, root license endpoint, and local git",
        "command": "./scripts/verify-github-license.sh",
        "checked_at": utc_now(),
        "repository": repository,
        "expected": {
            "visibility": expected.visibility,
            "default_branch": expected.default_branch,
            "description": expected.description,
            "topics": list(expected.topics),
        },
        **verification,
        "git_sha": verification.get("git_sha") or local_sha,
        "source_sha256": release_source_sha256(),
    }
    atomic_json(arguments.output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["status"] == "API_VERIFIED" else 2


if __name__ == "__main__":
    sys.exit(main())
