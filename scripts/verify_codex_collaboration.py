#!/usr/bin/env python3
"""Generate and validate the privacy-minimized Codex collaboration dossier."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from verification_lib import ROOT, atomic_json, utc_now

SESSION_ID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
ROLES = frozenset({"plan", "implement", "adversarial_review"})
REQUIRED_SLICES = frozenset(
    {
        "domain-state-machine",
        "hostile-evidence-sanitizer",
        "warrant-broker",
        "candidate-isolation",
        "agents-sdk",
        "mcp-zones",
        "web-ui",
        "release-verification",
    }
)
CONTINUOUS_BUILD_SESSION_ID = "019f5cdf-55ad-74f3-9a6c-af64f2478847"
PLANNING_SESSION_ID = "019f5c65-f787-7e63-b523-b8f4065a7819"
ROLE_METHOD = (
    "Conservative classification from the recorded task path and bounded task brief; "
    "role is not a native session_meta field."
)
PUBLIC_SOURCE = (
    "privacy-minimized local Codex session metadata and current repository test receipts"
)

SESSION_SELECTION: tuple[tuple[str, str], ...] = (
    (PLANNING_SESSION_ID, "plan"),
    (CONTINUOUS_BUILD_SESSION_ID, "implement"),
    ("019f5c9e-1d1c-73e2-8228-2c236dce5765", "plan"),
    ("019f5ce1-fe00-7113-93f1-4a694f9ebce7", "plan"),
    ("019f5cfc-e4ae-7c41-80f1-3f03afea6cdf", "plan"),
    ("019f5d17-7d99-7520-9686-fb54e941697e", "implement"),
    ("019f5d3d-42e6-7b22-ade6-e7cb591cf014", "implement"),
    ("019f5d3d-bd16-7b21-a7ec-8eeadff38954", "implement"),
    ("019f5d4e-1010-7580-a06b-d53593c1c29b", "adversarial_review"),
    ("019f5d69-b112-7492-88bf-a9649615e307", "implement"),
    ("019f5dbc-bd9a-7972-8079-b9258d785749", "implement"),
    ("019f5dc7-845a-7602-9a97-a6cf900e8e63", "adversarial_review"),
    ("019f5dd6-2066-7301-ab0b-6e0b534f0cb2", "adversarial_review"),
    ("019f5e30-c4b4-76f2-b849-364079e312d2", "plan"),
    ("019f5e48-18ce-7ab3-9e5d-200af2a9b08b", "adversarial_review"),
    ("019f5e6e-0d0e-7aa2-b870-27861cb65cee", "adversarial_review"),
    ("019f6084-7ed4-73e1-be83-1aa00e36f847", "adversarial_review"),
    ("019f6086-b240-7f22-9dc7-fa4dd68d2d2f", "adversarial_review"),
    ("019f6723-50f6-7e91-8408-36e0808bbe62", "adversarial_review"),
    ("019f6748-ef03-7913-ae8e-1191475e2324", "adversarial_review"),
    ("019f6749-2c0c-7e22-b83c-afabf5f61c74", "adversarial_review"),
    ("019f6749-632a-7ab0-b09f-cee5b9afedd0", "adversarial_review"),
)

SLICE_SELECTION: tuple[dict[str, Any], ...] = (
    {
        "slice_id": "domain-state-machine",
        "label": "Domain and state machine",
        "repository_paths": [
            "backend/src/crosspatch/domain",
            "backend/src/crosspatch/db/repositories.py",
        ],
        "session_ids": {
            "plan": [PLANNING_SESSION_ID],
            "implement": [CONTINUOUS_BUILD_SESSION_ID],
            "adversarial_review": ["019f5e6e-0d0e-7aa2-b870-27861cb65cee"],
        },
    },
    {
        "slice_id": "hostile-evidence-sanitizer",
        "label": "Hostile-evidence sanitizer and artifact boundary",
        "repository_paths": ["backend/src/crosspatch/evidence"],
        "session_ids": {
            "plan": ["019f5c9e-1d1c-73e2-8228-2c236dce5765"],
            "implement": [
                CONTINUOUS_BUILD_SESSION_ID,
                "019f5d17-7d99-7520-9686-fb54e941697e",
            ],
            "adversarial_review": ["019f6086-b240-7f22-9dc7-fa4dd68d2d2f"],
        },
    },
    {
        "slice_id": "warrant-broker",
        "label": "Canonical warrant and deterministic broker",
        "repository_paths": ["backend/src/crosspatch/broker"],
        "session_ids": {
            "plan": [PLANNING_SESSION_ID],
            "implement": [CONTINUOUS_BUILD_SESSION_ID],
            "adversarial_review": ["019f5d4e-1010-7580-a06b-d53593c1c29b"],
        },
    },
    {
        "slice_id": "candidate-isolation",
        "label": "Candidate isolation and trusted external verification",
        "repository_paths": ["backend/src/crosspatch/runner"],
        "session_ids": {
            "plan": [PLANNING_SESSION_ID],
            "implement": [CONTINUOUS_BUILD_SESSION_ID],
            "adversarial_review": [
                "019f5d4e-1010-7580-a06b-d53593c1c29b",
                "019f5dc7-845a-7602-9a97-a6cf900e8e63",
            ],
        },
    },
    {
        "slice_id": "agents-sdk",
        "label": "OpenAI Agents SDK wiring",
        "repository_paths": [
            "backend/src/crosspatch/agents",
            "backend/src/crosspatch/orchestration",
        ],
        "session_ids": {
            "plan": ["019f5cfc-e4ae-7c41-80f1-3f03afea6cdf"],
            "implement": [
                CONTINUOUS_BUILD_SESSION_ID,
                "019f5d3d-42e6-7b22-ade6-e7cb591cf014",
                "019f5dbc-bd9a-7972-8079-b9258d785749",
            ],
            "adversarial_review": ["019f6084-7ed4-73e1-be83-1aa00e36f847"],
        },
    },
    {
        "slice_id": "mcp-zones",
        "label": "Evidence, Broker, and Judge MCP zones",
        "repository_paths": ["backend/src/crosspatch/mcp"],
        "session_ids": {
            "plan": ["019f5ce1-fe00-7113-93f1-4a694f9ebce7"],
            "implement": [
                CONTINUOUS_BUILD_SESSION_ID,
                "019f5d3d-42e6-7b22-ade6-e7cb591cf014",
            ],
            "adversarial_review": ["019f5dd6-2066-7301-ab0b-6e0b534f0cb2"],
        },
    },
    {
        "slice_id": "web-ui",
        "label": "Tracepaper web UI and incident room",
        "repository_paths": ["web"],
        "session_ids": {
            "plan": [PLANNING_SESSION_ID],
            "implement": [
                CONTINUOUS_BUILD_SESSION_ID,
                "019f5d3d-bd16-7b21-a7ec-8eeadff38954",
                "019f5d69-b112-7492-88bf-a9649615e307",
            ],
            "adversarial_review": ["019f6723-50f6-7e91-8408-36e0808bbe62"],
        },
    },
    {
        "slice_id": "release-verification",
        "label": "Release verification and evidence",
        "repository_paths": [
            "scripts/release_verifier.py",
            "scripts/verification_lib.py",
            "artifacts/verification",
        ],
        "session_ids": {
            "plan": ["019f5e30-c4b4-76f2-b849-364079e312d2"],
            "implement": [CONTINUOUS_BUILD_SESSION_ID],
            "adversarial_review": [
                "019f5e48-18ce-7ab3-9e5d-200af2a9b08b",
                "019f6748-ef03-7913-ae8e-1191475e2324",
                "019f6749-2c0c-7e22-b83c-afabf5f61c74",
                "019f6749-632a-7ab0-b09f-cee5b9afedd0",
            ],
        },
    },
)

def _source_sha256(relative: str) -> str:
    return hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()


RECEIPTS: tuple[dict[str, Any], ...] = (
    {
        "receipt_id": "warrant-status-ui",
        "finding_session_id": "019f5d69-b112-7492-88bf-a9649615e307",
        "finding": (
            "The API returned PENDING_APPROVAL while the UI recognized only a "
            "fixture-shaped pending value and failed to reconcile the authoritative status."
        ),
        "regression_tests": [
            {
                "path": "web/tests/components/api.test.ts",
                "test_name": "discovers and decodes the exact pending warrant bindings",
                "source_sha256": _source_sha256("web/tests/components/api.test.ts"),
            },
            {
                "path": "web/tests/components/incident-room.test.tsx",
                "test_name": (
                    "refetches the room after approval and displays the authoritative "
                    "warrant status"
                ),
                "source_sha256": _source_sha256(
                    "web/tests/components/incident-room.test.tsx"
                ),
            },
        ],
    },
    {
        "receipt_id": "candidate-exit-code-spoof",
        "finding_session_id": "019f5d4e-1010-7580-a06b-d53593c1c29b",
        "finding": (
            "Candidate-controlled import-time exit zero could be confused with proof unless "
            "success came from the trusted external supervisor and oracle."
        ),
        "regression_tests": [
            {
                "path": "backend/tests/security/test_candidate_spoof.py",
                "test_name": (
                    "test_import_time_zero_exit_and_forged_stdout_cannot_spoof_success"
                ),
                "source_sha256": _source_sha256(
                    "backend/tests/security/test_candidate_spoof.py"
                ),
            }
        ],
    },
)


class DossierError(ValueError):
    """Raised when collaboration evidence cannot be proven."""


def _parse_utc(value: object, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DossierError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise DossierError(f"{field} must be a UTC timestamp") from error
    if parsed.utcoffset() != UTC.utcoffset(parsed):
        raise DossierError(f"{field} must be UTC")
    return parsed


def _sessions_root() -> Path:
    configured = os.environ.get("CODEX_HOME")
    return (Path(configured).expanduser() if configured else Path.home() / ".codex") / "sessions"


def _session_file(session_id: str, root: Path) -> Path | None:
    matches = tuple(root.rglob(f"*-{session_id}.jsonl")) if root.is_dir() else ()
    if len(matches) > 1:
        raise DossierError(f"duplicate local session metadata for {session_id}")
    return matches[0] if matches else None


def _last_json_record(path: Path) -> dict[str, Any]:
    with path.open("rb") as source:
        source.seek(0, os.SEEK_END)
        position = source.tell()
        buffer = b""
        while position > 0:
            size = min(65536, position)
            position -= size
            source.seek(position)
            buffer = source.read(size) + buffer
            lines = [line for line in buffer.splitlines() if line.strip()]
            if lines and (position == 0 or len(lines) > 1):
                try:
                    record = json.loads(lines[-1])
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise DossierError("local session metadata ends with invalid JSON") from error
                if not isinstance(record, dict):
                    raise DossierError("local session metadata record is not an object")
                return record
    raise DossierError("local session metadata is empty")


def _read_local_session(session_id: str, root: Path) -> tuple[dict[str, Any], str]:
    path = _session_file(session_id, root)
    if path is None:
        raise DossierError(f"local session metadata missing for {session_id}")
    try:
        first = json.loads(path.open(encoding="utf-8").readline())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DossierError(f"invalid local session_meta for {session_id}") from error
    if not isinstance(first, dict) or first.get("type") != "session_meta":
        raise DossierError(f"first record is not session_meta for {session_id}")
    payload = first.get("payload")
    if not isinstance(payload, dict) or payload.get("id") != session_id:
        raise DossierError(f"session_meta id mismatch for {session_id}")
    last = _last_json_record(path)
    observed = last.get("timestamp")
    _parse_utc(observed, field=f"observed_through[{session_id}]")
    return payload, str(observed)


def _git(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _safe_session_projection(payload: dict[str, Any]) -> dict[str, Any]:
    source = payload.get("source")
    task_path = "/root"
    parent: str | None = None
    if isinstance(source, dict):
        spawn = source.get("subagent", {}).get("thread_spawn", {})
        if not isinstance(spawn, dict):
            raise DossierError("invalid subagent session source")
        task_path = spawn.get("agent_path")
        parent = spawn.get("parent_thread_id")
        if not isinstance(task_path, str) or not task_path.startswith("/root"):
            raise DossierError("invalid subagent task path")
        if not isinstance(parent, str) or not SESSION_ID.fullmatch(parent):
            raise DossierError("invalid parent session id")
    elif not isinstance(source, str):
        raise DossierError("invalid root session source")
    started_at = payload.get("timestamp")
    _parse_utc(started_at, field="session_meta.timestamp")
    cwd = payload.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        raise DossierError("session_meta repository cwd is missing")
    try:
        repository_cwd_verified = Path(cwd).resolve() == ROOT.resolve()
    except OSError as error:
        raise DossierError("session_meta repository cwd cannot be resolved") from error
    if not repository_cwd_verified:
        raise DossierError("session_meta belongs to a different repository cwd")

    git = payload.get("git")
    if not isinstance(git, dict):
        raise DossierError("session_meta Git baseline is invalid")
    recorded_git_commit = git.get("commit_hash")
    recorded_git_branch = git.get("branch")
    if recorded_git_commit is None:
        if recorded_git_branch is not None:
            raise DossierError("session_meta Git branch has no recorded commit")
    else:
        if not isinstance(recorded_git_commit, str) or not GIT_SHA.fullmatch(
            recorded_git_commit
        ):
            raise DossierError("session_meta recorded Git commit is invalid")
        if not isinstance(recorded_git_branch, str) or not recorded_git_branch:
            raise DossierError("session_meta recorded Git branch is invalid")
        if _git("cat-file", "-e", f"{recorded_git_commit}^{{commit}}").returncode != 0:
            raise DossierError("session_meta recorded Git commit is missing")
        if (
            _git("merge-base", "--is-ancestor", recorded_git_commit, "HEAD").returncode
            != 0
        ):
            raise DossierError("session_meta recorded Git commit is not in repository history")

    projection = {
        "session_id": payload.get("id"),
        "started_at": started_at,
        "task_path": task_path,
        "parent_session_id": parent,
        "originator": payload.get("originator"),
        "cli_version": payload.get("cli_version"),
        "repository_cwd_verified": repository_cwd_verified,
        "recorded_git_commit": recorded_git_commit,
        "recorded_git_branch": recorded_git_branch,
    }
    if not all(
        isinstance(projection[field], str) and projection[field]
        for field in ("session_id", "started_at", "task_path", "originator", "cli_version")
    ):
        raise DossierError("session_meta safe projection is incomplete")
    return projection


def _projection_sha256(projection: dict[str, Any]) -> str:
    encoded = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def generate_dossier(*, sessions_root: Path) -> dict[str, Any]:
    sessions: list[dict[str, Any]] = []
    for session_id, role in SESSION_SELECTION:
        payload, observed_through = _read_local_session(session_id, sessions_root)
        projection = _safe_session_projection(payload)
        sessions.append(
            {
                "session_id": session_id,
                "started_at": projection["started_at"],
                "observed_through": observed_through,
                "role": role,
                "task_path": projection["task_path"],
                "parent_session_id": projection["parent_session_id"],
                "originator": projection["originator"],
                "cli_version": projection["cli_version"],
                "repository_cwd_verified": projection["repository_cwd_verified"],
                "session_meta_sha256": _projection_sha256(projection),
            }
        )
    return {
        "schema_version": 2,
        "generated_at": utc_now(),
        "generator": "scripts/verify_codex_collaboration.py",
        "source": PUBLIC_SOURCE,
        "role_method": ROLE_METHOD,
        "privacy": (
            "Only session identifiers, task lineage, dates, roles, repository-match proof, "
            "safe metadata fingerprints, and current regression-source hashes are retained; "
            "transcript bodies, local paths, and private Git history are excluded."
        ),
        "planning_session_id": PLANNING_SESSION_ID,
        "continuous_build_session_id": CONTINUOUS_BUILD_SESSION_ID,
        "sessions": sessions,
        "slices": list(SLICE_SELECTION),
        "receipts": list(RECEIPTS),
    }


def migrate_public_dossier(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise DossierError("existing dossier must be an object")
    sessions = payload.get("sessions")
    if not isinstance(sessions, list) or not sessions:
        raise DossierError("existing dossier sessions are missing")
    public_sessions: list[dict[str, Any]] = []
    for session in sessions:
        if not isinstance(session, dict):
            raise DossierError("existing dossier session is invalid")
        public_sessions.append(
            {
                key: value
                for key, value in session.items()
                if key not in {"recorded_git_commit", "recorded_git_branch"}
            }
        )
    return {
        "schema_version": 2,
        "generated_at": utc_now(),
        "generator": "scripts/verify_codex_collaboration.py",
        "source": PUBLIC_SOURCE,
        "role_method": ROLE_METHOD,
        "privacy": (
            "Only session identifiers, task lineage, dates, roles, repository-match proof, "
            "safe metadata fingerprints, and current regression-source hashes are retained; "
            "transcript bodies, local paths, and private Git history are excluded."
        ),
        "planning_session_id": PLANNING_SESSION_ID,
        "continuous_build_session_id": CONTINUOUS_BUILD_SESSION_ID,
        "sessions": public_sessions,
        "slices": list(SLICE_SELECTION),
        "receipts": list(RECEIPTS),
    }


def _validate_receipts(receipts: object, session_ids: set[str]) -> None:
    if not isinstance(receipts, list):
        raise DossierError("receipts must be a list")
    if {item.get("receipt_id") for item in receipts if isinstance(item, dict)} != {
        "warrant-status-ui",
        "candidate-exit-code-spoof",
    }:
        raise DossierError("required review receipts are missing")
    for receipt in receipts:
        if not isinstance(receipt, dict):
            raise DossierError("receipt is not an object")
        if receipt.get("finding_session_id") not in session_ids:
            raise DossierError("receipt finding session is unknown")
        tests = receipt.get("regression_tests")
        if not isinstance(tests, list) or not tests:
            raise DossierError("receipt tests are required")
        if "fixing_commits" in receipt:
            raise DossierError("public receipts must not depend on private Git history")
        for test in tests:
            if not isinstance(test, dict):
                raise DossierError("receipt test is not an object")
            relative = test.get("path")
            test_name = test.get("test_name")
            source_sha256 = test.get("source_sha256")
            if (
                not isinstance(relative, str)
                or not isinstance(test_name, str)
                or not isinstance(source_sha256, str)
                or not SHA256.fullmatch(source_sha256)
            ):
                raise DossierError("receipt test path, name, and source hash are required")
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts:
                raise DossierError("unsafe receipt test path")
            source = ROOT / path
            if not source.is_file() or test_name not in source.read_text(encoding="utf-8"):
                raise DossierError(f"receipt test is missing: {relative}::{test_name}")
            if source_sha256 != hashlib.sha256(source.read_bytes()).hexdigest():
                raise DossierError(f"receipt test source hash is stale: {relative}")


def validate_dossier(
    payload: object,
    *,
    narrative_path: Path,
    require_local_metadata: bool,
    sessions_root: Path,
) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema_version") != 2:
        raise DossierError("dossier schema_version must be 2")
    if payload.get("generator") != "scripts/verify_codex_collaboration.py":
        raise DossierError("dossier generator is invalid")
    if payload.get("source") != PUBLIC_SOURCE:
        raise DossierError("dossier source is invalid")
    if payload.get("planning_session_id") != PLANNING_SESSION_ID:
        raise DossierError("planning session id is invalid")
    if payload.get("continuous_build_session_id") != CONTINUOUS_BUILD_SESSION_ID:
        raise DossierError("continuous build session id is invalid")
    if payload.get("role_method") != ROLE_METHOD:
        raise DossierError("dossier role-classification method is invalid")
    sessions = payload.get("sessions")
    if not isinstance(sessions, list) or not sessions:
        raise DossierError("sessions must be a non-empty list")
    actual_selection = {
        (session.get("session_id"), session.get("role"))
        for session in sessions
        if isinstance(session, dict)
    }
    if actual_selection != set(SESSION_SELECTION) or len(actual_selection) != len(sessions):
        raise DossierError("dossier session selection does not match verified task set")
    by_id: dict[str, dict[str, Any]] = {}
    local_checks = 0
    for session in sessions:
        if not isinstance(session, dict):
            raise DossierError("session entry is not an object")
        session_id = session.get("session_id")
        if not isinstance(session_id, str) or not SESSION_ID.fullmatch(session_id):
            raise DossierError("session id is invalid")
        if session_id in by_id:
            raise DossierError("session ids must be unique")
        if session.get("role") not in ROLES:
            raise DossierError("session role is invalid")
        if not SHA256.fullmatch(str(session.get("session_meta_sha256", ""))):
            raise DossierError("session metadata fingerprint is invalid")
        started = _parse_utc(session.get("started_at"), field="started_at")
        observed = _parse_utc(session.get("observed_through"), field="observed_through")
        if started > observed:
            raise DossierError("session date range is reversed")
        task_path = session.get("task_path")
        if not isinstance(task_path, str) or not task_path.startswith("/root"):
            raise DossierError("session task path is invalid")
        parent = session.get("parent_session_id")
        if parent is not None and (not isinstance(parent, str) or not SESSION_ID.fullmatch(parent)):
            raise DossierError("session parent id is invalid")
        originator = session.get("originator")
        cli_version = session.get("cli_version")
        if not isinstance(originator, str) or not originator:
            raise DossierError("session originator is invalid")
        if not isinstance(cli_version, str) or not cli_version:
            raise DossierError("session cli version is invalid")
        if session.get("repository_cwd_verified") is not True:
            raise DossierError("session repository cwd was not verified")
        if "recorded_git_commit" in session or "recorded_git_branch" in session:
            raise DossierError("public dossier must not expose private Git history")
        by_id[session_id] = session

        local = (
            _session_file(session_id, sessions_root)
            if require_local_metadata
            else None
        )
        if local is None:
            if require_local_metadata:
                raise DossierError(f"local session metadata missing for {session_id}")
            continue
        local_payload, local_observed = _read_local_session(session_id, sessions_root)
        projection = _safe_session_projection(local_payload)
        if session["session_meta_sha256"] != _projection_sha256(projection):
            raise DossierError(f"local session metadata fingerprint mismatch for {session_id}")
        if session["started_at"] != projection["started_at"]:
            raise DossierError(f"local session start mismatch for {session_id}")
        if _parse_utc(local_observed, field="local observed_through") < observed:
            raise DossierError(f"local session history predates dossier for {session_id}")
        local_checks += 1

    slices = payload.get("slices")
    if not isinstance(slices, list) or {
        item.get("slice_id") for item in slices if isinstance(item, dict)
    } != REQUIRED_SLICES:
        raise DossierError("required repository slices are missing")
    if slices != list(SLICE_SELECTION):
        raise DossierError("dossier slice mapping does not match verified task map")
    for item in slices:
        if not isinstance(item, dict):
            raise DossierError("slice is not an object")
        paths = item.get("repository_paths")
        by_role = item.get("session_ids")
        if not isinstance(paths, list) or not paths or not isinstance(by_role, dict):
            raise DossierError("slice paths and session roles are required")
        if set(by_role) != ROLES:
            raise DossierError("slice must include plan, implement, and adversarial review")
        for relative in paths:
            path = Path(str(relative))
            if path.is_absolute() or ".." in path.parts or not (ROOT / path).exists():
                raise DossierError(f"slice repository path is invalid: {relative}")
        for role, referenced in by_role.items():
            if not isinstance(referenced, list) or not referenced:
                raise DossierError(f"slice role has no sessions: {role}")
            for session_id in referenced:
                if session_id not in by_id:
                    raise DossierError(f"unknown session reference: {session_id}")
                if by_id[session_id]["role"] != role:
                    raise DossierError(f"session role mismatch: {session_id}")

    if payload.get("receipts") != list(RECEIPTS):
        raise DossierError("dossier receipt mapping does not match verified Git/test map")
    _validate_receipts(payload.get("receipts"), set(by_id))
    if not narrative_path.is_file():
        raise DossierError("collaboration narrative is missing")
    narrative = narrative_path.read_text(encoding="utf-8")
    required_copy = (
        PLANNING_SESSION_ID,
        CONTINUOUS_BUILD_SESSION_ID,
        "curated Superpowers plugin",
        "planning output, not independent execution evidence",
        "warrant-status-ui",
        "candidate-exit-code-spoof",
    )
    if any(value not in narrative for value in required_copy):
        raise DossierError("collaboration narrative is incomplete")
    for slice_id in REQUIRED_SLICES:
        if f"`{slice_id}`" not in narrative:
            raise DossierError(f"collaboration narrative omits slice {slice_id}")
    return {
        "status": "PASS",
        "session_count": len(by_id),
        "slice_count": len(slices),
        "receipt_count": len(payload["receipts"]),
        "local_session_metadata_checked": local_checks,
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--refresh", action="store_true")
    action.add_argument("--check", action="store_true")
    parser.add_argument("--require-local-metadata", action="store_true")
    parser.add_argument("--dossier", type=Path, default=ROOT / "docs" / "codex-sessions.json")
    parser.add_argument(
        "--narrative",
        type=Path,
        default=ROOT / "docs" / "CODEX_COLLABORATION.md",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    sessions_root = _sessions_root()
    try:
        if arguments.refresh:
            if arguments.require_local_metadata:
                payload = generate_dossier(sessions_root=sessions_root)
            else:
                existing = json.loads(arguments.dossier.read_text(encoding="utf-8"))
                payload = migrate_public_dossier(existing)
        else:
            payload = json.loads(arguments.dossier.read_text(encoding="utf-8"))
        result = validate_dossier(
            payload,
            narrative_path=arguments.narrative,
            require_local_metadata=arguments.require_local_metadata,
            sessions_root=sessions_root,
        )
        if arguments.refresh:
            atomic_json(arguments.dossier, payload)
    except (DossierError, OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        print(f"Codex collaboration dossier FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
