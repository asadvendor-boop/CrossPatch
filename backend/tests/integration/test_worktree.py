from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from crosspatch.broker.broker import AuthoritySnapshot
from crosspatch.broker.warrant import BoundExecutionPlan, WarrantDocument
from crosspatch.domain.hashing import sha256_hex
from crosspatch.runner.candidate_context import load_and_verify_candidate_context
from crosspatch.runner.catalog import ExecutionCatalog
from crosspatch.runner.worktree import (
    EphemeralWorktreeFactory,
    PreparedWorkspace,
    UnsafeRepositorySnapshot,
    repository_manifest_sha256,
)

PATCH = b"""diff --git a/victim/src/victim/db.py b/victim/src/victim/db.py
index 1111111..2222222 100644
--- a/victim/src/victim/db.py
+++ b/victim/src/victim/db.py
@@ -1 +1 @@
-vulnerable = True
+vulnerable = False
"""


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        [shutil.which("git") or "git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(repo),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "CrossPatch test",
            "GIT_AUTHOR_EMAIL": "test@crosspatch.invalid",
            "GIT_COMMITTER_NAME": "CrossPatch test",
            "GIT_COMMITTER_EMAIL": "test@crosspatch.invalid",
        },
    )
    return result.stdout.strip()


def _repository(tmp_path: Path, *, symlink: bool = False) -> tuple[Path, str]:
    repo = tmp_path / "source"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    target = repo / "victim/src/victim/db.py"
    target.parent.mkdir(parents=True)
    target.write_text("vulnerable = True\n", encoding="utf-8")
    if symlink:
        (repo / "unsafe-link").symlink_to("/etc/passwd")
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "base")
    return repo, _git(repo, "rev-parse", "HEAD")


def _document(repo: Path, base_sha: str) -> WarrantDocument:
    plan = BoundExecutionPlan.from_execution_plan(
        ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")
    )
    issued = datetime(2026, 7, 14, 2, tzinfo=UTC)
    return WarrantDocument(
        format="crosspatch-warrant-v1",
        warrant_id="war_worktree",
        incident_id="inc_01",
        repository_id="repo_01",
        verdict_id="ver_01",
        verdict_sha256="1" * 64,
        candidate_id="cand_01",
        authority_snapshot_sha256="2" * 64,
        reviewed_evidence_manifest_sha256="3" * 64,
        reviewed_timeline_head="4" * 64,
        base_sha=base_sha,
        repository_manifest_sha256=repository_manifest_sha256(repo, base_sha),
        patch_b64=base64.b64encode(PATCH).decode("ascii"),
        patch_sha256=hashlib.sha256(PATCH).hexdigest(),
        allowed_paths=("victim/src/victim/db.py",),
        execution_plans=(plan,),
        test_plan_sha256=sha256_hex((plan,)),
        runner_digest="7" * 64,
        environment_digest="8" * 64,
        approver_identity="approver-1",
        issued_at=issued,
        expires_at=issued + timedelta(minutes=15),
        approval_mac_key_id="approval-v1",
        nonce="nonce_worktree",
    )


def test_manifest_git_trust_is_scoped_to_the_exact_runtime_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = (tmp_path / "root-owned-runtime-snapshot").resolve()
    repository.mkdir()
    git = Path(shutil.which("git") or pytest.fail("git is required"))
    captured: dict[str, object] = {}

    def run(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        return subprocess.CompletedProcess(command, 0, stdout=b"bound-tree", stderr=b"")

    monkeypatch.setattr("crosspatch.runner.worktree.subprocess.run", run)

    digest = repository_manifest_sha256(
        repository,
        "a" * 40,
        git_executable=git,
    )

    command = captured["command"]
    assert f"safe.directory={repository}" in command
    assert captured["environment"]["GIT_CONFIG_NOSYSTEM"] == "1"
    assert captured["environment"]["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert digest == hashlib.sha256(b"bound-tree").hexdigest()


@pytest.mark.asyncio
async def test_factory_uses_standalone_snapshot_applies_patch_and_removes_everything(
    tmp_path: Path,
):
    repo, base_sha = _repository(tmp_path)
    document = _document(repo, base_sha)
    authority = AuthoritySnapshot.from_warrant(document, repository_root=repo)
    jobs = tmp_path / "jobs"
    workspaces = tmp_path / "candidate-workspaces"
    factory = EphemeralWorktreeFactory(jobs_root=jobs, workspaces_root=workspaces)

    async with factory.create(document, authority) as prepared:
        assert isinstance(prepared, PreparedWorkspace)
        workspace = prepared.root
        assert (repo / "victim/src/victim/db.py").read_text() == "vulnerable = True\n"
        assert (workspace / "victim/src/victim/db.py").read_text() == "vulnerable = False\n"
        assert not (workspace / ".git").exists()
        context_path = prepared.context_path
        assert context_path.parent.is_relative_to(jobs)
        assert not context_path.is_relative_to(workspaces)
        assert workspace.is_relative_to(workspaces)
        context = load_and_verify_candidate_context(context_path, expected_root=workspace)
        assert context.base_sha == base_sha
        assert context.patch_sha256 == document.patch_sha256
        assert context.allowed_paths == document.allowed_paths
        assert context_path.stat().st_mode & 0o777 == 0o400
        assert workspace.stat().st_mode & 0o777 == 0o555
        assert (workspace / "victim/src/victim/db.py").stat().st_mode & 0o777 == 0o444

    assert jobs.is_dir()
    assert list(jobs.iterdir()) == []
    assert workspaces.is_dir()
    assert list(workspaces.iterdir()) == []


@pytest.mark.asyncio
async def test_archive_symlink_is_rejected_and_job_is_cleaned(tmp_path: Path):
    repo, base_sha = _repository(tmp_path, symlink=True)
    document = _document(repo, base_sha)
    authority = AuthoritySnapshot.from_warrant(document, repository_root=repo)
    jobs = tmp_path / "jobs"
    factory = EphemeralWorktreeFactory(jobs_root=jobs)

    with pytest.raises(UnsafeRepositorySnapshot, match="link|special"):
        async with factory.create(document, authority):
            raise AssertionError("unsafe snapshot became executable")

    assert list(jobs.iterdir()) == []


@pytest.mark.asyncio
async def test_manifest_or_base_sha_mismatch_fails_closed(tmp_path: Path):
    repo, base_sha = _repository(tmp_path)
    document = _document(repo, base_sha).model_copy(
        update={"repository_manifest_sha256": "a" * 64}
    )
    authority = AuthoritySnapshot.from_warrant(document, repository_root=repo)
    factory = EphemeralWorktreeFactory(jobs_root=tmp_path / "jobs")

    with pytest.raises(UnsafeRepositorySnapshot, match="manifest"):
        async with factory.create(document, authority):
            raise AssertionError("mismatched repository became executable")
