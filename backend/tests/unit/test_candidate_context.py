import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from crosspatch.runner.candidate_context import (
    CandidateContextViolation,
    load_and_verify_candidate_context,
)

GIT = "/usr/bin/git"


def _git(root: Path, *args: str) -> bytes:
    return subprocess.run(
        [GIT, "-C", str(root), *args],
        check=True,
        capture_output=True,
        env={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": "/nonexistent",
            "PATH": "/usr/bin:/bin",
        },
    ).stdout


def _patched_worktree(tmp_path: Path) -> tuple[Path, str, bytes, bytes]:
    root = tmp_path / "candidate"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "runner@crosspatch.invalid")
    _git(root, "config", "user.name", "CrossPatch runner")
    source = root / "victim" / "src" / "victim" / "db.py"
    source.parent.mkdir(parents=True)
    base_bytes = b"vulnerable = True\n"
    source.write_bytes(base_bytes)
    _git(root, "add", "victim/src/victim/db.py")
    _git(root, "commit", "-qm", "base")
    base_sha = _git(root, "rev-parse", "HEAD").decode().strip()
    source.write_text("vulnerable = False\n", encoding="utf-8")
    patch = _git(
        root,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-textconv",
        base_sha,
        "--",
        "victim/src/victim/db.py",
    )
    return root, base_sha, patch, base_bytes


def _write_context(
    path: Path,
    root: Path,
    base_sha: str,
    patch: bytes,
    base_bytes: bytes,
) -> None:
    relative = "victim/src/victim/db.py"
    path.write_text(
        json.dumps(
            {
                "allowed_paths": [relative],
                "base_sha": base_sha,
                "base_file_sha256": {relative: hashlib.sha256(base_bytes).hexdigest()},
                "candidate_file_sha256": {
                    relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
                },
                "candidate_root": str(root),
                "format": "crosspatch-candidate-context-v1",
                "patch_sha256": hashlib.sha256(patch).hexdigest(),
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)


def test_candidate_context_binds_a_real_nonempty_git_patch(tmp_path: Path):
    root, base_sha, patch, base_bytes = _patched_worktree(tmp_path)
    manifest = tmp_path / "candidate-context.json"
    _write_context(manifest, root, base_sha, patch, base_bytes)

    context = load_and_verify_candidate_context(manifest, expected_root=root)

    assert context.patch_sha256 == hashlib.sha256(patch).hexdigest()
    assert context.allowed_paths == ("victim/src/victim/db.py",)


def test_candidate_context_rejects_a_manifest_inside_the_candidate(tmp_path: Path):
    root, base_sha, patch, base_bytes = _patched_worktree(tmp_path)
    manifest = root / "candidate-context.json"
    _write_context(manifest, root, base_sha, patch, base_bytes)

    with pytest.raises(CandidateContextViolation, match="outside"):
        load_and_verify_candidate_context(manifest, expected_root=root)


def test_candidate_context_rejects_candidate_bytes_changed_after_publication(tmp_path: Path):
    root, base_sha, patch, base_bytes = _patched_worktree(tmp_path)
    manifest = tmp_path / "candidate-context.json"
    _write_context(manifest, root, base_sha, patch, base_bytes)
    (root / "victim/src/victim/db.py").write_text("tampered = True\n", encoding="utf-8")

    with pytest.raises(CandidateContextViolation, match="candidate file bytes"):
        load_and_verify_candidate_context(manifest, expected_root=root)


def test_candidate_context_rejects_a_duplicate_json_key(tmp_path: Path):
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    manifest = tmp_path / "candidate-context.json"
    manifest.write_text('{"format":"a","format":"b"}', encoding="utf-8")
    os.chmod(manifest, 0o600)

    with pytest.raises(CandidateContextViolation, match="duplicate"):
        load_and_verify_candidate_context(manifest, expected_root=candidate)
