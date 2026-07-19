"""Standalone, disposable source snapshots for approved patches."""

from __future__ import annotations

import asyncio
import hashlib
import os
import resource
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import TracebackType

from crosspatch.broker.broker import AuthoritySnapshot
from crosspatch.broker.paths import validate_declared_patch_paths
from crosspatch.broker.warrant import WarrantDocument
from crosspatch.domain.hashing import canonical_json
from crosspatch.runner.candidate_context import CONTEXT_FORMAT

_MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
_MAX_ARCHIVE_FILES = 50_000


class UnsafeRepositorySnapshot(ValueError):
    """Raised when the bound Git tree cannot become a safe standalone snapshot."""


@dataclass(frozen=True, slots=True)
class PreparedWorkspace(os.PathLike[str]):
    """A candidate tree plus its separately stored supervisor-only context."""

    root: Path
    context_path: Path

    def __fspath__(self) -> str:
        return str(self.root)


def _git_environment(home: Path) -> dict[str, str]:
    return {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _resolve_git(executable: str | Path | None) -> Path:
    value = str(executable) if executable is not None else shutil.which("git")
    if not value:
        raise UnsafeRepositorySnapshot("absolute Git executable is unavailable")
    path = Path(value).resolve(strict=True)
    if not path.is_absolute() or not os.access(path, os.X_OK):
        raise UnsafeRepositorySnapshot("Git executable must be absolute and executable")
    return path


def _git_prefix(git: Path, repository: Path) -> list[str]:
    return [
        str(git),
        # Runtime snapshots are deliberately owned by root and consumed by the
        # unprivileged broker UID.  Trust only this already-resolved repository
        # path; the sanitized environment disables system/global allowlists.
        "-c",
        f"safe.directory={repository}",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-C",
        str(repository),
    ]


def _run_git_bytes(git: Path, repository: Path, home: Path, *args: str) -> bytes:
    result = subprocess.run(
        [*_git_prefix(git, repository), *args],
        check=False,
        capture_output=True,
        env=_git_environment(home),
        timeout=30,
    )
    if result.returncode != 0:
        raise UnsafeRepositorySnapshot("bound Git object is unavailable")
    return result.stdout


def repository_manifest_sha256(
    repository_root: str | Path,
    base_sha: str,
    *,
    git_executable: str | Path | None = None,
) -> str:
    """Hash Git's raw recursive tree listing for a bound commit."""
    repository = Path(repository_root).resolve(strict=True)
    git = _resolve_git(git_executable)
    listing = _run_git_bytes(git, repository, repository, "ls-tree", "-r", "-z", base_sha)
    return hashlib.sha256(listing).hexdigest()


def _limit_archive_writer() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (_MAX_ARCHIVE_BYTES, _MAX_ARCHIVE_BYTES))


def _safe_member_name(name: str) -> PurePosixPath:
    if name != unicodedata.normalize("NFKC", name) or "\\" in name or "\x00" in name:
        raise UnsafeRepositorySnapshot("archive path is not canonical")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise UnsafeRepositorySnapshot("archive path escapes the standalone snapshot")
    if ".git" in path.parts:
        raise UnsafeRepositorySnapshot("archive contains Git control metadata")
    return path


def _extract_regular_archive(archive_path: Path, destination: Path) -> None:
    file_count = 0
    total_size = 0
    seen: set[str] = set()
    with tarfile.open(archive_path, mode="r:") as archive:
        for member in archive:
            relative = _safe_member_name(member.name)
            key = relative.as_posix()
            if key in seen:
                raise UnsafeRepositorySnapshot("archive contains duplicate paths")
            seen.add(key)
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            if not member.isreg():
                raise UnsafeRepositorySnapshot("archive contains a link or special file")
            file_count += 1
            total_size += member.size
            if file_count > _MAX_ARCHIVE_FILES or total_size > _MAX_ARCHIVE_BYTES:
                raise UnsafeRepositorySnapshot("archive exceeds snapshot limits")
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise UnsafeRepositorySnapshot("archive regular file has no content")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(target, flags, 0o755 if member.mode & 0o111 else 0o644)
            with source, os.fdopen(descriptor, "wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
                output.flush()
                os.fsync(output.fileno())


def _tree_manifest(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    count = 0
    for directory, directory_names, filenames in os.walk(root, followlinks=False):
        parent = Path(directory)
        for name in tuple(directory_names):
            child = parent / name
            if child.is_symlink():
                raise UnsafeRepositorySnapshot("snapshot directory contains a link")
        for name in filenames:
            child = parent / name
            metadata = child.lstat()
            if not stat.S_ISREG(metadata.st_mode) or child.is_symlink():
                raise UnsafeRepositorySnapshot("snapshot contains a link or special file")
            relative = child.relative_to(root).as_posix()
            result[relative] = hashlib.sha256(child.read_bytes()).hexdigest()
            count += 1
            if count > _MAX_ARCHIVE_FILES:
                raise UnsafeRepositorySnapshot("snapshot contains too many files")
    return result


def _seal_candidate_tree(root: Path) -> None:
    """Make a patched tree traversable but immutable to the candidate UID."""
    for directory, directory_names, filenames in os.walk(root, topdown=False):
        parent = Path(directory)
        for name in filenames:
            child = parent / name
            metadata = child.lstat()
            if not stat.S_ISREG(metadata.st_mode) or child.is_symlink():
                raise UnsafeRepositorySnapshot("candidate tree contains a special file")
            child.chmod(0o555 if metadata.st_mode & 0o111 else 0o444)
        for name in directory_names:
            child = parent / name
            if child.is_symlink() or not child.is_dir():
                raise UnsafeRepositorySnapshot("candidate tree contains a special directory")
            child.chmod(0o555)
    root.chmod(0o555)


class EphemeralWorktree:
    def __init__(
        self,
        *,
        jobs_root: Path,
        workspaces_root: Path,
        git: Path,
        document: WarrantDocument,
        authority: AuthoritySnapshot,
    ) -> None:
        self._jobs_root = jobs_root
        self._workspaces_root = workspaces_root
        self._git = git
        self._document = document
        self._authority = authority
        self._job_root: Path | None = None
        self._workspace_root: Path | None = None

    async def __aenter__(self) -> PreparedWorkspace:
        try:
            return await asyncio.to_thread(self._prepare)
        except BaseException:
            await asyncio.to_thread(self._cleanup)
            raise

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await asyncio.to_thread(self._cleanup)

    def _prepare(self) -> PreparedWorkspace:
        self._jobs_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._jobs_root.chmod(0o700)
        self._workspaces_root.mkdir(mode=0o755, parents=True, exist_ok=True)
        self._workspaces_root.chmod(0o755)
        self._job_root = Path(
            tempfile.mkdtemp(prefix=f"{self._document.warrant_id}-", dir=self._jobs_root)
        )
        self._job_root.chmod(0o700)
        workspace = Path(
            tempfile.mkdtemp(
                prefix=f"{self._document.warrant_id}-",
                dir=self._workspaces_root,
            )
        )
        self._workspace_root = workspace
        workspace.chmod(0o700)

        repository = self._authority.repository_root.resolve(strict=True)
        if not repository.is_dir():
            raise UnsafeRepositorySnapshot("authority repository root is not a directory")
        resolved_commit = (
            _run_git_bytes(
                self._git,
                repository,
                self._job_root,
                "rev-parse",
                "--verify",
                f"{self._document.base_sha}^{{commit}}",
            )
            .decode("ascii")
            .strip()
        )
        if resolved_commit != self._document.base_sha:
            raise UnsafeRepositorySnapshot("base SHA does not resolve to the exact bound commit")
        manifest = repository_manifest_sha256(
            repository, self._document.base_sha, git_executable=self._git
        )
        if manifest != self._document.repository_manifest_sha256:
            raise UnsafeRepositorySnapshot("repository manifest changed from the warrant")

        archive_path = self._job_root / "base.tar"
        with archive_path.open("xb") as archive_file:
            result = subprocess.run(
                [
                    *_git_prefix(self._git, repository),
                    "archive",
                    "--format=tar",
                    self._document.base_sha,
                ],
                check=False,
                stdout=archive_file,
                stderr=subprocess.PIPE,
                env=_git_environment(self._job_root),
                timeout=60,
                preexec_fn=_limit_archive_writer,
            )
        if result.returncode != 0 or archive_path.stat().st_size > _MAX_ARCHIVE_BYTES:
            raise UnsafeRepositorySnapshot("failed to materialize the bounded source archive")
        _extract_regular_archive(archive_path, workspace)
        archive_path.unlink()

        validate_declared_patch_paths(
            workspace, self._document.patch_bytes, self._document.allowed_paths
        )
        base_manifest = _tree_manifest(workspace)
        patch_path = self._job_root / "approved.patch"
        patch_path.write_bytes(self._document.patch_bytes)
        patch_path.chmod(0o400)
        apply_result = subprocess.run(
            [
                *_git_prefix(self._git, workspace),
                "apply",
                "--no-index",
                "--recount",
                "--whitespace=nowarn",
                str(patch_path),
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=_git_environment(self._job_root),
            timeout=30,
        )
        if apply_result.returncode != 0:
            raise UnsafeRepositorySnapshot("approved patch does not apply to the bound base")
        candidate_manifest = _tree_manifest(workspace)
        changed = tuple(
            sorted(
                path
                for path in set(base_manifest) | set(candidate_manifest)
                if base_manifest.get(path) != candidate_manifest.get(path)
            )
        )
        if changed != self._document.allowed_paths:
            raise UnsafeRepositorySnapshot("resulting tree changed outside exact allowed paths")

        context = {
            "allowed_paths": list(self._document.allowed_paths),
            "base_file_sha256": {
                path: base_manifest.get(path) for path in self._document.allowed_paths
            },
            "base_sha": self._document.base_sha,
            "candidate_file_sha256": {
                path: candidate_manifest.get(path) for path in self._document.allowed_paths
            },
            "candidate_root": str(workspace.resolve()),
            "format": CONTEXT_FORMAT,
            "patch_sha256": self._document.patch_sha256,
        }
        context_path = self._job_root / "candidate-context.json"
        context_path.write_bytes(canonical_json(context))
        # The trusted supervisor owns this oracle-only file. Candidate services
        # receive neither a mount nor a path to it.
        context_path.chmod(0o400)
        _seal_candidate_tree(workspace)
        return PreparedWorkspace(root=workspace, context_path=context_path)

    def _cleanup(self) -> None:
        if self._job_root is None:
            return
        roots = tuple(
            root for root in (self._workspace_root, self._job_root) if root is not None
        )
        self._workspace_root = None
        self._job_root = None
        for root in roots:
            if not root.exists():
                continue
            root.chmod(0o700)
            for directory, directory_names, filenames in os.walk(root, topdown=False):
                for name in filenames:
                    try:
                        (Path(directory) / name).chmod(0o600, follow_symlinks=False)
                    except (FileNotFoundError, NotImplementedError):
                        pass
                for name in directory_names:
                    try:
                        (Path(directory) / name).chmod(0o700, follow_symlinks=False)
                    except (FileNotFoundError, NotImplementedError):
                        pass
            shutil.rmtree(root)


class EphemeralWorktreeFactory:
    def __init__(
        self,
        *,
        jobs_root: str | Path,
        workspaces_root: str | Path | None = None,
        git_executable: str | Path | None = None,
    ) -> None:
        self._jobs_root = Path(jobs_root).resolve()
        self._workspaces_root = (
            Path(workspaces_root).resolve()
            if workspaces_root is not None
            else self._jobs_root.parent / f"{self._jobs_root.name}-workspaces"
        )
        self._git = _resolve_git(git_executable)

    def create(self, document: WarrantDocument, authority: AuthoritySnapshot) -> EphemeralWorktree:
        return EphemeralWorktree(
            jobs_root=self._jobs_root,
            workspaces_root=self._workspaces_root,
            git=self._git,
            document=document,
            authority=authority,
        )
