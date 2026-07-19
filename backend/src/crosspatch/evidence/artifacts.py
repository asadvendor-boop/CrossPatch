"""Incident-scoped, content-addressed storage for raw and sanitized artifacts."""

from __future__ import annotations

import errno
import hashlib
import os
import re
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, overload

_INCIDENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FILE_MODE = 0o600
_DIRECTORY_MODE = 0o700
_READ_CHUNK_BYTES = 1024 * 1024


class ArtifactError(RuntimeError):
    """Base class for artifact storage failures."""


class UnsafeArtifactPath(ArtifactError):
    """Raised when a path is not an ordinary, privately owned store path."""


class ArtifactIntegrityError(ArtifactError):
    """Raised when a typed reference does not match the artifact on disk."""


@dataclass(frozen=True, slots=True)
class RawArtifactRef:
    """Typed reference usable only with the bound incident's raw accessor."""

    incident_id: str
    sha256: str
    size_bytes: int
    namespace: Literal["raw"] = "raw"


@dataclass(frozen=True, slots=True)
class SanitizedArtifactRef:
    """Typed reference usable only with the bound incident's sanitized accessor."""

    incident_id: str
    sha256: str
    size_bytes: int
    namespace: Literal["sanitized"] = "sanitized"


ArtifactRef = RawArtifactRef | SanitizedArtifactRef


class ArtifactStore:
    """A store bound to one incident and two physically separate namespaces.

    The API intentionally has no generic ``get(hash)`` operation. Callers must
    possess a namespace-specific typed reference issued for this incident.
    """

    def __init__(
        self,
        raw_root: Path | str,
        sanitized_root: Path | str,
        *,
        incident_id: str,
    ) -> None:
        if not _INCIDENT_ID.fullmatch(incident_id) or incident_id in {".", ".."}:
            raise ValueError("incident_id must be a safe, non-empty storage identifier")

        self._raw_root = _absolute_path(raw_root)
        self._sanitized_root = _absolute_path(sanitized_root)
        if _paths_overlap(self._raw_root, self._sanitized_root):
            raise ValueError("raw and sanitized artifacts require separate roots")

        self.incident_id = incident_id
        _ensure_private_directory(self._raw_root)
        _ensure_private_directory(self._sanitized_root)
        if _paths_overlap(
            self._raw_root.resolve(strict=True),
            self._sanitized_root.resolve(strict=True),
        ):
            raise ValueError("raw and sanitized artifacts require separate roots")

        self._raw_incident_root = self._raw_root / incident_id
        self._sanitized_incident_root = self._sanitized_root / incident_id
        _ensure_private_directory(self._raw_incident_root)
        _ensure_private_directory(self._sanitized_incident_root)

    def put_raw(self, value: bytes) -> RawArtifactRef:
        """Durably store raw bytes without making them hash-addressable to callers."""
        digest = self._put("raw", value)
        return RawArtifactRef(
            incident_id=self.incident_id,
            sha256=digest,
            size_bytes=len(value),
        )

    def put_sanitized(self, value: bytes) -> SanitizedArtifactRef:
        """Durably store sanitized bytes in the separate sanitized root."""
        digest = self._put("sanitized", value)
        return SanitizedArtifactRef(
            incident_id=self.incident_id,
            sha256=digest,
            size_bytes=len(value),
        )

    def put_evidence_pair(
        self,
        *,
        raw: bytes,
        sanitized: bytes,
    ) -> tuple[RawArtifactRef, SanitizedArtifactRef]:
        """Publish sanitized data before raw bytes so failure never exposes raw alone.

        A sanitized-only content-addressed blob is safe quarantine and can be
        garbage-collected. Typed references are returned only after both writes
        pass their hash verification.
        """
        sanitized_ref = self.put_sanitized(sanitized)
        raw_ref = self.put_raw(raw)
        return raw_ref, sanitized_ref

    def read_raw(self, reference: RawArtifactRef) -> bytes:
        """Read and hash-verify one typed raw artifact for this incident."""
        if not isinstance(reference, RawArtifactRef):
            raise TypeError("read_raw requires a RawArtifactRef")
        self._validate_reference(reference)
        return self._read_verified(self._path("raw", reference.sha256), reference)

    def read_sanitized(self, reference: SanitizedArtifactRef) -> bytes:
        """Read and hash-verify one typed sanitized artifact for this incident."""
        if not isinstance(reference, SanitizedArtifactRef):
            raise TypeError("read_sanitized requires a SanitizedArtifactRef")
        self._validate_reference(reference)
        return self._read_verified(self._path("sanitized", reference.sha256), reference)

    @overload
    def path_for_test(self, reference: RawArtifactRef) -> Path: ...

    @overload
    def path_for_test(self, reference: SanitizedArtifactRef) -> Path: ...

    def path_for_test(self, reference: ArtifactRef) -> Path:
        """Return a path for storage security tests; never expose this in an API DTO."""
        if not isinstance(reference, (RawArtifactRef, SanitizedArtifactRef)):
            raise TypeError("path_for_test requires a typed artifact reference")
        self._validate_reference(reference)
        return self._path(reference.namespace, reference.sha256)

    def _path_for_digest_for_test(
        self, namespace: Literal["raw", "sanitized"], digest: str
    ) -> Path:
        """Return an unpublished target path for preplant attack tests."""
        return self._path(namespace, digest)

    def _put(self, namespace: Literal["raw", "sanitized"], value: bytes) -> str:
        if not isinstance(value, bytes):
            raise TypeError("artifact value must be bytes")
        digest = hashlib.sha256(value).hexdigest()
        final_path = self._path(namespace, digest)
        _ensure_private_directory(final_path.parent)

        if os.path.lexists(final_path):
            self._verify_existing(final_path, digest, len(value))
            return digest

        temporary = final_path.with_name(f".{digest}.{secrets.token_hex(16)}.tmp")
        descriptor: int | None = None
        try:
            descriptor = _open_exclusive_private(temporary)
            _write_all(descriptor, value)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None

            try:
                os.link(temporary, final_path, follow_symlinks=False)
            except FileExistsError:
                self._verify_existing(final_path, digest, len(value))
            _fsync_directory(final_path.parent)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
            _fsync_directory(final_path.parent)

        self._verify_existing(final_path, digest, len(value))
        return digest

    def _verify_existing(self, path: Path, digest: str, expected_size: int) -> None:
        value, metadata = _read_private_regular(path)
        if metadata.st_size != expected_size:
            raise ArtifactIntegrityError(f"artifact size mismatch: {path.name}")
        actual = hashlib.sha256(value).hexdigest()
        if actual != digest:
            raise ArtifactIntegrityError(f"artifact hash mismatch: {path.name}")

    def _read_verified(self, path: Path, reference: ArtifactRef) -> bytes:
        value, metadata = _read_private_regular(path)
        if metadata.st_size != reference.size_bytes:
            raise ArtifactIntegrityError(f"artifact size mismatch: {path.name}")
        if hashlib.sha256(value).hexdigest() != reference.sha256:
            raise ArtifactIntegrityError(f"artifact hash mismatch: {path.name}")
        return value

    def _validate_reference(self, reference: ArtifactRef) -> None:
        if reference.incident_id != self.incident_id:
            raise ArtifactIntegrityError("artifact reference belongs to a different incident")
        if not _SHA256.fullmatch(reference.sha256) or reference.size_bytes < 0:
            raise ArtifactIntegrityError("artifact reference is malformed")

    def _path(self, namespace: Literal["raw", "sanitized"], digest: str) -> Path:
        if not _SHA256.fullmatch(digest):
            raise ValueError("digest must be a lowercase SHA-256 hex string")
        root = self._raw_incident_root if namespace == "raw" else self._sanitized_incident_root
        return root / digest[:2] / f"{digest}.blob"


def _absolute_path(value: Path | str) -> Path:
    return Path(os.path.abspath(os.fspath(value)))


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _ensure_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=_DIRECTORY_MODE, parents=True, exist_ok=True)
    except FileExistsError as error:
        raise UnsafeArtifactPath(f"artifact directory is unsafe: {path}") from error
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise UnsafeArtifactPath(f"artifact directory is unsafe: {path}")
    path.chmod(_DIRECTORY_MODE)


def _open_exclusive_private(path: Path) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, _FILE_MODE)
    os.fchmod(descriptor, _FILE_MODE)
    return descriptor


def _write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    written = 0
    while written < len(view):
        count = os.write(descriptor, view[written:])
        if count <= 0:
            raise ArtifactError("artifact write made no progress")
        written += count


def _read_private_regular(path: Path) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.EMLINK}:
            raise UnsafeArtifactPath(f"artifact path is a link: {path}") from error
        raise
    try:
        before = os.fstat(descriptor)
        _validate_private_regular(path, before)
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, _READ_CHUNK_BYTES):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        _validate_private_regular(path, after)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise ArtifactIntegrityError(f"artifact changed while being read: {path.name}")
        path_metadata = path.lstat()
        if stat.S_ISLNK(path_metadata.st_mode) or (
            path_metadata.st_dev,
            path_metadata.st_ino,
        ) != (after.st_dev, after.st_ino):
            raise UnsafeArtifactPath(f"artifact path changed while being read: {path}")
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def _validate_private_regular(path: Path, metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise UnsafeArtifactPath(f"artifact is not a single-link regular file: {path}")
    if stat.S_IMODE(metadata.st_mode) != _FILE_MODE:
        raise UnsafeArtifactPath(f"artifact mode is not 0600: {path}")


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
