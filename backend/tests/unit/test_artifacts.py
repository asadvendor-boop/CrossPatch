from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest
from crosspatch.evidence.artifacts import (
    ArtifactIntegrityError,
    ArtifactStore,
    RawArtifactRef,
    SanitizedArtifactRef,
    UnsafeArtifactPath,
)

INCIDENT_ID = "inc-2026-0001"


def _store(tmp_path: Path, *, incident_id: str = INCIDENT_ID) -> ArtifactStore:
    return ArtifactStore(tmp_path / "raw", tmp_path / "sanitized", incident_id=incident_id)


def test_raw_and_sanitized_artifacts_use_separate_private_roots(tmp_path: Path) -> None:
    store = _store(tmp_path)

    raw = store.put_raw(b"raw sentinel")
    sanitized = store.put_sanitized(b"safe view")

    raw_path = store.path_for_test(raw)
    sanitized_path = store.path_for_test(sanitized)
    assert raw_path.is_relative_to(tmp_path / "raw")
    assert sanitized_path.is_relative_to(tmp_path / "sanitized")
    assert raw_path.parent != sanitized_path.parent
    assert stat.S_IMODE(raw_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(sanitized_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "raw").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "sanitized").stat().st_mode) == 0o700


def test_content_addressed_writes_are_idempotent_and_leave_no_temporary_files(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)

    first = store.put_raw(b"same bytes")
    second = store.put_raw(b"same bytes")

    assert first == second
    assert first.sha256 == hashlib.sha256(b"same bytes").hexdigest()
    assert [path.name for path in store.path_for_test(first).parent.iterdir()] == [
        f"{first.sha256}.blob"
    ]


@pytest.mark.parametrize("attack", ["symlink", "hardlink"])
def test_preplanted_link_is_rejected_without_modifying_external_target(
    tmp_path: Path, attack: str
) -> None:
    store = _store(tmp_path)
    payload = b"sentinel"
    digest = hashlib.sha256(payload).hexdigest()
    final_path = store._path_for_digest_for_test("raw", digest)
    final_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.write_bytes(payload)
    if attack == "symlink":
        final_path.symlink_to(outside)
    else:
        os.link(outside, final_path)

    with pytest.raises(UnsafeArtifactPath):
        store.put_raw(payload)

    assert outside.read_bytes() == payload


def test_hash_is_verified_when_an_incident_scoped_typed_ref_is_read(tmp_path: Path) -> None:
    store = _store(tmp_path)
    ref = store.put_raw(b"original")
    store.path_for_test(ref).write_bytes(b"tampered")

    with pytest.raises(ArtifactIntegrityError, match="hash mismatch"):
        store.read_raw(ref)


def test_cross_incident_ref_and_untyped_hash_access_are_unavailable(tmp_path: Path) -> None:
    first = _store(tmp_path, incident_id="inc-a")
    second = _store(tmp_path, incident_id="inc-b")
    ref = first.put_raw(b"incident a")

    with pytest.raises(ArtifactIntegrityError, match="incident"):
        second.read_raw(ref)
    assert not hasattr(first, "get")
    with pytest.raises(TypeError):
        first.read_raw(ref.sha256)  # type: ignore[arg-type]


def test_typed_namespaces_cannot_be_confused(tmp_path: Path) -> None:
    store = _store(tmp_path)
    raw = store.put_raw(b"raw")
    sanitized = store.put_sanitized(b"sanitized")

    assert isinstance(raw, RawArtifactRef)
    assert isinstance(sanitized, SanitizedArtifactRef)
    with pytest.raises(TypeError):
        store.read_raw(sanitized)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        store.read_sanitized(raw)  # type: ignore[arg-type]


@pytest.mark.parametrize("incident_id", ["../escape", "a/b", ".", "", "two words"])
def test_incident_id_cannot_escape_its_namespace(tmp_path: Path, incident_id: str) -> None:
    with pytest.raises(ValueError, match="incident_id"):
        _store(tmp_path, incident_id=incident_id)


def test_roots_must_be_distinct(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="separate"):
        ArtifactStore(tmp_path, tmp_path, incident_id=INCIDENT_ID)


def test_roots_must_not_be_nested(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="separate"):
        ArtifactStore(
            tmp_path / "artifacts", tmp_path / "artifacts" / "safe", incident_id=INCIDENT_ID
        )
