from __future__ import annotations

import base64
import hashlib
import io
import json
import stat
import struct
import warnings
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest
from crosspatch.export import verifier as export_verifier
from crosspatch.export.builder import CaseBinding, CaseExportBuilder, ExportArtifact
from crosspatch.export.verifier import VerificationLimits, verify_export
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def public_key(signing_key: Ed25519PrivateKey) -> bytes:
    return signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


@pytest.fixture
def binding() -> CaseBinding:
    return CaseBinding(
        incident_id="inc-a",
        base_sha="1" * 40,
        verdict_sha256="2" * 64,
        warrant_sha256="3" * 64,
        receipt_sha256="4" * 64,
        timeline_head="5" * 64,
    )


@pytest.fixture
def artifacts() -> tuple[ExportArtifact, ...]:
    return (
        ExportArtifact(
            path="evidence/victim-log.txt",
            incident_id="inc-a",
            kind="sanitized_evidence",
            data=b"sanitized output; POTENTIAL_INSTRUCTION_REDACTED",
            provenance="crosspatch.evidence-service",
        ),
        ExportArtifact(
            path="verdicts/magistrate.json",
            incident_id="inc-a",
            kind="verdict",
            data=b'{"verdict":"CLEAR"}',
            provenance="crosspatch.orchestrator",
        ),
    )


@pytest.fixture
def export_zip(
    signing_key: Ed25519PrivateKey,
    binding: CaseBinding,
    artifacts: tuple[ExportArtifact, ...],
) -> bytes:
    return CaseExportBuilder(signing_key).build(binding, artifacts)


def _members(archive: bytes) -> dict[str, tuple[zipfile.ZipInfo, bytes]]:
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        return {info.filename: (info, source.read(info)) for info in source.infolist()}


def _archive(members: list[tuple[zipfile.ZipInfo | str, bytes]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for info_or_name, data in members:
            if isinstance(info_or_name, str):
                target.writestr(info_or_name, data)
            else:
                target.writestr(info_or_name, data)
    return output.getvalue()


def _replace_member(archive: bytes, name: str, value: bytes) -> bytes:
    members = _members(archive)
    members[name] = (members[name][0], value)
    return _archive([(info, data) for info, data in members.values()])


def _append_member(archive: bytes, info_or_name: zipfile.ZipInfo | str, value: bytes) -> bytes:
    original = list(_members(archive).values())
    return _archive([*original, (info_or_name, value)])


def _signed_archive(
    signing_key: Ed25519PrivateKey,
    manifest: dict[str, object],
    files: dict[str, bytes],
) -> bytes:
    manifest_bytes = _canonical(manifest)
    signature = signing_key.sign(manifest_bytes)
    return _archive(
        [
            ("manifest.json", manifest_bytes),
            ("manifest.sig", base64.b64encode(signature)),
            *files.items(),
        ]
    )


def test_valid_export_is_canonical_signed_and_incident_bound(export_zip: bytes, public_key: bytes):
    result = verify_export(export_zip, public_key)

    assert result.valid is True
    assert result.errors == ()
    assert result.manifest is not None
    assert result.manifest["incident"]["id"] == "inc-a"
    assert result.manifest["incident"]["timeline_head"] == "5" * 64
    encoded = export_zip.lower()
    assert b"raw-password" not in encoded
    assert b"raw_sha256" not in encoded


def test_payload_equivalence_export_manifest_decodes_typed_recorded_proof(
    signing_key: Ed25519PrivateKey,
    public_key: bytes,
    artifacts: tuple[ExportArtifact, ...],
) -> None:
    binding = CaseBinding(
        incident_id="inc-equivalence-export",
        base_sha="1" * 40,
        verdict_sha256="2" * 64,
        warrant_sha256="3" * 64,
        receipt_sha256="4" * 64,
        timeline_head="5" * 64,
        scenario="webhook-payload-equivalence",
        plan_id="victim.payload-equivalence.candidate",
        plan_sha256="6" * 64,
        execution_status="EXECUTED",
        response_statuses=(202, 200, 409),
        counts=(1, 1, 1),
        trusted_observation_sha256="7" * 64,
    )
    rebound_artifacts = tuple(
        replace(artifact, incident_id=binding.incident_id) for artifact in artifacts
    )

    result = verify_export(
        CaseExportBuilder(signing_key).build(binding, rebound_artifacts),
        public_key,
    )

    assert result.valid is True
    assert result.manifest is not None
    assert result.manifest["incident"] == {
        "base_sha": "1" * 40,
        "counts": {"receipts": 1, "jobs": 1, "deliveries": 1},
        "execution_status": "EXECUTED",
        "id": "inc-equivalence-export",
        "plan_id": "victim.payload-equivalence.candidate",
        "plan_sha256": "6" * 64,
        "receipt_sha256": "4" * 64,
        "response_statuses": [202, 200, 409],
        "scenario": "webhook-payload-equivalence",
        "timeline_head": "5" * 64,
        "trusted_observation_sha256": "7" * 64,
        "verdict_sha256": "2" * 64,
        "warrant_sha256": "3" * 64,
    }


@pytest.mark.parametrize(
    "overrides",
    [
        {"scenario": "webhook-payload-equivalence"},
        {
            "scenario": "webhook-payload-equivalence",
            "plan_id": "victim.payload-equivalence.candidate",
            "plan_sha256": "6" * 64,
            "execution_status": "EXECUTED",
            "response_statuses": (202, 99, 409),
            "counts": (1, 1, 1),
            "trusted_observation_sha256": "7" * 64,
        },
    ],
)
def test_payload_equivalence_export_binding_fails_closed_when_partial_or_malformed(
    binding: CaseBinding,
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        replace(binding, **overrides)


def test_builder_rejects_raw_unpublished_cross_incident_and_unsafe_artifacts(
    signing_key: Ed25519PrivateKey,
    binding: CaseBinding,
) -> None:
    invalid = (
        ExportArtifact(
            path="evidence/raw.log",
            incident_id="inc-a",
            kind="raw_evidence",
            data=b"secret",
            provenance="raw-store",
        ),
        ExportArtifact(
            path="evidence/private.log",
            incident_id="inc-a",
            kind="sanitized_evidence",
            data=b"private",
            provenance="evidence",
            publicable=False,
        ),
        ExportArtifact(
            path="evidence/b.log",
            incident_id="inc-b",
            kind="sanitized_evidence",
            data=b"B-UNIQUE-SENTINEL",
            provenance="evidence",
        ),
        ExportArtifact(
            path="../escape",
            incident_id="inc-a",
            kind="test",
            data=b"x",
            provenance="runner",
        ),
    )
    for artifact in invalid:
        with pytest.raises(ValueError):
            CaseExportBuilder(signing_key).build(binding, (artifact,))


def test_export_verifier_detects_tampered_blob(export_zip: bytes, public_key: bytes) -> None:
    member = next(name for name in _members(export_zip) if name.startswith("incidents/"))
    tampered = _replace_member(export_zip, member, b"tampered")

    assert verify_export(tampered, public_key).valid is False


def test_rehashed_manifest_and_blob_still_fail_pinned_signature(
    export_zip: bytes, public_key: bytes
) -> None:
    members = _members(export_zip)
    manifest = json.loads(members["manifest.json"][1])
    member = next(name for name in members if name.startswith("incidents/"))
    replacement = b"attacker rewrite"
    for entry in manifest["files"]:
        if entry["path"] == member:
            entry["sha256"] = hashlib.sha256(replacement).hexdigest()
            entry["size_bytes"] = len(replacement)
    tampered = _replace_member(export_zip, member, replacement)
    tampered = _replace_member(tampered, "manifest.json", _canonical(manifest))

    assert verify_export(tampered, public_key).valid is False


def test_bad_signature_fails(export_zip: bytes, public_key: bytes) -> None:
    bad = _replace_member(export_zip, "manifest.sig", base64.b64encode(b"0" * 64))
    assert verify_export(bad, public_key).valid is False


@pytest.mark.parametrize("malformation", ["duplicate", "traversal", "symlink", "unmanifested"])
def test_archive_structure_fails_closed_without_extraction(
    malformation: str,
    export_zip: bytes,
    public_key: bytes,
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.write_text("unchanged")
    first_artifact = next(name for name in _members(export_zip) if name.startswith("incidents/"))
    if malformation == "duplicate":
        members = list(_members(export_zip).values())
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            malformed = _archive([*members, (first_artifact, b"duplicate")])
    elif malformation == "traversal":
        malformed = _append_member(export_zip, "../outside", b"changed")
    elif malformation == "symlink":
        info = zipfile.ZipInfo("incidents/inc-a/evidence/link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        malformed = _append_member(export_zip, info, b"../../outside")
    else:
        malformed = _append_member(export_zip, "incidents/inc-a/unmanifested", b"surprise")

    result = verify_export(malformed, public_key)
    assert result.valid is False
    assert outside.read_text() == "unchanged"


def test_signed_cross_incident_member_is_rejected(
    signing_key: Ed25519PrivateKey,
    public_key: bytes,
    export_zip: bytes,
) -> None:
    manifest = json.loads(_members(export_zip)["manifest.json"][1])
    payload = b"B-UNIQUE-SENTINEL"
    path = "incidents/inc-b/evidence/b.log"
    manifest["files"] = [
        {
            "incident_id": "inc-b",
            "kind": "sanitized_evidence",
            "path": path,
            "provenance": "evidence",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        }
    ]
    malicious = _signed_archive(signing_key, manifest, {path: payload})

    result = verify_export(malicious, public_key)
    assert result.valid is False
    assert "B-UNIQUE-SENTINEL" not in repr(result)


def test_compression_ratio_and_size_limits_fail_closed(
    signing_key: Ed25519PrivateKey,
    public_key: bytes,
    binding: CaseBinding,
) -> None:
    artifact = ExportArtifact(
        path="tests/large.txt",
        incident_id="inc-a",
        kind="test",
        data=b"0" * 20_000,
        provenance="runner",
    )
    archive = CaseExportBuilder(signing_key).build(binding, (artifact,))
    limits = VerificationLimits(
        max_members=16,
        max_archive_bytes=100_000,
        max_member_bytes=50_000,
        max_total_bytes=50_000,
        max_compression_ratio=5,
    )

    assert verify_export(archive, public_key, limits=limits).valid is False


def test_central_directory_bound_is_checked_before_zip_parser_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    eocd = struct.pack(
        "<4s4H2LH",
        b"PK\x05\x06",
        0,
        0,
        3,
        3,
        4_096,
        0,
        0,
    )
    limits = VerificationLimits(
        max_members=16,
        max_archive_bytes=10_000,
        max_member_bytes=1_000,
        max_total_bytes=2_000,
        max_central_directory_bytes=128,
    )

    def parser_must_not_run(*_args, **_kwargs):
        raise AssertionError("ZIP parser ran before central-directory bounds")

    monkeypatch.setattr(export_verifier.zipfile, "ZipFile", parser_must_not_run)

    result = verify_export(eocd, b"k" * 32, limits=limits)

    assert result.valid is False
    assert result.errors == ("CENTRAL_DIRECTORY_SIZE",)


def test_manifest_with_duplicate_json_key_is_rejected(
    export_zip: bytes,
    public_key: bytes,
) -> None:
    duplicate = b'{"format":"crosspatch-case-v1","format":"crosspatch-case-v1"}'
    malformed = _replace_member(export_zip, "manifest.json", duplicate)
    assert verify_export(malformed, public_key).valid is False


def test_export_artifact_data_is_immutable_bytes(binding: CaseBinding) -> None:
    with pytest.raises(TypeError):
        replace(
            ExportArtifact(
                path="tests/x",
                incident_id="inc-a",
                kind="test",
                data=b"x",
                provenance="runner",
            ),
            data="not-bytes",  # type: ignore[arg-type]
        )
