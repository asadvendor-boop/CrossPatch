from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import httpx
import pytest
from crosspatch.db.models import (
    ControlWarrantRecord,
    IncidentRecord,
    MutationAuthorityRecord,
    PublishedCaseRecord,
    TimelineEventRecord,
    WarrantRecord,
)
from crosspatch.replay.app import create_replay_app
from crosspatch.replay.importer import import_sealed_case
from crosspatch.runtime.database import RuntimeDatabase
from crosspatch.runtime.readers import DatabasePublishedCaseReader
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select

ROOT = Path(__file__).resolve().parents[3]
SEALED_ARCHIVE = (
    ROOT
    / "artifacts/verification/paced-batches/paced-20260714T103240Z/run-04"
    / "real-model-cases/inc_e032c6cde04f44b8a5dc6371c8c6f690.zip"
)
PINNED_KEY = (
    ROOT
    / "artifacts/verification/paced-batches/paced-20260714T103240Z"
    / "local-export-public-key.json"
)
INCIDENT_ID = "inc_e032c6cde04f44b8a5dc6371c8c6f690"


def _read_only_url(path: Path) -> str:
    return f"sqlite+aiosqlite:///file:{path}?mode=ro&uri=true"


@pytest.mark.asyncio
async def test_signed_case_import_uses_the_existing_published_projection_boundary(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "replay.db"

    result = await import_sealed_case(SEALED_ARCHIVE, PINNED_KEY, database_path)

    assert result.incident_id == INCIDENT_ID
    assert result.event_count == 58
    assert result.source_case_sha256 == (
        "3b2c0915fc3e87666b33d5e5a7cc67532a3853b7766a485237ee04dc1612f6bb"
    )
    assert len(result.manifest_sha256) == 64
    assert database_path.stat().st_mode & 0o777 == 0o444

    database = RuntimeDatabase(_read_only_url(database_path))
    try:
        cases = await DatabasePublishedCaseReader(database.store).list_public_cases()
        assert len(cases) == 1
        assert cases[0]["incident_id"] == INCIDENT_ID
        projection = cases[0]["projection"]
        assert projection["incident"]["state"] == "VERIFIED"
        assert len(projection["events"]) == 58
        warrant = projection["warrants"][0]
        anatomy = json.loads(warrant["public_warrant_bytes"])
        assert anatomy["allowed_paths"] == ["victim/src/victim/db.py"]
        assert anatomy["plan_ids"] == ["victim.duplicate-race.candidate"]
        assert anatomy["approver_identity"] == "approver-1"
        assert anatomy["nonce_sha256"] == warrant["nonce_sha256"]

        async with database.sessions() as session:
            assert await session.scalar(select(func.count()).select_from(IncidentRecord)) == 1
            assert await session.scalar(select(func.count()).select_from(PublishedCaseRecord)) == 1
            for authority_model in (
                MutationAuthorityRecord,
                ControlWarrantRecord,
                WarrantRecord,
                TimelineEventRecord,
            ):
                assert await session.scalar(select(func.count()).select_from(authority_model)) == 0
    finally:
        await database.close()


@pytest.mark.asyncio
async def test_replay_api_has_only_health_and_published_case_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "replay.db"
    await import_sealed_case(SEALED_ARCHIVE, PINNED_KEY, database_path)
    monkeypatch.setenv("OPENAI_API_KEY", "")
    app = create_replay_app(database_url=_read_only_url(database_path))

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://replay") as client:
            health = await client.get("/healthz")
            index = await client.get("/api/public/cases")
            detail = await client.get(f"/api/public/cases/{INCIDENT_ID}")
            assert health.status_code == 200
            assert index.status_code == 200
            assert detail.status_code == 200
            assert index.json()["cases"][0]["incident_id"] == INCIDENT_ID
            assert detail.json()["projection"]["incident"]["id"] == INCIDENT_ID

            forbidden = (
                ("POST", "/api/incidents"),
                ("GET", f"/api/incidents/{INCIDENT_ID}"),
                ("POST", "/api/warrants/war-replay/approve"),
                ("POST", "/api/warrants/war-replay/reject"),
                ("GET", f"/api/incidents/{INCIDENT_ID}/export"),
                ("POST", "/mcp"),
            )
            for method, path in forbidden:
                response = await client.request(method, path, json={})
                assert response.status_code == 404, (method, path, response.text)


@pytest.mark.asyncio
async def test_import_fails_closed_before_creating_storage_on_archive_or_key_tamper(
    tmp_path: Path,
) -> None:
    tampered_archive = tmp_path / "tampered.zip"
    archive_bytes = bytearray(SEALED_ARCHIVE.read_bytes())
    archive_bytes[len(archive_bytes) // 2] ^= 0x01
    tampered_archive.write_bytes(archive_bytes)

    bad_key = tmp_path / "bad-key.json"
    key_document = json.loads(PINNED_KEY.read_text(encoding="utf-8"))
    key_document["public_key_sha256"] = "0" * 64
    bad_key.write_text(json.dumps(key_document), encoding="utf-8")

    for archive, key, output, expected in (
        (
            tampered_archive,
            PINNED_KEY,
            tmp_path / "archive-tamper.db",
            "not the pinned run-04 artifact",
        ),
        (
            SEALED_ARCHIVE,
            bad_key,
            tmp_path / "key-tamper.db",
            "public-key document hashes are invalid",
        ),
    ):
        with pytest.raises(ValueError, match=expected):
            await import_sealed_case(archive, key, output)
        assert not output.exists()


@pytest.mark.asyncio
async def test_import_rejects_a_valid_but_unpinned_signing_key(tmp_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    challenge = b"crosspatch-replay-alternate-key-control"
    signature = private_key.sign(challenge)
    alternate_key = tmp_path / "alternate-key.json"
    alternate_key.write_text(
        json.dumps(
            {
                "algorithm": "Ed25519",
                "machine_generated": True,
                "private_seed_included": False,
                "proof_challenge_base64": base64.b64encode(challenge).decode("ascii"),
                "proof_signature_base64": base64.b64encode(signature).decode("ascii"),
                "proof_signature_sha256": hashlib.sha256(signature).hexdigest(),
                "public_key_base64": base64.b64encode(public_key).decode("ascii"),
                "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
                "status": "PASS",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="not the pinned cohort key"):
        await import_sealed_case(SEALED_ARCHIVE, alternate_key, tmp_path / "alternate.db")


@pytest.mark.asyncio
async def test_failed_publication_never_removes_an_independent_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "replay.db"

    def competing_publication(_source: Path, target: Path) -> None:
        target.write_bytes(b"independently-created-database")
        raise FileExistsError("destination won by another publisher")

    monkeypatch.setattr("crosspatch.replay.importer.os.link", competing_publication)

    with pytest.raises(FileExistsError, match="another publisher"):
        await import_sealed_case(SEALED_ARCHIVE, PINNED_KEY, destination)

    assert destination.read_bytes() == b"independently-created-database"


@pytest.mark.asyncio
async def test_post_link_replacement_is_rejected_without_removing_the_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "replay.db"
    real_link = os.link

    def replace_after_link(source: Path, target: Path) -> None:
        real_link(source, target)
        target.unlink()
        target.write_bytes(b"replacement-owned-by-another-publisher")

    monkeypatch.setattr("crosspatch.replay.importer.os.link", replace_after_link)

    with pytest.raises(ValueError, match="identity changed during publication"):
        await import_sealed_case(SEALED_ARCHIVE, PINNED_KEY, destination)

    assert destination.read_bytes() == b"replacement-owned-by-another-publisher"


def test_replay_factory_rejects_any_model_key_or_writable_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "paid-key-must-never-enter-replay")
    with pytest.raises(ValueError, match="model credentials"):
        create_replay_app(database_url="sqlite+aiosqlite:///replay.db")

    monkeypatch.setenv("OPENAI_API_KEY", "")
    with pytest.raises(ValueError, match="read-only SQLite"):
        create_replay_app(database_url="sqlite+aiosqlite:///replay.db")
