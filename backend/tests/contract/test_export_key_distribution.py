from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import stat
from pathlib import Path

import pytest
from crosspatch.export.verifier import verify_export
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[3]
PRODUCTION_SOURCE = (
    ROOT
    / "artifacts/verification/operator-session-20260717T074450Z"
    / "production-export-public-key.json"
)
SEALED_SOURCE = (
    ROOT
    / "artifacts/verification/paced-batches/paced-20260714T103240Z"
    / "local-export-public-key.json"
)
PRODUCTION_CASE = (
    ROOT
    / "artifacts/verification/operator-session-20260717T074450Z/real-model-cases"
    / "inc_03d46c72ab2f4ca8943f3fa5fd83b152.zip"
)
SEALED_CASE = (
    ROOT
    / "artifacts/verification/paced-batches/paced-20260714T103240Z/run-04/real-model-cases"
    / "inc_e032c6cde04f44b8a5dc6371c8c6f690.zip"
)
PUBLIC_DIRECTORY = ROOT / "web/public/verification"


def _load_script():
    path = ROOT / "scripts/publish_export_public_keys.py"
    specification = importlib.util.spec_from_file_location(
        "crosspatch_publish_export_public_keys",
        path,
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _payload(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def _public_key(payload: dict[str, object]) -> bytes:
    return base64.b64decode(str(payload["public_key_base64"]), validate=True)


def test_generator_copies_only_valid_runtime_proofs_and_builds_complete_manifest(
    tmp_path: Path,
) -> None:
    module = _load_script()

    outputs = module.publish(output_directory=tmp_path)

    assert (tmp_path / "production-export-public-key.json").read_bytes() == (
        PRODUCTION_SOURCE.read_bytes()
    )
    assert (tmp_path / "sealed-cohort-export-public-key.json").read_bytes() == (
        SEALED_SOURCE.read_bytes()
    )
    manifest = _payload(tmp_path / "export-public-keys.json")
    assert outputs == {
        "production-export-public-key.json",
        "sealed-cohort-export-public-key.json",
        "export-public-keys.json",
    }
    for filename in outputs:
        assert stat.S_IMODE((tmp_path / filename).stat().st_mode) == 0o644
    assert manifest["schema_version"] == "crosspatch.export-public-keys.v1"
    assert manifest["machine_generated"] is True
    assert manifest["private_seed_included"] is False
    assert manifest["generator"] == "scripts/publish_export_public_keys.py"
    assert [item["role"] for item in manifest["keys"]] == [
        "production",
        "sealed-cohort",
    ]
    for item, source in zip(
        manifest["keys"],
        (PRODUCTION_SOURCE, SEALED_SOURCE),
        strict=True,
    ):
        source_payload = _payload(source)
        assert item["status"] == "PASS"
        assert item["runtime_proof_verified"] is True
        assert item["source_artifact_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
        assert item["public_key_sha256"] == source_payload["public_key_sha256"]
        assert item["git_sha"] == source_payload["git_sha"]


def test_generator_rejects_unexpected_secret_bearing_proof_fields(tmp_path: Path) -> None:
    module = _load_script()
    payload = _payload(PRODUCTION_SOURCE)
    payload["private_seed_base64"] = "c2VjcmV0LW1hdGVyaWFs"
    contradictory = tmp_path / "contradictory-proof.json"
    contradictory.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(module.ExportKeyDistributionError, match="unexpected fields"):
        module._load_validated_proof(contradictory)


def test_distributed_keys_verify_only_their_recorded_export_lineage() -> None:
    production = _payload(PUBLIC_DIRECTORY / "production-export-public-key.json")
    sealed = _payload(PUBLIC_DIRECTORY / "sealed-cohort-export-public-key.json")
    production_key = _public_key(production)
    sealed_key = _public_key(sealed)

    assert verify_export(PRODUCTION_CASE, production_key).valid is True
    assert verify_export(SEALED_CASE, sealed_key).valid is True
    assert verify_export(PRODUCTION_CASE, sealed_key).valid is False
    assert verify_export(SEALED_CASE, production_key).valid is False
    assert production["public_key_sha256"] == hashlib.sha256(production_key).hexdigest()
    assert sealed["public_key_sha256"] == hashlib.sha256(sealed_key).hexdigest()
    assert production["public_key_sha256"] != sealed["public_key_sha256"]


def test_checked_in_distribution_is_deterministic_and_contains_no_private_material(
    tmp_path: Path,
) -> None:
    module = _load_script()
    module.publish(output_directory=tmp_path)

    for filename in (
        "production-export-public-key.json",
        "sealed-cohort-export-public-key.json",
        "export-public-keys.json",
    ):
        checked_in = (PUBLIC_DIRECTORY / filename).read_bytes()
        assert checked_in == (tmp_path / filename).read_bytes()
        assert stat.S_IMODE((PUBLIC_DIRECTORY / filename).stat().st_mode) == 0o644
        lowered = checked_in.lower()
        assert b"private_key" not in lowered
        assert json.loads(checked_in)["private_seed_included"] is False

    for source in (PRODUCTION_SOURCE, SEALED_SOURCE):
        payload = _payload(source)
        public_key = Ed25519PublicKey.from_public_bytes(_public_key(payload))
        challenge = base64.b64decode(str(payload["proof_challenge_base64"]), validate=True)
        signature = base64.b64decode(str(payload["proof_signature_base64"]), validate=True)
        try:
            public_key.verify(signature, challenge)
        except InvalidSignature as error:
            raise AssertionError(f"runtime proof signature failed for {source}") from error
