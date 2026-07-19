from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"


def _load_script(name: str) -> ModuleType:
    path = SCRIPTS / name
    assert path.is_file(), f"missing checked-in release generator: scripts/{name}"
    specification = importlib.util.spec_from_file_location(f"crosspatch_{path.stem}", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    sys.path.insert(0, str(SCRIPTS))
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPTS))
    return module


def _stub_provisional_claim_map(
    module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(module, "ensure_external_artifacts", lambda: ())
    monkeypatch.setattr(
        module,
        "load_claim_map_base",
        lambda: {"claims": []},
        raising=False,
    )
    monkeypatch.setattr(
        module,
        "rebind_refreshed_claims",
        lambda base, _refreshed: base,
        raising=False,
    )
    monkeypatch.setattr(module, "generate_claim_map", lambda: {"claims": []})


def _ecosystem(component: dict[str, Any]) -> str:
    properties = component.get("properties", [])
    return next(
        item["value"]
        for item in properties
        if item.get("name") == "crosspatch:ecosystem"
    )


def test_sbom_is_deterministic_and_covers_both_locked_dependency_graphs() -> None:
    module = _load_script("generate_sbom.py")

    first = module.canonical_json_bytes(module.build_sbom(ROOT))
    second = module.canonical_json_bytes(module.build_sbom(ROOT))
    payload = json.loads(first)

    assert first == second
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["specVersion"] == "1.5"

    uv_lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    expected_python = {
        (package["name"], package["version"])
        for package in uv_lock["package"]
        if "version" in package and "editable" not in package.get("source", {})
    }
    npm_lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
    expected_npm = {
        (path.rsplit("node_modules/", maxsplit=1)[1], package["version"])
        for path, package in npm_lock["packages"].items()
        if "node_modules/" in path and isinstance(package.get("version"), str)
    }
    actual_python = {
        (component["name"], component["version"])
        for component in payload["components"]
        if _ecosystem(component) == "python"
    }
    actual_npm = {
        (component["name"], component["version"])
        for component in payload["components"]
        if _ecosystem(component) == "npm"
    }

    assert actual_python == expected_python
    assert actual_npm == expected_npm
    lock_hashes = {
        item["name"]: item["value"] for item in payload["metadata"]["properties"]
    }
    assert lock_hashes == {
        "crosspatch:package-lock.json:sha256": hashlib.sha256(
            (ROOT / "package-lock.json").read_bytes()
        ).hexdigest(),
        "crosspatch:uv.lock:sha256": hashlib.sha256(
            (ROOT / "uv.lock").read_bytes()
        ).hexdigest(),
    }


def test_build_context_scan_fails_closed_without_leaking_the_detected_secret(
    tmp_path: Path,
) -> None:
    module = _load_script("scan_build_context.py")
    secret = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4P5q6"
    (tmp_path / ".dockerignore").write_text(
        ".env\n.env.*\n!.env.example\nignored/\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={secret}\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text("OPENAI_API_KEY=\n", encoding="utf-8")
    (tmp_path / "ignored").mkdir()
    (tmp_path / "ignored" / "key.txt").write_text(secret, encoding="utf-8")
    (tmp_path / "app.py").write_text(f'OPENAI_API_KEY = "{secret}"\n', encoding="utf-8")

    result = module.scan_context(tmp_path)
    encoded = json.dumps(result, sort_keys=True)

    assert result["status"] == "FAIL"
    assert result["findings"] == [
        {
            "line": 1,
            "path": "app.py",
            "rule": "OPENAI_API_KEY",
            "value_sha256": hashlib.sha256(secret.encode()).hexdigest(),
        }
    ]
    assert secret not in encoded
    assert not any(item["path"] in {".env", "ignored/key.txt"} for item in result["findings"])


def test_build_context_scan_allows_only_explicitly_documented_test_material(
    tmp_path: Path,
) -> None:
    module = _load_script("scan_build_context.py")
    fake = "ghp_" + "F" * 36
    (tmp_path / ".dockerignore").write_text("", encoding="utf-8")
    fixture_path = tmp_path / "tests" / "fixtures" / "provider_token.py"
    fixture_path.parent.mkdir(parents=True)
    fixture_path.write_text(
        f'TOKEN = "{fake}"  # secret-scan: allow=test-fixture\n',
        encoding="utf-8",
    )
    (tmp_path / "settings.example").write_text(
        "OPENAI_API_KEY=<replace-with-secret-manager-reference>\n",
        encoding="utf-8",
    )

    result = module.scan_context(tmp_path)

    assert result["status"] == "PASS"
    assert result["findings"] == []
    assert result["allowlisted"] == [
        {
            "line": 1,
            "path": "tests/fixtures/provider_token.py",
            "reason": "test-fixture",
            "rule": "GITHUB_TOKEN",
            "value_sha256": hashlib.sha256(fake.encode()).hexdigest(),
        }
    ]


def test_build_context_scan_rejects_undocumented_allow_reasons(tmp_path: Path) -> None:
    module = _load_script("scan_build_context.py")
    fake = "ghp_" + "A1b2C3d4E5f6G7h8I9j0" * 2
    (tmp_path / ".dockerignore").write_text("", encoding="utf-8")
    (tmp_path / "fixture.py").write_text(
        f'TOKEN = "{fake}"  # secret-scan: allow=temporary\n',
        encoding="utf-8",
    )

    result = module.scan_context(tmp_path)

    assert result["status"] == "FAIL"
    assert result["allowlisted"] == []
    assert result["findings"][0]["rule"] == "GITHUB_TOKEN"


def test_build_context_scan_rejects_test_fixture_marker_outside_fixture_tree(
    tmp_path: Path,
) -> None:
    module = _load_script("scan_build_context.py")
    fake = "ghp_" + "Q7w8E9r0T1y2U3i4O5p6" * 2
    (tmp_path / ".dockerignore").write_text("", encoding="utf-8")
    (tmp_path / "production.conf").write_text(
        f'TOKEN = "{fake}"  # secret-scan: allow=test-fixture\n',
        encoding="utf-8",
    )

    result = module.scan_context(tmp_path)

    assert result["status"] == "FAIL"
    assert result["allowlisted"] == []
    assert result["findings"][0]["path"] == "production.conf"


def test_build_context_scan_does_not_treat_placeholder_substrings_as_an_allowlist(
    tmp_path: Path,
) -> None:
    module = _load_script("scan_build_context.py")
    value = "A9exampleQ7w8E0r1T2y3U4i5O6p7L8k9"
    (tmp_path / ".dockerignore").write_text("", encoding="utf-8")
    (tmp_path / "settings.py").write_text(
        f'PRODUCTION_TOKEN = "{value}"\n',
        encoding="utf-8",
    )

    result = module.scan_context(tmp_path)

    assert result["status"] == "FAIL"
    assert result["allowlisted"] == []
    assert result["findings"] == [
        {
            "line": 1,
            "path": "settings.py",
            "rule": "SECRET_ASSIGNMENT",
            "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
        }
    ]


def test_build_context_scan_covers_private_key_and_dockerfile_secret_forms(
    tmp_path: Path,
) -> None:
    module = _load_script("scan_build_context.py")
    password = "D9t8r7F6v5B4n3M2" + "k1J0h9G8f7D6s5A4"
    (tmp_path / ".dockerignore").write_text("", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        "ENV DATABASE_PASSWORD " + password + "\n"
        "-----BEGIN ENCRYPTED " + "PRIVATE KEY-----\n"
        "-----BEGIN DSA " + "PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    result = module.scan_context(tmp_path)
    encoded = json.dumps(result, sort_keys=True)

    assert result["status"] == "FAIL"
    assert [(item["line"], item["rule"]) for item in result["findings"]] == [
        (1, "SECRET_ASSIGNMENT"),
        (2, "PRIVATE_KEY"),
        (3, "PRIVATE_KEY"),
    ]
    assert password not in encoded


def test_build_context_scan_distinguishes_code_from_literal_secret_material(
    tmp_path: Path,
) -> None:
    module = _load_script("scan_build_context.py")
    secret = "A9zY8xW7vU6tS5rQ" + "4pN3mL2kJ1hG0fE9"
    (tmp_path / ".dockerignore").write_text("", encoding="utf-8")
    (tmp_path / "keys.py").write_text(
        "private_key = Ed25519PrivateKey.from_private_bytes(digest)\n"
        f'CROSSPATCH_DATABASE_PASSWORD = "{secret}"\n',
        encoding="utf-8",
    )

    result = module.scan_context(tmp_path)

    assert result["findings"] == [
        {
            "line": 2,
            "path": "keys.py",
            "rule": "SECRET_ASSIGNMENT",
            "value_sha256": hashlib.sha256(secret.encode()).hexdigest(),
        }
    ]


def test_generated_release_evidence_and_coverage_are_not_in_the_build_context() -> None:
    module = _load_script("scan_build_context.py")
    matcher = module._DockerIgnore.load(ROOT / ".dockerignore")

    assert not matcher.includes(".coverage", is_directory=False)
    assert not matcher.includes(
        "artifacts/verification/build-context-secret-scan.json",
        is_directory=False,
    )
    assert not matcher.includes("web/tsconfig.tsbuildinfo", is_directory=False)
    assert matcher.includes("artifacts/verification/README.md", is_directory=False)


class _Completed:
    def __init__(self, stdout: str, *, returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


def _write_preflight_evidence(root: Path) -> dict[str, Any]:
    module = _load_script("scan_build_context.py")
    result = module.scan_context(root)
    assert result["status"] == "PASS"
    evidence_path = root / "artifacts" / "verification"
    evidence_path.mkdir(parents=True, exist_ok=True)
    (evidence_path / "build-context-secret-scan.json").write_text(
        json.dumps(result),
        encoding="utf-8",
    )
    return result


def _prepare_provenance_root(root: Path) -> dict[str, Any]:
    (root / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (root / ".dockerignore").write_text(
        "artifacts/verification/*.json\n",
        encoding="utf-8",
    )
    (root / "app.py").write_text("VERSION = 1\n", encoding="utf-8")
    return _write_preflight_evidence(root)


def _write_immutable_build_evidence(
    root: Path,
    *,
    manifest: str,
    tar_sha256: str,
) -> str:
    module = _load_script("build_immutable_images.py")
    payload = {
        "build_context_manifest_sha256": manifest,
        "build_context_tar_sha256": tar_sha256,
        "generator": module.GENERATOR,
        "images": [
            {"dockerfile": dockerfile, "tag": tag, "target": target}
            for dockerfile, target, tag in module.BUILD_TARGETS
        ],
        "machine_generated": True,
        "schema_version": 1,
        "status": "PASS",
    }
    encoded = json.dumps(payload, sort_keys=True).encode()
    path = root / "artifacts" / "verification" / "immutable-build.json"
    path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


def test_immutable_builder_uses_one_preflight_bound_tar_for_all_local_images(
    tmp_path: Path,
) -> None:
    module = _load_script("build_immutable_images.py")
    preflight = _prepare_provenance_root(tmp_path)
    commands: list[list[str]] = []
    context_hashes: list[str] = []

    def fake_run(argv: list[str], **kwargs: Any) -> _Completed:
        commands.append(argv)
        context_hashes.append(hashlib.sha256(kwargs["input"]).hexdigest())
        return _Completed("")

    result = module.build_images(
        tmp_path,
        run=fake_run,
        checked_at=lambda: datetime(2026, 7, 14, tzinfo=UTC),
    )

    assert result["status"] == "PASS"
    assert result["build_context_manifest_sha256"] == preflight[
        "build_context_manifest_sha256"
    ]
    assert context_hashes == [result["build_context_tar_sha256"]] * 3
    assert {command[command.index("--tag") + 1] for command in commands} == {
        "crosspatch-app:local",
        "crosspatch-runner:local",
        "crosspatch-web:local",
    }
    for command in commands:
        rendered = " ".join(command)
        assert (
            f"{module.CONTEXT_MANIFEST_LABEL}="
            f"{preflight['build_context_manifest_sha256']}"
        ) in rendered
        assert (
            f"{module.CONTEXT_TAR_LABEL}={result['build_context_tar_sha256']}"
        ) in rendered
        assert command[-1] == "-"


def test_immutable_builder_rejects_context_drift_before_docker(tmp_path: Path) -> None:
    module = _load_script("build_immutable_images.py")
    _prepare_provenance_root(tmp_path)
    (tmp_path / "app.py").write_text("VERSION = 2\n", encoding="utf-8")

    def unexpected_run(_argv: list[str], **_kwargs: Any) -> _Completed:
        raise AssertionError("Docker must not receive a context that failed preflight binding")

    with pytest.raises(module.ImmutableBuildError, match="preflight manifest"):
        module.build_images(tmp_path, run=unexpected_run)


def test_immutable_builder_verifies_prebuilt_image_labels_without_rebuilding(
    tmp_path: Path,
) -> None:
    module = _load_script("build_immutable_images.py")
    preflight = _prepare_provenance_root(tmp_path)
    context_manifest = preflight["build_context_manifest_sha256"]
    context_tar = "d" * 64
    commands: list[list[str]] = []

    def fake_snapshot(
        _root: Path,
        _destination: Path,
        expected_manifest: str,
    ) -> str:
        assert expected_manifest == context_manifest
        return context_tar

    def fake_run(argv: list[str], **_kwargs: Any) -> _Completed:
        commands.append(argv)
        assert argv[:3] == ["docker", "image", "inspect"]
        tag = argv[3]
        return _Completed(
            json.dumps(
                [
                    {
                        "Config": {
                            "Labels": {
                                module.CONTEXT_MANIFEST_LABEL: context_manifest,
                                module.CONTEXT_TAR_LABEL: context_tar,
                            }
                        },
                        "Id": "sha256:" + hashlib.sha256(tag.encode()).hexdigest(),
                    }
                ]
            )
        )

    result = module.verify_images(
        tmp_path,
        run=fake_run,
        snapshot=fake_snapshot,
        checked_at=lambda: datetime(2026, 7, 18, tzinfo=UTC),
    )

    assert result["status"] == "PASS"
    assert result["build_context_manifest_sha256"] == context_manifest
    assert result["build_context_tar_sha256"] == context_tar
    assert [command[3] for command in commands] == [
        "crosspatch-app:local",
        "crosspatch-runner:local",
        "crosspatch-web:local",
    ]
    assert all(command[:2] == ["docker", "image"] for command in commands)


def test_immutable_builder_rejects_prebuilt_image_label_drift(tmp_path: Path) -> None:
    module = _load_script("build_immutable_images.py")
    preflight = _prepare_provenance_root(tmp_path)
    context_manifest = preflight["build_context_manifest_sha256"]

    def fake_run(argv: list[str], **_kwargs: Any) -> _Completed:
        tag = argv[3]
        return _Completed(
            json.dumps(
                [
                    {
                        "Config": {
                            "Labels": {
                                module.CONTEXT_MANIFEST_LABEL: context_manifest,
                                module.CONTEXT_TAR_LABEL: "0" * 64,
                            }
                        },
                        "Id": "sha256:" + hashlib.sha256(tag.encode()).hexdigest(),
                    }
                ]
            )
        )

    with pytest.raises(module.ImmutableBuildError, match="immutable context labels"):
        module.verify_images(tmp_path, run=fake_run)


def test_image_provenance_rejects_context_changes_after_the_preflight_scan(
    tmp_path: Path,
) -> None:
    module = _load_script("capture_image_provenance.py")
    _prepare_provenance_root(tmp_path)
    (tmp_path / "app.py").write_text("VERSION = 2\n", encoding="utf-8")

    def unexpected_run(_argv: list[str], **_kwargs: Any) -> _Completed:
        raise AssertionError("Docker must not run after the build context changed")

    with pytest.raises(module.ProvenanceError, match="changed after the preflight scan"):
        module.capture_image_provenance(tmp_path, run=unexpected_run)


def test_image_provenance_reads_deployed_container_image_ids_and_repo_digests(
    tmp_path: Path,
) -> None:
    module = _load_script("capture_image_provenance.py")
    preflight = _prepare_provenance_root(tmp_path)
    app_image = "sha256:" + "1" * 64
    web_image = "sha256:" + "2" * 64
    runner_image = "sha256:" + "3" * 64
    context_manifest = preflight["build_context_manifest_sha256"]
    context_tar = "d" * 64
    immutable_evidence_sha256 = _write_immutable_build_evidence(
        tmp_path,
        manifest=context_manifest,
        tar_sha256=context_tar,
    )

    containers = [
        {
            "Config": {
                "Image": "crosspatch-app:local",
                "Labels": {"com.docker.compose.service": "api"},
            },
            "Id": "container-api",
            "Image": app_image,
            "State": {"ExitCode": 0, "Status": "running"},
        },
        {
            "Config": {
                "Image": "crosspatch-web:local",
                "Labels": {"com.docker.compose.service": "web"},
            },
            "Id": "container-web",
            "Image": web_image,
            "State": {"ExitCode": 0, "Status": "running"},
        },
        {
            "Config": {
                "Image": "crosspatch-app:local",
                "Labels": {"com.docker.compose.service": "migrate-control"},
            },
            "Id": "container-migrate",
            "Image": app_image,
            "State": {"ExitCode": 0, "Status": "exited"},
        },
        {
            "Config": {
                "Image": "crosspatch-runner:local",
                "Labels": {"com.docker.compose.service": "runner"},
            },
            "Id": "container-runner",
            "Image": runner_image,
            "State": {"ExitCode": 0, "Status": "running"},
        },
    ]
    build_labels = {
        module.CONTEXT_MANIFEST_LABEL: context_manifest,
        module.CONTEXT_TAR_LABEL: context_tar,
    }
    images = [
        {
            "Config": {"Labels": build_labels},
            "Id": app_image,
            "RepoDigests": ["crosspatch-api@sha256:" + "a" * 64],
        },
        {"Config": {"Labels": build_labels}, "Id": web_image, "RepoDigests": []},
        {
            "Config": {"Labels": build_labels},
            "Id": runner_image,
            "RepoDigests": ["crosspatch-runner@sha256:" + "b" * 64],
        },
    ]

    def fake_run(argv: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str] | _Completed:
        if argv == ["docker", "compose", "ps", "--all", "--services"]:
            return _Completed("api\nmigrate-control\nrunner\nweb\n")
        if argv == ["docker", "compose", "ps", "--all", "-q"]:
            return _Completed(
                "container-api\ncontainer-migrate\ncontainer-runner\ncontainer-web\n"
            )
        if argv[:4] == ["docker", "inspect", "--type", "container"]:
            return _Completed(json.dumps(containers))
        if argv[:3] == ["docker", "image", "inspect"]:
            return _Completed(json.dumps(images))
        if argv == ["git", "rev-parse", "HEAD"]:
            return _Completed("a" * 40 + "\n")
        raise AssertionError(f"unexpected command: {argv}")

    result = module.capture_image_provenance(
        tmp_path,
        run=fake_run,
        checked_at=lambda: datetime(2026, 7, 14, tzinfo=UTC),
    )

    assert result["status"] == "PASS"
    assert result["build_context_manifest_sha256"] == preflight[
        "build_context_manifest_sha256"
    ]
    assert len(result["build_context_evidence_sha256"]) == 64
    assert [item["service"] for item in result["services"]] == [
        "api",
        "migrate-control",
        "runner",
        "web",
    ]
    assert result["build_context_tar_sha256"] == context_tar
    assert result["immutable_build_evidence_sha256"] == immutable_evidence_sha256
    assert result["services"][0]["image_id"] == app_image
    assert result["services"][0]["repo_digests"] == [
        "crosspatch-api@sha256:" + "a" * 64
    ]
    assert result["services"][1]["state"] == "exited"
    assert result["services"][2]["build_context_tar_sha256"] == context_tar
    assert result["services"][3]["repo_digests"] == []
    assert len(result["deployment_manifest_sha256"]) == 64

    images[0]["Config"]["Labels"][module.CONTEXT_MANIFEST_LABEL] = "0" * 64
    with pytest.raises(module.ProvenanceError, match="build-context labels"):
        module.capture_image_provenance(tmp_path, run=fake_run)
    images[0]["Config"]["Labels"][module.CONTEXT_MANIFEST_LABEL] = context_manifest
    images[0]["Config"]["Labels"][module.CONTEXT_TAR_LABEL] = "e" * 64
    with pytest.raises(module.ProvenanceError, match="immutable build evidence"):
        module.capture_image_provenance(tmp_path, run=fake_run)


def test_image_provenance_rejects_an_unhealthy_or_unreadable_deployment(
    tmp_path: Path,
) -> None:
    module = _load_script("capture_image_provenance.py")
    _prepare_provenance_root(tmp_path)

    def fake_run(argv: list[str], **_kwargs: Any) -> _Completed:
        if argv == ["docker", "compose", "ps", "--all", "--services"]:
            return _Completed("api\n")
        if argv == ["docker", "compose", "ps", "--all", "-q"]:
            return _Completed("container-api\n")
        if argv[:4] == ["docker", "inspect", "--type", "container"]:
            return _Completed(
                json.dumps(
                    [
                        {
                            "Config": {
                                "Image": "crosspatch-api:local",
                                "Labels": {"com.docker.compose.service": "api"},
                            },
                            "Id": "container-api",
                            "Image": "sha256:" + "1" * 64,
                            "State": {"ExitCode": 1, "Status": "exited"},
                        }
                    ]
                )
            )
        raise AssertionError(f"unexpected command: {argv}")

    with pytest.raises(module.ProvenanceError, match="healthy running or successful one-shot"):
        module.capture_image_provenance(
            tmp_path,
            run=fake_run,
        )


def test_export_public_key_evidence_is_usable_and_never_contains_the_private_seed() -> None:
    module = _load_script("generate_export_public_key.py")
    seed = b"private-export-seed-that-must-never-enter-release-evidence"
    private_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(module.PROOF_CHALLENGE)

    evidence = module.build_public_key_evidence(
        public_bytes,
        signature,
        git_sha="a" * 40,
        checked_at=datetime(2026, 7, 14, tzinfo=UTC),
    )
    encoded = json.dumps(evidence, sort_keys=True).encode()
    encoded_public = base64.b64decode(evidence["public_key_base64"], validate=True)
    encoded_challenge = base64.b64decode(
        evidence["proof_challenge_base64"], validate=True
    )
    encoded_signature = base64.b64decode(
        evidence["proof_signature_base64"], validate=True
    )

    assert evidence["status"] == "PASS"
    assert evidence["algorithm"] == "Ed25519"
    assert evidence["private_seed_included"] is False
    assert evidence["self_test"] == "PASS"
    assert evidence["runtime_service"] == "api"
    assert encoded_public == public_bytes
    assert encoded_challenge == module.PROOF_CHALLENGE
    private_key.public_key().verify(encoded_signature, encoded_challenge)
    assert evidence["public_key_sha256"] == hashlib.sha256(public_bytes).hexdigest()
    assert seed not in encoded
    assert hashlib.sha256(seed).hexdigest().encode() not in encoded

    with pytest.raises(module.PublicKeyGenerationError, match="proof is invalid"):
        module.build_public_key_evidence(
            public_bytes,
            bytes(64),
            git_sha="a" * 40,
            checked_at=datetime(2026, 7, 14, tzinfo=UTC),
        )


def test_export_public_key_proof_is_read_from_the_running_api_without_seed_output() -> None:
    module = _load_script("generate_export_public_key.py")
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = private_key.sign(module.PROOF_CHALLENGE)
    payload = json.dumps(
        {
            "public_key_base64": base64.b64encode(public_bytes).decode("ascii"),
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        }
    )
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: Any) -> _Completed:
        seen.append(argv)
        return _Completed(payload)

    actual_public, actual_signature = module.runtime_public_key_proof(run=fake_run)

    assert actual_public == public_bytes
    assert actual_signature == signature
    assert seen[0][:6] == [
        "docker",
        "compose",
        "exec",
        "-T",
        "api",
        "/opt/crosspatch/venv/bin/python",
    ]
    assert "SIGNING_SEED" not in " ".join(seen[0])
    assert "_release_mode_enabled" in seen[0][-1]


def test_strict_compose_environment_is_isolated_random_and_image_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script("release_verifier.py")
    image_ids = {
        "crosspatch-app:local": "sha256:" + "1" * 64,
        "crosspatch-runner:local": "sha256:" + "2" * 64,
        "crosspatch-web:local": "sha256:" + "3" * 64,
    }
    counter = 0

    def token_factory(_bytes: int = 48) -> str:
        nonlocal counter
        counter += 1
        return base64.urlsafe_b64encode(
            hashlib.sha512(f"strict-proof-{counter}".encode()).digest()
        ).decode("ascii").rstrip("=")

    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-inherited")
    strict = module.StrictComposeEnvironment(
        image_id_reader=lambda: image_ids,
        project_suffix="a1b2c3d4e5f6",
        token_factory=token_factory,
    )
    environment = strict.environment()
    secret_values = [
        environment[name] for name in module.STRICT_SECRET_ENVIRONMENT_NAMES
    ]

    assert environment["COMPOSE_PROJECT_NAME"] == (
        "crosspatch-release-proof-a1b2c3d4e5f6"
    )
    assert environment["CROSSPATCH_RELEASE_MODE"] == "1"
    assert environment["CROSSPATCH_BIND_ADDRESS"] == "127.0.0.1"
    assert environment["CROSSPATCH_HTTP_PORT"] == "0"
    assert environment["CROSSPATCH_HTTPS_PORT"] == "0"
    assert environment["OPENAI_API_KEY"] == ""
    assert len(secret_values) == len(set(secret_values))
    assert all(len(value.encode()) >= 32 for value in secret_values)
    assert all(not value.startswith("crosspatch-local-") for value in secret_values)
    assert environment["CROSSPATCH_RUNNER_DIGEST"] == "2" * 64
    assert environment["CROSSPATCH_ENVIRONMENT_DIGEST"] not in {
        "0" * 64,
        hashlib.sha256(b"crosspatch-environment-dev").hexdigest(),
    }
    assert strict.redactions == tuple(secret_values)
    assert strict.cleanup_environment()["COMPOSE_PROJECT_NAME"] == (
        environment["COMPOSE_PROJECT_NAME"]
    )


def test_hosted_release_identity_is_derived_before_release_startup() -> None:
    module = _load_script("derive_release_identity.py")
    image_ids = {
        "crosspatch-app:local": "sha256:" + "1" * 64,
        "crosspatch-runner:local": "sha256:" + "2" * 64,
        "crosspatch-web:local": "sha256:" + "3" * 64,
    }

    identity = module.derive_release_identity(
        ROOT,
        image_ids=image_ids,
        commit_sha="a" * 40,
    )
    dotenv = module.dotenv(identity)

    assert identity["status"] == "PASS"
    assert identity["runner_digest"] == "2" * 64
    assert re.fullmatch(r"[0-9a-f]{64}", identity["environment_digest"])
    assert identity["environment_digest"] != "0" * 64
    assert dotenv == (
        f"CROSSPATCH_RUNNER_DIGEST={'2' * 64}\n"
        f"CROSSPATCH_ENVIRONMENT_DIGEST={identity['environment_digest']}\n"
    )


def test_strict_cleanup_refuses_the_default_or_unrelated_compose_project() -> None:
    module = _load_script("release_verifier.py")

    for project in ("crosspatch", "other-release-proof"):
        with pytest.raises(ValueError, match="isolated strict project"):
            module.strict_compose_cleanup_command(project)

    assert module.strict_compose_cleanup_command(
        "crosspatch-release-proof-a1b2c3d4e5f6"
    ) == [
        "docker",
        "compose",
        "--profile",
        "verification",
        "down",
        "--volumes",
        "--remove-orphans",
    ]


def test_command_evidence_redacts_process_environment_secrets() -> None:
    module = _load_script("verification_lib.py")
    secret = hashlib.sha256(b"release-proof-redaction-contract").hexdigest()

    result = module.command_result(
        [
            sys.executable,
            "-c",
            (
                "import os,sys; print(os.environ['PROOF_SECRET'], file=sys.stderr); "
                "assert sys.argv[1] == os.environ['PROOF_SECRET']"
            ),
            secret,
        ],
        environment={"PROOF_SECRET": secret},
        redactions=(secret,),
    )

    encoded = json.dumps(result, sort_keys=True)
    assert result["status"] == "PASS"
    assert secret not in encoded
    assert "[REDACTED]" in result["stderr"]
    assert "[REDACTED]" in result["command"]


def test_external_artifacts_refresh_github_before_hosted_acceptance(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_script("release_verifier.py")
    commands: list[list[str]] = []
    demo_command = module.demo_readiness_command()
    artifact_directory = tmp_path / "artifacts" / "verification"
    artifact_directory.mkdir(parents=True)
    monkeypatch.setattr(module, "ARTIFACT_DIR", artifact_directory)
    monkeypatch.setattr(module, "demo_readiness_command", lambda: demo_command)

    artifacts = {
        "evaluate-demo-readiness.sh": (
            "demo-readiness.json",
            "scripts/evaluate-demo-readiness.sh",
            "DEMO_READY",
        ),
        "verify-github-license.sh": (
            "github-license.json",
            "scripts/verify-github-license.sh",
            "BLOCKED",
        ),
        "verify-hosted.sh": (
            "hosted-acceptance.json",
            "scripts/verify-hosted.sh",
            "BLOCKED",
        ),
    }
    for filename, generator, status in artifacts.values():
        (artifact_directory / filename).write_text(
            json.dumps(
                {
                    "checked_at": "2026-07-15T00:00:00Z",
                    "generator": generator,
                    "machine_generated": True,
                    "status": status,
                }
            ),
            encoding="utf-8",
        )

    def fake_run(argv: list[str], **_kwargs: Any) -> _Completed:
        commands.append(argv)
        filename, generator, status = artifacts[Path(argv[0]).name]
        (artifact_directory / filename).write_text(
            json.dumps(
                {
                    "checked_at": "2026-07-16T00:00:00Z",
                    "generator": generator,
                    "machine_generated": True,
                    "status": status,
                }
            ),
            encoding="utf-8",
        )
        return _Completed("", returncode=0 if filename == "demo-readiness.json" else 2)

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    refreshed = module.ensure_external_artifacts()

    assert [Path(command[0]).name for command in commands] == [
        "evaluate-demo-readiness.sh",
        "verify-github-license.sh",
        "verify-hosted.sh",
    ]
    assert commands[0][1] == "--verify-sealed-batch-dir"
    assert commands[0][2].endswith(
        "artifacts/verification/paced-batches/paced-20260714T103240Z"
    )
    assert refreshed == (
        "demo-readiness.json",
        "github-license.json",
        "hosted-acceptance.json",
    )


def test_external_artifact_inventory_rejects_an_unobserved_refresh(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_script("release_verifier.py")
    artifact_directory = tmp_path / "artifacts" / "verification"
    artifact_directory.mkdir(parents=True)
    monkeypatch.setattr(module, "ARTIFACT_DIR", artifact_directory)
    monkeypatch.setattr(module, "demo_readiness_command", lambda: ["demo-readiness"])
    monkeypatch.setattr(module.subprocess, "run", lambda *_args, **_kwargs: _Completed(""))

    with pytest.raises(RuntimeError, match="did not produce or validate"):
        module.ensure_external_artifacts()


def test_external_artifact_inventory_rejects_unchanged_nonsealed_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_script("release_verifier.py")
    demo_command = module.demo_readiness_command()
    artifact_directory = tmp_path / "artifacts" / "verification"
    artifact_directory.mkdir(parents=True)
    monkeypatch.setattr(module, "ARTIFACT_DIR", artifact_directory)
    monkeypatch.setattr(module, "demo_readiness_command", lambda: demo_command)
    payloads = {
        "demo-readiness.json": (
            "scripts/evaluate-demo-readiness.sh",
            "DEMO_READY",
        ),
        "github-license.json": (
            "scripts/verify-github-license.sh",
            "API_VERIFIED",
        ),
        "hosted-acceptance.json": (
            "scripts/verify-hosted.sh",
            "VERIFIED",
        ),
    }
    for filename, (generator, status) in payloads.items():
        (artifact_directory / filename).write_text(
            json.dumps(
                {
                    "checked_at": "2026-07-15T00:00:00Z",
                    "generator": generator,
                    "machine_generated": True,
                    "status": status,
                }
            ),
            encoding="utf-8",
        )
    commands: list[list[str]] = []

    def fake_run(argv: list[str], **_kwargs: Any) -> _Completed:
        commands.append(argv)
        return _Completed("")

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="github-license.json"):
        module.ensure_external_artifacts()
    assert [Path(command[0]).name for command in commands] == [
        "evaluate-demo-readiness.sh",
        "verify-github-license.sh",
    ]


def test_strict_source_gate_rejects_nonartifact_changes_and_allows_own_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script("release_verifier.py")
    monkeypatch.setattr(
        module,
        "release_source_changes",
        lambda: (
            "artifacts/verification/backend-tests.json",
            "web/next-env.d.ts",
        ),
    )

    with pytest.raises(RuntimeError, match="web/next-env.d.ts"):
        module.require_clean_release_source(
            allowed_prefixes=("artifacts/verification",)
        )

    monkeypatch.setattr(
        module,
        "release_source_changes",
        lambda: ("artifacts/verification/backend-tests.json",),
    )
    artifact = module.source_integrity_artifact(
        allowed_prefixes=("artifacts/verification",)
    )
    assert artifact["status"] == "PASS"
    assert artifact["git_sha"] == module.git_sha()
    assert artifact["observed_generated_path_count"] == 1


def test_strict_release_verifier_runs_all_supply_chain_generators(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script("release_verifier.py")
    command_groups: dict[str, list[list[str]]] = {}
    group_options: dict[str, dict[str, Any]] = {}
    group_order: list[str] = []
    clean_checks: list[tuple[str, ...]] = []

    def fake_run_group(
        filename: str,
        _source: str,
        commands: list[list[str]],
        **options: Any,
    ) -> dict[str, str]:
        group_order.append(filename)
        command_groups[filename] = commands
        group_options[filename] = options
        return {"status": "PASS"}

    monkeypatch.setattr(module, "run_group", fake_run_group)
    _stub_provisional_claim_map(module, monkeypatch)
    monkeypatch.setattr(
        module,
        "validate_claim_inputs",
        lambda: {"status": "PASS", "checks": []},
    )
    monkeypatch.setattr(module, "command_result", lambda _argv: {"status": "PASS"})
    monkeypatch.setattr(module, "atomic_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "git_sha", lambda: "a" * 40)
    monkeypatch.setattr(
        module,
        "require_clean_release_source",
        lambda *, allowed_prefixes=(): clean_checks.append(tuple(allowed_prefixes)),
    )
    monkeypatch.setenv(
        "CROSSPATCH_VICTIM_WEBHOOK_SECRET",
        "release-test-victim-secret-A1b2C3d4E5f6",
    )
    monkeypatch.setattr(sys, "argv", ["release_verifier.py", "--strict"])

    assert module.main() == 0
    assert clean_checks == [
        (),
        ("artifacts/verification", "docs/CLAIM_MAP.json"),
    ]
    preflight = command_groups["supply-chain-preflight.json"]
    provenance = command_groups["supply-chain-provenance.json"]
    compose = command_groups["compose-policy.json"]
    rendered = [" ".join(command) for command in preflight + compose + provenance]
    for generator in (
        "scripts/generate_sbom.py",
        "scripts/scan_build_context.py",
        "scripts/build_immutable_images.py",
        "scripts/capture_image_provenance.py",
        "scripts/generate_export_public_key.py",
    ):
        assert sum(generator in command for command in rendered) == 1
    assert group_order.index("supply-chain-preflight.json") < group_order.index(
        "compose-policy.json"
    )
    assert any("scripts/scan_build_context.py" in command for command in rendered)
    assert any("scripts/build_immutable_images.py" in command for command in rendered)
    assert ["docker", "compose", "build"] not in compose
    assert next(
        index
        for index, command in enumerate(compose)
        if "scripts/build_immutable_images.py" in command
    ) < next(
        index
        for index, command in enumerate(compose)
        if command[:3] == ["docker", "compose", "up"]
    )
    warrant = command_groups["warrant-boundary.json"]
    sidecar = next(
        command
        for command in warrant
        if "CROSSPATCH_PRODUCTION_SIDECAR_TEST=1" in command
    )
    assert [
        "-e",
        "CROSSPATCH_TEST_LIVE_VICTIM_SECRET",
    ] == sidecar[sidecar.index("CROSSPATCH_TEST_LIVE_VICTIM_SECRET") - 1 :][:2]
    assert "release-test-victim-secret" not in " ".join(sidecar)
    postgres = next(command for command in warrant if "postgres-verifier" in command)
    assert any("test_control_db_hardening_postgres.py" in item for item in postgres)
    production_broker_probe = next(
        command
        for command in warrant
        if "/app/backend/tests/security/production_broker_runner_probe.py" in command
    )
    assert production_broker_probe == [
        "docker",
        "compose",
        "exec",
        "-T",
        "broker-mcp",
        "/opt/crosspatch/venv/bin/python",
        "/app/backend/tests/security/production_broker_runner_probe.py",
    ]
    strict_groups = {
        "compose-policy.json": {3, 4},
        "supply-chain-provenance.json": {0, 1},
        "race-reproduction.json": {1},
        "warrant-boundary.json": {1, 2, 3},
        "strict-compose-cleanup.json": {0},
    }
    owners: set[int] = set()
    redactions: tuple[str, ...] | None = None
    for filename, expected_indexes in strict_groups.items():
        options = group_options[filename]
        environments = options["command_environments"]
        assert set(environments) == expected_indexes
        for provider in environments.values():
            owners.add(id(provider.__self__))
        assert options["stop_on_failure"] is True
        current_redactions = options["redactions"]
        assert current_redactions
        if redactions is None:
            redactions = current_redactions
        else:
            assert current_redactions == redactions
        rendered_commands = "\n".join(
            " ".join(command) for command in command_groups[filename]
        )
        assert all(secret not in rendered_commands for secret in current_redactions)
    assert len(owners) == 1
    assert group_order.index("warrant-boundary.json") < group_order.index(
        "strict-compose-cleanup.json"
    )


def test_strict_builds_required_local_images_before_image_consumers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script("release_verifier.py")
    available_images: set[str] = set()
    group_order: list[str] = []
    artifact_writes: list[str] = []
    consumer_groups = {
        "backend-tests.json",
        "frontend-tests.json",
        "warrant-boundary.json",
    }

    def fake_command_result(argv: list[str], **_options: Any) -> dict[str, str]:
        if "scripts/build_immutable_images.py" in argv:
            assert "--build-only" in argv
            assert "--output" not in argv
            available_images.update(module._LOCAL_IMAGE_TAGS)
        return {"status": "PASS"}

    def fake_run_group(
        filename: str,
        _source: str,
        commands: list[list[str]],
        **_options: Any,
    ) -> dict[str, str]:
        group_order.append(filename)
        if filename == "compose-policy.json":
            immutable_builds = [
                command
                for command in commands
                if "scripts/build_immutable_images.py" in command
            ]
            assert len(immutable_builds) == 1
            assert "--verify-only" in immutable_builds[0]
        if filename in consumer_groups:
            assert available_images == set(module._LOCAL_IMAGE_TAGS)
        if filename in {"backend-tests.json", "frontend-tests.json"}:
            assert "immutable-build.json" not in artifact_writes
            assert "compose-policy.json" not in artifact_writes
        artifact_writes.append(filename)
        return {"status": "PASS"}

    monkeypatch.setattr(module, "run_group", fake_run_group)
    _stub_provisional_claim_map(module, monkeypatch)
    monkeypatch.setattr(
        module,
        "validate_claim_inputs",
        lambda: {"status": "PASS", "checks": []},
    )
    monkeypatch.setattr(module, "command_result", fake_command_result)
    monkeypatch.setattr(
        module,
        "atomic_json",
        lambda path, _payload: artifact_writes.append(path.name),
    )
    monkeypatch.setattr(module, "git_sha", lambda: "a" * 40)
    monkeypatch.setattr(module, "require_clean_release_source", lambda **_kwargs: None)
    monkeypatch.setattr(sys, "argv", ["release_verifier.py", "--strict"])

    assert module.main() == 0
    assert group_order.index("backend-tests.json") < group_order.index(
        "compose-policy.json"
    )
    assert group_order.index("frontend-tests.json") < group_order.index(
        "compose-policy.json"
    )
    assert group_order.index("compose-policy.json") < group_order.index(
        "warrant-boundary.json"
    )


def test_public_bootstrap_keeps_full_claim_map_until_preconsumer_images_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script("release_verifier.py")
    events: list[str] = []
    claim_map: dict[str, object] = {"claims": []}
    provisional_map: dict[str, object] = {"claims": ["temporary"]}

    def fake_run_group(
        filename: str,
        _source: str,
        _commands: list[list[str]],
        **_options: Any,
    ) -> dict[str, str]:
        events.append(filename)
        return {"status": "PASS"}

    def fake_command_result(argv: list[str], **_options: Any) -> dict[str, str]:
        if "scripts/build_immutable_images.py" in argv and "--build-only" in argv:
            events.append("preconsumer-images-built")
        return {"status": "PASS"}

    def fake_write_provisional(payload: dict[str, object]) -> dict[str, object]:
        assert payload is claim_map
        events.append("bootstrap-provisional-map-written")
        return provisional_map

    def fake_restore_structural(payload: dict[str, object]) -> dict[str, object]:
        assert payload is claim_map
        events.append("bootstrap-structural-map-restored")
        return payload

    monkeypatch.setattr(module, "run_group", fake_run_group)
    monkeypatch.setattr(module, "ensure_external_artifacts", lambda: ())
    monkeypatch.setattr(module, "load_public_bootstrap_claim_map", lambda: claim_map)
    monkeypatch.setattr(
        module,
        "rebind_refreshed_claims",
        lambda base, _refreshed: base,
    )
    monkeypatch.setattr(
        module,
        "write_public_bootstrap_provisional_claim_map",
        fake_write_provisional,
    )
    monkeypatch.setattr(
        module,
        "restore_public_bootstrap_structural_claim_map",
        fake_restore_structural,
    )
    monkeypatch.setattr(module, "generate_claim_map", lambda: {"claims": []})
    monkeypatch.setattr(
        module,
        "validate_claim_inputs",
        lambda: {"status": "PASS", "checks": []},
    )
    monkeypatch.setattr(module, "command_result", fake_command_result)
    monkeypatch.setattr(module, "atomic_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "git_sha", lambda: "a" * 40)
    monkeypatch.setattr(module, "require_clean_release_source", lambda **_kwargs: None)
    monkeypatch.setattr(
        sys,
        "argv",
        ["release_verifier.py", "--strict", "--public-bootstrap"],
    )

    assert module.main() == 0
    assert events.index("preconsumer-images-built") < events.index(
        "bootstrap-provisional-map-written"
    ) < events.index("backend-tests.json")
    assert events.index("backend-tests.json") < events.index(
        "bootstrap-structural-map-restored"
    ) < events.index("frontend-tests.json")


def test_failed_supply_chain_preflight_prevents_compose_build_and_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script("release_verifier.py")
    command_groups: dict[str, list[list[str]]] = {}
    written: dict[str, dict[str, Any]] = {}

    def fake_run_group(
        filename: str,
        _source: str,
        commands: list[list[str]],
        **_options: Any,
    ) -> dict[str, str]:
        command_groups[filename] = commands
        return {
            "status": "FAIL" if filename == "supply-chain-preflight.json" else "PASS"
        }

    monkeypatch.setattr(module, "run_group", fake_run_group)
    _stub_provisional_claim_map(module, monkeypatch)
    monkeypatch.setattr(
        module,
        "validate_claim_inputs",
        lambda: {"status": "PASS", "checks": []},
    )
    monkeypatch.setattr(module, "command_result", lambda _argv: {"status": "PASS"})
    monkeypatch.setattr(
        module,
        "atomic_json",
        lambda path, payload: written.__setitem__(path.name, payload),
    )
    monkeypatch.setattr(module, "git_sha", lambda: "a" * 40)
    monkeypatch.setattr(module, "require_clean_release_source", lambda **_kwargs: None)
    monkeypatch.setenv(
        "CROSSPATCH_VICTIM_WEBHOOK_SECRET",
        "release-test-victim-secret-A1b2C3d4E5f6",
    )
    monkeypatch.setattr(sys, "argv", ["release_verifier.py", "--strict"])

    assert module.main() == 1
    assert not any(
        "scripts/build_immutable_images.py" in command
        for command in command_groups["compose-policy.json"]
    )
    assert "supply-chain-provenance.json" not in command_groups
    assert written["image-provenance.json"]["status"] == "BLOCKED"
    assert written["export-public-key.json"]["status"] == "BLOCKED"
    assert written["immutable-build.json"]["status"] == "BLOCKED"
    assert written["supply-chain-provenance.json"]["status"] == "BLOCKED"


def test_strict_release_verifier_cleans_its_project_when_warrant_gate_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script("release_verifier.py")
    group_order: list[str] = []

    def fake_run_group(
        filename: str,
        _source: str,
        _commands: list[list[str]],
        **_options: Any,
    ) -> dict[str, str]:
        group_order.append(filename)
        if filename == "warrant-boundary.json":
            raise RuntimeError("simulated warrant verifier interruption")
        return {"status": "PASS"}

    monkeypatch.setattr(module, "run_group", fake_run_group)
    _stub_provisional_claim_map(module, monkeypatch)
    monkeypatch.setattr(
        module,
        "validate_claim_inputs",
        lambda: {"status": "PASS", "checks": []},
    )
    monkeypatch.setattr(module, "command_result", lambda _argv: {"status": "PASS"})
    monkeypatch.setattr(module, "atomic_json", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(module, "git_sha", lambda: "a" * 40)
    monkeypatch.setattr(module, "require_clean_release_source", lambda **_kwargs: None)
    monkeypatch.setattr(sys, "argv", ["release_verifier.py", "--strict"])

    with pytest.raises(RuntimeError, match="warrant verifier interruption"):
        module.main()

    assert group_order[-2:] == [
        "warrant-boundary.json",
        "strict-compose-cleanup.json",
    ]


def test_failed_compose_stage_cannot_publish_old_deployment_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script("release_verifier.py")
    command_groups: dict[str, list[list[str]]] = {}
    written: dict[str, dict[str, Any]] = {}

    def fake_run_group(
        filename: str,
        _source: str,
        commands: list[list[str]],
        **_options: Any,
    ) -> dict[str, str]:
        command_groups[filename] = commands
        return {"status": "FAIL" if filename == "compose-policy.json" else "PASS"}

    monkeypatch.setattr(module, "run_group", fake_run_group)
    _stub_provisional_claim_map(module, monkeypatch)
    monkeypatch.setattr(
        module,
        "validate_claim_inputs",
        lambda: {"status": "PASS", "checks": []},
    )
    monkeypatch.setattr(module, "command_result", lambda _argv: {"status": "PASS"})
    monkeypatch.setattr(
        module,
        "atomic_json",
        lambda path, payload: written.__setitem__(path.name, payload),
    )
    monkeypatch.setattr(module, "git_sha", lambda: "a" * 40)
    monkeypatch.setattr(module, "require_clean_release_source", lambda **_kwargs: None)
    monkeypatch.setenv(
        "CROSSPATCH_VICTIM_WEBHOOK_SECRET",
        "release-test-victim-secret-A1b2C3d4E5f6",
    )
    monkeypatch.setattr(sys, "argv", ["release_verifier.py", "--strict"])

    assert module.main() == 1
    assert any(
        "scripts/build_immutable_images.py" in command
        for command in command_groups["compose-policy.json"]
    )
    assert "supply-chain-provenance.json" not in command_groups
    assert written["image-provenance.json"]["reason_code"] == "COMPOSE_STAGE_FAILED"
    assert written["export-public-key.json"]["reason_code"] == "COMPOSE_STAGE_FAILED"


def test_supply_chain_runbook_names_artifacts_and_keeps_hosted_status_independent() -> None:
    deployment = (ROOT / "docs" / "DEPLOYMENT.md").read_text(encoding="utf-8")
    artifact_readme = (ROOT / "artifacts" / "verification" / "README.md").read_text(
        encoding="utf-8"
    )
    combined = deployment + artifact_readme

    for required in (
        "artifacts/verification/sbom.cdx.json",
        "artifacts/verification/build-context-secret-scan.json",
        "artifacts/verification/immutable-build.json",
        "artifacts/verification/image-provenance.json",
        "artifacts/verification/export-public-key.json",
        "secret-scan: allow=test-fixture",
    ):
        assert required in combined
    assert "private seed" in combined.lower()
    assert "running api" in combined.lower()
    assert "does not establish hosted" in combined.lower()
