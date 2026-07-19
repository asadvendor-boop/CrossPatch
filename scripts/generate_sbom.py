#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM from the committed lockfiles."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import tomllib
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote

from verification_lib import ROOT, atomic_json

GENERATOR = "scripts/generate_sbom.py"


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _properties(ecosystem: str) -> list[dict[str, str]]:
    return [{"name": "crosspatch:ecosystem", "value": ecosystem}]


def _python_hashes(package: dict[str, Any]) -> list[dict[str, str]]:
    values: set[str] = set()
    sdist = package.get("sdist")
    if isinstance(sdist, dict) and isinstance(sdist.get("hash"), str):
        values.add(sdist["hash"])
    wheels = package.get("wheels", [])
    if isinstance(wheels, list):
        values.update(
            wheel["hash"]
            for wheel in wheels
            if isinstance(wheel, dict) and isinstance(wheel.get("hash"), str)
        )
    result = []
    for value in sorted(values):
        algorithm, separator, content = value.partition(":")
        if separator != ":" or algorithm.casefold() != "sha256" or len(content) != 64:
            raise ValueError(f"unsupported Python lock hash: {value}")
        result.append({"alg": "SHA-256", "content": content})
    return result


def _npm_hashes(package: dict[str, Any]) -> list[dict[str, str]]:
    integrity = package.get("integrity")
    if not isinstance(integrity, str):
        return []
    algorithm, separator, encoded = integrity.partition("-")
    if separator != "-" or algorithm.casefold() not in {"sha256", "sha384", "sha512"}:
        raise ValueError(f"unsupported npm integrity value: {integrity}")
    try:
        content = base64.b64decode(encoded, validate=True).hex()
    except ValueError as error:
        raise ValueError("npm integrity value is not strict base64") from error
    return [{"alg": algorithm.upper().replace("SHA", "SHA-"), "content": content}]


def _python_components(lock: dict[str, Any]) -> list[dict[str, Any]]:
    components = []
    for package in lock.get("package", []):
        if not isinstance(package, dict) or not isinstance(package.get("version"), str):
            continue
        source = package.get("source", {})
        if isinstance(source, dict) and "editable" in source:
            continue
        name = str(package["name"])
        version = package["version"]
        normalized = name.casefold().replace("_", "-")
        component: dict[str, Any] = {
            "bom-ref": f"pkg:pypi/{quote(normalized)}@{quote(version)}",
            "name": name,
            "properties": _properties("python"),
            "purl": f"pkg:pypi/{quote(normalized)}@{quote(version)}",
            "type": "library",
            "version": version,
        }
        hashes = _python_hashes(package)
        if hashes:
            component["hashes"] = hashes
        components.append(component)
    return components


def _npm_components(lock: dict[str, Any]) -> list[dict[str, Any]]:
    by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    packages = lock.get("packages", {})
    if not isinstance(packages, dict):
        raise ValueError("package-lock.json packages must be an object")
    for path, package in packages.items():
        if (
            not isinstance(path, str)
            or "node_modules/" not in path
            or not isinstance(package, dict)
            or not isinstance(package.get("version"), str)
        ):
            continue
        name = path.rsplit("node_modules/", maxsplit=1)[1]
        version = package["version"]
        purl = f"pkg:npm/{quote(name, safe='/')}@{quote(version)}"
        component: dict[str, Any] = {
            "bom-ref": purl,
            "name": name,
            "properties": _properties("npm"),
            "purl": purl,
            "type": "library",
            "version": version,
        }
        hashes = _npm_hashes(package)
        if hashes:
            component["hashes"] = hashes
        license_value = package.get("license")
        if isinstance(license_value, str) and license_value:
            component["licenses"] = [{"license": {"name": license_value}}]
        identity = (name, version)
        existing = by_identity.get(identity)
        if existing is not None and existing != component:
            raise ValueError(f"npm lock contains inconsistent metadata for {name}@{version}")
        by_identity[identity] = component
    return list(by_identity.values())


def build_sbom(root: Path = ROOT) -> dict[str, Any]:
    uv_path = root / "uv.lock"
    npm_path = root / "package-lock.json"
    project_path = root / "pyproject.toml"
    uv_lock = tomllib.loads(uv_path.read_text(encoding="utf-8"))
    npm_lock = json.loads(npm_path.read_text(encoding="utf-8"))
    project = tomllib.loads(project_path.read_text(encoding="utf-8"))["project"]
    components = _python_components(uv_lock) + _npm_components(npm_lock)
    components.sort(
        key=lambda item: (
            _properties_value(item, "crosspatch:ecosystem"),
            item["name"].casefold(),
            item["version"],
            item["bom-ref"],
        )
    )
    serial_digest = hashlib.sha256(uv_path.read_bytes() + npm_path.read_bytes()).digest()[:16]
    return {
        "bomFormat": "CycloneDX",
        "components": components,
        "metadata": {
            "component": {
                "bom-ref": f"pkg:pypi/crosspatch@{quote(str(project['version']))}",
                "name": str(project["name"]),
                "type": "application",
                "version": str(project["version"]),
            },
            "properties": [
                {"name": "crosspatch:package-lock.json:sha256", "value": _sha256(npm_path)},
                {"name": "crosspatch:uv.lock:sha256", "value": _sha256(uv_path)},
            ],
            "tools": {
                "components": [
                    {
                        "name": "CrossPatch deterministic lockfile SBOM generator",
                        "type": "application",
                        "version": "1",
                    }
                ]
            },
        },
        "serialNumber": f"urn:uuid:{uuid.UUID(bytes=serial_digest, version=5)}",
        "specVersion": "1.5",
        "version": 1,
    }


def _properties_value(component: dict[str, Any], name: str) -> str:
    return next(item["value"] for item in component["properties"] if item["name"] == name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "verification" / "sbom.cdx.json",
    )
    arguments = parser.parse_args()
    atomic_json(arguments.output, build_sbom(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
