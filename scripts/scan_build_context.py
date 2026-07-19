#!/usr/bin/env python3
"""Fail closed when Docker build-context files contain credential material."""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from verification_lib import ROOT, atomic_json

GENERATOR = "scripts/scan_build_context.py"
MAX_SCANNED_FILE_BYTES = 16 * 1024 * 1024
ALLOW_MARKER = re.compile(r"#\s*secret-scan:\s*allow=(?P<reason>test-fixture)\b")


@dataclass(frozen=True, slots=True)
class _Rule:
    name: str
    pattern: re.Pattern[str]
    value_group: str | int = 0


_RULES = (
    _Rule(
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----"
        ),
    ),
    _Rule("OPENAI_API_KEY", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b")),
    _Rule(
        "GITHUB_TOKEN",
        re.compile(r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b"),
    ),
    _Rule("AWS_ACCESS_KEY_ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    _Rule("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{32,}\b")),
    _Rule("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b")),
    _Rule(
        "SECRET_ASSIGNMENT",
        re.compile(
            r"(?i)\b(?P<name>(?:[A-Z][A-Z0-9_]*_)?"
            r"(?:API_KEY|PASSWORD|PRIVATE_KEY|SECRET|TOKEN))\s*[:=]\s*"
            r"(?P<quote>[\"'])(?P<value>[A-Za-z0-9_./+=-]{20,})(?P=quote)"
        ),
        "value",
    ),
    _Rule(
        "SECRET_ASSIGNMENT",
        re.compile(
            r"^\s*(?:(?:export|ENV|ARG)\s+)?(?P<name>[A-Z][A-Z0-9_]*"
            r"(?:API_KEY|PASSWORD|PRIVATE_KEY|SECRET|TOKEN))\s*(?::|=|\s)\s*"
            r"(?P<value>[A-Za-z0-9_./+=-]{20,})\s*(?:#.*)?$"
        ),
        "value",
    ),
)

_PLACEHOLDER_MARKERS = frozenset(
    {
        "change-me",
        "changeme",
        "dummy",
        "example",
        "external-oracle-secret",
        "fake",
        "fixture",
        "issued-",
        "local-",
        "local_only",
        "local-only",
        "never-returned",
        "placeholder",
        "replace-",
        "rotated-token",
        "sentinel",
        "test-",
        "token-value",
    }
)


@dataclass(frozen=True, slots=True)
class _DockerIgnorePattern:
    value: str
    negated: bool
    directory_only: bool

    def matches(self, relative: str, *, is_directory: bool) -> bool:
        value = self.value.rstrip("/")
        path = PurePosixPath(relative)
        if self.directory_only:
            parts = path.parts
            if "/" in value:
                return relative == value or relative.startswith(f"{value}/")
            return any(fnmatch.fnmatchcase(part, value) for part in parts)
        if "/" in value:
            return fnmatch.fnmatchcase(relative, value)
        return fnmatch.fnmatchcase(path.name, value) or (
            is_directory and fnmatch.fnmatchcase(relative, value)
        )


class _DockerIgnore:
    def __init__(self, patterns: tuple[_DockerIgnorePattern, ...]) -> None:
        self._patterns = patterns

    @classmethod
    def load(cls, path: Path) -> _DockerIgnore:
        patterns: list[_DockerIgnorePattern] = []
        if not path.is_file():
            raise ValueError("build-context scan requires .dockerignore")
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            negated = line.startswith("!")
            value = line[1:] if negated else line
            value = value.removeprefix("./").removeprefix("/")
            if not value or value == "." or "\x00" in value:
                raise ValueError(f"unsupported .dockerignore pattern: {raw_line!r}")
            patterns.append(
                _DockerIgnorePattern(
                    value=value,
                    negated=negated,
                    directory_only=value.endswith("/"),
                )
            )
        return cls(tuple(patterns))

    def includes(self, relative: str, *, is_directory: bool) -> bool:
        included = True
        for pattern in self._patterns:
            if pattern.matches(relative, is_directory=is_directory):
                included = pattern.negated
        return included


def _included_files(root: Path, matcher: _DockerIgnore) -> tuple[Path, ...]:
    files: list[Path] = []
    for current, directories, names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_directories = []
        for name in sorted(directories):
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            if matcher.includes(relative, is_directory=True):
                kept_directories.append(name)
        directories[:] = kept_directories
        for name in sorted(names):
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            if matcher.includes(relative, is_directory=False):
                files.append(candidate)
    return tuple(sorted(files, key=lambda path: path.relative_to(root).as_posix()))


def _placeholder_assignment(match: re.Match[str], relative: str) -> str | None:
    if "name" not in match.re.groupindex or "value" not in match.re.groupindex:
        return None
    value = match.group("value")
    lowered = value.casefold()
    name = match.group("name").casefold()
    if name.startswith("insecure_") and any(
        marker in lowered for marker in _PLACEHOLDER_MARKERS
    ):
        return "insecure-value-rejection-constant"
    if "/tests/" in f"/{relative}" and name.startswith("random_secret"):
        return "named-test-fixture"
    return None


def _explicit_test_fixture(relative: str) -> bool:
    parts = PurePosixPath(relative).parts
    return any(parts[index : index + 2] == ("tests", "fixtures") for index in range(len(parts)))


def _looks_like_secret_material(value: str) -> bool:
    if len(value) < 24:
        return False
    classes = sum(
        (
            any(character.islower() for character in value),
            any(character.isupper() for character in value),
            any(character.isdigit() for character in value),
            any(not character.isalnum() for character in value),
        )
    )
    if classes < 3:
        return False
    counts = Counter(value)
    entropy = -sum(
        (count / len(value)) * math.log2(count / len(value)) for count in counts.values()
    )
    return entropy >= 3.5


def _record(
    *,
    relative: str,
    line_number: int,
    rule: _Rule,
    value: str,
    reason: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "line": line_number,
        "path": relative,
        "rule": rule.name,
        "value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
    }
    if reason is not None:
        result["reason"] = reason
    return result


def _scan_file(relative: str, payload: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    allowlisted: list[dict[str, Any]] = []
    for line_number, line in enumerate(payload.decode("utf-8", errors="replace").splitlines(), 1):
        allow = ALLOW_MARKER.search(line)
        if allow is not None and not _explicit_test_fixture(relative):
            allow = None
        claimed_spans: list[tuple[int, int]] = []
        for rule in _RULES:
            for match in rule.pattern.finditer(line):
                if any(match.start() < end and start < match.end() for start, end in claimed_spans):
                    continue
                value = match.group(rule.value_group)
                if rule.name == "SECRET_ASSIGNMENT" and not _looks_like_secret_material(value):
                    continue
                reason = allow.group("reason") if allow is not None else None
                reason = reason or _placeholder_assignment(match, relative)
                record = _record(
                    relative=relative,
                    line_number=line_number,
                    rule=rule,
                    value=value,
                    reason=reason,
                )
                if reason is None:
                    findings.append(record)
                else:
                    allowlisted.append(record)
                claimed_spans.append(match.span())
    return findings, allowlisted


def scan_context(root: Path = ROOT) -> dict[str, Any]:
    resolved = root.resolve(strict=True)
    matcher = _DockerIgnore.load(resolved / ".dockerignore")
    findings: list[dict[str, Any]] = []
    allowlisted: list[dict[str, Any]] = []
    manifest = hashlib.sha256()
    scanned_bytes = 0
    scanned_files = 0
    for path in _included_files(resolved, matcher):
        relative = path.relative_to(resolved).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            findings.append(
                {
                    "line": 0,
                    "path": relative,
                    "rule": "SYMLINK_BUILD_CONTEXT_ENTRY",
                    "value_sha256": hashlib.sha256(target.encode()).hexdigest(),
                }
            )
            continue
        size = path.stat().st_size
        if size > MAX_SCANNED_FILE_BYTES:
            findings.append(
                {
                    "line": 0,
                    "path": relative,
                    "rule": "UNSCANNED_LARGE_FILE",
                    "value_sha256": hashlib.sha256(f"{relative}:{size}".encode()).hexdigest(),
                }
            )
            continue
        payload = path.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        manifest.update(relative.encode("utf-8") + b"\0" + digest.encode("ascii") + b"\n")
        file_findings, file_allowlisted = _scan_file(relative, payload)
        findings.extend(file_findings)
        allowlisted.extend(file_allowlisted)
        scanned_bytes += len(payload)
        scanned_files += 1
    findings.sort(key=lambda item: (item["path"], item["line"], item["rule"]))
    allowlisted.sort(key=lambda item: (item["path"], item["line"], item["rule"]))
    return {
        "allowlisted": allowlisted,
        "build_context_manifest_sha256": manifest.hexdigest(),
        "dockerignore_sha256": hashlib.sha256(
            (resolved / ".dockerignore").read_bytes()
        ).hexdigest(),
        "findings": findings,
        "generator": GENERATOR,
        "machine_generated": True,
        "scanned_bytes": scanned_bytes,
        "scanned_files": scanned_files,
        "schema_version": 1,
        "source": "files included by the checked-in root .dockerignore",
        "status": "PASS" if not findings else "FAIL",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "verification" / "build-context-secret-scan.json",
    )
    arguments = parser.parse_args()
    result = scan_context(arguments.root)
    atomic_json(arguments.output, result)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
