"""Repository path policy enforced before any candidate workspace is created."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from pathlib import Path, PurePosixPath, PureWindowsPath


class PathPolicyViolation(ValueError):
    """Raised when a patch path can escape or modify runner-owned controls."""


class PatchFormatViolation(PathPolicyViolation):
    """Raised when diff bytes use a format the broker cannot prove safe."""


_DRIVE_PREFIX = re.compile(r"[A-Za-z]:")
_PROTECTED_EXACT = frozenset(
    {
        ".gitmodules",
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
        "package-lock.json",
        "package.json",
        "pnpm-lock.yaml",
        "pyproject.toml",
        "uv.lock",
        "yarn.lock",
    }
)
_PROTECTED_PREFIXES = (
    ".git/",
    ".github/",
    ".superpowers/",
    "backend/src/crosspatch/broker/",
    "backend/src/crosspatch/runner/",
    "docs/",
    "infra/",
)


def _normalize_candidate_path(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise PathPolicyViolation("patch paths must be non-empty strings")
    normalized = unicodedata.normalize("NFKC", value)
    if normalized != value:
        raise PathPolicyViolation("patch paths must already be Unicode-normalized")
    if "\x00" in normalized or "\\" in normalized:
        raise PathPolicyViolation("patch paths cannot contain NUL or backslash characters")
    pure = PurePosixPath(normalized)
    if (
        pure.is_absolute()
        or PureWindowsPath(normalized).is_absolute()
        or _DRIVE_PREFIX.match(normalized)
    ):
        raise PathPolicyViolation("absolute patch paths are forbidden")
    if normalized != pure.as_posix() or any(part in {"", ".", ".."} for part in pure.parts):
        raise PathPolicyViolation("patch paths must already be normalized and cannot traverse")
    return pure.as_posix()


def _is_protected(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if path in _PROTECTED_EXACT:
        return True
    if any(path.startswith(prefix) for prefix in _PROTECTED_PREFIXES):
        return True
    return "tests" in parts


def validate_patch_paths(repository_root: str | Path, paths: Iterable[str]) -> tuple[str, ...]:
    """Return canonical paths or reject before any worktree/process side effect."""
    root = Path(repository_root).resolve()
    canonical: set[str] = set()
    for value in paths:
        normalized = _normalize_candidate_path(value)
        if _is_protected(normalized):
            raise PathPolicyViolation(f"runner-owned or protected path: {normalized}")
        current = root
        for part in PurePosixPath(normalized).parts:
            current /= part
            if current.is_symlink():
                raise PathPolicyViolation(f"patch path contains a symlink: {normalized}")
        resolved = (root / normalized).resolve(strict=False)
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise PathPolicyViolation("patch path escapes the repository root") from error
        canonical.add(normalized)
    if not canonical:
        raise PathPolicyViolation("a warrant must bind at least one patch path")
    return tuple(sorted(canonical))


_DIFF_HEADER = re.compile(r"^diff --git a/([^\s\"\\]+) b/([^\s\"\\]+)$")
_INDEX_LINE = re.compile(r"^index [0-9a-f]{7,64}\.\.[0-9a-f]{7,64} (100644|100755)$")
_UNSAFE_CONTROL_PREFIXES = (
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
    "similarity index ",
    "dissimilarity index ",
    "old mode ",
    "new mode ",
    "new file mode ",
    "deleted file mode ",
    "GIT binary patch",
    "Binary files ",
)
_MAX_PATCH_BYTES = 1_048_576


def derive_patch_paths(patch: bytes) -> tuple[str, ...]:
    """Strictly derive mutation paths from canonical unified-diff bytes.

    CrossPatch intentionally accepts only in-place regular-file modifications.
    This small language excludes Git's rename/copy, binary, type-change, quoted
    path, and new/deleted-file surfaces before repository access occurs.
    """
    if not patch:
        raise PatchFormatViolation("patch bytes must not be empty")
    if len(patch) > _MAX_PATCH_BYTES:
        raise PatchFormatViolation("patch exceeds the one-megabyte broker limit")
    if b"\x00" in patch:
        raise PatchFormatViolation("patch bytes contain NUL")
    if b"\r" in patch:
        raise PatchFormatViolation("patch must use canonical LF line endings")
    if not patch.endswith(b"\n"):
        raise PatchFormatViolation("patch must end with LF")
    try:
        text = patch.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PatchFormatViolation("patch must be valid UTF-8") from error

    lines = text.splitlines()
    section_starts = [index for index, line in enumerate(lines) if line.startswith("diff ")]
    if not section_starts or section_starts[0] != 0:
        raise PatchFormatViolation("patch must start with a diff --git header")

    derived: list[str] = []
    for section_number, start in enumerate(section_starts):
        end = (
            section_starts[section_number + 1]
            if section_number + 1 < len(section_starts)
            else len(lines)
        )
        header = lines[start]
        match = _DIFF_HEADER.fullmatch(header)
        if match is None:
            raise PatchFormatViolation("diff header contains an unsupported path encoding")
        old_path, new_path = match.groups()
        old_path = _normalize_candidate_path(old_path)
        new_path = _normalize_candidate_path(new_path)
        if old_path != new_path:
            raise PatchFormatViolation("cross-path changes, renames, and copies are forbidden")
        if _is_protected(old_path):
            raise PathPolicyViolation(f"runner-owned or protected path: {old_path}")

        body = lines[start + 1 : end]
        if any(line.startswith(_UNSAFE_CONTROL_PREFIXES) for line in body):
            raise PatchFormatViolation("diff contains binary, rename, copy, or mode controls")
        index_lines = [line for line in body if line.startswith("index ")]
        if len(index_lines) != 1 or _INDEX_LINE.fullmatch(index_lines[0]) is None:
            raise PatchFormatViolation("diff must bind one regular-file index line")
        if body.count(f"--- a/{old_path}") != 1 or body.count(f"+++ b/{new_path}") != 1:
            raise PatchFormatViolation("diff file markers do not match the header path")
        if not any(line.startswith("@@ ") for line in body):
            raise PatchFormatViolation("diff section contains no text hunk")
        derived.append(old_path)

    if len(derived) != len(set(derived)):
        raise PatchFormatViolation("a patch path may appear in only one diff section")
    return tuple(sorted(derived))


def validate_declared_patch_paths(
    repository_root: str | Path,
    patch: bytes,
    declared_paths: Iterable[str],
) -> tuple[str, ...]:
    """Require declared warrant paths to exactly equal paths from actual bytes."""
    derived = derive_patch_paths(patch)
    declared = validate_patch_paths(repository_root, declared_paths)
    if declared != derived:
        raise PathPolicyViolation("declared paths do not match paths derived from patch bytes")
    # Revalidate the derived names against the live standalone snapshot so
    # existing symlink ancestors cannot turn a safe lexical name into escape.
    validated = validate_patch_paths(repository_root, derived)
    if validated != derived:  # defensive: both sides are canonical sorted tuples
        raise PathPolicyViolation("derived patch paths are not canonical")
    return derived
