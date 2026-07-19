from pathlib import Path

import pytest
from crosspatch.broker.paths import PathPolicyViolation, validate_patch_paths


@pytest.mark.parametrize(
    "path",
    [
        "../escape",
        "/absolute",
        "C:/windows-absolute",
        ".git/config",
        ".gitmodules",
        "tests/test_race.py",
        "victim/tests/test_race.py",
        "backend/tests/test_broker.py",
        "compose.yaml",
        "backend/src/crosspatch/runner/catalog.py",
        "safe/../../escape.py",
        "safe\x00file.py",
    ],
)
def test_protected_or_escaping_paths_are_rejected(tmp_path: Path, path: str):
    with pytest.raises(PathPolicyViolation):
        validate_patch_paths(tmp_path, [path])


def test_candidate_source_paths_are_normalized_and_accepted(tmp_path: Path):
    assert validate_patch_paths(
        tmp_path,
        ["victim/src/victim/db.py", "victim/src/victim/webhooks.py"],
    ) == ("victim/src/victim/db.py", "victim/src/victim/webhooks.py")
