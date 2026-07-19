from pathlib import Path

import pytest
from crosspatch.broker.paths import (
    PatchFormatViolation,
    PathPolicyViolation,
    derive_patch_paths,
    validate_declared_patch_paths,
)

VALID_PATCH = b"""diff --git a/victim/src/victim/db.py b/victim/src/victim/db.py
index 1111111..2222222 100644
--- a/victim/src/victim/db.py
+++ b/victim/src/victim/db.py
@@ -1 +1 @@
-vulnerable = True
+vulnerable = False
"""


@pytest.mark.parametrize(
    "patch",
    [
        b"diff --git a/../escape.py b/../escape.py\n--- a/../escape.py\n+++ b/../escape.py\n",
        b'diff --git "a/victim/src/x.py" "b/../../escape.py"\n',
        b"diff --git a/victim/src/x.py b/victim/src/y.py\n"
        b"similarity index 100%\nrename from victim/src/x.py\n"
        b"rename to ../../escape.py\n",
        b"diff --git a/victim/src/x.py b/victim/src/x.py\n"
        b"new file mode 120000\n--- /dev/null\n+++ b/victim/src/x.py\n"
        b"@@ -0,0 +1 @@\n+../../secret\n",
        b"diff --git a/victim/src/x.py b/victim/src/x.py\n"
        b"new file mode 160000\n--- /dev/null\n+++ b/victim/src/x.py\n"
        b"@@ -0,0 +1 @@\n+Subproject commit deadbeef\n",
        b"diff --git a/.git/config b/.git/config\n--- a/.git/config\n+++ b/.git/config\n",
        b"diff --git a/victim/src/x.bin b/victim/src/x.bin\nGIT binary patch\nliteral 4\nAAAA\n",
        b"diff --git a/victim/tests/test_race.py b/victim/tests/test_race.py\n"
        b"--- a/victim/tests/test_race.py\n+++ b/victim/tests/test_race.py\n",
        b"diff --git a/victim/src/x.py b/victim/src/x.py\n"
        b"copy from victim/src/x.py\ncopy to victim/src/y.py\n",
        b"diff --git a/victim/src/x.py b/victim/src/x.py\r\n"
        b"--- a/victim/src/x.py\r\n+++ b/victim/src/x.py\r\n",
        b"diff --git a/victim/src/x.py b/victim/src/x.py\nold mode 100644\nnew mode 100755\n",
    ],
    ids=[
        "traversal",
        "quoted-escape",
        "rename-escape",
        "symlink-mode",
        "submodule-mode",
        "git-metadata",
        "binary",
        "protected-test",
        "copy",
        "crlf",
        "mode-change",
    ],
)
def test_hostile_diff_formats_are_rejected_before_repository_access(patch: bytes):
    with pytest.raises((PatchFormatViolation, PathPolicyViolation)):
        derive_patch_paths(patch)


def test_paths_are_derived_from_diff_and_must_equal_sorted_declaration(tmp_path: Path):
    path = tmp_path / "victim/src/victim/db.py"
    path.parent.mkdir(parents=True)
    path.write_text("vulnerable = True\n", encoding="utf-8")

    assert derive_patch_paths(VALID_PATCH) == ("victim/src/victim/db.py",)
    assert validate_declared_patch_paths(tmp_path, VALID_PATCH, ("victim/src/victim/db.py",)) == (
        "victim/src/victim/db.py",
    )

    with pytest.raises(PathPolicyViolation, match="declared paths"):
        validate_declared_patch_paths(
            tmp_path,
            VALID_PATCH,
            ("victim/src/victim/db.py", "victim/src/victim/webhooks.py"),
        )


def test_existing_symlink_target_is_rejected(tmp_path: Path):
    outside = tmp_path.parent / "outside-crosspatch.py"
    outside.write_text("secret = True\n", encoding="utf-8")
    path = tmp_path / "victim/src/victim/db.py"
    path.parent.mkdir(parents=True)
    path.symlink_to(outside)

    with pytest.raises(PathPolicyViolation, match="escapes|symlink"):
        validate_declared_patch_paths(tmp_path, VALID_PATCH, ("victim/src/victim/db.py",))
