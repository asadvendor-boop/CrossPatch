import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[3]
EXACT_NPM_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")


def test_python_dependencies_have_a_frozen_uv_lock():
    lock_path = ROOT / "uv.lock"

    assert lock_path.is_file(), "uv.lock must be committed"
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    crosspatch = next(package for package in lock["package"] if package["name"] == "crosspatch")

    assert lock["requires-python"] == ">=3.12, <3.14"
    assert crosspatch["source"] == {"editable": "."}


def test_npm_dependencies_are_exact_and_match_the_workspace_lock():
    lock_path = ROOT / "package-lock.json"

    assert lock_path.is_file(), "root package-lock.json must lock the npm workspace"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    locked_packages = lock["packages"]

    assert lock["lockfileVersion"] == 3
    assert locked_packages[""]["workspaces"] == ["web"]
    manifests = ((ROOT / "package.json", ""), (ROOT / "web/package.json", "web"))
    for manifest_path, workspace in manifests:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for section in ("dependencies", "devDependencies", "overrides"):
            for package, requested in manifest.get(section, {}).items():
                assert EXACT_NPM_VERSION.fullmatch(requested), f"{package} is not exactly pinned"
                candidate_paths = [f"node_modules/{package}"]
                if workspace:
                    candidate_paths.insert(0, f"{workspace}/node_modules/{package}")
                installed = next(
                    (locked_packages[path] for path in candidate_paths if path in locked_packages),
                    None,
                )
                assert installed is not None, f"{package} is absent from package-lock.json"
                assert installed["version"] == requested


def test_postcss_override_keeps_the_root_next_resolver_anchor_in_sync():
    root_manifest = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    web_manifest = json.loads((ROOT / "web/package.json").read_text(encoding="utf-8"))

    assert root_manifest["devDependencies"]["next"] == web_manifest["dependencies"]["next"]
    assert root_manifest["overrides"]["postcss"] == "8.5.19"


def test_sharp_wasm_runtime_is_present_in_the_cross_platform_lock_tree():
    lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
    packages = lock["packages"]

    sharp_wasm = packages["node_modules/@img/sharp-wasm32"]
    assert sharp_wasm["dependencies"]["@emnapi/runtime"] == "^1.7.0"
    assert packages["node_modules/@emnapi/runtime"]["version"] == "1.11.2"


def test_bootstrap_installs_from_frozen_dependency_locks():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    bootstrap = makefile.split("bootstrap:", maxsplit=1)[1].split("\n\n", maxsplit=1)[0]

    assert "uv sync --frozen --extra dev" in bootstrap
    assert "\tnpm ci" in bootstrap


def test_web_image_uses_the_declared_npm_version_for_the_frozen_lock():
    manifest = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert manifest["packageManager"] == "npm@11.6.2"
    version_read = "require('./package.json').packageManager.replace(/^npm@/, '')"
    install = 'npm install --global "npm@${NPM_VERSION}"'
    frozen_install = "npm ci --ignore-scripts --no-audit --no-fund"
    assert version_read in dockerfile
    assert install in dockerfile
    assert 'test "$(npm --version)" = "${NPM_VERSION}"' in dockerfile
    assert dockerfile.index(version_read) < dockerfile.index(install)
    assert dockerfile.index(install) < dockerfile.index(frozen_install)


def test_python_image_seals_the_virtualenv_before_the_runtime_copy():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    dependency_stage = dockerfile.split("FROM ${PYTHON_IMAGE} AS python-dependencies", 1)[
        1
    ].split("FROM ${PYTHON_IMAGE} AS python-runtime", 1)[0]
    runtime_stage = dockerfile.split("FROM ${PYTHON_IMAGE} AS python-runtime", 1)[1].split(
        "FROM ${NODE_IMAGE} AS web-build", 1
    )[0]

    assert "UV_CONCURRENT_DOWNLOADS=2" in dependency_stage
    assert "RUN --mount=type=cache,target=/root/.cache/uv" in dependency_stage
    assert "uv sync --frozen --no-dev" in dependency_stage
    assert "--no-cache" not in dependency_stage
    assert "chmod -R a-w /opt/crosspatch" in dependency_stage
    assert dependency_stage.index("uv sync --frozen --no-dev") < (
        dependency_stage.index("chmod -R a-w /opt/crosspatch")
    )
    assert (
        "COPY --from=python-dependencies --chown=root:root "
        "/opt/crosspatch/venv/ /opt/crosspatch/venv/"
    ) in runtime_stage
    assert "chmod -R a-w /opt/crosspatch" not in runtime_stage


def test_python_bootstrap_version_is_architecture_neutral_and_pinned():
    assert (ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.13.7"


def test_release_gate_builds_and_smoke_tests_a_clean_wheel_install():
    verifier = (ROOT / "scripts/release_verifier.py").read_text(encoding="utf-8")
    installer_path = ROOT / "scripts/verify_package_install.py"

    assert '"scripts/verify_package_install.py"' in verifier
    assert installer_path.is_file()
    installer = installer_path.read_text(encoding="utf-8")
    for required in (
        '"build"',
        '"--wheel"',
        '"uv", "sync", "--frozen", "--no-install-project"',
        '"pip",',
        '"install",',
        '"crosspatch", "--help"',
        'environment.pop("PYTHONPATH", None)',
    ):
        assert required in installer


def test_python_build_and_clean_install_are_constrained_by_the_frozen_lock():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    backend_requirements = project["build-system"]["requires"]
    dev_requirements = project["project"]["optional-dependencies"]["dev"]
    installer = (ROOT / "scripts/verify_package_install.py").read_text(encoding="utf-8")

    assert backend_requirements == ["setuptools==80.9.0"]
    assert "setuptools==80.9.0" in dev_requirements
    assert '"--no-isolation"' in installer
    assert '"UV_PROJECT_ENVIRONMENT": str(virtual_environment)' in installer
    assert '"sync", "--frozen", "--no-install-project"' in installer
    assert '"--no-deps"' in installer
