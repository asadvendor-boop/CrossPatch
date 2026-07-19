from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github" / "workflows" / "keyless-judge.yml"
CLAIM_VERIFIER = ROOT / "scripts" / "verify_claim_map.py"

PINNED_ACTIONS = {
    "actions/checkout": "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
    "actions/setup-node": "820762786026740c76f36085b0efc47a31fe5020",
    "astral-sh/setup-uv": "11f9893b081a58869d3b5fccaea48c9e9e46f990",
}


def test_make_judge_is_a_frozen_keyless_verification_matrix() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "judge: export OPENAI_API_KEY :=" in makefile, (
        "the whole target, including Compose auto-dotenv handling, must override the key"
    )
    result = subprocess.run(
        ["make", "-n", "judge"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    commands = result.stdout
    required_in_order = (
        "uv sync --frozen --extra dev",
        "npm ci --ignore-scripts --no-audit --no-fund",
        "docker compose --env-file /dev/null build runner",
        "OPENAI_API_KEY= uv run --frozen --extra dev python -m pytest -m 'not real_model'",
        "npm run lint",
        "npm run typecheck",
        "npm --workspace @crosspatch/web test -- --run",
        "npm run build",
        "docker compose --env-file /dev/null config --quiet",
        "python scripts/verify_capture_integrity.py",
        "python scripts/verify_claim_map.py --check",
    )
    offsets = [commands.index(fragment) for fragment in required_in_order]
    assert offsets == sorted(offsets)
    assert "scripts/verify-release.sh" not in commands
    assert "demo_readiness" not in commands


def test_keyless_python_gate_overrides_a_repository_dotenv_key(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=paid-key-value-that-must-not-load\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["OPENAI_API_KEY"] = ""
    environment["PYTHONPATH"] = str(ROOT / "backend" / "src")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from crosspatch.config import Settings; "
                "value=Settings().openai_api_key; "
                "assert value is None or value.get_secret_value() == ''"
            ),
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_keyless_workflow_is_valid_pinned_and_has_no_secret_dependency() -> None:
    assert WORKFLOW.is_file(), "B2 must ship a push workflow"
    source = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.load(source, Loader=yaml.BaseLoader)
    assert isinstance(workflow, dict)
    assert set(workflow["on"]) == {"push", "pull_request"}
    assert workflow["permissions"] == {"contents": "read"}
    assert "secrets." not in source

    judge = workflow["jobs"]["judge"]
    assert judge["runs-on"] == "ubuntu-24.04"
    assert judge["env"]["OPENAI_API_KEY"] == ""
    assert int(judge["timeout-minutes"]) <= 20
    steps = judge["steps"]
    uses = [step["uses"] for step in steps if "uses" in step]
    assert len(uses) == len(PINNED_ACTIONS)
    for reference in uses:
        action, revision = reference.split("@", maxsplit=1)
        assert PINNED_ACTIONS[action] == revision
        assert re.fullmatch(r"[0-9a-f]{40}", revision)

    checkout = next(step for step in steps if step.get("name") == "Checkout")
    assert checkout["with"]["fetch-depth"] == "0"
    setup_uv = next(step for step in steps if step.get("name") == "Set up uv")
    assert setup_uv["with"]["version"] == "0.10.12"
    setup_node = next(step for step in steps if step.get("name") == "Set up Node")
    assert setup_node["with"]["node-version-file"] == ".node-version"
    pinned_npm = next(step for step in steps if step.get("name") == "Activate pinned npm")
    assert "packageManager.replace(/^npm@/, '')" in pinned_npm["run"]
    assert 'npm install --global "npm@${NPM_VERSION}"' in pinned_npm["run"]
    assert 'test "$(npm --version)" = "${NPM_VERSION}"' in pinned_npm["run"]
    assert steps.index(setup_node) < steps.index(pinned_npm) < len(steps) - 1
    assert steps[-1] == {"name": "Run keyless judge gate", "run": "make judge"}


def test_readme_starts_event_first_then_keeps_the_exact_three_line_judge_block() -> None:
    source = (ROOT / "README.md").read_text(encoding="utf-8")
    event_first = "The agent-release gate that survived a live tampered-evidence attack"
    heading = "## Verify every claim yourself"
    assert source.index(event_first) < source.index(heading)
    assert "in about a minute, on a fresh clone" in source
    after_heading = source.split(heading, maxsplit=1)[1]
    block = after_heading.split("```bash", maxsplit=1)[1].split("```", maxsplit=1)[0]
    assert [line for line in block.splitlines() if line] == [
        "git clone https://github.com/asadvendor-boop/CrossPatch.git",
        "cd CrossPatch",
        "make judge",
    ]


def _claim_payload(root: Path) -> tuple[Path, Path]:
    artifact = root / "artifacts" / "verification" / "proof.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(
        json.dumps(
            {
                "machine_generated": True,
                "status": "PASS",
                "generator": "scripts/generator.sh",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    generator = root / "scripts" / "generator.sh"
    generator.parent.mkdir()
    generator.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    generator.chmod(0o755)
    claim_map = root / "docs" / "CLAIM_MAP.json"
    claim_map.parent.mkdir()
    claim_map.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "claims": [
                    {
                        "claim_id": "control.proof",
                        "artifact_path": "artifacts/verification/proof.json",
                        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        "artifact_status": "PASS",
                        "generator": "scripts/generator.sh",
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return claim_map, artifact


def test_claim_map_verifier_recomputes_hashes_and_fails_on_drift(
    tmp_path: Path,
) -> None:
    assert CLAIM_VERIFIER.is_file() and CLAIM_VERIFIER.stat().st_mode & 0o111
    claim_map, artifact = _claim_payload(tmp_path)
    command = [
        sys.executable,
        str(CLAIM_VERIFIER),
        "--check",
        "--root",
        str(tmp_path),
        "--claim-map",
        str(claim_map),
    ]

    valid = subprocess.run(command, check=False, capture_output=True, text=True)
    assert valid.returncode == 0, valid.stdout + valid.stderr
    assert json.loads(valid.stdout) == {
        "claim_count": 1,
        "status": "PASS",
        "verified_artifact_count": 1,
    }

    artifact.write_bytes(artifact.read_bytes() + b"\n")
    drift = subprocess.run(command, check=False, capture_output=True, text=True)
    assert drift.returncode != 0
    assert "artifact sha256 drift" in drift.stderr.lower()


def test_checked_in_claim_map_rehashes_without_codex_or_model_credentials() -> None:
    result = subprocess.run(
        [sys.executable, str(CLAIM_VERIFIER), "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    claim_count = len(json.loads((ROOT / "docs" / "CLAIM_MAP.json").read_text())["claims"])
    assert payload["claim_count"] == claim_count
    assert payload["verified_artifact_count"] > 0
