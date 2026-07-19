from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from crosspatch.runner.catalog import CANDIDATE_PLAN_IDS, ExecutionCatalog, ExecutionPlan
from crosspatch.runner.process import FixedProcessRunner, RunnerPolicyViolation


class OnePlanCatalog:
    def __init__(self, plan: ExecutionPlan) -> None:
        self.plan = plan

    def resolve(self, plan_id: str) -> ExecutionPlan:
        if plan_id != self.plan.plan_id:
            raise LookupError(plan_id)
        return self.plan


@pytest.mark.asyncio
async def test_runner_builds_a_fixed_secret_free_environment(tmp_path: Path, monkeypatch):
    output = tmp_path / "environment.json"
    script = (
        "import json,os,pathlib; "
        "pathlib.Path('environment.json').write_text("
        "json.dumps(dict(os.environ), sort_keys=True))"
    )
    plan = ExecutionPlan("test.environment", (sys.executable, "-c", script), timeout_seconds=5)
    runner = FixedProcessRunner(catalog=OnePlanCatalog(plan))
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-cross")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-cross")

    receipt = await runner.run(tmp_path, plan)

    assert receipt.exit_code == 0
    assert receipt.passed is False
    assert receipt.verification_code == "UNSUPERVISED_PROCESS_EXIT"
    environment = json.loads(output.read_text(encoding="utf-8"))
    assert "OPENAI_API_KEY" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert environment["npm_config_ignore_scripts"] == "true"
    assert environment["PYTHONPATH"] == f"{tmp_path}/backend/src:{tmp_path}/victim/src"
    assert Path(environment["HOME"]).is_relative_to(tmp_path.parent)


@pytest.mark.asyncio
async def test_default_runner_rejects_non_catalog_argv_before_process(tmp_path: Path):
    runner = FixedProcessRunner(catalog=ExecutionCatalog.default())
    hostile = ExecutionPlan("victim.single-delivery", ("/bin/sh", "-c", "id"))

    with pytest.raises(RunnerPolicyViolation, match="catalog"):
        await runner.run(tmp_path, hostile)


@pytest.mark.asyncio
@pytest.mark.parametrize("plan_id", sorted(CANDIDATE_PLAN_IDS))
async def test_direct_runner_refuses_candidate_plan_that_requires_the_sidecar(
    tmp_path: Path,
    plan_id: str,
) -> None:
    runner = FixedProcessRunner(catalog=ExecutionCatalog.default())
    candidate = ExecutionCatalog.default().resolve(plan_id)

    with pytest.raises(RunnerPolicyViolation, match="trusted candidate sidecar"):
        await runner.run(tmp_path, candidate)


@pytest.mark.asyncio
async def test_timeout_kills_the_entire_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    script = (
        "import os,pathlib,subprocess,sys,time; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        "pathlib.Path('child.pid').write_text(str(p.pid)); "
        "time.sleep(60)"
    )
    plan = ExecutionPlan("test.timeout", (sys.executable, "-c", script), timeout_seconds=1)
    runner = FixedProcessRunner(catalog=OnePlanCatalog(plan))
    killpg = os.killpg
    kill_calls: list[tuple[int, int]] = []

    def tracked_killpg(process_group: int, signal_number: int) -> None:
        kill_calls.append((process_group, signal_number))
        killpg(process_group, signal_number)

    monkeypatch.setattr(os, "killpg", tracked_killpg)

    receipt = await runner.run(tmp_path, plan)

    assert receipt.timed_out is True
    assert receipt.passed is False
    assert kill_calls == [(kill_calls[0][0], __import__("signal").SIGKILL)]
    child_pid = int((tmp_path / "child.pid").read_text())
    for _ in range(100):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        await __import__("asyncio").sleep(0.01)
    else:
        pytest.fail("runner left a child process alive after timeout")
