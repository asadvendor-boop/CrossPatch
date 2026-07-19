from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from crosspatch.runner.reproduction import PayloadEquivalenceReproducer, RaceReproducer
from crosspatch.runtime.factories import (
    create_broker_mcp_app,
    create_control_app,
    create_evidence_mcp_app,
    create_judge_mcp_app,
)
from crosspatch.runtime.incidents import BundledIncidentLauncher
from crosspatch.runtime.readers import DatabasePublishedCaseReader
from crosspatch.runtime.scenarios import OPERATOR_SCENARIOS


@pytest.mark.asyncio
async def test_zero_argument_factories_are_launchable_and_health_checks_database(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CROSSPATCH_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'factory.db'}")
    monkeypatch.setenv("CROSSPATCH_REPOSITORY_ROOT", str(Path(__file__).parents[3]))
    monkeypatch.setenv("CROSSPATCH_ALLOWED_ORIGINS", "https://crosspatch.test")
    monkeypatch.setenv("CROSSPATCH_RUNNER_DIGEST", "7" * 64)
    monkeypatch.setenv("CROSSPATCH_ENVIRONMENT_DIGEST", "8" * 64)
    monkeypatch.setenv("CROSSPATCH_VICTIM_DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv(
        "CROSSPATCH_VICTIM_WORKER_DATABASE_URL",
        "postgresql://worker-unused",
    )
    monkeypatch.setenv("CROSSPATCH_VICTIM_URL", "http://victim")
    monkeypatch.setenv(
        "CROSSPATCH_VICTIM_WEBHOOK_SECRET",
        "test-webhook-secret-at-least-32-characters",
    )
    jobs_root = tmp_path / "runner-jobs"
    workspaces_root = tmp_path / "candidate-workspaces"
    jobs_root.mkdir()
    workspaces_root.mkdir()
    monkeypatch.setenv("CROSSPATCH_RUNNER_JOBS_ROOT", str(jobs_root))
    monkeypatch.setenv("CROSSPATCH_RUNNER_WORKSPACES_ROOT", str(workspaces_root))
    monkeypatch.setenv("CROSSPATCH_RUNNER_URL", "http://runner:9020")
    monkeypatch.setenv("CROSSPATCH_RUNNER_UID", "10001")
    monkeypatch.setenv("CROSSPATCH_RUNNER_TOKEN", "test-runner-service-token-with-32-characters")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    control = create_control_app()
    evidence = create_evidence_mcp_app()
    broker = create_broker_mcp_app()
    judge = create_judge_mcp_app()
    assert callable(control)
    assert callable(evidence)
    assert callable(broker)
    assert callable(judge)
    assert isinstance(control.state.public_case_reader, DatabasePublishedCaseReader)
    assert judge._authenticated_app._policy.config.incident_scoped is False  # type: ignore[attr-defined]
    launcher = control.state.control_service._launcher
    assert isinstance(launcher, BundledIncidentLauncher)
    assert set(launcher._reproduction_factories) == {
        *OPERATOR_SCENARIOS,
        "webhook-race:instruction-like-log",
    }
    race = launcher._reproduction_factories["webhook-race"]()
    equivalence = launcher._reproduction_factories["webhook-payload-equivalence"]()
    assert isinstance(race, RaceReproducer)
    assert isinstance(equivalence, PayloadEquivalenceReproducer)
    for reproducer in (race, equivalence):
        assert reproducer.database.dsn == "postgresql://unused"
        assert reproducer.drain_jobs.__self__.database.dsn == "postgresql://worker-unused"

    reconciliation_calls = 0

    async def reconcile_runtime_work() -> int:
        nonlocal reconciliation_calls
        reconciliation_calls += 1
        return 0

    monkeypatch.setattr(
        control.state.control_service,
        "reconcile_runtime_work",
        reconcile_runtime_work,
    )

    # The runtime wrapper forwards ASGI lifespan to FastMCP's inner app;
    # entering it proves database bootstrap and MCP session-manager startup.
    for surface, name in (
        (evidence, "evidence"),
        (broker, "broker"),
        (judge, "judge"),
    ):
        async with surface._app.router.lifespan_context(surface._app):  # type: ignore[attr-defined]
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=surface),
                base_url="http://test",
            ) as client:
                response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {
            "status": "ok",
            "database": "ok",
            "surface": name,
        }

    async with control.router.lifespan_context(control):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=control), base_url="http://test"
        ) as client:
            response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "database": "ok",
        "model_runtime": "abstain_only",
    }
    assert reconciliation_calls == 1
