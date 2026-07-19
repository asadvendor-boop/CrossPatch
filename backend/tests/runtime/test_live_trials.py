from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
import pytest_asyncio
from crosspatch.api.dependencies import Role
from crosspatch.domain.enums import IncidentState
from crosspatch.runtime.auth import DatabaseTokenAuthenticator
from crosspatch.runtime.database import RuntimeDatabase
from crosspatch.runtime.live_trials import (
    LiveTrialBudgetExceeded,
    LiveTrialRateLimited,
    LiveTrialRepository,
)


@pytest_asyncio.fixture
async def database(tmp_path):
    runtime = RuntimeDatabase(f"sqlite+aiosqlite:///{tmp_path / 'live-trials.db'}")
    await runtime.bootstrap()
    try:
        yield runtime
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_two_credentials_share_one_global_spend_ceiling(database) -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    repository = LiveTrialRepository(
        database.sessions,
        global_cap_usd=20,
        requests_per_window=3,
        window_seconds=3600,
        clock=lambda: now,
    )
    first = await repository.issue(
        actor="approver-1",
        expires_at=now + timedelta(days=30),
    )
    second = await repository.issue(
        actor="approver-1",
        expires_at=now + timedelta(days=30),
    )

    await repository.reserve(first.subject, amount_usd=12, operation="initial-run")
    with pytest.raises(LiveTrialBudgetExceeded, match="global live-trial budget"):
        await repository.reserve(second.subject, amount_usd=12, operation="initial-run")

    budget = await repository.global_budget()
    assert budget.cap_usd == 20
    assert budget.reserved_usd == 12
    assert budget.spent_usd == 0


@pytest.mark.asyncio
async def test_rate_limit_is_per_credential_and_dynamic_bearer_authenticates(database) -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    repository = LiveTrialRepository(
        database.sessions,
        global_cap_usd=20,
        requests_per_window=1,
        window_seconds=3600,
        clock=lambda: now,
    )
    first = await repository.issue(
        actor="approver-1",
        expires_at=now + timedelta(days=30),
    )
    second = await repository.issue(
        actor="approver-1",
        expires_at=now + timedelta(days=30),
    )
    await repository.reserve(first.subject, amount_usd=1, operation="initial-run")
    with pytest.raises(LiveTrialRateLimited, match="rate limit"):
        await repository.reserve(first.subject, amount_usd=1, operation="revision")
    await repository.reserve(second.subject, amount_usd=1, operation="initial-run")

    authenticator = DatabaseTokenAuthenticator(database.sessions, ())
    principal = await authenticator.authenticate(first.token)
    assert principal is not None
    assert principal.subject == first.subject
    assert principal.role is Role.LIVE_TRIAL
    assert principal.incident_ids == frozenset()
    assert first.token not in repr(principal)


@pytest.mark.asyncio
async def test_reservation_binds_only_to_credential_owned_live_trial_and_settles(database) -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    repository = LiveTrialRepository(database.sessions, clock=lambda: now)
    issued = await repository.issue(
        actor="approver-1",
        expires_at=now + timedelta(days=30),
    )
    reservation_id = await repository.reserve(
        issued.subject,
        amount_usd=4,
        operation="initial-run",
    )
    await database.store.create_incident(
        incident_id="inc-owned-live-trial",
        title="Owned live trial",
        scenario="webhook-race",
        state=IncidentState.OPEN,
        base_sha="1" * 40,
        repository_manifest_sha256="2" * 64,
        catalog_sha256="3" * 64,
        actor=issued.subject,
        live_trial=True,
    )

    await repository.bind_incident(
        reservation_id,
        subject=issued.subject,
        incident_id="inc-owned-live-trial",
    )
    assert await repository.owns(issued.subject, "inc-owned-live-trial") is True
    await repository.settle(reservation_id, actual_usd="1.25")

    budget = await repository.global_budget()
    assert budget.spent_usd == Decimal("1.25")
    assert budget.reserved_usd == 0


@pytest.mark.asyncio
async def test_revoked_live_trial_bearer_fails_authentication(database) -> None:
    now = datetime(2026, 7, 14, 12, tzinfo=UTC)
    repository = LiveTrialRepository(database.sessions, clock=lambda: now)
    issued = await repository.issue(
        actor="approver-1",
        expires_at=now + timedelta(days=30),
    )
    authenticator = DatabaseTokenAuthenticator(database.sessions, ())
    assert await authenticator.authenticate(issued.token) is not None

    await repository.revoke(issued.subject, actor="approver-1")

    assert await authenticator.authenticate(issued.token) is None
