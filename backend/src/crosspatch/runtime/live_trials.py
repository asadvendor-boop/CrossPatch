"""Durable live-trial credentials, per-credential rate limits, and global budget."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from crosspatch.api.dependencies import Role
from crosspatch.db.models import (
    ApiIncidentGrantRecord,
    ApiPrincipalRecord,
    IncidentRecord,
    LiveTrialBudgetRecord,
    LiveTrialCredentialRecord,
    LiveTrialReservationRecord,
)

_GLOBAL_BUDGET_ID = "global"
_MICRO = Decimal(1_000_000)


class LiveTrialDenied(PermissionError):
    pass


class LiveTrialBudgetExceeded(LiveTrialDenied):
    pass


class LiveTrialRateLimited(LiveTrialDenied):
    pass


def _microusd(value: int | float | Decimal) -> int:
    try:
        amount = Decimal(str(value))
    except InvalidOperation as error:
        raise ValueError("live-trial USD amount is invalid") from error
    if not amount.is_finite() or amount <= 0:
        raise ValueError("live-trial USD amount must be positive")
    return int((amount * _MICRO).to_integral_value(rounding=ROUND_CEILING))


def _nonnegative_microusd(value: int | float | Decimal | str) -> int:
    try:
        amount = Decimal(str(value))
    except InvalidOperation as error:
        raise ValueError("live-trial USD amount is invalid") from error
    if not amount.is_finite() or amount < 0:
        raise ValueError("live-trial USD amount must be non-negative")
    return int((amount * _MICRO).to_integral_value(rounding=ROUND_CEILING))


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class IssuedLiveTrialCredential:
    token: str
    subject: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class LiveTrialBudgetView:
    cap_usd: Decimal
    spent_usd: Decimal
    reserved_usd: Decimal


class LiveTrialRepository:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        *,
        global_cap_usd: int | float | Decimal = 20,
        requests_per_window: int = 3,
        window_seconds: int = 3600,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if requests_per_window < 1 or window_seconds < 1:
            raise ValueError("live-trial rate limits must be positive")
        self._sessions = sessions
        self._cap = _microusd(global_cap_usd)
        self._requests_per_window = requests_per_window
        self._window_seconds = window_seconds
        self._clock = clock or (lambda: datetime.now(UTC))

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("live-trial clock must be timezone-aware")
        return value.astimezone(UTC)

    async def _budget_locked(self, session: AsyncSession, now: datetime):
        if session.bind is not None and session.bind.dialect.name == "postgresql":
            await session.execute(
                text("SELECT pg_advisory_xact_lock(435276112)")
            )
        budget = await session.scalar(
            select(LiveTrialBudgetRecord)
            .where(LiveTrialBudgetRecord.id == _GLOBAL_BUDGET_ID)
            .with_for_update()
        )
        if budget is None:
            budget = LiveTrialBudgetRecord(
                id=_GLOBAL_BUDGET_ID,
                cap_microusd=self._cap,
                spent_microusd=0,
                reserved_microusd=0,
                updated_at=now,
            )
            session.add(budget)
            await session.flush()
        elif budget.cap_microusd != self._cap:
            raise RuntimeError("configured global live-trial budget changed")
        return budget

    async def issue(
        self,
        *,
        actor: str,
        expires_at: datetime,
    ) -> IssuedLiveTrialCredential:
        now = self._now()
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ValueError("live-trial credential expiry must be timezone-aware")
        expiry = expires_at.astimezone(UTC)
        if expiry <= now:
            raise ValueError("live-trial credential must expire in the future")
        token = secrets.token_urlsafe(48)
        subject = f"live-trial-{uuid4().hex}"
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        async with self._sessions() as session, session.begin():
            await self._budget_locked(session, now)
            session.add(
                ApiPrincipalRecord(
                    subject=subject,
                    bearer_sha256=digest,
                    role=Role.LIVE_TRIAL.value,
                    expires_at=expiry,
                    revoked=False,
                    created_at=now,
                    updated_at=now,
                )
            )
            session.add(
                LiveTrialCredentialRecord(
                    subject=subject,
                    created_by=actor,
                    rate_window_started_at=now,
                    rate_count=0,
                    revoked_at=None,
                    revoked_by=None,
                    created_at=now,
                    updated_at=now,
                )
            )
        return IssuedLiveTrialCredential(token, subject, expiry)

    async def revoke(self, subject: str, *, actor: str) -> None:
        now = self._now()
        async with self._sessions() as session, session.begin():
            credential = await session.scalar(
                select(LiveTrialCredentialRecord)
                .where(LiveTrialCredentialRecord.subject == subject)
                .with_for_update()
            )
            principal = await session.get(ApiPrincipalRecord, subject)
            if (
                credential is None
                or principal is None
                or principal.role != Role.LIVE_TRIAL.value
            ):
                raise LookupError(subject)
            principal.revoked = True
            principal.updated_at = now
            if credential.revoked_at is None:
                credential.revoked_at = now
                credential.revoked_by = actor
                credential.updated_at = now

    async def reserve(
        self,
        subject: str,
        *,
        amount_usd: int | float | Decimal,
        operation: str,
    ) -> str:
        amount = _microusd(amount_usd)
        if operation not in {"initial-run", "revision"}:
            raise ValueError("unsupported live-trial budget operation")
        now = self._now()
        async with self._sessions() as session, session.begin():
            credential = await session.scalar(
                select(LiveTrialCredentialRecord)
                .where(LiveTrialCredentialRecord.subject == subject)
                .with_for_update()
            )
            principal = await session.get(ApiPrincipalRecord, subject)
            if (
                credential is None
                or principal is None
                or principal.revoked
                or principal.role != Role.LIVE_TRIAL.value
                or _aware(principal.expires_at) <= now
            ):
                raise LiveTrialDenied("live-trial credential is unavailable")
            window_start = _aware(credential.rate_window_started_at)
            if now >= window_start + timedelta(seconds=self._window_seconds):
                credential.rate_window_started_at = now
                credential.rate_count = 0
            if credential.rate_count >= self._requests_per_window:
                raise LiveTrialRateLimited("live-trial per-credential rate limit reached")
            budget = await self._budget_locked(session, now)
            if budget.spent_microusd + budget.reserved_microusd + amount > budget.cap_microusd:
                raise LiveTrialBudgetExceeded("global live-trial budget exhausted")
            reservation_id = f"trial-reservation-{uuid4().hex}"
            credential.rate_count += 1
            credential.updated_at = now
            budget.reserved_microusd += amount
            budget.updated_at = now
            session.add(
                LiveTrialReservationRecord(
                    id=reservation_id,
                    subject=subject,
                    operation=operation,
                    reserved_microusd=amount,
                    status="RESERVED",
                    created_at=now,
                )
            )
        return reservation_id

    async def bind_incident(
        self,
        reservation_id: str,
        *,
        subject: str,
        incident_id: str,
    ) -> None:
        async with self._sessions() as session, session.begin():
            reservation = await session.scalar(
                select(LiveTrialReservationRecord)
                .where(LiveTrialReservationRecord.id == reservation_id)
                .with_for_update()
            )
            incident = await session.get(IncidentRecord, incident_id)
            grant = await session.scalar(
                select(ApiIncidentGrantRecord).where(
                    ApiIncidentGrantRecord.subject == subject,
                    ApiIncidentGrantRecord.incident_id == incident_id,
                )
            )
            if (
                reservation is None
                or reservation.status != "RESERVED"
                or reservation.subject != subject
                or reservation.incident_id is not None
                or incident is None
                or not incident.live_trial
                or incident.owner_subject != subject
                or grant is None
            ):
                raise LiveTrialDenied("live-trial reservation ownership mismatch")
            reservation.incident_id = incident_id

    async def owns(self, subject: str, incident_id: str) -> bool:
        async with self._sessions() as session:
            incident = await session.get(IncidentRecord, incident_id)
            if (
                incident is None
                or not incident.live_trial
                or incident.owner_subject != subject
            ):
                return False
            grant = await session.scalar(
                select(ApiIncidentGrantRecord.id).where(
                    ApiIncidentGrantRecord.subject == subject,
                    ApiIncidentGrantRecord.incident_id == incident_id,
                )
            )
            return grant is not None

    async def settle(
        self,
        reservation_id: str,
        *,
        actual_usd: int | float | Decimal | str,
    ) -> None:
        actual = _nonnegative_microusd(actual_usd)
        now = self._now()
        async with self._sessions() as session, session.begin():
            reservation = await session.scalar(
                select(LiveTrialReservationRecord)
                .where(LiveTrialReservationRecord.id == reservation_id)
                .with_for_update()
            )
            if reservation is None:
                raise LookupError(reservation_id)
            if reservation.status != "RESERVED":
                raise LiveTrialDenied("live-trial reservation already settled")
            budget = await self._budget_locked(session, now)
            if budget.reserved_microusd < reservation.reserved_microusd:
                raise RuntimeError("global live-trial reserved budget is inconsistent")
            budget.reserved_microusd -= reservation.reserved_microusd
            budget.spent_microusd += actual
            budget.updated_at = now
            reservation.actual_microusd = actual
            reservation.status = "SETTLED"
            reservation.settled_at = now

    async def global_budget(self) -> LiveTrialBudgetView:
        now = self._now()
        async with self._sessions() as session, session.begin():
            budget = await self._budget_locked(session, now)
            return LiveTrialBudgetView(
                Decimal(budget.cap_microusd) / _MICRO,
                Decimal(budget.spent_microusd) / _MICRO,
                Decimal(budget.reserved_microusd) / _MICRO,
            )
