"""Persistent API identities and shared judge-token revocation state."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import create_engine, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session

from crosspatch.api.dependencies import Principal, Role
from crosspatch.config import validate_judge_token_expiry
from crosspatch.db.models import (
    ApiIncidentGrantRecord,
    ApiPrincipalRecord,
    JudgeTokenAuditRecord,
    JudgeTokenRecord,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class ApiCredential:
    token: str
    subject: str
    role: Role
    expires_at: datetime
    csrf_token: str | None = None
    step_up_token: str | None = None
    step_up_expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if len(self.token) < 32 or not self.subject:
            raise ValueError("API bearer credentials require strong token material and a subject")
        if self.expires_at.tzinfo is None:
            raise ValueError("API credential expiry must be timezone-aware")
        if self.role is Role.APPROVER and (
            not self.csrf_token or not self.step_up_token or self.step_up_expires_at is None
        ):
            raise ValueError("approver credentials require CSRF and step-up controls")


class DatabaseTokenAuthenticator:
    """Authenticate configured bearer material against its durable digest record."""

    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        credentials: tuple[ApiCredential, ...],
    ) -> None:
        self._sessions = sessions
        self._credentials = {_digest(item.token): item for item in credentials}
        if len(self._credentials) != len(credentials):
            raise ValueError("API bearer credentials must be unique")

    async def provision(self) -> None:
        now = datetime.now(UTC)
        async with self._sessions() as session, session.begin():
            for bearer_sha256, credential in self._credentials.items():
                record = await session.get(ApiPrincipalRecord, credential.subject)
                values = {
                    "bearer_sha256": bearer_sha256,
                    "role": credential.role.value,
                    "csrf_sha256": (
                        _digest(credential.csrf_token) if credential.csrf_token else None
                    ),
                    "step_up_sha256": (
                        _digest(credential.step_up_token) if credential.step_up_token else None
                    ),
                    "expires_at": credential.expires_at,
                    "step_up_expires_at": credential.step_up_expires_at,
                    "updated_at": now,
                }
                if record is None:
                    session.add(
                        ApiPrincipalRecord(
                            subject=credential.subject,
                            created_at=now,
                            revoked=False,
                            **values,
                        )
                    )
                else:
                    for name, value in values.items():
                        setattr(record, name, value)

    async def authenticate(self, bearer_token: str) -> Principal | None:
        bearer_sha256 = _digest(bearer_token)
        credential = self._credentials.get(bearer_sha256)
        async with self._sessions() as session:
            record = await session.scalar(
                select(ApiPrincipalRecord).where(ApiPrincipalRecord.bearer_sha256 == bearer_sha256)
            )
            if record is None or record.revoked:
                return None
            role = Role(record.role)
            if credential is None and role is not Role.LIVE_TRIAL:
                return None
            expires_at = _aware(record.expires_at)
            if expires_at <= datetime.now(UTC):
                return None
            incident_ids = frozenset(
                (
                    await session.scalars(
                        select(ApiIncidentGrantRecord.incident_id).where(
                            ApiIncidentGrantRecord.subject == record.subject
                        )
                    )
                ).all()
            )
        return Principal(
            subject=record.subject,
            role=role,
            incident_ids=incident_ids,
            expires_at=expires_at,
            csrf_token=credential.csrf_token if credential is not None else None,
            step_up_token=credential.step_up_token if credential is not None else None,
            step_up_expires_at=(
                _aware(record.step_up_expires_at) if record.step_up_expires_at is not None else None
            ),
        )

    async def revalidate(self, principal: Principal) -> bool:
        if not principal.is_active():
            return False
        async with self._sessions() as session:
            record = await session.get(ApiPrincipalRecord, principal.subject)
            return (
                record is not None
                and not record.revoked
                and Role(record.role) is principal.role
                and _aware(record.expires_at) > datetime.now(UTC)
            )


class JudgeTokenRepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    @dataclass(frozen=True, slots=True)
    class TokenStatus:
        token_id: str
        expires_at: datetime
        revoked: bool
        created_at: datetime
        revoked_at: datetime | None

    @dataclass(frozen=True, slots=True)
    class AuditEvent:
        action: str
        token_id: str
        actor: str
        created_at: datetime

    @staticmethod
    def _status(record: JudgeTokenRecord) -> TokenStatus:
        return JudgeTokenRepository.TokenStatus(
            token_id=record.jti,
            expires_at=_aware(record.expires_at),
            revoked=record.revoked,
            created_at=_aware(record.created_at),
            revoked_at=(_aware(record.revoked_at) if record.revoked_at is not None else None),
        )

    @staticmethod
    def _validate_actor(actor: str) -> str:
        normalized = actor.strip()
        if not normalized or len(normalized) > 128:
            raise ValueError("judge token audit actor is required and bounded")
        return normalized

    @staticmethod
    def _audit(
        session: AsyncSession,
        *,
        token_id: str,
        action: str,
        actor: str,
        now: datetime,
    ) -> None:
        session.add(
            JudgeTokenAuditRecord(
                id=f"judge_audit_{uuid4().hex}",
                token_id=token_id,
                action=action,
                actor=actor,
                created_at=now,
            )
        )

    async def register(
        self,
        token: str,
        *,
        jti: str,
        expires_at: datetime,
        actor: str,
    ) -> None:
        normalized = validate_judge_token_expiry(expires_at)
        if not token.strip() or not jti.strip():
            raise ValueError("judge token and JTI are required")
        audit_actor = self._validate_actor(actor)
        token_sha256 = _digest(token)
        now = datetime.now(UTC)
        async with self._sessions() as session, session.begin():
            existing = await session.scalar(
                select(JudgeTokenRecord).where(
                    (JudgeTokenRecord.token_sha256 == token_sha256) | (JudgeTokenRecord.jti == jti)
                )
            )
            if existing is None:
                token_record = JudgeTokenRecord(
                    token_sha256=token_sha256,
                    jti=jti,
                    expires_at=normalized,
                    revoked=False,
                    created_at=now,
                )
                session.add(token_record)
                await session.flush()
                self._audit(
                    session,
                    token_id=jti,
                    action="ISSUED",
                    actor=audit_actor,
                    now=now,
                )
            elif existing.token_sha256 != token_sha256 or existing.jti != jti:
                raise ValueError("judge token digest or JTI is already bound")
            elif existing.revoked:
                raise ValueError("revoked judge tokens cannot be re-registered")
            elif _aware(existing.expires_at) != normalized:
                raise ValueError("registered judge token expiry cannot change")

    async def revoke(self, token: str, *, actor: str) -> None:
        audit_actor = self._validate_actor(actor)
        now = datetime.now(UTC)
        async with self._sessions() as session, session.begin():
            record = await session.get(JudgeTokenRecord, _digest(token), with_for_update=True)
            if record is not None and not record.revoked:
                self._audit(
                    session,
                    token_id=record.jti,
                    action="REVOKED",
                    actor=audit_actor,
                    now=now,
                )
                await session.flush()
                record.revoked = True
                record.revoked_at = now

    async def revoke_by_token_id(
        self,
        token_id: str,
        *,
        actor: str,
    ) -> TokenStatus | None:
        if not token_id.strip():
            raise ValueError("judge token ID is required")
        audit_actor = self._validate_actor(actor)
        now = datetime.now(UTC)
        async with self._sessions() as session, session.begin():
            record = await session.scalar(
                select(JudgeTokenRecord)
                .where(JudgeTokenRecord.jti == token_id)
                .with_for_update()
            )
            if record is None:
                return None
            if not record.revoked:
                self._audit(
                    session,
                    token_id=record.jti,
                    action="REVOKED",
                    actor=audit_actor,
                    now=now,
                )
                await session.flush()
                record.revoked = True
                record.revoked_at = now
            return self._status(record)

    async def list_tokens(self) -> tuple[TokenStatus, ...]:
        async with self._sessions() as session:
            records = tuple(
                (
                    await session.scalars(
                        select(JudgeTokenRecord).order_by(
                            JudgeTokenRecord.created_at,
                            JudgeTokenRecord.jti,
                        )
                    )
                ).all()
            )
            return tuple(self._status(record) for record in records)

    async def audit_events(self) -> tuple[AuditEvent, ...]:
        async with self._sessions() as session:
            records = tuple(
                (
                    await session.scalars(
                        select(JudgeTokenAuditRecord).order_by(
                            JudgeTokenAuditRecord.created_at,
                            JudgeTokenAuditRecord.id,
                        )
                    )
                ).all()
            )
            return tuple(
                self.AuditEvent(
                    action=record.action,
                    token_id=record.token_id,
                    actor=record.actor,
                    created_at=_aware(record.created_at),
                )
                for record in records
            )

    async def active_count(self) -> int:
        async with self._sessions() as session:
            value = await session.scalar(
                select(func.count())
                .select_from(JudgeTokenRecord)
                .where(JudgeTokenRecord.revoked.is_(False))
                .where(JudgeTokenRecord.expires_at > datetime.now(UTC))
            )
            return int(value or 0)


class DatabaseJudgeTokenRegistry:
    """Synchronous AuthPolicy adapter reading the database on every request."""

    def __init__(self, database_url: str, *, clock=None) -> None:
        self._engine = create_engine(database_url, pool_pre_ping=True)
        self._clock = clock or (lambda: datetime.now(UTC))

    def is_active(self, token: str) -> bool:
        digest = _digest(token)
        with Session(self._engine) as session:
            record = session.get(JudgeTokenRecord, digest)
            return bool(
                record is not None
                and not record.revoked
                and _aware(record.expires_at) > _aware(self._clock())
            )

    @property
    def active_count(self) -> int:
        with Session(self._engine) as session:
            value = session.scalar(
                select(func.count())
                .select_from(JudgeTokenRecord)
                .where(JudgeTokenRecord.revoked.is_(False))
                .where(JudgeTokenRecord.expires_at > _aware(self._clock()))
            )
            return int(value or 0)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(active_count={self.active_count})"

    def close(self) -> None:
        self._engine.dispose()
