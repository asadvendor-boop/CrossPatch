"""PostgreSQL row-lock implementation of the warrant claim boundary."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from crosspatch.broker.approval import (
    WarrantApproval,
    canonical_approval_bytes,
    parse_approval_json,
)
from crosspatch.broker.broker import (
    AuthorityLoader,
    AuthoritySnapshot,
    BrokerResult,
    BrokerStatus,
    ClaimValidator,
    PolicyRejected,
    TamperRejected,
    WarrantState,
    _ClaimedWarrant,
    _ClaimOutcome,
)
from crosspatch.broker.warrant import (
    WarrantDocument,
    canonical_warrant_bytes,
    parse_warrant_json,
)
from crosspatch.db.models import MutationAuthorityRecord, WarrantRecord
from crosspatch.domain.hashing import canonical_json


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def canonical_authority_bytes(authority: AuthoritySnapshot) -> bytes:
    return canonical_json(authority.model_dump(mode="json"))


def parse_authority_json(raw: bytes) -> AuthoritySnapshot:
    def strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate authority key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=strict_pairs)
        authority = AuthoritySnapshot.model_validate(value)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise TamperRejected("INVALID_AUTHORITY_SNAPSHOT") from error
    if raw != canonical_authority_bytes(authority):
        raise TamperRejected("NONCANONICAL_AUTHORITY_SNAPSHOT")
    return authority


class PostgresWarrantStore:
    """Claim a warrant and its current authority under database row locks."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    @staticmethod
    async def _database_now(session: AsyncSession) -> datetime:
        now = await session.scalar(select(func.clock_timestamp()))
        if now is None:
            raise RuntimeError("PostgreSQL clock_timestamp returned no value")
        return now

    @staticmethod
    async def _lock_authority(session: AsyncSession, incident_id: str) -> None:
        # A transaction advisory lock lets the broker serialize against the
        # control-plane authority publisher while retaining SELECT-only table
        # privileges. Both writer and claimant use this exact lock domain.
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:incident_id, 435276111))"),
            {"incident_id": incident_id},
        )

    async def add_approved(
        self,
        document: WarrantDocument,
        approval: WarrantApproval,
        authority: AuthoritySnapshot,
    ) -> None:
        if document.incident_id != authority.incident_id:
            raise ValueError("warrant and authority incidents differ")
        now = datetime.now(UTC)
        async with self._sessions() as session, session.begin():
            await self._lock_authority(session, document.incident_id)
            current = await session.get(
                MutationAuthorityRecord,
                document.incident_id,
                with_for_update=True,
            )
            snapshot = canonical_authority_bytes(authority)
            if current is None:
                session.add(
                    MutationAuthorityRecord(
                        incident_id=document.incident_id,
                        snapshot_json=snapshot,
                        version=1,
                        updated_at=now,
                    )
                )
            else:
                current.snapshot_json = snapshot
                current.version += 1
                current.updated_at = now
            session.add(
                WarrantRecord(
                    id=document.warrant_id,
                    incident_id=document.incident_id,
                    nonce_sha256=hashlib.sha256(document.nonce.encode("utf-8")).hexdigest(),
                    document_json=canonical_warrant_bytes(document),
                    approval_json=canonical_approval_bytes(approval),
                    state=WarrantState.APPROVED.value,
                    expires_at=document.expires_at,
                    created_at=now,
                    updated_at=now,
                )
            )

    async def replace_authority(self, authority: AuthoritySnapshot) -> None:
        """Publish a new current selection/evidence snapshot transactionally."""
        async with self._sessions() as session, session.begin():
            await self._lock_authority(session, authority.incident_id)
            current = await session.get(
                MutationAuthorityRecord,
                authority.incident_id,
                with_for_update=True,
            )
            if current is None:
                raise LookupError(authority.incident_id)
            current.snapshot_json = canonical_authority_bytes(authority)
            current.version += 1
            current.updated_at = datetime.now(UTC)

    async def claim_warrant(
        self,
        warrant_id: str,
        validator: ClaimValidator,
        authority_loader: AuthorityLoader,
    ) -> _ClaimOutcome:
        del authority_loader  # PostgreSQL supplies the authority under its own row lock.
        async with self._sessions() as session, session.begin():
            record = await session.scalar(
                select(WarrantRecord).where(WarrantRecord.id == warrant_id).with_for_update()
            )
            if record is None:
                return _ClaimOutcome(
                    rejection=BrokerStatus.NOT_FOUND,
                    error_code="WARRANT_NOT_FOUND",
                )
            if record.state != WarrantState.APPROVED.value:
                return _ClaimOutcome(
                    rejection=BrokerStatus.REPLAY_REJECTED,
                    error_code="WARRANT_ALREADY_CLAIMED",
                )
            now = _aware_utc(await self._database_now(session))
            try:
                document = parse_warrant_json(record.document_json)
                approval = parse_approval_json(record.approval_json)
            except ValueError:
                record.state = WarrantState.REJECTED.value
                record.updated_at = now
                return _ClaimOutcome(
                    rejection=BrokerStatus.TAMPER_REJECTED,
                    error_code="PERSISTED_CANONICAL_BYTES_INVALID",
                )
            duplicated_bindings_match = (
                record.id == document.warrant_id
                and record.incident_id == document.incident_id
                and record.nonce_sha256 == hashlib.sha256(document.nonce.encode()).hexdigest()
                and _aware_utc(record.expires_at) == _aware_utc(document.expires_at)
            )
            if not duplicated_bindings_match:
                record.state = WarrantState.REJECTED.value
                record.updated_at = now
                return _ClaimOutcome(
                    rejection=BrokerStatus.TAMPER_REJECTED,
                    error_code="INDEXED_WARRANT_BINDING_CHANGED",
                )
            if now > _aware_utc(record.expires_at) or now > _aware_utc(document.expires_at):
                record.state = WarrantState.EXPIRED.value
                record.updated_at = now
                return _ClaimOutcome(
                    rejection=BrokerStatus.EXPIRED,
                    error_code="WARRANT_EXPIRED",
                )
            await self._lock_authority(session, record.incident_id)
            authority_record = await session.scalar(
                select(MutationAuthorityRecord).where(
                    MutationAuthorityRecord.incident_id == record.incident_id
                )
            )
            if authority_record is None:
                record.state = WarrantState.REJECTED.value
                record.updated_at = now
                return _ClaimOutcome(
                    rejection=BrokerStatus.TAMPER_REJECTED,
                    error_code="AUTHORITY_SNAPSHOT_MISSING",
                )
            try:
                authority = parse_authority_json(authority_record.snapshot_json)
                validated = validator(document, approval, now, authority)
            except PolicyRejected as error:
                record.state = WarrantState.REJECTED.value
                record.updated_at = now
                return _ClaimOutcome(
                    rejection=BrokerStatus.POLICY_REJECTED,
                    error_code=str(error) or "PATCH_POLICY_REJECTED",
                )
            except (TamperRejected, ValueError) as error:
                record.state = WarrantState.REJECTED.value
                record.updated_at = now
                return _ClaimOutcome(
                    rejection=BrokerStatus.TAMPER_REJECTED,
                    error_code=str(error) or "WARRANT_TAMPER_REJECTED",
                )
            record.state = WarrantState.CONSUMING.value
            record.claimed_at = now
            record.nonce_consumed_at = now
            record.updated_at = now
            return _ClaimOutcome(
                claimed=_ClaimedWarrant(
                    document=document,
                    approval=approval,
                    authority=validated,
                )
            )

    async def finish(self, warrant_id: str, result: BrokerResult) -> None:
        async with self._sessions() as session, session.begin():
            record = await session.scalar(
                select(WarrantRecord).where(WarrantRecord.id == warrant_id).with_for_update()
            )
            if record is None or record.state != WarrantState.CONSUMING.value:
                raise RuntimeError("only a consuming warrant can finish")
            now = await self._database_now(session)
            record.state = WarrantState.CONSUMED.value
            record.result_json = canonical_json(result)
            record.finished_at = now
            record.updated_at = now
