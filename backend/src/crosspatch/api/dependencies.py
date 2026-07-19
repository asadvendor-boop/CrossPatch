"""Dependency-injected authentication and control service contracts."""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from crosspatch.api.models import (
    EvidenceView,
    IncidentRoomView,
    IncidentView,
    JudgeTokenListView,
    JudgeTokenMetadataView,
    JudgeTokenView,
    LiveTrialCredentialView,
    PublishedEvent,
    WarrantView,
)


class Role(StrEnum):
    READ_ONLY = "read_only"
    OPERATOR = "operator"
    APPROVER = "approver"
    LIVE_TRIAL = "live_trial"


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    role: Role
    incident_ids: frozenset[str]
    expires_at: datetime
    csrf_token: str | None = None
    step_up_token: str | None = None
    step_up_expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.subject or not isinstance(self.role, Role):
            raise ValueError("principal subject and role are required")
        if "*" in self.incident_ids:
            raise ValueError("wildcard incident authorization is forbidden")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("principal expiry must be timezone-aware")

    def can_access(self, incident_id: str) -> bool:
        return incident_id in self.incident_ids

    def is_active(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        return self.expires_at.astimezone(UTC) > current.astimezone(UTC)


@runtime_checkable
class TokenAuthenticator(Protocol):
    async def authenticate(self, bearer_token: str) -> Principal | None: ...

    async def revalidate(self, principal: Principal) -> bool: ...


@runtime_checkable
class PublicCaseReader(Protocol):
    """Narrow publication-only reader used by the credential-free case browser."""

    async def list_public_cases(self) -> Sequence[Mapping[str, object]]: ...

    async def get_public_case(self, incident_id: str) -> Mapping[str, object]: ...


class PublicCasesUnavailable(RuntimeError):
    """The public projection cannot be proven safe enough to serve."""


@runtime_checkable
class ControlService(Protocol):
    """Incident-bound application interface shared by every HTTP client.

    ``get_warrant_for_principal`` is intentionally authorization-aware because a
    warrant-only URL cannot safely resolve its incident before access control.
    Implementations must make that lookup a single authorized repository query.
    """

    async def open_incident(
        self,
        *,
        scenario: str,
        title: str | None,
        actor: str,
        evidence_profile: str = "standard",
    ) -> IncidentView: ...

    async def open_live_trial(
        self, *, scenario: str, title: str | None, actor: str
    ) -> IncidentView: ...

    async def get_incident(self, incident_id: str) -> IncidentView | None: ...

    async def get_room(
        self, incident_id: str, principal: Principal
    ) -> IncidentRoomView | None: ...

    async def list_evidence(self, incident_id: str) -> Sequence[EvidenceView]: ...

    async def list_events(
        self, incident_id: str, *, after: int, limit: int
    ) -> Sequence[PublishedEvent]: ...

    def stream_events(self, incident_id: str, *, after: int) -> AsyncIterator[PublishedEvent]: ...

    async def get_warrant_for_principal(
        self, warrant_id: str, principal: Principal
    ) -> WarrantView | None: ...

    async def decide_warrant(
        self,
        *,
        warrant_id: str,
        approve: bool,
        warrant_sha256: str,
        actor: str,
        reason: str | None = None,
    ) -> WarrantView: ...

    async def decide_live_trial_warrant(
        self,
        *,
        warrant_id: str,
        approve: bool,
        warrant_sha256: str,
        actor: str,
        reason: str | None = None,
    ) -> WarrantView: ...

    async def request_live_trial_revision(
        self,
        *,
        warrant_id: str,
        warrant_sha256: str,
        comment: str,
        actor: str,
    ) -> IncidentView: ...

    async def export_case(self, incident_id: str) -> bytes: ...

    async def rotate_judge_token(
        self, *, actor: str, incident_id: str | None = None
    ) -> JudgeTokenView: ...

    async def list_judge_tokens(self) -> JudgeTokenListView: ...

    async def revoke_judge_token(
        self,
        token_id: str,
        *,
        actor: str,
    ) -> JudgeTokenMetadataView: ...

    async def rotate_live_trial_credential(
        self,
        *,
        actor: str,
    ) -> LiveTrialCredentialView: ...

    async def revoke_live_trial_credential(
        self,
        subject: str,
        *,
        actor: str,
    ) -> None: ...


class StaticTokenAuthenticator:
    """Small lock-free authenticator for local deployments and contract tests."""

    def __init__(self, tokens: Mapping[str, Principal]) -> None:
        if any(not token for token in tokens):
            raise ValueError("bearer tokens cannot be empty")
        self._tokens = dict(tokens)
        self._revoked_subjects: set[str] = set()

    async def authenticate(self, bearer_token: str) -> Principal | None:
        principal = self._tokens.get(bearer_token)
        if principal is None or not await self.revalidate(principal):
            return None
        return principal

    async def revalidate(self, principal: Principal) -> bool:
        return principal.subject not in self._revoked_subjects and principal.is_active()

    def revoke(self, subject: str) -> None:
        self._revoked_subjects.add(subject)


_BEARER = HTTPBearer(auto_error=False, scheme_name="BearerAuth")


async def get_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_BEARER),
) -> Principal:
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    authenticator: TokenAuthenticator = request.app.state.authenticator
    principal = await authenticator.authenticate(credentials.credentials)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired credential",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def get_service(request: Request) -> ControlService:
    return request.app.state.control_service


def get_public_case_reader(request: Request) -> PublicCaseReader:
    reader = getattr(request.app.state, "public_case_reader", None)
    if reader is None or not isinstance(reader, PublicCaseReader):
        raise PublicCasesUnavailable
    return reader


def require_incident_access(principal: Principal, incident_id: str) -> None:
    if not principal.can_access(incident_id):
        # Deliberately hide whether the incident exists.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")


def require_operator(principal: Principal) -> None:
    if principal.role not in {Role.OPERATOR, Role.APPROVER}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="operator role required")


def require_approver(principal: Principal) -> None:
    if principal.role is not Role.APPROVER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="approver role required")


def require_approval_controls(
    request: Request,
    principal: Principal,
    *,
    origin: str | None,
    csrf_token: str | None,
    step_up_token: str | None,
) -> None:
    require_approver(principal)
    allowed_origins: frozenset[str] = request.app.state.allowed_origins
    if origin is None or origin not in allowed_origins:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="origin rejected")
    if (
        principal.csrf_token is None
        or csrf_token is None
        or not hmac.compare_digest(principal.csrf_token, csrf_token)
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
    now = datetime.now(UTC)
    if (
        principal.step_up_token is None
        or step_up_token is None
        or principal.step_up_expires_at is None
        or principal.step_up_expires_at.astimezone(UTC) <= now
        or not hmac.compare_digest(principal.step_up_token, step_up_token)
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="step-up required")
