"""Strict service-token authentication for every MCP HTTP request."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import threading
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs

from pydantic import BaseModel, ConfigDict, field_validator

from crosspatch.config import validate_judge_token_expiry

_JTI = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_INCIDENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_JWT_ALGORITHM = "HS256"
_JWT_TYPE = "JWT"
_MAX_CLOCK_SKEW_SECONDS = 30
_CURRENT_AUTHORIZATION: ContextVar[Any | None] = ContextVar(
    "crosspatch_mcp_authorization",
    default=None,
)


class MCPAuthError(PermissionError):
    """An authentication or authorization failure with an HTTP status."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class AuthConfig:
    issuer: str
    audience: str
    zone: str
    allowed_subjects: frozenset[str]
    signing_secret: bytes
    allowed_hosts: frozenset[str]
    allowed_origins: frozenset[str]
    max_token_lifetime_seconds: int | None = 300
    allow_missing_origin: bool = True
    incident_scoped: bool = False

    def __post_init__(self) -> None:
        if len(self.signing_secret) < 32:
            raise ValueError("MCP signing secret must contain at least 32 bytes")
        if not self.issuer or not self.audience or not self.zone:
            raise ValueError("MCP issuer, audience, and zone are required")
        if not self.allowed_subjects or not self.allowed_hosts:
            raise ValueError("MCP subjects and hosts must be explicitly allowlisted")
        if self.max_token_lifetime_seconds is not None and self.max_token_lifetime_seconds < 1:
            raise ValueError("MCP token lifetime must be positive")
        if not isinstance(self.incident_scoped, bool):
            raise ValueError("MCP incident scope policy must be boolean")


class JudgeToken(BaseModel):
    """Judge-token availability contract."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    expires_at: datetime

    _validate_expiry = field_validator("expires_at")(validate_judge_token_expiry)


@dataclass(frozen=True, slots=True)
class _JudgeTokenRecord:
    digest: str
    expires_at: datetime
    revoked: bool = False


class JudgeTokenRegistry:
    """Revocable token digests with overlapping rotation support."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._records: dict[str, _JudgeTokenRecord] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def register(self, token: str, *, expires_at: datetime) -> None:
        if not token.strip():
            raise ValueError("judge token must not be blank")
        normalized_expiry = validate_judge_token_expiry(expires_at)
        digest = self._digest(token)
        with self._lock:
            self._records[digest] = _JudgeTokenRecord(digest, normalized_expiry)

    def rotate(self, token: str, *, expires_at: datetime) -> None:
        """Add a replacement without revoking still-valid tokens."""
        self.register(token, expires_at=expires_at)

    def revoke(self, token: str) -> None:
        digest = self._digest(token)
        with self._lock:
            record = self._records.get(digest)
            if record is not None:
                self._records[digest] = _JudgeTokenRecord(
                    digest=record.digest,
                    expires_at=record.expires_at,
                    revoked=True,
                )

    def is_active(self, token: str) -> bool:
        digest = self._digest(token)
        with self._lock:
            record = self._records.get(digest)
        if record is None or record.revoked:
            return False
        return record.expires_at > self._clock().astimezone(UTC)

    @property
    def active_count(self) -> int:
        with self._lock:
            records = tuple(self._records.values())
        now = self._clock().astimezone(UTC)
        return sum(not record.revoked and record.expires_at > now for record in records)

    @property
    def stored_hashes(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._records)


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise MCPAuthError("malformed bearer token", status_code=401) from error


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JWT field: {key}")
        result[key] = value
    return result


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class TokenIssuer:
    """Small deterministic HS256 issuer for zone-specific service credentials."""

    def __init__(self, config: AuthConfig) -> None:
        self._config = config

    def issue(
        self,
        *,
        subject: str,
        jti: str,
        issued_at: datetime,
        expires_at: datetime,
        incident_id: str | None = None,
    ) -> str:
        if not _JTI.fullmatch(jti):
            raise ValueError("invalid MCP token JTI")
        if (
            issued_at.tzinfo is None
            or issued_at.utcoffset() is None
            or expires_at.tzinfo is None
            or expires_at.utcoffset() is None
        ):
            raise ValueError("MCP token timestamps must be timezone-aware")
        issued = issued_at.astimezone(UTC)
        expires = expires_at.astimezone(UTC)
        if expires <= issued:
            raise ValueError("MCP token must expire after it is issued")
        header = {"alg": _JWT_ALGORITHM, "typ": _JWT_TYPE}
        claims = {
            "iss": self._config.issuer,
            "aud": self._config.audience,
            "sub": subject,
            "zone": self._config.zone,
            "iat": int(issued.timestamp()),
            "exp": int(expires.timestamp()),
            "jti": jti,
        }
        if self._config.incident_scoped:
            if not isinstance(incident_id, str) or not _INCIDENT_ID.fullmatch(incident_id):
                raise ValueError("incident-scoped MCP token requires a valid incident ID")
            claims["incident_id"] = incident_id
        elif incident_id is not None:
            raise ValueError("unscoped MCP token cannot include an incident ID")
        encoded_header = _base64url_encode(_canonical_json(header))
        encoded_claims = _base64url_encode(_canonical_json(claims))
        signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
        signature = hmac.new(
            self._config.signing_secret,
            signing_input,
            hashlib.sha256,
        ).digest()
        return f"{encoded_header}.{encoded_claims}.{_base64url_encode(signature)}"


@dataclass(frozen=True, slots=True)
class AuthenticatedIdentity:
    subject: str
    jti: str
    token_digest: str
    origin: str | None
    expires_at: datetime
    incident_id: str | None


@dataclass(frozen=True, slots=True)
class _ReplayState:
    session_id: str | None
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class _SessionBinding:
    subject: str
    jti: str
    token_digest: str
    origin: str | None
    expires_at: datetime
    last_seen_at: datetime
    incident_id: str | None


class AuthPolicy:
    """JWT validation, replay prevention, and MCP session binding."""

    def __init__(
        self,
        config: AuthConfig,
        *,
        clock: Callable[[], datetime] | None = None,
        judge_tokens: JudgeTokenRegistry | None = None,
        max_replay_entries: int = 4096,
        max_session_entries: int = 2048,
        session_idle_ttl_seconds: int = 600,
        allow_registered_token_reuse: bool = False,
    ) -> None:
        if max_replay_entries < 1 or max_session_entries < 1:
            raise ValueError("MCP auth state limits must be positive")
        if session_idle_ttl_seconds < 1:
            raise ValueError("MCP session idle TTL must be positive")
        if not isinstance(allow_registered_token_reuse, bool):
            raise ValueError("registered MCP token reuse policy must be boolean")
        if allow_registered_token_reuse and judge_tokens is None:
            raise ValueError(
                "reusable MCP bearer sessions require a revocable token registry"
            )
        if allow_registered_token_reuse and config.zone != "judge":
            raise ValueError(
                "reusable registered bearer sessions are limited to the judge trust zone"
            )
        self.config = config
        self._clock = clock or (lambda: datetime.now(UTC))
        self._judge_tokens = judge_tokens
        self._max_replay_entries = max_replay_entries
        self._max_session_entries = max_session_entries
        self._session_idle_ttl_seconds = session_idle_ttl_seconds
        self._allow_registered_token_reuse = allow_registered_token_reuse
        self._jti_sessions: dict[str, _ReplayState] = {}
        self._sessions: dict[str, _SessionBinding] = {}
        self._lock = threading.Lock()

    @property
    def has_judge_token_registry(self) -> bool:
        return self._judge_tokens is not None

    @property
    def allows_registered_token_reuse(self) -> bool:
        return self._allow_registered_token_reuse

    @property
    def tracked_replay_count(self) -> int:
        with self._lock:
            self._cleanup_locked(self._now())
            return len(self._jti_sessions)

    @property
    def active_session_count(self) -> int:
        with self._lock:
            self._cleanup_locked(self._now())
            return len(self._sessions)

    def _now(self) -> datetime:
        return self._clock().astimezone(UTC)

    def _cleanup_locked(self, now: datetime) -> None:
        expired_jtis = {
            jti for jti, state in self._jti_sessions.items() if state.expires_at <= now
        }
        for jti in expired_jtis:
            state = self._jti_sessions.pop(jti)
            if state.session_id is not None:
                self._sessions.pop(state.session_id, None)

        idle_before = now.timestamp() - self._session_idle_ttl_seconds
        idle_sessions = tuple(
            session_id
            for session_id, binding in self._sessions.items()
            if binding.expires_at <= now or binding.last_seen_at.timestamp() <= idle_before
        )
        for session_id in idle_sessions:
            binding = self._sessions.pop(session_id)
            replay = self._jti_sessions.get(binding.jti)
            if replay is not None and replay.session_id == session_id:
                self._jti_sessions[binding.jti] = _ReplayState(None, replay.expires_at)

    def _decode(self, token: str) -> dict[str, Any]:
        try:
            encoded_header, encoded_claims, encoded_signature = token.split(".")
        except ValueError as error:
            raise MCPAuthError("malformed bearer token", status_code=401) from error
        signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
        expected_signature = hmac.new(
            self.config.signing_secret,
            signing_input,
            hashlib.sha256,
        ).digest()
        signature = _base64url_decode(encoded_signature)
        if not hmac.compare_digest(signature, expected_signature):
            raise MCPAuthError("invalid bearer token signature", status_code=401)
        try:
            header = json.loads(
                _base64url_decode(encoded_header),
                object_pairs_hook=_reject_duplicate_json_pairs,
            )
            claims = json.loads(
                _base64url_decode(encoded_claims),
                object_pairs_hook=_reject_duplicate_json_pairs,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise MCPAuthError("malformed bearer token", status_code=401) from error
        if header != {"alg": _JWT_ALGORITHM, "typ": _JWT_TYPE}:
            raise MCPAuthError("unsupported bearer token header", status_code=401)
        if not isinstance(claims, dict):
            raise MCPAuthError("malformed bearer token claims", status_code=401)
        return claims

    def _verify_claims(
        self,
        claims: dict[str, Any],
    ) -> tuple[str, str, datetime, str | None]:
        required = {"iss", "aud", "sub", "zone", "iat", "exp", "jti"}
        if self.config.incident_scoped:
            required.add("incident_id")
        if set(claims) != required:
            raise MCPAuthError("bearer token claim set is invalid", status_code=401)
        subject = claims.get("sub")
        jti = claims.get("jti")
        issued_at = claims.get("iat")
        expires_at = claims.get("exp")
        incident_id = claims.get("incident_id")
        if not isinstance(subject, str) or not isinstance(jti, str) or not _JTI.fullmatch(jti):
            raise MCPAuthError("bearer token identity is invalid", status_code=401)
        if not isinstance(issued_at, int) or isinstance(issued_at, bool):
            raise MCPAuthError("bearer token issued-at is invalid", status_code=401)
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            raise MCPAuthError("bearer token expiry is invalid", status_code=401)
        if self.config.incident_scoped and (
            not isinstance(incident_id, str) or not _INCIDENT_ID.fullmatch(incident_id)
        ):
            raise MCPAuthError("bearer token incident scope is invalid", status_code=401)
        now = int(self._now().timestamp())
        if expires_at <= now or issued_at > now + _MAX_CLOCK_SKEW_SECONDS:
            raise MCPAuthError("bearer token is expired or not yet valid", status_code=401)
        max_lifetime = self.config.max_token_lifetime_seconds
        if max_lifetime is not None and expires_at - issued_at > max_lifetime:
            raise MCPAuthError("bearer token lifetime exceeds zone policy", status_code=401)
        if (
            claims.get("iss") != self.config.issuer
            or claims.get("aud") != self.config.audience
            or claims.get("zone") != self.config.zone
            or subject not in self.config.allowed_subjects
        ):
            raise MCPAuthError("bearer token is not valid for this trust zone", status_code=401)
        return (
            subject,
            jti,
            datetime.fromtimestamp(expires_at, tz=UTC),
            incident_id if isinstance(incident_id, str) else None,
        )

    def authorize(
        self,
        credential: str | None,
        *,
        host: str,
        origin: str | None,
        session_id: str | None,
    ) -> AuthenticatedIdentity:
        normalized_host = host.lower().rstrip(".")
        normalized_allowed_hosts = {
            value.lower().rstrip(".") for value in self.config.allowed_hosts
        }
        if normalized_host not in normalized_allowed_hosts:
            raise MCPAuthError("request host is not allowed", status_code=403)
        if origin is None:
            if not self.config.allow_missing_origin:
                raise MCPAuthError("request origin is required", status_code=403)
        elif origin not in self.config.allowed_origins:
            raise MCPAuthError("request origin is not allowed", status_code=403)
        if credential is None or not credential:
            raise MCPAuthError("bearer token is required", status_code=401)
        claims = self._decode(credential)
        subject, jti, expires_at, incident_id = self._verify_claims(claims)
        if self._judge_tokens is not None and not self._judge_tokens.is_active(credential):
            raise MCPAuthError("judge token is revoked or unavailable", status_code=401)
        token_digest = hashlib.sha256(credential.encode("utf-8")).hexdigest()
        identity = AuthenticatedIdentity(
            subject,
            jti,
            token_digest,
            origin,
            expires_at,
            incident_id,
        )
        now = self._now()
        with self._lock:
            self._cleanup_locked(now)
            if session_id is None:
                if self._allow_registered_token_reuse:
                    return identity
                if jti in self._jti_sessions:
                    raise MCPAuthError("bearer token replay detected", status_code=403)
                if len(self._jti_sessions) >= self._max_replay_entries:
                    raise MCPAuthError("MCP replay state capacity exhausted", status_code=503)
                self._jti_sessions[jti] = _ReplayState(None, expires_at)
                return identity
            binding = self._sessions.get(session_id)
            replay = self._jti_sessions.get(jti)
            binding_mismatch = (
                binding is None
                or binding.subject != subject
                or binding.jti != jti
                or binding.token_digest != token_digest
                or binding.origin != origin
                or binding.incident_id != incident_id
            )
            replay_mismatch = (
                not self._allow_registered_token_reuse
                and (replay is None or replay.session_id != session_id)
            )
            if binding_mismatch or replay_mismatch:
                raise MCPAuthError("MCP session identity does not match", status_code=403)
            self._sessions[session_id] = _SessionBinding(
                subject,
                jti,
                token_digest,
                origin,
                expires_at,
                now,
                incident_id,
            )
        return identity

    def bind_session(self, identity: AuthenticatedIdentity, session_id: str) -> None:
        if not session_id:
            raise MCPAuthError("MCP session identifier is missing", status_code=403)
        binding = _SessionBinding(
            identity.subject,
            identity.jti,
            identity.token_digest,
            identity.origin,
            identity.expires_at,
            self._now(),
            identity.incident_id,
        )
        with self._lock:
            now = self._now()
            self._cleanup_locked(now)
            if self._allow_registered_token_reuse:
                existing_binding = self._sessions.get(session_id)
                if existing_binding is not None and (
                    existing_binding.subject != binding.subject
                    or existing_binding.jti != binding.jti
                    or existing_binding.token_digest != binding.token_digest
                    or existing_binding.origin != binding.origin
                    or existing_binding.expires_at != binding.expires_at
                    or existing_binding.incident_id != binding.incident_id
                ):
                    raise MCPAuthError(
                        "MCP session identity does not match", status_code=403
                    )
                if existing_binding is None and len(self._sessions) >= self._max_session_entries:
                    raise MCPAuthError(
                        "MCP session state capacity exhausted", status_code=503
                    )
                self._sessions[session_id] = binding
                return
            replay = self._jti_sessions.get(identity.jti)
            if replay is None:
                raise MCPAuthError("MCP replay state is missing", status_code=403)
            if replay.session_id not in {None, session_id}:
                raise MCPAuthError("bearer token replay detected", status_code=403)
            existing_binding = self._sessions.get(session_id)
            if existing_binding is not None and (
                existing_binding.subject != binding.subject
                or existing_binding.jti != binding.jti
                or existing_binding.token_digest != binding.token_digest
                or existing_binding.origin != binding.origin
                or existing_binding.expires_at != binding.expires_at
                or existing_binding.incident_id != binding.incident_id
            ):
                raise MCPAuthError("MCP session identity does not match", status_code=403)
            if existing_binding is None and len(self._sessions) >= self._max_session_entries:
                raise MCPAuthError("MCP session state capacity exhausted", status_code=503)
            self._jti_sessions[identity.jti] = _ReplayState(
                session_id,
                identity.expires_at,
            )
            self._sessions[session_id] = binding

    def require_incident(self, incident_id: str) -> str:
        """Authorize one incident before any Evidence MCP reader is invoked."""
        if not _INCIDENT_ID.fullmatch(incident_id):
            raise MCPAuthError("invalid incident identifier", status_code=403)
        authorized_incident = self.authorized_incident()
        if not hmac.compare_digest(authorized_incident, incident_id):
            raise MCPAuthError("MCP incident scope does not match", status_code=403)
        return incident_id

    def authorized_incident(self) -> str:
        """Return the current request's explicit incident grant."""
        current = _CURRENT_AUTHORIZATION.get()
        if current is None or current[0] is not self:
            raise MCPAuthError("MCP request identity is unavailable", status_code=403)
        identity: AuthenticatedIdentity = current[1]
        if not self.config.incident_scoped or identity.incident_id is None:
            raise MCPAuthError("MCP incident scope does not match", status_code=403)
        return identity.incident_id

    def release_session(self, session_id: str) -> None:
        if not session_id:
            return
        with self._lock:
            self._cleanup_locked(self._now())
            binding = self._sessions.pop(session_id, None)
            if binding is None:
                return
            replay = self._jti_sessions.get(binding.jti)
            if replay is not None and replay.session_id == session_id:
                self._jti_sessions[binding.jti] = _ReplayState(None, replay.expires_at)


class MCPAuthMiddleware:
    """Pure ASGI middleware so streaming responses are not buffered."""

    def __init__(self, app: Any, policy: AuthPolicy) -> None:
        self._app = app
        self._policy = policy

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", ())
        }
        query = parse_qs(scope.get("query_string", b"").decode("ascii", errors="ignore"))
        credential: str | None = None
        authorization = headers.get("authorization")
        if authorization is not None and authorization.startswith("Bearer "):
            credential = authorization.removeprefix("Bearer ")
        if "access_token" in query:
            credential = None
        try:
            identity = self._policy.authorize(
                credential,
                host=headers.get("host", ""),
                origin=headers.get("origin"),
                session_id=headers.get("mcp-session-id"),
            )
        except MCPAuthError as error:
            await send(
                {
                    "type": "http.response.start",
                    "status": error.status_code,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            body = json.dumps({"error": "MCP authorization failed"}).encode()
            await send({"type": "http.response.body", "body": body})
            return

        async def authenticated_send(message: dict[str, Any]) -> None:
            nonlocal response_status
            if message["type"] == "http.response.start":
                response_status = int(message["status"])
                response_headers = {
                    key.decode("latin-1").lower(): value.decode("latin-1")
                    for key, value in message.get("headers", ())
                }
                session_id = response_headers.get("mcp-session-id")
                if session_id is not None:
                    self._policy.bind_session(identity, session_id)
            await send(message)

        response_status: int | None = None
        authorization_context = _CURRENT_AUTHORIZATION.set((self._policy, identity))
        try:
            await self._app(scope, receive, authenticated_send)
            if (
                scope.get("method") == "DELETE"
                and 200 <= (response_status or 500) < 300
                and headers.get("mcp-session-id")
            ):
                self._policy.release_session(headers["mcp-session-id"])
        finally:
            _CURRENT_AUTHORIZATION.reset(authorization_context)
