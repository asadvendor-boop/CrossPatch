"""Zero-argument ASGI factories for the durable CrossPatch runtime surfaces."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import secrets
import stat
from collections.abc import Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from crosspatch.agents.factory import AgentFactory
from crosspatch.agents.sdk import AgentsSDKRuntime
from crosspatch.api.app import create_app
from crosspatch.api.dependencies import Role
from crosspatch.broker.approval import ApprovalService
from crosspatch.broker.broker import Broker
from crosspatch.broker.store import PostgresWarrantStore
from crosspatch.config import DEFAULT_JUDGE_TOKEN_EXPIRY, validate_judge_token_expiry
from crosspatch.mcp.auth import AuthConfig, AuthPolicy, TokenIssuer
from crosspatch.mcp.broker_server import build_broker_mcp
from crosspatch.mcp.evidence_server import build_evidence_mcp
from crosspatch.mcp.judge_server import build_judge_mcp
from crosspatch.orchestration.coordinator import Coordinator
from crosspatch.orchestration.sessions import IncidentSessionStore
from crosspatch.runner.catalog import ExecutionCatalog
from crosspatch.runner.reproduction import (
    C2_WEBHOOK_LOG_FIXTURE,
    PayloadEquivalenceReproducer,
    RaceReproducer,
)
from crosspatch.runner.runner_service import build_runner_service_client_from_environment
from crosspatch.runner.secrets import validate_release_secret
from crosspatch.runner.worktree import EphemeralWorktreeFactory
from crosspatch.runtime.auth import (
    ApiCredential,
    DatabaseJudgeTokenRegistry,
    DatabaseTokenAuthenticator,
    JudgeTokenRepository,
)
from crosspatch.runtime.authority import (
    AuthorityPolicy,
    DatabaseAuthorityGateway,
    PersistingAgentRuntime,
)
from crosspatch.runtime.control import DatabaseControlService
from crosspatch.runtime.database import RuntimeDatabase
from crosspatch.runtime.incidents import BundledIncidentLauncher
from crosspatch.runtime.live_trials import LiveTrialRepository
from crosspatch.runtime.readers import (
    DatabaseCitationAuthority,
    DatabaseEvidenceReader,
    DatabasePublishedCaseReader,
)

_DEFAULT_API_EXPIRY = datetime(2027, 9, 1, 7, tzinfo=UTC)
_MODEL_PRICING_PER_MILLION = {
    "gpt-5.6-sol": (5.0, 0.50, 30.0),
    "gpt-5.6-terra": (2.50, 0.25, 15.0),
    "gpt-5.6-luna": (1.0, 0.10, 6.0),
}
_PRICING_SOURCE = "https://developers.openai.com/api/docs/pricing"
_TRUE = frozenset({"1", "true", "yes"})
_FALSE = frozenset({"0", "false", "no", ""})


class _LockedStoreAuthoritySentinel:
    """Prevent an accidental unlocked authority read in the PostgreSQL broker."""

    def read_for_claim(self, _warrant_id: str):
        raise RuntimeError("PostgreSQL broker authority must be read under the claim lock")


def _environment(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name, default)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _release_mode_enabled() -> bool:
    value = os.getenv("CROSSPATCH_RELEASE_MODE", "0").strip().casefold()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ValueError("CROSSPATCH_RELEASE_MODE must be a boolean value")


def _boolean_environment(name: str, *, default: bool) -> bool:
    value = os.getenv(name, "1" if default else "0").strip().casefold()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ValueError(f"{name} must be a boolean value")


def _validate_release_credential(value: str, *, label: str) -> str:
    if _release_mode_enabled() and value.startswith("crosspatch-local-"):
        raise ValueError(
            f"release mode requires a random {label} and rejects source defaults"
        )
    return validate_release_secret(os.environ, value, label=label)


def _bound_digest(name: str, development_default: str) -> str:
    value = _required_environment(name, development_default)
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{name} must be exactly 64 lowercase hexadecimal characters")
    if _release_mode_enabled() and value in {"0" * 64, development_default}:
        raise ValueError(f"release mode rejects the placeholder {name}")
    return value


def _required_environment(name: str, default: str) -> str:
    value = _environment(name, default)
    if value is None:
        raise ValueError(f"{name} cannot be blank")
    return value


def _positive_decimal_environment(name: str, default: str) -> Decimal:
    try:
        value = Decimal(_required_environment(name, default))
    except InvalidOperation as error:
        raise ValueError(f"{name} must be a decimal value") from error
    if not value.is_finite() or value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _positive_integer_environment(name: str, default: str) -> int:
    raw = _required_environment(name, default)
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if value < 1:
        raise ValueError(f"{name} must be positive")
    return value


def _csv(name: str, default: str) -> tuple[str, ...]:
    values = tuple(
        value.strip() for value in _required_environment(name, default).split(",") if value.strip()
    )
    if not values:
        raise ValueError(f"{name} requires at least one value")
    return values


def _aware_datetime(name: str, default: datetime) -> datetime:
    value = _environment(name)
    if value is None:
        return default
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return parsed.astimezone(UTC)


def _state_root() -> Path:
    value = _required_environment("CROSSPATCH_STATE_ROOT", ".crosspatch")
    return Path(value).expanduser().resolve()


@contextmanager
def _locked_secret(path: Path) -> Iterator[None]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    lock_path = path.with_name(f".{path.name}.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _read_private(path: Path) -> bytes:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"runtime secret path must be a regular file: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        path.chmod(0o600)
    value = path.read_bytes()
    if not value:
        raise ValueError(f"runtime secret file is empty: {path}")
    return value


def _publish_private(path: Path, value: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        view = memoryview(value)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("runtime secret write made no progress")
            written += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _material(name: str, environment: str, *, size: int = 32) -> bytes:
    configured = _environment(environment)
    if configured is not None:
        _validate_release_credential(configured, label=environment)
        value = configured.encode("utf-8")
        if len(value) < size:
            raise ValueError(f"{environment} must contain at least {size} bytes")
        return value
    if _release_mode_enabled():
        raise ValueError(f"release mode requires explicit {environment}")
    path = _state_root() / "secrets" / name
    with _locked_secret(path):
        try:
            value = _read_private(path)
        except FileNotFoundError:
            value = os.urandom(size)
            _publish_private(path, value)
            value = _read_private(path)
    if len(value) < size:
        raise ValueError(f"runtime secret is shorter than {size} bytes: {path}")
    return value


def _token(name: str, environment: str) -> str:
    configured = _environment(environment)
    if configured is not None:
        _validate_release_credential(configured, label=environment)
        if len(configured) < 32:
            raise ValueError(f"{environment} must contain at least 32 characters")
        return configured
    if _release_mode_enabled():
        raise ValueError(f"release mode requires explicit {environment}")
    path = _state_root() / "secrets" / name
    with _locked_secret(path):
        try:
            value = _read_private(path).decode("ascii").strip()
        except FileNotFoundError:
            value = secrets.token_urlsafe(48)
            _publish_private(path, f"{value}\n".encode("ascii"))
            value = _read_private(path).decode("ascii").strip()
    if len(value) < 32:
        raise ValueError(f"runtime bearer token is too short: {path}")
    return value


def _database() -> RuntimeDatabase:
    default = f"sqlite+aiosqlite:///{_state_root() / 'crosspatch.db'}"
    value = _required_environment("CROSSPATCH_DATABASE_URL", default)
    if _release_mode_enabled():
        try:
            parsed = urlsplit(value)
            password = unquote(parsed.password or "")
        except (UnicodeError, ValueError) as error:
            raise ValueError("release mode requires a valid control database URL") from error
        if parsed.scheme.split("+", 1)[0] not in {"postgres", "postgresql"}:
            raise ValueError("release mode requires a PostgreSQL control database URL")
        _validate_release_credential(password, label="control database password")
    return RuntimeDatabase(value)


def _origins() -> tuple[str, ...]:
    return _csv("CROSSPATCH_ALLOWED_ORIGINS", "http://localhost:3000")


def _auth_config(
    *,
    audience: str,
    zone: str,
    subjects: frozenset[str],
    signing_secret: bytes,
    hosts_environment: str,
    default_hosts: str,
    max_lifetime: int | None,
    incident_scoped: bool = False,
) -> AuthConfig:
    configured_hosts = _environment(hosts_environment) or _environment(
        "CROSSPATCH_MCP_ALLOWED_HOSTS"
    )
    return AuthConfig(
        issuer="crosspatch-control",
        audience=audience,
        zone=zone,
        allowed_subjects=subjects,
        signing_secret=signing_secret,
        allowed_hosts=frozenset(
            value.strip()
            for value in (configured_hosts or default_hosts).split(",")
            if value.strip()
        ),
        allowed_origins=frozenset(_origins()),
        max_token_lifetime_seconds=max_lifetime,
        incident_scoped=incident_scoped,
    )


def _mcp_signing_material(name: str, environment: str) -> bytes:
    specific = _environment(environment)
    shared = _environment("CROSSPATCH_MCP_SIGNING_SECRET")
    if specific is not None or shared is None:
        return _material(name, environment)
    value = shared.encode("utf-8")
    if len(value) < 32:
        raise ValueError("CROSSPATCH_MCP_SIGNING_SECRET must contain at least 32 bytes")
    return value


def _ephemeral_provider(
    issuer: TokenIssuer,
    subject: str,
) -> Callable[[str | None], str]:
    def provide(incident_id: str | None = None) -> str:
        now = datetime.now(UTC)
        return issuer.issue(
            subject=subject,
            jti=f"svc-{uuid4().hex}",
            issued_at=now,
            expires_at=now + timedelta(minutes=4),
            incident_id=incident_id,
        )

    return provide


def _model_cost_usd(notice: Any) -> float:
    try:
        input_rate, cached_rate, output_rate = _MODEL_PRICING_PER_MILLION[notice.model]
    except KeyError as error:
        raise ValueError(f"no API price is configured for model {notice.model!r}") from error
    uncached = max(0, notice.input_tokens - notice.cached_input_tokens)
    long_context = notice.input_tokens > 272_000
    input_multiplier = 2.0 if long_context else 1.0
    output_multiplier = 1.5 if long_context else 1.0
    cost = (
        uncached * input_rate * input_multiplier
        + notice.cached_input_tokens * cached_rate * input_multiplier
        + notice.output_tokens * output_rate * output_multiplier
    ) / 1_000_000
    return round(cost, 12)


def _private_ed25519_key() -> Ed25519PrivateKey:
    seed = _material("export-ed25519.seed", "CROSSPATCH_EXPORT_SIGNING_SEED")
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())


def _reproduction_factories() -> dict[str, Callable[[], Any]]:
    from victim.db import Database
    from victim.worker import DeliveryWorker

    oracle_database_url = _required_environment(
        "CROSSPATCH_VICTIM_DATABASE_URL",
        "postgresql://crosspatch_victim_oracle@victim-postgres:5432/crosspatch_victim",
    )
    worker_database_url = _required_environment(
        "CROSSPATCH_VICTIM_WORKER_DATABASE_URL",
        "postgresql://crosspatch_victim_worker@victim-postgres:5432/crosspatch_victim",
    )
    signing_secret = _required_environment(
        "CROSSPATCH_VICTIM_WEBHOOK_SECRET",
        _token("victim-webhook.token", "CROSSPATCH_VICTIM_WEBHOOK_SECRET"),
    )
    victim_url = _required_environment("CROSSPATCH_VICTIM_URL", "http://victim:8001")

    def build(
        reproducer_type: type[RaceReproducer] | type[PayloadEquivalenceReproducer],
        **options: Any,
    ):
        return reproducer_type(
            database=Database(oracle_database_url),
            signing_secret=signing_secret,
            victim_url=victim_url,
            drain_jobs=DeliveryWorker(Database(worker_database_url)).drain,
            **options,
        )

    return {
        "webhook-race": lambda: build(RaceReproducer),
        "webhook-race:instruction-like-log": lambda: build(
            RaceReproducer,
            webhook_log_fixture=C2_WEBHOOK_LOG_FIXTURE,
        ),
        "webhook-payload-equivalence": lambda: build(PayloadEquivalenceReproducer),
    }


def create_control_app() -> FastAPI:
    """Build the API with concrete repositories; startup owns database bootstrap."""
    database = _database()
    repository_root = Path(
        _required_environment("CROSSPATCH_REPOSITORY_ROOT", os.getcwd())
    ).resolve(strict=True)
    runner_digest = _bound_digest(
        "CROSSPATCH_RUNNER_DIGEST", hashlib.sha256(b"crosspatch-runner-dev").hexdigest()
    )
    environment_digest = _bound_digest(
        "CROSSPATCH_ENVIRONMENT_DIGEST",
        hashlib.sha256(b"crosspatch-environment-dev").hexdigest(),
    )
    approval_key = _material("approval-mac.key", "CROSSPATCH_APPROVAL_MAC_KEY")
    authority = DatabaseAuthorityGateway(
        database.store,
        AuthorityPolicy(
            repository_root=repository_root,
            repository_id=_required_environment("CROSSPATCH_REPOSITORY_ID", "crosspatch"),
            approver_identity=_required_environment("CROSSPATCH_APPROVER_SUBJECT", "approver-1"),
            approval_mac_key_id="approval-v1",
            approval_service=ApprovalService(keys={"approval-v1": approval_key}),
            runner_digest=runner_digest,
            environment_digest=environment_digest,
        ),
    )

    openai_api_key = _environment("OPENAI_API_KEY")
    coordinator: Coordinator | None = None
    sdk_sessions: IncidentSessionStore | None = None
    if openai_api_key is not None:
        evidence_config = _auth_config(
            audience="crosspatch-evidence",
            zone="evidence",
            subjects=frozenset({"crosspatch-orchestrator"}),
            signing_secret=_mcp_signing_material(
                "evidence-mcp-signing.key", "CROSSPATCH_EVIDENCE_MCP_SIGNING_SECRET"
            ),
            hosts_environment="CROSSPATCH_EVIDENCE_ALLOWED_HOSTS",
            default_hosts="evidence-mcp,evidence-mcp:8011,localhost,localhost:8011",
            max_lifetime=300,
            incident_scoped=True,
        )
        broker_config = _auth_config(
            audience="crosspatch-broker",
            zone="broker",
            subjects=frozenset({"Bailiff"}),
            signing_secret=_mcp_signing_material(
                "broker-mcp-signing.key", "CROSSPATCH_BROKER_MCP_SIGNING_SECRET"
            ),
            hosts_environment="CROSSPATCH_BROKER_ALLOWED_HOSTS",
            default_hosts="broker-mcp,broker-mcp:8012,localhost,localhost:8012",
            max_lifetime=300,
        )
        agent_factory = AgentFactory(
            evidence_mcp_url=_required_environment(
                "CROSSPATCH_EVIDENCE_MCP_URL", "http://evidence-mcp:8011/mcp"
            ),
            broker_mcp_url=_required_environment(
                "CROSSPATCH_BROKER_MCP_URL", "http://broker-mcp:8012/mcp"
            ),
            evidence_token=_ephemeral_provider(
                TokenIssuer(evidence_config), "crosspatch-orchestrator"
            ),
            broker_token=_ephemeral_provider(TokenIssuer(broker_config), "Bailiff"),
            origin=_origins()[0],
        )
        sdk_sessions = IncidentSessionStore(
            _required_environment(
                "CROSSPATCH_AGENT_SESSION_DATABASE",
                str(_state_root() / "agent-sessions.db"),
            )
        )

        async def persist_telemetry(notice: Any) -> None:
            await database.store.append_event(
                notice.incident_id,
                "MODEL_METRICS_RECORDED",
                "runtime",
                {
                    "seat": notice.seat.value,
                    "model": notice.model,
                    "effort": notice.effort.value,
                    "source": "openai-responses-api",
                    "response_id": notice.response_id,
                    "request_id": notice.request_id,
                    "latency_ms": notice.latency_ms,
                    "input_tokens": notice.input_tokens,
                    "cached_input_tokens": notice.cached_input_tokens,
                    "output_tokens": notice.output_tokens,
                    "total_tokens": notice.total_tokens,
                    "uncached": notice.cached_input_tokens == 0,
                    "cost_usd": _model_cost_usd(notice),
                    "cost_status": "ESTIMATE_OFFICIAL_LIST_PRICE",
                    "schema_valid": notice.schema_valid,
                    "failure_reason": notice.failure_outcome,
                    "pricing_source": _PRICING_SOURCE,
                    "pricing_version": "2026-07-14",
                },
            )

        citations = DatabaseCitationAuthority(database.sessions)
        runtime = PersistingAgentRuntime(
            AgentsSDKRuntime(
                factory=agent_factory,
                sessions=sdk_sessions,
                telemetry_sink=persist_telemetry,
            ),
            database.store,
            citations=citations,
        )
        coordinator = Coordinator(
            runtime=runtime,
            authority=authority,
            citations=citations,
        )

    raw_root = Path(
        _required_environment(
            "CROSSPATCH_RAW_ARTIFACT_ROOT", str(_state_root() / "artifacts" / "raw")
        )
    )
    sanitized_root = Path(
        _required_environment(
            "CROSSPATCH_SANITIZED_ARTIFACT_ROOT",
            str(_state_root() / "artifacts" / "sanitized"),
        )
    )
    launcher = BundledIncidentLauncher(
        store=database.store,
        authority=authority,
        coordinator=coordinator,
        reproduction_factories=_reproduction_factories(),
        raw_artifact_root=raw_root,
        sanitized_artifact_root=sanitized_root,
        openai_api_key=openai_api_key,
        source_root=repository_root,
    )
    judge_expiry = validate_judge_token_expiry(
        _aware_datetime("CROSSPATCH_JUDGE_TOKEN_EXPIRES_AT", DEFAULT_JUDGE_TOKEN_EXPIRY)
    )
    judge_config = _auth_config(
        audience="crosspatch-judge",
        zone="judge",
        subjects=frozenset({"judge-client"}),
        signing_secret=_mcp_signing_material(
            "judge-mcp-signing.key", "CROSSPATCH_JUDGE_MCP_SIGNING_SECRET"
        ),
        hosts_environment="CROSSPATCH_JUDGE_ALLOWED_HOSTS",
        default_hosts="judge-mcp,judge-mcp:8013,localhost,localhost:8013",
        max_lifetime=None,
        incident_scoped=_boolean_environment(
            "CROSSPATCH_JUDGE_INCIDENT_SCOPED", default=False
        ),
    )
    api_expiry = _aware_datetime("CROSSPATCH_API_TOKEN_EXPIRES_AT", _DEFAULT_API_EXPIRY)
    live_trials = LiveTrialRepository(
        database.sessions,
        global_cap_usd=_positive_decimal_environment(
            "CROSSPATCH_LIVE_TRIAL_GLOBAL_BUDGET_USD", "20"
        ),
        requests_per_window=_positive_integer_environment(
            "CROSSPATCH_LIVE_TRIAL_REQUESTS_PER_WINDOW", "3"
        ),
        window_seconds=_positive_integer_environment(
            "CROSSPATCH_LIVE_TRIAL_WINDOW_SECONDS", "3600"
        ),
    )
    service = DatabaseControlService(
        store=database.store,
        authority=authority,
        launcher=launcher,
        judge_tokens=JudgeTokenRepository(database.sessions),
        judge_issuer=TokenIssuer(judge_config),
        judge_token_expires_at=judge_expiry,
        export_signing_key=_private_ed25519_key(),
        approval_resumer=launcher.execute_approved_only,
        repair_resumer=launcher.repair_failed,
        model_runtime="configured" if openai_api_key is not None else "abstain_only",
        live_trials=live_trials,
        live_trial_token_expires_at=api_expiry,
        live_trial_run_reservation_usd=_positive_decimal_environment(
            "CROSSPATCH_LIVE_TRIAL_RUN_RESERVATION_USD", "4"
        ),
    )

    approver_subject = _required_environment("CROSSPATCH_APPROVER_SUBJECT", "approver-1")
    authenticator = DatabaseTokenAuthenticator(
        database.sessions,
        (
            ApiCredential(
                token=_token("reader.token", "CROSSPATCH_READER_TOKEN"),
                subject=_required_environment(
                    "CROSSPATCH_READER_SUBJECT", "judge-reader-1"
                ),
                role=Role.READ_ONLY,
                expires_at=api_expiry,
            ),
            ApiCredential(
                token=_token("operator.token", "CROSSPATCH_OPERATOR_TOKEN"),
                subject=_required_environment("CROSSPATCH_OPERATOR_SUBJECT", "operator-1"),
                role=Role.OPERATOR,
                expires_at=api_expiry,
            ),
            ApiCredential(
                token=_token("approver.token", "CROSSPATCH_APPROVER_TOKEN"),
                subject=approver_subject,
                role=Role.APPROVER,
                expires_at=api_expiry,
                csrf_token=_token("approver-csrf.token", "CROSSPATCH_APPROVER_CSRF_TOKEN"),
                step_up_token=_token("approver-step-up.token", "CROSSPATCH_APPROVER_STEP_UP_TOKEN"),
                step_up_expires_at=api_expiry,
            ),
        ),
    )
    app = create_app(
        service=service,
        authenticator=authenticator,
        allowed_origins=_origins(),
        public_case_reader=DatabasePublishedCaseReader(database.store),
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await database.bootstrap()
        await authenticator.provision()
        await service.reconcile_runtime_work()
        try:
            yield
        finally:
            await service.close()
            if sdk_sessions is not None:
                await sdk_sessions.close()
            await database.close()

    app.router.lifespan_context = lifespan
    app.state.runtime_database = database
    return app


class _MCPRuntimeApp:
    """Expose a database-aware liveness probe without weakening MCP auth."""

    def __init__(
        self,
        authenticated_app: Any,
        inner_app: Any,
        database: RuntimeDatabase,
        *,
        surface: str,
    ) -> None:
        self._authenticated_app = authenticated_app
        # FastMCP owns this application's lifespan and session manager.
        self._app = inner_app
        self._database = database
        self._surface = surface

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if (
            scope.get("type") == "http"
            and scope.get("method") in {"GET", "HEAD"}
            and scope.get("path") == "/healthz"
        ):
            try:
                healthy = await self._database.health()
            except Exception:
                healthy = False
            response = JSONResponse(
                status_code=200 if healthy else 503,
                content={
                    "status": "ok" if healthy else "unavailable",
                    "database": "ok" if healthy else "failed",
                    "surface": self._surface,
                },
            )
            await response(scope, receive, send)
            return
        await self._authenticated_app(scope, receive, send)


def _install_mcp_lifespan(
    surface: Any,
    database: RuntimeDatabase,
    *,
    close: Callable[[], None] | None = None,
):
    inner = surface.inner_app
    original = inner.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app):
        await database.bootstrap()
        try:
            async with original(app):
                yield
        finally:
            if close is not None:
                close()
            await database.close()

    inner.router.lifespan_context = lifespan
    return _MCPRuntimeApp(
        surface.app,
        inner,
        database,
        surface=surface.name.removeprefix("crosspatch-"),
    )


def create_evidence_mcp_app():
    database = _database()
    config = _auth_config(
        audience="crosspatch-evidence",
        zone="evidence",
        subjects=frozenset({"crosspatch-orchestrator"}),
        signing_secret=_mcp_signing_material(
            "evidence-mcp-signing.key", "CROSSPATCH_EVIDENCE_MCP_SIGNING_SECRET"
        ),
        hosts_environment="CROSSPATCH_EVIDENCE_ALLOWED_HOSTS",
        default_hosts="evidence-mcp,evidence-mcp:8011,localhost,localhost:8011",
        max_lifetime=300,
        incident_scoped=True,
    )
    surface = build_evidence_mcp(
        DatabaseEvidenceReader(database.store),
        auth=AuthPolicy(config),
    )
    return _install_mcp_lifespan(surface, database)


def create_broker_mcp_app():
    """Build the one-tool broker around the locked store and trusted runner client."""
    database = _database()
    approval_key = _material("approval-mac.key", "CROSSPATCH_APPROVAL_MAC_KEY")
    broker = Broker(
        store=PostgresWarrantStore(database.sessions),
        approvals=ApprovalService(keys={"approval-v1": approval_key}),
        authority=_LockedStoreAuthoritySentinel(),
        worktrees=EphemeralWorktreeFactory(
            jobs_root=_required_environment(
                "CROSSPATCH_RUNNER_JOBS_ROOT", str(_state_root() / "runner-jobs")
            ),
            workspaces_root=_required_environment(
                "CROSSPATCH_RUNNER_WORKSPACES_ROOT",
                str(_state_root() / "candidate-workspaces"),
            ),
        ),
        process_runner=build_runner_service_client_from_environment(),
        catalog=ExecutionCatalog.default(),
        runner_digest=_bound_digest(
            "CROSSPATCH_RUNNER_DIGEST",
            hashlib.sha256(b"crosspatch-runner-dev").hexdigest(),
        ),
        environment_digest=_bound_digest(
            "CROSSPATCH_ENVIRONMENT_DIGEST",
            hashlib.sha256(b"crosspatch-environment-dev").hexdigest(),
        ),
    )
    config = _auth_config(
        audience="crosspatch-broker",
        zone="broker",
        subjects=frozenset({"Bailiff"}),
        signing_secret=_mcp_signing_material(
            "broker-mcp-signing.key", "CROSSPATCH_BROKER_MCP_SIGNING_SECRET"
        ),
        hosts_environment="CROSSPATCH_BROKER_ALLOWED_HOSTS",
        default_hosts="broker-mcp,broker-mcp:8012,localhost,localhost:8012",
        max_lifetime=300,
    )
    surface = build_broker_mcp(broker, auth=AuthPolicy(config))
    return _install_mcp_lifespan(surface, database)


def create_judge_mcp_app():
    database = _database()
    config = _auth_config(
        audience="crosspatch-judge",
        zone="judge",
        subjects=frozenset({"judge-client"}),
        signing_secret=_mcp_signing_material(
            "judge-mcp-signing.key", "CROSSPATCH_JUDGE_MCP_SIGNING_SECRET"
        ),
        hosts_environment="CROSSPATCH_JUDGE_ALLOWED_HOSTS",
        default_hosts="judge-mcp,judge-mcp:8013,localhost,localhost:8013",
        max_lifetime=None,
        incident_scoped=_boolean_environment(
            "CROSSPATCH_JUDGE_INCIDENT_SCOPED", default=False
        ),
    )
    registry = DatabaseJudgeTokenRegistry(database.sync_url)
    surface = build_judge_mcp(
        DatabasePublishedCaseReader(database.store),
        auth=AuthPolicy(
            config,
            judge_tokens=registry,
            allow_registered_token_reuse=True,
        ),
    )
    return _install_mcp_lifespan(surface, database, close=registry.close)
