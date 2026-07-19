from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import pytest
from crosspatch.api.app import create_app
from crosspatch.api.dependencies import Principal, Role, StaticTokenAuthenticator
from crosspatch.api.models import (
    EvidenceView,
    IncidentView,
    JudgeTokenView,
    PublishedEvent,
    WarrantView,
)
from crosspatch.runtime.authority import WarrantDecisionConflict
from pydantic import ValidationError

WARRANT_DOCUMENT = '{"incident_id":"inc-a"}'
WARRANT_SHA256 = hashlib.sha256(WARRANT_DOCUMENT.encode("ascii")).hexdigest()


class FakeControlService:
    def __init__(self) -> None:
        self.incidents = {
            "inc-a": IncidentView(
                id="inc-a",
                title="Webhook race A",
                scenario="webhook-race",
                state="APPROVAL_PENDING",
                timeline_head="a" * 64,
                pending_warrant_id="war-a",
            ),
            "inc-b": IncidentView(
                id="inc-b",
                title="B-UNIQUE-SENTINEL",
                scenario="webhook-race",
                state="OPEN",
                timeline_head=None,
            ),
        }
        self.evidence = {
            "inc-a": (
                EvidenceView(
                    id="ev-a",
                    incident_id="inc-a",
                    kind="log",
                    provenance="victim.log",
                    text="sanitized A",
                    sanitized_sha256="b" * 64,
                    tags=("prompt_injection",),
                    published=True,
                ),
            ),
            "inc-b": (
                EvidenceView(
                    id="ev-b",
                    incident_id="inc-b",
                    kind="log",
                    provenance="victim.log",
                    text="B-UNIQUE-SENTINEL raw-password=do-not-leak",
                    sanitized_sha256="c" * 64,
                    tags=(),
                    published=True,
                ),
            ),
        }
        self.warrant = WarrantView(
            id="war-a",
            incident_id="inc-a",
            status="PENDING_APPROVAL",
            canonical_document=WARRANT_DOCUMENT,
            warrant_sha256=WARRANT_SHA256,
            expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        )
        self.decisions: list[tuple[str, bool, str, str]] = []
        self.opened: list[str] = []
        self.opened_profiles: list[tuple[str, str]] = []
        self.lookup_calls: list[tuple[str, str]] = []
        self.judge_token_actions: list[tuple[str, str, str | None]] = []
        self.expired_decision = False

    async def open_incident(
        self,
        *,
        scenario: str,
        title: str | None,
        actor: str,
        evidence_profile: str = "standard",
    ) -> IncidentView:
        self.opened.append(actor)
        self.opened_profiles.append((scenario, evidence_profile))
        return IncidentView(
            id="inc-new",
            title=title or "Webhook race",
            scenario=scenario,
            state="OPEN",
            timeline_head=None,
        )

    async def open_live_trial(
        self, *, scenario: str, title: str | None, actor: str
    ) -> IncidentView:
        self.opened.append(f"live:{actor}")
        return IncidentView(
            id="inc-live-new",
            title=title or "Webhook live trial",
            scenario=scenario,
            state="OPEN",
            timeline_head=None,
        )

    async def get_incident(self, incident_id: str) -> IncidentView | None:
        self.lookup_calls.append(("incident", incident_id))
        return self.incidents.get(incident_id)

    async def list_evidence(self, incident_id: str) -> tuple[EvidenceView, ...]:
        self.lookup_calls.append(("evidence", incident_id))
        return self.evidence.get(incident_id, ())

    async def list_events(self, incident_id: str, *, after: int, limit: int):
        self.lookup_calls.append(("events", incident_id))
        return ()

    async def stream_events(self, incident_id: str, *, after: int) -> AsyncIterator[PublishedEvent]:
        if False:  # pragma: no cover - preserve async-generator protocol
            yield

    async def get_warrant_for_principal(
        self, warrant_id: str, principal: Principal
    ) -> WarrantView | None:
        self.lookup_calls.append(("warrant", warrant_id))
        if warrant_id == self.warrant.id and principal.can_access(self.warrant.incident_id):
            return self.warrant
        return None

    async def decide_warrant(
        self,
        *,
        warrant_id: str,
        approve: bool,
        warrant_sha256: str,
        actor: str,
        reason: str | None = None,
    ) -> WarrantView:
        if self.expired_decision:
            raise WarrantDecisionConflict("WARRANT_EXPIRED", "warrant is expired")
        self.decisions.append(
            (warrant_id, approve, warrant_sha256, actor if reason is None else f"{actor}:{reason}")
        )
        return self.warrant.model_copy(update={"status": "APPROVED" if approve else "REJECTED"})

    async def decide_live_trial_warrant(
        self,
        *,
        warrant_id: str,
        approve: bool,
        warrant_sha256: str,
        actor: str,
        reason: str | None = None,
    ) -> WarrantView:
        return await self.decide_warrant(
            warrant_id=warrant_id,
            approve=approve,
            warrant_sha256=warrant_sha256,
            actor=actor,
            reason=reason,
        )

    async def request_live_trial_revision(
        self,
        *,
        warrant_id: str,
        warrant_sha256: str,
        comment: str,
        actor: str,
    ) -> IncidentView:
        self.decisions.append((warrant_id, False, warrant_sha256, f"revision:{actor}:{comment}"))
        return IncidentView(
            id="inc-a",
            title="Incident A",
            scenario="webhook-race",
            state="PATCHING",
            timeline_head="d" * 64,
        )

    async def export_case(self, incident_id: str) -> bytes:
        self.lookup_calls.append(("export", incident_id))
        return b"PK-signed-sanitized-case"

    async def rotate_judge_token(
        self, *, actor: str, incident_id: str | None = None
    ) -> JudgeTokenView:
        self.judge_token_actions.append(("ROTATE", actor, incident_id))
        return JudgeTokenView(
            token="rotated-token-" "value-at-least-32-chars",
            expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        )

    async def list_judge_tokens(self):
        return {
            "tokens": [
                {
                    "token_id": "judge-runtime-jti-1",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "revoked": False,
                    "created_at": "2026-07-14T12:00:00Z",
                    "revoked_at": None,
                }
            ]
        }

    async def revoke_judge_token(self, token_id: str, *, actor: str):
        self.judge_token_actions.append(("REVOKE", actor, token_id))
        return {
            "token_id": token_id,
            "expires_at": "2099-01-01T00:00:00Z",
            "revoked": True,
            "created_at": "2026-07-14T12:00:00Z",
            "revoked_at": "2026-07-14T12:01:00Z",
        }

    async def rotate_live_trial_credential(self, *, actor: str):
        self.judge_token_actions.append(("ROTATE_LIVE_TRIAL", actor, None))
        return {
            "token": "live-trial-token-value-at-least-32-characters",
            "subject": "live-trial-subject-1",
            "expires_at": "2099-01-01T00:00:00Z",
            "global_budget_cap_usd": "20.000000",
        }

    async def revoke_live_trial_credential(self, subject: str, *, actor: str) -> None:
        self.judge_token_actions.append(("REVOKE_LIVE_TRIAL", actor, subject))


def _principal(subject: str, role: Role, incidents: set[str]) -> Principal:
    return Principal(
        subject=subject,
        role=role,
        incident_ids=frozenset(incidents),
        expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        csrf_token="csrf-token",
        step_up_token="step-up-token",
        step_up_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
    )


@pytest.fixture
def api_fixture():
    service = FakeControlService()
    auth = StaticTokenAuthenticator(
        {
            "read-a": _principal("reader-a", Role.READ_ONLY, {"inc-a"}),
            "operator-a": _principal("operator-a", Role.OPERATOR, {"inc-a"}),
            "approver-a": _principal("approver-a", Role.APPROVER, {"inc-a"}),
            "live-trial-a": _principal("live-trial-a", Role.LIVE_TRIAL, set()),
            "live-trial-own": _principal("live-trial-own", Role.LIVE_TRIAL, {"inc-a"}),
        }
    )
    app = create_app(
        service=service,
        authenticator=auth,
        allowed_origins=("https://crosspatch.test",),
    )
    return app, service


def _headers(token: str, *, mutation: bool = False) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if mutation:
        headers |= {
            "Origin": "https://crosspatch.test",
            "X-CSRF-Token": "csrf-token",
            "X-CrossPatch-Step-Up": "step-up-token",
        }
    return headers


@pytest.mark.asyncio
async def test_rest_requires_bearer_and_authorizes_incident_before_lookup(api_fixture) -> None:
    app, service = api_fixture
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        unauthenticated = await client.get("/api/incidents/inc-a")
        cross_incident = await client.get("/api/incidents/inc-b", headers=_headers("read-a"))

    assert unauthenticated.status_code == 401
    assert cross_incident.status_code == 404
    assert ("incident", "inc-b") not in service.lookup_calls
    assert "B-UNIQUE-SENTINEL" not in cross_incident.text


@pytest.mark.asyncio
async def test_incident_snapshot_discovers_pending_warrant_without_timeline_inference(
    api_fixture,
) -> None:
    app, _ = api_fixture
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/incidents/inc-a", headers=_headers("read-a"))

    assert response.status_code == 200
    assert response.json()["pending_warrant_id"] == "war-a"


@pytest.mark.asyncio
async def test_operator_can_open_incident_but_read_only_cannot(api_fixture) -> None:
    app, service = api_fixture
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        denied = await client.post(
            "/api/incidents",
            headers=_headers("read-a"),
            json={"scenario": "webhook-race"},
        )
        opened = await client.post(
            "/api/incidents",
            headers=_headers("operator-a"),
            json={"scenario": "webhook-race"},
        )

    assert denied.status_code == 403
    assert opened.status_code == 201
    assert opened.json()["id"] == "inc-new"
    assert service.opened == ["operator-a"]


@pytest.mark.asyncio
async def test_operator_opens_payload_equivalence_and_unknown_scenario_returns_422(
    api_fixture,
) -> None:
    app, service = api_fixture
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        opened = await client.post(
            "/api/incidents",
            headers=_headers("operator-a"),
            json={"scenario": "webhook-payload-equivalence"},
        )
        denied = await client.post(
            "/api/incidents",
            headers=_headers("operator-a"),
            json={"scenario": "model-authored-scenario"},
        )

    assert opened.status_code == 201
    assert opened.json()["scenario"] == "webhook-payload-equivalence"
    assert denied.status_code == 422
    assert denied.json() == {"detail": "unsupported incident scenario"}
    assert service.opened == ["operator-a"]


@pytest.mark.asyncio
async def test_operator_selects_closed_instruction_log_profile_and_other_roles_fail_closed(
    api_fixture,
) -> None:
    app, service = api_fixture
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        opened = await client.post(
            "/api/incidents",
            headers=_headers("operator-a"),
            json={
                "scenario": "webhook-race",
                "title": "Poisoned webhook logs — due process held",
                "evidence_profile": "instruction-like-log",
            },
        )
        wrong_scenario = await client.post(
            "/api/incidents",
            headers=_headers("operator-a"),
            json={
                "scenario": "webhook-payload-equivalence",
                "evidence_profile": "instruction-like-log",
            },
        )
        live_trial = await client.post(
            "/api/incidents",
            headers=_headers("live-trial-a"),
            json={
                "scenario": "webhook-race",
                "evidence_profile": "instruction-like-log",
            },
        )

    assert opened.status_code == 201
    assert service.opened_profiles[-1] == ("webhook-race", "instruction-like-log")
    assert wrong_scenario.status_code == 422
    assert wrong_scenario.json() == {
        "detail": "instruction-like-log evidence is supported only for webhook-race"
    }
    assert live_trial.status_code == 422
    assert live_trial.json() == {"detail": "live trials support only standard evidence"}
    assert service.opened == ["operator-a"]


@pytest.mark.asyncio
async def test_live_trial_credential_opens_only_the_bundled_live_trial(api_fixture) -> None:
    app, service = api_fixture
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        opened = await client.post(
            "/api/incidents",
            headers=_headers("live-trial-a"),
            json={"scenario": "webhook-race"},
        )
        denied = await client.post(
            "/api/incidents",
            headers=_headers("live-trial-a"),
            json={"scenario": "webhook-payload-equivalence"},
        )

    assert opened.status_code == 201
    assert opened.json()["id"] == "inc-live-new"
    assert denied.status_code == 422
    assert service.opened == ["live:live-trial-a"]


@pytest.mark.asyncio
async def test_evidence_surface_returns_only_sanitized_published_shape(api_fixture) -> None:
    app, _ = api_fixture
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/incidents/inc-a/evidence", headers=_headers("read-a"))

    assert response.status_code == 200
    encoded = response.text.lower()
    assert response.json()[0]["text"] == "sanitized A"
    assert "raw_" not in encoded
    assert "do-not-leak" not in encoded


@pytest.mark.asyncio
async def test_approval_requires_role_origin_csrf_step_up_and_exact_hash(api_fixture) -> None:
    app, service = api_fixture
    body = {"confirmation": "APPROVE", "warrant_sha256": WARRANT_SHA256}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        role_denied = await client.post(
            "/api/warrants/war-a/approve",
            headers=_headers("operator-a", mutation=True),
            json=body,
        )
        no_csrf = await client.post(
            "/api/warrants/war-a/approve",
            headers={
                "Authorization": "Bearer approver-a",
                "Origin": "https://crosspatch.test",
                "X-CrossPatch-Step-Up": "step-up-token",
            },
            json=body,
        )
        bad_origin = await client.post(
            "/api/warrants/war-a/approve",
            headers=_headers("approver-a", mutation=True) | {"Origin": "https://attacker.test"},
            json=body,
        )
        no_step_up = await client.post(
            "/api/warrants/war-a/approve",
            headers={
                "Authorization": "Bearer approver-a",
                "Origin": "https://crosspatch.test",
                "X-CSRF-Token": "csrf-token",
            },
            json=body,
        )
        wrong_confirmation = await client.post(
            "/api/warrants/war-a/approve",
            headers=_headers("approver-a", mutation=True),
            json=body | {"confirmation": "yes"},
        )
        wrong_hash = await client.post(
            "/api/warrants/war-a/approve",
            headers=_headers("approver-a", mutation=True),
            json=body | {"warrant_sha256": "e" * 64},
        )
        approved = await client.post(
            "/api/warrants/war-a/approve",
            headers=_headers("approver-a", mutation=True),
            json=body,
        )

    assert [
        response.status_code for response in (role_denied, no_csrf, bad_origin, no_step_up)
    ] == [
        403,
        403,
        403,
        403,
    ]
    assert wrong_confirmation.status_code == 422
    assert wrong_hash.status_code == 409
    assert approved.status_code == 200
    assert service.decisions == [("war-a", True, WARRANT_SHA256, "approver-a")]


@pytest.mark.asyncio
async def test_live_trial_approves_only_its_granted_warrant_with_origin_and_hash(
    api_fixture,
) -> None:
    app, service = api_fixture
    body = {"confirmation": "APPROVE", "warrant_sha256": WARRANT_SHA256}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        foreign = await client.post(
            "/api/warrants/war-a/approve",
            headers={
                "Authorization": "Bearer live-trial-a",
                "Origin": "https://crosspatch.test",
            },
            json=body,
        )
        bad_origin = await client.post(
            "/api/warrants/war-a/approve",
            headers={
                "Authorization": "Bearer live-trial-own",
                "Origin": "https://invalid.test",
            },
            json=body,
        )
        approved = await client.post(
            "/api/warrants/war-a/approve",
            headers={
                "Authorization": "Bearer live-trial-own",
                "Origin": "https://crosspatch.test",
            },
            json=body,
        )

    assert foreign.status_code == 404
    assert bad_origin.status_code == 403
    assert approved.status_code == 200
    assert service.decisions == [("war-a", True, WARRANT_SHA256, "live-trial-own")]


@pytest.mark.asyncio
async def test_request_revision_is_live_trial_only_and_returns_accepted(api_fixture) -> None:
    app, service = api_fixture
    body = {
        "confirmation": "REQUEST_REVISION",
        "warrant_sha256": WARRANT_SHA256,
        "comment": "Use the cited uniqueness evidence and narrow the patch.",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        denied = await client.post(
            "/api/warrants/war-a/request-revision",
            headers=_headers("approver-a", mutation=True),
            json=body,
        )
        accepted = await client.post(
            "/api/warrants/war-a/request-revision",
            headers={
                "Authorization": "Bearer live-trial-own",
                "Origin": "https://crosspatch.test",
            },
            json=body,
        )

    assert denied.status_code == 403
    assert accepted.status_code == 202
    assert accepted.json()["state"] == "PATCHING"
    assert service.decisions == [
        (
            "war-a",
            False,
            WARRANT_SHA256,
            "revision:live-trial-own:Use the cited uniqueness evidence and narrow the patch.",
        )
    ]


@pytest.mark.asyncio
async def test_live_trial_rejection_requires_and_records_a_bounded_reason(api_fixture) -> None:
    app, service = api_fixture
    base = {"confirmation": "REJECT", "warrant_sha256": WARRANT_SHA256}
    headers = {
        "Authorization": "Bearer live-trial-own",
        "Origin": "https://crosspatch.test",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        missing = await client.post(
            "/api/warrants/war-a/reject",
            headers=headers,
            json=base,
        )
        rejected = await client.post(
            "/api/warrants/war-a/reject",
            headers=headers,
            json=base | {"reason": "The cited evidence does not justify this scope."},
        )

    assert missing.status_code == 422
    assert rejected.status_code == 200
    assert service.decisions == [
        (
            "war-a",
            False,
            WARRANT_SHA256,
            "live-trial-own:The cited evidence does not justify this scope.",
        )
    ]


def test_warrant_view_rejects_document_hash_mismatch() -> None:
    with pytest.raises(ValidationError):
        WarrantView(
            id="war-a",
            incident_id="inc-a",
            status="PENDING_APPROVAL",
            canonical_document=WARRANT_DOCUMENT,
            warrant_sha256="0" * 64,
            expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        )


def test_token_and_warrant_expiries_must_be_timezone_aware() -> None:
    with pytest.raises(ValidationError):
        JudgeTokenView(
            token="x" * 32,
            expires_at=datetime(2099, 1, 1),
        )
    with pytest.raises(ValidationError):
        WarrantView(
            id="war-a",
            incident_id="inc-a",
            status="PENDING_APPROVAL",
            canonical_document=WARRANT_DOCUMENT,
            warrant_sha256=WARRANT_SHA256,
            expires_at=datetime(2099, 1, 1),
        )


@pytest.mark.asyncio
async def test_chunked_request_body_limit_cannot_be_bypassed(api_fixture) -> None:
    app, service = api_fixture
    limited_app = create_app(
        service=service,
        authenticator=app.state.authenticator,
        allowed_origins=("https://crosspatch.test",),
        max_request_bytes=32,
    )

    async def body():
        yield b'{"scenario":"'
        yield b"x" * 128
        yield b'"}'

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=limited_app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/incidents",
            headers=_headers("operator-a"),
            content=body(),
        )

    assert response.status_code == 413


@pytest.mark.asyncio
async def test_export_and_warrant_lookup_are_incident_authorized(api_fixture) -> None:
    app, service = api_fixture
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        exported = await client.get("/api/incidents/inc-a/export", headers=_headers("read-a"))
        cross_export = await client.get("/api/incidents/inc-b/export", headers=_headers("read-a"))
        reader_warrant = await client.get(
            "/api/warrants/war-a", headers=_headers("read-a")
        )
        operator_warrant = await client.get(
            "/api/warrants/war-a", headers=_headers("operator-a")
        )

    assert exported.status_code == 200
    assert exported.content == b"PK-signed-sanitized-case"
    assert cross_export.status_code == 404
    assert reader_warrant.status_code == 403
    assert "canonical_document" not in reader_warrant.text
    assert operator_warrant.status_code == 200
    assert operator_warrant.json()["canonical_document"] == WARRANT_DOCUMENT
    assert ("export", "inc-b") not in service.lookup_calls
    assert "B-UNIQUE-SENTINEL" not in cross_export.text


@pytest.mark.asyncio
async def test_incomplete_case_export_returns_conflict_not_internal_error(api_fixture) -> None:
    app, service = api_fixture

    async def incomplete_export(_incident_id: str) -> bytes:
        raise ValueError("case export requires a persisted verdict, warrant, and broker receipt")

    service.export_case = incomplete_export
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.get("/api/incidents/inc-a/export", headers=_headers("read-a"))

    assert response.status_code == 409
    assert response.json() == {
        "detail": "Case export is available after verified execution.",
        "code": "CASE_EXPORT_NOT_READY",
    }


@pytest.mark.asyncio
async def test_judge_token_rotation_requires_full_approval_controls(api_fixture) -> None:
    app, service = api_fixture
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        denied = await client.post(
            "/api/judge-tokens/rotate",
            headers=_headers("operator-a", mutation=True),
            json={"confirmation": "ROTATE"},
        )
        rotated = await client.post(
            "/api/judge-tokens/rotate",
            headers=_headers("approver-a", mutation=True),
            json={"confirmation": "ROTATE"},
        )

    assert denied.status_code == 403
    assert rotated.status_code == 200
    assert rotated.json()["token"] == "rotated-token-value-at-least-32-chars"
    assert service.judge_token_actions == [("ROTATE", "approver-a", None)]


@pytest.mark.asyncio
async def test_judge_token_list_and_revoke_are_approver_only_and_actor_attributed(
    api_fixture,
) -> None:
    app, service = api_fixture
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        operator_list = await client.get(
            "/api/judge-tokens",
            headers=_headers("operator-a"),
        )
        listed = await client.get(
            "/api/judge-tokens",
            headers=_headers("approver-a"),
        )
        operator_revoke = await client.post(
            "/api/judge-tokens/judge-runtime-jti-1/revoke",
            headers=_headers("operator-a", mutation=True),
            json={"confirmation": "REVOKE"},
        )
        revoked = await client.post(
            "/api/judge-tokens/judge-runtime-jti-1/revoke",
            headers=_headers("approver-a", mutation=True),
            json={"confirmation": "REVOKE"},
        )

    assert operator_list.status_code == operator_revoke.status_code == 403
    assert listed.status_code == 200
    assert listed.json()["tokens"][0]["token_id"] == "judge-runtime-jti-1"
    assert "token" not in listed.json()["tokens"][0]
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] is True
    assert service.judge_token_actions == [
        ("REVOKE", "approver-a", "judge-runtime-jti-1")
    ]


@pytest.mark.asyncio
async def test_live_trial_credential_rotation_uses_approver_controls(api_fixture) -> None:
    app, service = api_fixture
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        denied = await client.post(
            "/api/live-trial-credentials/rotate",
            headers=_headers("operator-a", mutation=True),
            json={"confirmation": "ROTATE"},
        )
        issued = await client.post(
            "/api/live-trial-credentials/rotate",
            headers=_headers("approver-a", mutation=True),
            json={"confirmation": "ROTATE"},
        )

    assert denied.status_code == 403
    assert issued.status_code == 200
    assert issued.json()["subject"] == "live-trial-subject-1"
    assert issued.json()["global_budget_cap_usd"] == "20.000000"
    assert service.judge_token_actions[-1] == (
        "ROTATE_LIVE_TRIAL",
        "approver-a",
        None,
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        revoked = await client.post(
            "/api/live-trial-credentials/live-trial-subject-1/revoke",
            headers=_headers("approver-a", mutation=True),
            json={"confirmation": "REVOKE"},
        )
    assert revoked.status_code == 204
    assert service.judge_token_actions[-1] == (
        "REVOKE_LIVE_TRIAL",
        "approver-a",
        "live-trial-subject-1",
    )


@pytest.mark.asyncio
async def test_expired_warrant_decision_is_exposed_as_typed_http_conflict(api_fixture) -> None:
    app, service = api_fixture
    service.expired_decision = True
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as client:
        response = await client.post(
            "/api/warrants/war-a/approve",
            headers=_headers("approver-a", mutation=True),
            json={"confirmation": "APPROVE", "warrant_sha256": WARRANT_SHA256},
        )

    assert response.status_code == 409
    assert response.json() == {
        "detail": "warrant is expired",
        "code": "WARRANT_EXPIRED",
    }
