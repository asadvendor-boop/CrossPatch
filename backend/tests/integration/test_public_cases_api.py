from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime

import httpx
import pytest
from crosspatch.api.app import create_app
from crosspatch.api.dependencies import StaticTokenAuthenticator
from crosspatch.domain.hashing import canonical_json, sha256_hex


class _UnusedControlService:
    pass


def _event(
    incident_id: str,
    sequence: int,
    event_type: str,
    created_at: str,
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "id": f"evt-public-{sequence}",
        "incident_id": incident_id,
        "sequence": sequence,
        "type": event_type,
        "actor": "Magistrate" if event_type == "VERDICT" else "runtime",
        "summary": event_type.replace("_", " ").title(),
        "details": details or {},
        "event_hash": f"{sequence:x}"[-1] * 64,
        "created_at": created_at,
        "published": True,
    }


def _verdict(
    incident_id: str,
    index: int,
    verdict: str,
    created_at: str,
) -> dict[str, object]:
    return {
        "id": f"verdict-public-{index}",
        "incident_id": incident_id,
        "verdict": verdict,
        "verdict_sha256": f"{index + 7:x}"[-1] * 64,
        "source": "Magistrate",
        "created_at": created_at,
    }


def _projection(incident_id: str, *, title: str) -> dict[str, object]:
    started = datetime(2026, 7, 15, 12, tzinfo=UTC).isoformat()
    remanded = datetime(2026, 7, 15, 12, 0, 1, tzinfo=UTC).isoformat()
    cleared = datetime(2026, 7, 15, 12, 0, 3, tzinfo=UTC).isoformat()
    first_metric = datetime(2026, 7, 15, 12, 0, 4, tzinfo=UTC).isoformat()
    second_metric = datetime(2026, 7, 15, 12, 0, 5, tzinfo=UTC).isoformat()
    verified = datetime(2026, 7, 15, 12, 0, 7, tzinfo=UTC).isoformat()
    completed = datetime(2026, 7, 15, 12, 0, 8, tzinfo=UTC).isoformat()
    return {
        "incident": {
            "id": incident_id,
            "title": title,
            "state": "VERIFIED",
            "severity": "UNSET",
            "scenario": "webhook-race",
            "base_sha": "1" * 40,
            "created_at": started,
            "updated_at": completed,
        },
        "seats": [],
        "events": [
            _event(incident_id, 1, "INCIDENT_OPENED", started),
            _event(
                incident_id,
                2,
                "VERDICT",
                remanded,
                {"verdict": "REMAND", "remand_target": "Counsel"},
            ),
            _event(incident_id, 3, "VERDICT", cleared, {"verdict": "CLEAR"}),
            _event(
                incident_id,
                4,
                "MODEL_METRICS_RECORDED",
                first_metric,
                {"seat": "Inspector", "effort": "medium", "cost_usd": 0.0123},
            ),
            _event(
                incident_id,
                5,
                "MODEL_METRICS_RECORDED",
                second_metric,
                {"seat": "Magistrate", "effort": "high", "cost_usd": 0.0045},
            ),
            _event(
                incident_id,
                6,
                "VERIFIED",
                verified,
                {"receipt_id": "receipt-public", "warrant_id": "warrant-public"},
            ),
            _event(
                incident_id,
                7,
                "BAILIFF_COMPLETED",
                completed,
                {"warrant_id": "warrant-public", "status": "EXECUTED"},
            ),
        ],
        "verdicts": [
            _verdict(incident_id, 1, "REMAND", remanded),
            _verdict(incident_id, 2, "CLEAR", cleared),
        ],
        "specialist_summaries": [],
        "warrants": [],
        "artifacts": {
            "evidence": [],
            "diff": None,
            "tests": [],
            "warrant": None,
        },
        "pending_warrant": None,
    }


def _public_warrant(incident_id: str) -> dict[str, object]:
    warrant = {
        "allowed_paths": ["victim/src/victim/db.py"],
        "approver_identity": "operator-metrics",
        "authority_snapshot_sha256": "a" * 64,
        "base_sha": "2" * 40,
        "canonical_warrant_sha256": "3" * 64,
        "environment_digest": "b" * 64,
        "expires_at": "2026-07-15T12:15:00+00:00",
        "format": "crosspatch-public-warrant-anatomy-v1",
        "incident_id": incident_id,
        "nonce_sha256": "1" * 64,
        "patch_sha256": "4" * 64,
        "plan_ids": ["victim.duplicate-race.candidate"],
        "repository_manifest_sha256": "c" * 64,
        "reviewed_evidence_manifest_sha256": "5" * 64,
        "reviewed_timeline_head": "6" * 64,
        "runner_digest": "7" * 64,
        "test_plan_sha256": "8" * 64,
        "verdict_sha256": "9" * 64,
        "warrant_id": "warrant-public",
    }
    public_bytes = canonical_json(warrant).decode("utf-8")
    return {
        "warrant_id": "warrant-public",
        "canonical_sha256": "3" * 64,
        "public_warrant_bytes": public_bytes,
        "public_warrant_sha256": hashlib.sha256(public_bytes.encode()).hexdigest(),
        "nonce_sha256": "1" * 64,
        "binding_hashes": {
            "authority_snapshot_sha256": "a" * 64,
            "base_sha": "2" * 40,
            "environment_digest": "b" * 64,
            "patch_sha256": "4" * 64,
            "repository_manifest_sha256": "c" * 64,
            "reviewed_evidence_manifest_sha256": "5" * 64,
            "reviewed_timeline_head": "6" * 64,
            "runner_digest": "7" * 64,
            "test_plan_sha256": "8" * 64,
            "verdict_sha256": "9" * 64,
        },
        "approval_status": "APPROVED",
        "approval_id": "approval-public",
        "consumption_status": "CONSUMED",
        "execution_status": "EXECUTED",
        "receipt_ids": ["receipt-public"],
        "created_at": "2026-07-15T12:00:03.500000+00:00",
        "expires_at": "2026-07-15T12:15:00+00:00",
        "consumed_at": "2026-07-15T12:00:07+00:00",
    }


def _projection_with_recorded_impact_metrics(
    incident_id: str,
    *,
    title: str,
) -> dict[str, object]:
    projection = _projection(incident_id, title=title)
    events = projection["events"]
    assert isinstance(events, list)
    events.extend(
        [
            _event(
                incident_id,
                0,
                "EVIDENCE_CAPTURED",
                "2026-07-15T12:00:00.500000+00:00",
                {"evidence_id": "evidence-public", "outcome": "FAILED"},
            ),
            _event(
                incident_id,
                0,
                "REASONING_ESCALATED",
                "2026-07-15T12:00:02+00:00",
                {
                    "seat": "Counsel",
                    "effort": "high",
                    "escalation_count": 1,
                    "reason": "remand",
                },
            ),
            _event(
                incident_id,
                0,
                "MODEL_METRICS_RECORDED",
                "2026-07-15T12:00:02.500000+00:00",
                {"seat": "Counsel", "effort": "high", "cost_usd": 0.002},
            ),
            _event(
                incident_id,
                0,
                "WARRANT_APPROVED",
                "2026-07-15T12:00:06+00:00",
                {
                    "approval_id": "approval-public",
                    "warrant_sha256": "3" * 64,
                    "approver_identity": "operator-metrics",
                },
            ),
            _event(
                incident_id,
                0,
                "EXECUTION_STARTED",
                "2026-07-15T12:00:06.500000+00:00",
                {"warrant_id": "warrant-public"},
            ),
        ]
    )
    events.sort(key=lambda event: str(event["created_at"]))
    for sequence, item in enumerate(events, start=1):
        item["id"] = f"evt-public-{sequence}"
        item["sequence"] = sequence
        item["event_hash"] = f"{sequence:x}"[-1] * 64
    projection["warrants"] = [_public_warrant(incident_id)]
    return projection


def _case(incident_id: str, *, title: str) -> dict[str, object]:
    projection = _projection(incident_id, title=title)
    return {
        "incident_id": incident_id,
        "revision": 1,
        "manifest_sha256": sha256_hex(projection),
        "projection": projection,
    }


class _PublishedReader:
    def __init__(self) -> None:
        self.cases = {
            "inc-public-one": _case("inc-public-one", title="Published one"),
            "inc-public-two": _case("inc-public-two", title="Published two"),
        }

    async def list_public_cases(self):
        return list(self.cases.values())

    async def get_public_case(self, incident_id: str):
        try:
            return self.cases[incident_id]
        except KeyError as error:
            raise LookupError(incident_id) from error


def _app(reader: object | None = None):
    return create_app(
        service=_UnusedControlService(),
        authenticator=StaticTokenAuthenticator({}),
        allowed_origins=("https://crosspatch.test",),
        public_case_reader=reader,
    )


@pytest.mark.asyncio
async def test_public_cases_list_and_detail_require_no_bearer() -> None:
    app = _app(_PublishedReader())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        listed = await client.get("/api/public/cases")
        detail = await client.get("/api/public/cases/inc-public-one")

    assert listed.status_code == 200
    assert [item["incident_id"] for item in listed.json()["cases"]] == [
        "inc-public-one",
        "inc-public-two",
    ]
    assert listed.json()["cases"][0]["state"] == "VERIFIED"
    assert listed.json()["cases"][0]["verdict_path"] == ["REMAND", "CLEAR"]
    assert listed.json()["cases"][0]["recorded_cost_usd"] == 0.0168
    assert listed.json()["cases"][0]["duration_seconds"] == 8
    assert detail.status_code == 200
    assert detail.json()["incident_id"] == "inc-public-one"
    assert detail.json()["display_title"] == "Published one"
    assert detail.json()["projection"]["incident"]["title"] == "Published one"
    assert "canonical_document" not in detail.text
    assert "raw_path" not in detail.text


@pytest.mark.asyncio
async def test_public_case_detail_accepts_exact_typed_trusted_observation() -> None:
    reader = _PublishedReader()
    projection = _projection("inc-public-one", title="Published one")
    observation = {
        "counts": {"receipts": 2, "jobs": 3, "deliveries": 4},
        "response_statuses": [202, 200, 409],
    }
    projection["artifacts"]["tests"] = [
        {
            "id": "receipt-public",
            "label": "victim.payload-equivalence.candidate",
            "plan_sha256": "a" * 64,
            "state": "passed",
            "passed": True,
            "duration_ms": 1200,
            "detail": "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED",
            "warrant_id": "warrant-public",
            "evidence_id": "evidence-public",
            "receipt_sha256": "b" * 64,
            "trusted_observation": observation,
            "trusted_observation_sha256": sha256_hex(observation),
        }
    ]
    reader.cases["inc-public-one"] = {
        "incident_id": "inc-public-one",
        "revision": 1,
        "manifest_sha256": sha256_hex(projection),
        "projection": projection,
    }
    app = _app(reader)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/public/cases/inc-public-one")

    assert response.status_code == 200
    assert response.json()["projection"]["artifacts"]["tests"][0][
        "trusted_observation"
    ] == observation
    assert response.json()["projection"]["artifacts"]["tests"][0][
        "trusted_observation_sha256"
    ] == sha256_hex(observation)


@pytest.mark.asyncio
async def test_public_case_detail_exposes_only_typed_payload_equivalence_proof() -> None:
    reader = _PublishedReader()
    projection = _projection(
        "inc-equivalence-public",
        title="Equivalent webhook retry rejected",
    )
    projection["incident"]["scenario"] = "webhook-payload-equivalence"
    observation = {
        "counts": {"receipts": 1, "jobs": 1, "deliveries": 1},
        "response_statuses": [202, 200, 409],
    }
    projection["artifacts"]["evidence"] = [
        {
            "classification": "UNTRUSTED_EVIDENCE",
            "evidence_id": "ev-equivalence-public",
            "incident_id": "inc-equivalence-public",
            "provenance": "deterministic webhook payload-equivalence reproduction",
            "kind": "test_output",
            "sanitized_sha256": "c" * 64,
            "captured_at": "2026-07-15T12:00:00+00:00",
            "text": "statuses=202,200,409 counts=1,1,1",
            "tags": [],
        }
    ]
    projection["artifacts"]["tests"] = [
        {
            "id": "receipt-equivalence-public",
            "label": "victim.payload-equivalence.candidate",
            "plan_sha256": "a" * 64,
            "state": "passed",
            "passed": True,
            "duration_ms": 1200,
            "detail": "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED",
            "warrant_id": "warrant-public",
            "evidence_id": "ev-equivalence-public",
            "receipt_sha256": "b" * 64,
            "trusted_observation": observation,
            "trusted_observation_sha256": sha256_hex(observation),
        }
    ]
    reader.cases["inc-equivalence-public"] = {
        "incident_id": "inc-equivalence-public",
        "revision": 1,
        "manifest_sha256": sha256_hex(projection),
        "projection": projection,
    }
    app = _app(reader)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/public/cases/inc-equivalence-public")

    assert response.status_code == 200
    body = response.json()
    assert body["projection"]["incident"]["scenario"] == (
        "webhook-payload-equivalence"
    )
    projected_test = body["projection"]["artifacts"]["tests"][0]
    assert projected_test["label"] == "victim.payload-equivalence.candidate"
    assert projected_test["state"] == "passed"
    assert projected_test["trusted_observation"] == observation
    assert projected_test["trusted_observation_sha256"] == sha256_hex(observation)
    assert all(
        marker not in response.text
        for marker in (
            "raw_body_bytes",
            "webhook_signing_secret",
            "raw_artifact_path",
            "approval_mac_key",
            "candidate_context",
            "raw_receipt",
        )
    )


@pytest.mark.asyncio
async def test_public_case_detail_rejects_unregistered_scenario_projection() -> None:
    reader = _PublishedReader()
    projection = _projection("inc-public-one", title="Published one")
    projection["incident"]["scenario"] = "webhook-model-authored"
    reader.cases["inc-public-one"] = {
        "incident_id": "inc-public-one",
        "revision": 1,
        "manifest_sha256": sha256_hex(projection),
        "projection": projection,
    }
    app = _app(reader)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/public/cases/inc-public-one")

    assert response.status_code == 503
    assert response.json() == {
        "detail": "published cases unavailable",
        "code": "PUBLIC_CASES_UNAVAILABLE",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "trusted_observation",
    [
        {
            "counts": {"receipts": -1, "jobs": 3, "deliveries": 4},
            "response_statuses": [202, 200, 409],
        },
        {
            "counts": {"receipts": 2, "jobs": 3, "deliveries": 4},
            "response_statuses": [202, 99, 409],
        },
    ],
)
async def test_public_case_detail_rejects_invalid_trusted_observation(
    trusted_observation: dict[str, object],
) -> None:
    reader = _PublishedReader()
    projection = _projection("inc-public-one", title="Published one")
    projection["artifacts"]["tests"] = [
        {
            "id": "receipt-public",
            "label": "victim.payload-equivalence.candidate",
            "plan_sha256": "a" * 64,
            "state": "passed",
            "passed": True,
            "duration_ms": 1200,
            "detail": "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED",
            "warrant_id": "warrant-public",
            "evidence_id": "evidence-public",
            "receipt_sha256": "b" * 64,
            "trusted_observation": trusted_observation,
            "trusted_observation_sha256": sha256_hex(trusted_observation),
        }
    ]
    reader.cases["inc-public-one"] = {
        "incident_id": "inc-public-one",
        "revision": 1,
        "manifest_sha256": sha256_hex(projection),
        "projection": projection,
    }
    app = _app(reader)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/public/cases/inc-public-one")

    assert response.status_code == 503


@pytest.mark.asyncio
async def test_public_case_detail_rejects_resealed_tampered_observation_digest() -> None:
    reader = _PublishedReader()
    projection = _projection("inc-public-one", title="Published one")
    original = {
        "counts": {"receipts": 2, "jobs": 3, "deliveries": 4},
        "response_statuses": [202, 200, 409],
    }
    tampered = {
        "counts": {"receipts": 2, "jobs": 99, "deliveries": 4},
        "response_statuses": [202, 200, 409],
    }
    projection["artifacts"]["tests"] = [
        {
            "id": "receipt-public",
            "label": "victim.payload-equivalence.candidate",
            "plan_sha256": "a" * 64,
            "state": "passed",
            "passed": True,
            "duration_ms": 1200,
            "detail": "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED",
            "warrant_id": "warrant-public",
            "evidence_id": "evidence-public",
            "receipt_sha256": "b" * 64,
            "trusted_observation": tampered,
            "trusted_observation_sha256": sha256_hex(original),
        }
    ]
    reader.cases["inc-public-one"] = {
        "incident_id": "inc-public-one",
        "revision": 1,
        "manifest_sha256": sha256_hex(projection),
        "projection": projection,
    }
    app = _app(reader)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/public/cases/inc-public-one")

    assert response.status_code == 503


@pytest.mark.asyncio
async def test_public_case_summary_derives_impact_metrics_from_recorded_events() -> None:
    reader = _PublishedReader()
    projection = _projection_with_recorded_impact_metrics(
        "inc-public-one",
        title="Published one",
    )
    reader.cases["inc-public-one"] = {
        "incident_id": "inc-public-one",
        "revision": 1,
        "manifest_sha256": sha256_hex(projection),
        "projection": projection,
    }
    app = _app(reader)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/public/cases")

    assert response.status_code == 200
    summary = response.json()["cases"][0]
    assert summary["evidence_to_verified_seconds"] == 6.5
    assert summary["human_gate_dwell_seconds"] == 2.5
    assert summary["execution_verification_seconds"] == 0.5
    assert summary["seat_spend"] == [
        {
            "seat": "Counsel",
            "effort": "high",
            "escalation_count": 1,
            "cost_usd": 0.002,
        },
        {
            "seat": "Inspector",
            "effort": "medium",
            "escalation_count": 0,
            "cost_usd": 0.0123,
        },
        {
            "seat": "Magistrate",
            "effort": "high",
            "escalation_count": 0,
            "cost_usd": 0.0045,
        },
    ]


@pytest.mark.asyncio
async def test_public_api_replaces_legacy_run_title_without_rewriting_canonical_bytes() -> None:
    reader = _PublishedReader()
    legacy_title = "Genuine fresh-output release evaluation 10"
    reader.cases["inc-public-one"] = _case("inc-public-one", title=legacy_title)
    app = _app(reader)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        listed = await client.get("/api/public/cases")
        detail = await client.get("/api/public/cases/inc-public-one")

    assert listed.status_code == 200
    assert listed.json()["cases"][0]["title"] == "Duplicate order-paid delivery"
    assert detail.status_code == 200
    assert detail.json()["display_title"] == "Duplicate order-paid delivery"
    assert detail.json()["projection"]["incident"]["title"] == legacy_title
    assert json.loads(detail.json()["canonical_projection_json"])["incident"]["title"] == (
        legacy_title
    )


@pytest.mark.asyncio
async def test_public_case_detail_carries_exact_backend_canonical_projection_bytes() -> None:
    reader = _PublishedReader()
    envelope = deepcopy(reader.cases["inc-public-one"])
    projection = envelope["projection"]
    assert isinstance(projection, dict)
    events = projection["events"]
    assert isinstance(events, list)
    events[3]["details"]["canonical_number_vectors"] = {
        "zero": 0.0,
        "one": 1.0,
        "negative_zero": -0.0,
        "small_exponent": 1e-7,
        "large_exponent": 1e20,
    }
    envelope["manifest_sha256"] = sha256_hex(projection)
    reader.cases["inc-public-one"] = envelope
    app = _app(reader)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/public/cases/inc-public-one")

    assert response.status_code == 200
    body = response.json()
    canonical = body["canonical_projection_json"]
    assert canonical.encode("utf-8") == canonical_json(projection)
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == body["manifest_sha256"]
    assert json.loads(canonical) == body["projection"]
    assert '"zero":0.0' in canonical
    assert '"one":1.0' in canonical
    assert '"negative_zero":-0.0' in canonical
    assert '"small_exponent":1e-07' in canonical
    assert '"large_exponent":1e+20' in canonical


@pytest.mark.asyncio
@pytest.mark.parametrize("incident_id", ["inc-missing", "inc-inflight", "inc-live-trial"])
async def test_public_case_detail_hides_every_nonpublished_incident(incident_id: str) -> None:
    app = _app(_PublishedReader())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(f"/api/public/cases/{incident_id}")

    assert response.status_code == 404
    assert response.json() == {"detail": "case not found"}


@pytest.mark.asyncio
async def test_public_cases_fail_closed_when_reader_is_unavailable() -> None:
    app = _app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        listed = await client.get("/api/public/cases")
        detail = await client.get("/api/public/cases/inc-public-one")

    for response in (listed, detail):
        assert response.status_code == 503
        assert response.json() == {
            "detail": "published cases unavailable",
            "code": "PUBLIC_CASES_UNAVAILABLE",
        }


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["manifest", "secret", "cross_incident", "schema"])
async def test_public_cases_reject_tampered_or_unsafe_projection_without_leaking(
    failure: str,
) -> None:
    marker = "PRIVATE-SENTINEL-MUST-NOT-LEAK"
    reader = _PublishedReader()
    envelope = deepcopy(reader.cases["inc-public-one"])
    projection = envelope["projection"]
    assert isinstance(projection, dict)
    if failure == "manifest":
        projection["incident"]["title"] = marker
    elif failure == "secret":
        projection["artifacts"]["raw_path"] = marker
        envelope["manifest_sha256"] = sha256_hex(projection)
    elif failure == "cross_incident":
        projection["events"] = [
            {
                "id": "evt-cross",
                "incident_id": "inc-private-other",
                "sequence": 1,
                "type": "INCIDENT_OPENED",
                "actor": "operator",
                "summary": marker,
                "details": {},
                "event_hash": "2" * 64,
                "created_at": "2026-07-15T12:00:00+00:00",
                "published": True,
            }
        ]
        envelope["manifest_sha256"] = sha256_hex(projection)
    else:
        projection["incident"]["state"] = "OPEN"
        projection["incident"]["title"] = marker
        envelope["manifest_sha256"] = sha256_hex(projection)
    reader.cases["inc-public-one"] = envelope
    app = _app(reader)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/public/cases/inc-public-one")

    assert response.status_code == 503
    assert response.json() == {
        "detail": "published cases unavailable",
        "code": "PUBLIC_CASES_UNAVAILABLE",
    }
    assert marker not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "unknown_verdict",
        "verdict_mismatch",
        "malformed_event",
        "negative_cost",
        "nonfinite_cost",
        "cross_incident_verdict",
        "impossible_terminal_path",
    ],
)
async def test_public_case_summary_metrics_fail_closed_on_untrusted_record_values(
    failure: str,
) -> None:
    reader = _PublishedReader()
    envelope = deepcopy(reader.cases["inc-public-one"])
    projection = envelope["projection"]
    assert isinstance(projection, dict)
    events = projection["events"]
    verdicts = projection["verdicts"]
    assert isinstance(events, list)
    assert isinstance(verdicts, list)

    if failure == "unknown_verdict":
        verdicts[-1]["verdict"] = "CONFIRMED"
        events[2]["details"]["verdict"] = "CONFIRMED"
    elif failure == "verdict_mismatch":
        verdicts[0]["verdict"] = "CLEAR"
    elif failure == "malformed_event":
        events[3]["created_at"] = "not-a-timestamp"
    elif failure == "negative_cost":
        events[3]["details"]["cost_usd"] = -0.01
    elif failure == "nonfinite_cost":
        events[3]["details"]["cost_usd"] = float("inf")
    elif failure == "cross_incident_verdict":
        verdicts[-1]["incident_id"] = "inc-private-other"
    else:
        verdicts[:] = [
            _verdict(
                "inc-public-one",
                1,
                "BLOCK",
                "2026-07-15T12:00:03+00:00",
            )
        ]
        events[1:3] = [
            _event(
                "inc-public-one",
                2,
                "VERDICT",
                "2026-07-15T12:00:03+00:00",
                {"verdict": "BLOCK"},
            )
        ]
        for sequence, event in enumerate(events, start=1):
            event["sequence"] = sequence

    if failure == "nonfinite_cost":
        envelope["manifest_sha256"] = "0" * 64
    else:
        envelope["manifest_sha256"] = sha256_hex(projection)
    reader.cases["inc-public-one"] = envelope
    app = _app(reader)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/public/cases")

    assert response.status_code == 503
    assert response.json() == {
        "detail": "published cases unavailable",
        "code": "PUBLIC_CASES_UNAVAILABLE",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "noncontiguous_events",
        "out_of_order_events",
        "verdict_mismatch",
        "failed_after_clear",
        "missing_metrics",
        "invalid_metrics",
    ],
)
async def test_public_case_detail_applies_the_same_record_semantics_as_the_index(
    failure: str,
) -> None:
    reader = _PublishedReader()
    envelope = deepcopy(reader.cases["inc-public-one"])
    projection = envelope["projection"]
    assert isinstance(projection, dict)
    events = projection["events"]
    verdicts = projection["verdicts"]
    assert isinstance(events, list)
    assert isinstance(verdicts, list)

    if failure == "noncontiguous_events":
        events[1]["sequence"] = 8
    elif failure == "out_of_order_events":
        events[1], events[2] = events[2], events[1]
    elif failure == "verdict_mismatch":
        verdicts[0]["verdict"] = "CLEAR"
    elif failure == "failed_after_clear":
        events.insert(
            3,
            _event(
                "inc-public-one",
                4,
                "TEST_FAILED",
                "2026-07-15T12:00:03.500000+00:00",
            ),
        )
        for sequence, event in enumerate(events, start=1):
            event["sequence"] = sequence
    elif failure == "missing_metrics":
        events[:] = [
            event for event in events if event["type"] != "MODEL_METRICS_RECORDED"
        ]
        for sequence, event in enumerate(events, start=1):
            event["sequence"] = sequence
    else:
        events[3]["details"]["cost_usd"] = "0.0123"

    envelope["manifest_sha256"] = sha256_hex(projection)
    reader.cases["inc-public-one"] = envelope
    app = _app(reader)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        detail = await client.get("/api/public/cases/inc-public-one")

    assert detail.status_code == 503
    assert detail.json() == {
        "detail": "published cases unavailable",
        "code": "PUBLIC_CASES_UNAVAILABLE",
    }


@pytest.mark.asyncio
async def test_public_cases_surface_has_no_mutation_methods() -> None:
    app = _app(_PublishedReader())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        responses = [
            await client.request(method, "/api/public/cases/inc-public-one")
            for method in ("POST", "PUT", "PATCH", "DELETE")
        ]

    assert all(response.status_code == 405 for response in responses)
