from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from crosspatch.evals import real_model
from crosspatch.evals.real_model import (
    GateConfiguration,
    LiveEvaluationClient,
    build_run_record,
    evaluate,
)


def _metric(
    seat: str,
    model: str,
    *,
    cached_input_tokens: int = 0,
    schema_valid: bool = True,
) -> dict[str, object]:
    return {
        "seat": seat,
        "model": model,
        "effort": "none" if seat == "Bailiff" else "medium",
        "response_id": f"resp_{seat.casefold()}",
        "latency_ms": 125,
        "input_tokens": 100,
        "cached_input_tokens": cached_input_tokens,
        "output_tokens": 25,
        "cost_usd": 0.001,
        "schema_valid": schema_valid,
        "failure_reason": None,
    }


def _all_metrics() -> list[dict[str, object]]:
    return [
        _metric("Prosecutor", "gpt-5.6-luna"),
        _metric("Inspector", "gpt-5.6-terra"),
        _metric("Counsel", "gpt-5.6-terra"),
        _metric("Magistrate", "gpt-5.6-sol"),
        _metric("Bailiff", "gpt-5.6-luna"),
    ]


def test_missing_key_generates_only_an_honest_blocked_gate(tmp_path: Path) -> None:
    output = tmp_path / "real-model-runs.jsonl"

    result = evaluate(
        GateConfiguration(runs=10, fresh_output_required=True, output=output),
        environment={},
    )

    summary = json.loads((tmp_path / "demo-readiness.json").read_text())
    assert result == summary
    assert summary["status"] == "DEMO_READINESS_BLOCKED"
    assert summary["reason"] == "OPENAI_API_KEY_MISSING"
    assert summary["qualifying_runs"] == 0
    assert summary["required_runs"] == 10
    assert summary["run_artifacts"] == []
    assert not output.exists(), "missing credentials must not create substitute run records"


def test_gate_accepts_prompt_cache_hits_but_rejects_incomplete_runs() -> None:
    metrics = _all_metrics()
    metrics[0] = _metric(
        "Prosecutor",
        "gpt-5.6-luna",
        cached_input_tokens=16,
    )

    record = build_run_record(
        run_number=1,
        incident_id="inc_1",
        state="VERIFIED",
        duration_ms=900,
        metrics=metrics,
        case_artifact_path="artifacts/verification/cases/inc_1.zip",
        case_artifact_sha256="a" * 64,
        case_export_verified=True,
        failure_reason=None,
    )

    assert record["qualifying"] is True
    assert record["qualification_failures"] == []
    assert record["aggregate_metrics"]["cached_input_tokens"] == 16
    assert record["prompt_cache_used"] is True

    no_bailiff = build_run_record(
        run_number=2,
        incident_id="inc_2",
        state="VERIFIED",
        duration_ms=900,
        metrics=_all_metrics()[:-1],
        case_artifact_path="artifacts/verification/cases/inc_2.zip",
        case_artifact_sha256="b" * 64,
        case_export_verified=True,
        failure_reason=None,
    )
    assert no_bailiff["qualifying"] is False
    assert "MISSING_REQUIRED_SEAT_METRICS" in no_bailiff["qualification_failures"]


def test_gate_rejects_reused_model_response_even_when_prompt_input_is_cached() -> None:
    metrics = _all_metrics()
    metrics[1]["response_id"] = str(metrics[0]["response_id"])
    metrics[1]["cached_input_tokens"] = 100

    record = build_run_record(
        run_number=1,
        incident_id="inc_reused_response",
        state="VERIFIED",
        duration_ms=900,
        metrics=metrics,
        case_artifact_path="artifacts/verification/cases/inc_reused_response.zip",
        case_artifact_sha256="d" * 64,
        case_export_verified=True,
        failure_reason=None,
    )

    assert record["qualifying"] is False
    assert record["fresh_model_outputs"] is False
    assert record["prompt_cache_used"] is True
    assert "REUSED_MODEL_RESPONSE" in record["qualification_failures"]


def test_gate_accepts_only_verified_uncached_schema_valid_exact_model_run() -> None:
    record = build_run_record(
        run_number=1,
        incident_id="inc_1",
        state="VERIFIED",
        duration_ms=900,
        metrics=_all_metrics(),
        case_artifact_path="artifacts/verification/cases/inc_1.zip",
        case_artifact_sha256="c" * 64,
        case_export_verified=True,
        failure_reason=None,
    )

    assert record["qualifying"] is True
    assert record["qualification_failures"] == []
    assert record["aggregate_metrics"]["schema_valid"] is True
    assert record["aggregate_metrics"]["cached_input_tokens"] == 0


def test_gate_requires_a_verified_signed_case_export() -> None:
    record = build_run_record(
        run_number=1,
        incident_id="inc_unverified_export",
        state="VERIFIED",
        duration_ms=900,
        metrics=_all_metrics(),
        case_artifact_path="artifacts/verification/cases/inc_unverified_export.zip",
        case_artifact_sha256="e" * 64,
        case_export_verified=False,
        failure_reason=None,
    )

    assert record["qualifying"] is False
    assert record["case_export_verified"] is False
    assert "CASE_EXPORT_UNVERIFIED" in record["qualification_failures"]


def test_gate_rejects_response_identity_reuse_across_incident_runs() -> None:
    records = [
        build_run_record(
            run_number=run_number,
            incident_id=f"inc_{run_number}",
            state="VERIFIED",
            duration_ms=900,
            metrics=_all_metrics(),
            case_artifact_path=f"artifacts/verification/cases/inc_{run_number}.zip",
            case_artifact_sha256=("a" if run_number == 1 else "b") * 64,
            case_export_verified=True,
            failure_reason=None,
        )
        for run_number in (1, 2)
    ]

    real_model.enforce_cohort_uniqueness(records)

    assert all(record["qualifying"] is False for record in records)
    assert all(record["fresh_model_outputs"] is False for record in records)
    assert all(
        "REUSED_MODEL_RESPONSE_ACROSS_RUNS" in record["qualification_failures"]
        for record in records
    )


def test_live_run_derives_export_qualification_from_signature_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened_payloads: list[dict[str, object]] = []

    class Response:
        def __init__(self, *, payload=None, content: bytes = b"") -> None:
            self._payload = payload
            self.content = content

        def raise_for_status(self) -> None:
            return None

        def json(self):
            return self._payload

    class Client:
        def request(self, method: str, path: str, **kwargs):
            if method == "POST":
                opened_payloads.append(kwargs["json"])
                return Response(payload={"id": "inc-signed-check", "state": "OPEN"})
            assert path == "/api/incidents/inc-signed-check/room"
            return Response(
                payload={
                    "incident": {"state": "VERIFIED"},
                    "events": [
                        {"type": "MODEL_METRICS_RECORDED", "details": metric}
                        for metric in _all_metrics()
                    ],
                }
            )

        def get(self, path: str):
            assert path == "/api/incidents/inc-signed-check/export"
            return Response(content=b"case-export-bytes")

        def close(self) -> None:
            return None

    monkeypatch.setattr(real_model.httpx, "Client", lambda **_kwargs: Client())
    monkeypatch.setattr(
        real_model,
        "verify_export",
        lambda _case, _key: SimpleNamespace(valid=False),
    )
    client = LiveEvaluationClient(
        api_url="https://crosspatch.test",
        token="operator-token",
        timeout_seconds=30,
        export_public_key=b"k" * 32,
    )

    record = client.run_once(
        GateConfiguration(
            runs=10,
            fresh_output_required=True,
            output=tmp_path / "runs.jsonl",
        ),
        run_number=1,
    )

    assert record["case_export_verified"] is False
    assert record["qualifying"] is False
    assert "CASE_EXPORT_UNVERIFIED" in record["qualification_failures"]
    assert opened_payloads == [{
        "scenario": "webhook-race",
        "title": "Duplicate order-paid delivery",
    }]


def test_live_gate_requires_ten_fresh_output_runs_and_safe_control_url(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least ten"):
        GateConfiguration(runs=9, fresh_output_required=True, output=tmp_path / "runs.jsonl")
    with pytest.raises(ValueError, match="--fresh-output"):
        GateConfiguration(runs=10, fresh_output_required=False, output=tmp_path / "runs.jsonl")
    with pytest.raises(ValueError, match="HTTPS"):
        GateConfiguration(
            runs=10,
            fresh_output_required=True,
            output=tmp_path / "runs.jsonl",
            api_url="http://example.com",
        )


@pytest.mark.parametrize(
    "api_url",
    (
        "http://localhost.evidence.invalid",
        "http://127.0.0.1.evidence.invalid",
        "http://localhost@evidence.invalid",
    ),
)
def test_live_gate_rejects_loopback_prefix_hosts_before_bearer_configuration(
    tmp_path: Path,
    api_url: str,
) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        GateConfiguration(
            runs=10,
            fresh_output_required=True,
            output=tmp_path / "runs.jsonl",
            api_url=api_url,
        )


def test_live_gate_allows_local_development_tls_without_weakening_hosted_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients: list[dict[str, object]] = []

    class _Client:
        def __init__(self, **kwargs):
            clients.append(kwargs)

        def close(self) -> None:
            return None

    monkeypatch.setattr(real_model.httpx, "Client", _Client)

    local = LiveEvaluationClient(
        api_url="https://localhost",
        token="operator-token",
        timeout_seconds=30,
        export_public_key=b"l" * 32,
    )
    hosted = LiveEvaluationClient(
        api_url="https://demo.crosspatch.example",
        token="operator-token",
        timeout_seconds=30,
        export_public_key=b"h" * 32,
    )
    local.close()
    hosted.close()

    assert clients[0]["verify"] is False
    assert clients[1]["verify"] is True
