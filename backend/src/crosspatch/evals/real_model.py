"""Strict genuine-model release gate.

The evaluator drives the real control API and waits for the normal human
approval flow. It never approves a warrant, fabricates a case export, or
counts a replayed/partial run. Prompt-cache reads are metered separately from
fresh model output. Missing credentials are an expected blocked state and
produce only the aggregate blocked artifact.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from crosspatch.export.verifier import verify_export
from crosspatch.url_policy import validated_control_url

MINIMUM_GENUINE_RUNS = 10
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_EXPECTED_MODELS = {
    "Prosecutor": "gpt-5.6-luna",
    "Inspector": "gpt-5.6-terra",
    "Counsel": "gpt-5.6-terra",
    "Magistrate": "gpt-5.6-sol",
    "Bailiff": "gpt-5.6-luna",
}
_TERMINAL_STATES = frozenset({"VERIFIED", "BLOCKED", "HUMAN_ESCALATION"})


@dataclass(frozen=True, slots=True)
class GateConfiguration:
    runs: int
    fresh_output_required: bool
    output: Path
    api_url: str | None = None
    timeout_seconds: float = 1_800.0
    poll_seconds: float = 1.0

    def __post_init__(self) -> None:
        if self.runs < MINIMUM_GENUINE_RUNS:
            raise ValueError("the demo gate requires at least ten genuine runs")
        if not self.fresh_output_required:
            raise ValueError("the demo gate requires --fresh-output")
        if self.output.suffix != ".jsonl":
            raise ValueError("real-model run output must be JSONL")
        if self.timeout_seconds <= 0 or self.poll_seconds <= 0:
            raise ValueError("evaluation timeouts must be positive")
        if self.api_url is not None:
            _validate_api_url(self.api_url)


class LiveEvaluationError(RuntimeError):
    """A real local runtime failed before it could yield a qualifying run."""


def _validate_api_url(value: str) -> str:
    return validated_control_url(value)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _atomic_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(value)
        temporary.chmod(0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _artifact_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _blocked_summary(
    configuration: GateConfiguration,
    *,
    reason: str,
    qualifying_runs: int = 0,
    run_artifacts: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    return {
        "format": "crosspatch.demo-readiness.v1",
        "status": "DEMO_READINESS_BLOCKED",
        "reason": reason,
        "required_runs": MINIMUM_GENUINE_RUNS,
        "requested_runs": configuration.runs,
        "qualifying_runs": qualifying_runs,
        "fresh_model_outputs_required": True,
        "prompt_cache_allowed": True,
        "run_artifacts": list(run_artifacts),
        "generated_at": _utc_now(),
        "generator": "python -m crosspatch.evals.real_model",
        "provenance": "machine-generated from the genuine-model release gate",
    }


def _write_summary(configuration: GateConfiguration, summary: dict[str, Any]) -> None:
    target = configuration.output.with_name("demo-readiness.json")
    _atomic_write(target, (_canonical_json(summary) + "\n").encode("ascii"))


def _is_nonnegative_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0


def _metric_failures(metrics: Sequence[Mapping[str, object]]) -> list[str]:
    failures: set[str] = set()
    seen: dict[str, str] = {}
    response_ids: set[str] = set()
    if not metrics:
        failures.add("MISSING_MODEL_METRICS")
    for metric in metrics:
        seat = metric.get("seat")
        model = metric.get("model")
        if not isinstance(seat, str) or not isinstance(model, str):
            failures.add("INVALID_MODEL_METRICS")
            continue
        seen[seat] = model
        if seat not in _EXPECTED_MODELS or _EXPECTED_MODELS[seat] != model:
            failures.add("MODEL_POLICY_MISMATCH")
        response_id = metric.get("response_id")
        if not isinstance(response_id, str) or not response_id.startswith("resp_"):
            failures.add("MISSING_RESPONSE_ID")
        elif response_id in response_ids:
            failures.add("REUSED_MODEL_RESPONSE")
        else:
            response_ids.add(response_id)
        if not _is_nonnegative_number(metric.get("cost_usd")):
            failures.add("MISSING_COST_METRICS")
        latency = metric.get("latency_ms")
        if not _is_nonnegative_number(latency) or latency == 0:
            failures.add("MISSING_LATENCY_METRICS")
        for name in ("input_tokens", "cached_input_tokens", "output_tokens"):
            value = metric.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                failures.add("INVALID_TOKEN_METRICS")
        if metric.get("schema_valid") is not True:
            failures.add("SCHEMA_INVALID")
        if metric.get("failure_reason") is not None:
            failures.add("MODEL_FAILURE_RECORDED")
    if any(seen.get(seat) != model for seat, model in _EXPECTED_MODELS.items()):
        failures.add("MISSING_REQUIRED_SEAT_METRICS")
    return sorted(failures)


def build_run_record(
    *,
    run_number: int,
    incident_id: str,
    state: str,
    duration_ms: int,
    metrics: Sequence[Mapping[str, object]],
    case_artifact_path: str | None,
    case_artifact_sha256: str | None,
    case_export_verified: bool,
    failure_reason: str | None,
) -> dict[str, Any]:
    """Build one qualifying decision from observed, externally persisted facts."""

    failures = set(_metric_failures(metrics))
    if state != "VERIFIED":
        failures.add("INCIDENT_NOT_VERIFIED")
    if duration_ms <= 0:
        failures.add("MISSING_END_TO_END_LATENCY")
    if not case_artifact_path or not case_artifact_sha256:
        failures.add("MISSING_CASE_ARTIFACT")
    elif not _SHA256.fullmatch(case_artifact_sha256):
        failures.add("INVALID_CASE_ARTIFACT_HASH")
    if case_export_verified is not True:
        failures.add("CASE_EXPORT_UNVERIFIED")
    if failure_reason is not None:
        failures.add("RUN_FAILURE_RECORDED")

    total_cost = sum(
        float(metric["cost_usd"])
        for metric in metrics
        if _is_nonnegative_number(metric.get("cost_usd"))
    )
    cached_tokens = sum(
        int(metric["cached_input_tokens"])
        for metric in metrics
        if isinstance(metric.get("cached_input_tokens"), int)
        and not isinstance(metric.get("cached_input_tokens"), bool)
        and int(metric["cached_input_tokens"]) >= 0
    )
    ordered_failures = sorted(failures)
    return {
        "format": "crosspatch.real-model-run.v1",
        "run_number": run_number,
        "incident_id": incident_id,
        "state": state,
        "duration_ms": duration_ms,
        "fresh_model_outputs": "REUSED_MODEL_RESPONSE" not in failures,
        "prompt_cache_used": cached_tokens > 0,
        "metrics": [dict(metric) for metric in metrics],
        "aggregate_metrics": {
            "cost_usd": round(total_cost, 12),
            "cached_input_tokens": cached_tokens,
            "schema_valid": not any(
                failure in failures
                for failure in ("SCHEMA_INVALID", "INVALID_MODEL_METRICS")
            ),
            "failure_count": sum(
                1 for metric in metrics if metric.get("failure_reason") is not None
            ),
        },
        "case_artifact_path": case_artifact_path,
        "case_artifact_sha256": case_artifact_sha256,
        "case_export_verified": case_export_verified,
        "failure_reason": failure_reason,
        "qualification_failures": ordered_failures,
        "qualifying": not ordered_failures,
        "generated_at": _utc_now(),
        "generator": "crosspatch.evals.real_model",
        "provenance": "machine-generated from API state, model usage, and signed case export",
    }


def enforce_cohort_uniqueness(records: list[dict[str, Any]]) -> None:
    """Disqualify every run sharing a model response identity with another run."""
    locations: dict[str, set[int]] = {}
    for index, record in enumerate(records):
        metrics = record.get("metrics")
        if not isinstance(metrics, list):
            continue
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            response_id = metric.get("response_id")
            if isinstance(response_id, str) and response_id:
                locations.setdefault(response_id, set()).add(index)

    affected = {
        index
        for indexes in locations.values()
        if len(indexes) > 1
        for index in indexes
    }
    for index in affected:
        record = records[index]
        failures = set(record.get("qualification_failures", ()))
        failures.add("REUSED_MODEL_RESPONSE_ACROSS_RUNS")
        record["qualification_failures"] = sorted(failures)
        record["fresh_model_outputs"] = False
        record["qualifying"] = False


def _extract_metrics(room: Mapping[str, Any]) -> list[dict[str, object]]:
    metrics: list[dict[str, object]] = []
    events = room.get("events", [])
    if not isinstance(events, list):
        return metrics
    for event in events:
        if not isinstance(event, dict) or event.get("type") != "MODEL_METRICS_RECORDED":
            continue
        details = event.get("details")
        if isinstance(details, dict):
            metrics.append(dict(details))
    return metrics


class LiveEvaluationClient:
    """Drive only public control-plane operations; approval remains human-owned."""

    def __init__(
        self,
        *,
        api_url: str,
        token: str,
        timeout_seconds: float,
        export_public_key: bytes,
    ) -> None:
        self._api_url = _validate_api_url(api_url)
        if not token.strip():
            raise ValueError("CROSSPATCH_TOKEN is required for genuine evaluation")
        if len(export_public_key) != 32:
            raise ValueError("CrossPatch export public key must contain 32 bytes")
        self._export_public_key = export_public_key
        parsed = urlparse(self._api_url)
        local_development_tls = parsed.scheme == "https" and parsed.hostname in {
            "localhost",
            "127.0.0.1",
            "::1",
        }
        self._http = httpx.Client(
            base_url=self._api_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=httpx.Timeout(min(timeout_seconds, 30.0)),
            follow_redirects=False,
            verify=not local_development_tls,
        )

    def close(self) -> None:
        self._http.close()

    def _json(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        response = self._http.request(method, path, **kwargs)
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict):
            raise LiveEvaluationError("control API returned a non-object payload")
        return value

    def run_once(
        self,
        configuration: GateConfiguration,
        *,
        run_number: int,
    ) -> dict[str, Any]:
        started = time.monotonic()
        opened = self._json(
            "POST",
            "/api/incidents",
            json={
                "scenario": "webhook-race",
                "title": "Duplicate order-paid delivery",
            },
            headers={"X-CrossPatch-Eval-Mode": "fresh-output"},
        )
        incident_id = opened.get("id")
        if not isinstance(incident_id, str):
            raise LiveEvaluationError("incident creation omitted its identifier")

        deadline = started + configuration.timeout_seconds
        room: dict[str, Any] = {}
        state = str(opened.get("state", "OPEN"))
        while time.monotonic() < deadline:
            room = self._json("GET", f"/api/incidents/{incident_id}/room")
            incident = room.get("incident")
            if not isinstance(incident, dict):
                raise LiveEvaluationError("incident room omitted incident state")
            state = str(incident.get("state", "UNKNOWN"))
            if state in _TERMINAL_STATES:
                break
            time.sleep(configuration.poll_seconds)

        failure_reason: str | None = None
        case_path: str | None = None
        case_sha256: str | None = None
        case_export_verified = False
        if state == "VERIFIED":
            response = self._http.get(f"/api/incidents/{incident_id}/export")
            response.raise_for_status()
            case_bytes = response.content
            case_file = configuration.output.parent / "real-model-cases" / f"{incident_id}.zip"
            _atomic_write(case_file, case_bytes)
            case_path = _artifact_path(case_file)
            case_sha256 = hashlib.sha256(case_bytes).hexdigest()
            case_export_verified = verify_export(
                case_bytes,
                self._export_public_key,
            ).valid
        elif state == "APPROVAL_PENDING":
            failure_reason = "HUMAN_APPROVAL_TIMEOUT"
        elif state not in _TERMINAL_STATES:
            failure_reason = "INCIDENT_TIMEOUT"
        else:
            failure_reason = f"TERMINAL_{state}"

        return build_run_record(
            run_number=run_number,
            incident_id=incident_id,
            state=state,
            duration_ms=max(1, round((time.monotonic() - started) * 1000)),
            metrics=_extract_metrics(room),
            case_artifact_path=case_path,
            case_artifact_sha256=case_sha256,
            case_export_verified=case_export_verified,
            failure_reason=failure_reason,
        )


def _load_export_public_key(
    configuration: GateConfiguration,
    environment: Mapping[str, str],
) -> bytes | None:
    configured = environment.get("CROSSPATCH_EXPORT_PUBLIC_KEY_PATH", "").strip()
    path = (
        Path(configured)
        if configured
        else configuration.output.parent / "export-public-key.json"
    )
    if not path.is_absolute():
        path = Path.cwd() / path
    try:
        payload = json.loads(path.read_bytes())
        public_key = base64.b64decode(payload["public_key_base64"], validate=True)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, binascii.Error):
        return None
    return public_key if len(public_key) == 32 else None


def evaluate(
    configuration: GateConfiguration,
    *,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Evaluate the release gate without ever manufacturing qualifying runs."""

    values = dict(os.environ if environment is None else environment)
    if not values.get("OPENAI_API_KEY", "").strip():
        summary = _blocked_summary(configuration, reason="OPENAI_API_KEY_MISSING")
        _write_summary(configuration, summary)
        return summary

    api_url = configuration.api_url or values.get("CROSSPATCH_API_URL", "")
    token = values.get("CROSSPATCH_TOKEN", "")
    if not api_url or not token:
        summary = _blocked_summary(
            configuration,
            reason="LOCAL_RUNTIME_CONFIGURATION_MISSING",
        )
        _write_summary(configuration, summary)
        return summary

    export_public_key = _load_export_public_key(configuration, values)
    if export_public_key is None:
        summary = _blocked_summary(
            configuration,
            reason="EXPORT_PUBLIC_KEY_MISSING_OR_INVALID",
        )
        _write_summary(configuration, summary)
        return summary

    records: list[dict[str, Any]] = []
    client = LiveEvaluationClient(
        api_url=api_url,
        token=token,
        timeout_seconds=configuration.timeout_seconds,
        export_public_key=export_public_key,
    )
    try:
        for run_number in range(1, configuration.runs + 1):
            try:
                record = client.run_once(configuration, run_number=run_number)
            except Exception as error:
                record = build_run_record(
                    run_number=run_number,
                    incident_id=f"run-error-{run_number}",
                    state="ERROR",
                    duration_ms=1,
                    metrics=(),
                    case_artifact_path=None,
                    case_artifact_sha256=None,
                    case_export_verified=False,
                    failure_reason=type(error).__name__,
                )
            records.append(record)
    finally:
        client.close()

    enforce_cohort_uniqueness(records)

    encoded = "".join(_canonical_json(record) + "\n" for record in records).encode("ascii")
    _atomic_write(configuration.output, encoded)
    output_artifact = {
        "artifact_path": _artifact_path(configuration.output),
        "artifact_sha256": hashlib.sha256(encoded).hexdigest(),
        "generator": "crosspatch.evals.real_model",
        "provenance": "machine-generated genuine-model run records",
    }
    qualifying = sum(1 for record in records if record["qualifying"] is True)
    if qualifying >= MINIMUM_GENUINE_RUNS:
        summary = {
            "format": "crosspatch.demo-readiness.v1",
            "status": "DEMO_READY",
            "reason": None,
            "required_runs": MINIMUM_GENUINE_RUNS,
            "requested_runs": configuration.runs,
            "qualifying_runs": qualifying,
            "fresh_model_outputs_required": True,
            "prompt_cache_allowed": True,
            "run_artifacts": [output_artifact],
            "generated_at": _utc_now(),
            "generator": "python -m crosspatch.evals.real_model",
            "provenance": "machine-generated from genuine fresh-output end-to-end runs",
        }
    else:
        summary = _blocked_summary(
            configuration,
            reason="INSUFFICIENT_QUALIFYING_RUNS",
            qualifying_runs=qualifying,
            run_artifacts=(output_artifact,),
        )
    _write_summary(configuration, summary)
    return summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate genuine CrossPatch model runs")
    parser.add_argument("--runs", type=int, required=True)
    parser.add_argument(
        "--fresh-output",
        action="store_true",
        help="require distinct real model response IDs; prompt-cache input reads remain allowed",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--api-url")
    parser.add_argument("--timeout-seconds", type=float, default=1_800.0)
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    configuration = GateConfiguration(
        runs=arguments.runs,
        fresh_output_required=arguments.fresh_output,
        output=arguments.output,
        api_url=arguments.api_url,
        timeout_seconds=arguments.timeout_seconds,
        poll_seconds=arguments.poll_seconds,
    )
    result = evaluate(configuration)
    print(_canonical_json(result))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
