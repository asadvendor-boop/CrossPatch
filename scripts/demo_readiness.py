#!/usr/bin/env python3
"""Adapt the canonical genuine-model evaluator into claim-map evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import sys
import zipfile
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from crosspatch.evals.real_model import GateConfiguration, evaluate
from crosspatch.export.verifier import verify_export
from verification_lib import (
    ARTIFACT_DIR,
    ROOT,
    atomic_json,
    current_git_sha,
    release_source_sha256,
)

GENERATOR = "scripts/evaluate-demo-readiness.sh"
RUNS_PATH = ARTIFACT_DIR / "real-model-runs.jsonl"
COMMAND = (
    "uv run --frozen --extra dev python -m crosspatch.evals.real_model "
    "--runs {runs} --fresh-output "
    "--output artifacts/verification/real-model-runs.jsonl"
)


class PacedAggregationError(ValueError):
    """A saved paced run failed the genuine-run release contract."""


_EXECUTION_FAILURE_EVENTS = frozenset(
    {
        "BACKGROUND_TASK_FAILED",
        "EXECUTION_FAILED",
        "REPAIR_CYCLE_FAILED",
    }
)


def _audit_case_file(case_bytes: bytes, *, incident_id: str, run_number: int) -> dict[str, Any]:
    """Derive outcome claims from the signed case file, never from model prose."""

    try:
        with zipfile.ZipFile(io.BytesIO(case_bytes)) as archive:
            members = [name for name in archive.namelist() if name.endswith("/case-file.json")]
            if len(members) != 1:
                raise PacedAggregationError("CASE_FILE_MEMBER_INVALID")
            case_file = json.loads(archive.read(members[0]))
    except (KeyError, OSError, zipfile.BadZipFile, json.JSONDecodeError) as error:
        raise PacedAggregationError("CASE_FILE_INVALID") from error

    incident = case_file.get("incident")
    if not isinstance(incident, dict):
        raise PacedAggregationError("CASE_FILE_INCIDENT_INVALID")
    if incident.get("id") != incident_id or incident.get("state") != "VERIFIED":
        raise PacedAggregationError("CASE_FILE_NOT_VERIFIED")

    verdict_rows = case_file.get("verdicts")
    if not isinstance(verdict_rows, list) or not verdict_rows:
        raise PacedAggregationError("CASE_FILE_VERDICTS_INVALID")
    verdicts = [row.get("verdict") for row in verdict_rows if isinstance(row, dict)]
    if len(verdicts) != len(verdict_rows) or verdicts[-1] != "CLEAR":
        raise PacedAggregationError("CASE_FILE_FINAL_VERDICT_NOT_CLEAR")

    event_rows = case_file.get("events")
    if not isinstance(event_rows, list):
        raise PacedAggregationError("CASE_FILE_EVENTS_INVALID")
    event_types = [row.get("type") for row in event_rows if isinstance(row, dict)]
    if len(event_types) != len(event_rows) or "VERIFIED" not in event_types:
        raise PacedAggregationError("CASE_FILE_VERIFICATION_EVENT_MISSING")

    warrants = case_file.get("warrants")
    if not isinstance(warrants, list) or len(warrants) != 1:
        raise PacedAggregationError("CASE_FILE_WARRANT_COUNT_INVALID")
    warrant = warrants[0]
    if not isinstance(warrant, dict) or (
        warrant.get("approval_status"),
        warrant.get("consumption_status"),
        warrant.get("execution_status"),
    ) != ("APPROVED", "CONSUMED", "EXECUTED"):
        raise PacedAggregationError("CASE_FILE_WARRANT_NOT_EXECUTED")
    receipts = warrant.get("receipt_ids")
    if not isinstance(receipts, list) or len(receipts) != 1 or not isinstance(receipts[0], str):
        raise PacedAggregationError("CASE_FILE_RECEIPT_INVALID")

    failure_events = sorted(set(event_types) & _EXECUTION_FAILURE_EVENTS)
    test_failed = "TEST_FAILED" in event_types
    repair_passed = test_failed and "RETRY_STARTED" in event_types and "VERIFIED" in event_types
    return {
        "run_number": run_number,
        "incident_id": incident_id,
        "final_state": incident["state"],
        "verdict_sequence": verdicts,
        "preapproval_remands": verdicts.count("REMAND"),
        "reasoning_escalations": event_types.count("REASONING_ESCALATED"),
        "abstain": "ABSTAIN" in verdicts,
        "execution_failure_events": failure_events,
        "first_patch_failed": test_failed,
        "repair_passed": repair_passed,
        "receipt_id": receipts[0],
    }


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PacedAggregationError("CHECKED_AT_MUST_BE_TIMEZONE_AWARE")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _relative_file(path: Path, *, root: Path) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(resolved_root)
    except ValueError as error:
        raise PacedAggregationError("ARTIFACT_OUTSIDE_ROOT") from error
    if not resolved.is_file():
        raise PacedAggregationError("ARTIFACT_MISSING")
    return relative


def aggregate_paced_records(
    batch: Path,
    *,
    root: Path = ROOT,
    checked_at: datetime | None = None,
) -> dict[str, Any]:
    """Validate ten saved single-incident runs without invoking a model or API."""

    batch = batch.resolve()
    root = root.resolve()
    _relative_file(batch / "local-export-public-key.json", root=root)
    key_payload = json.loads((batch / "local-export-public-key.json").read_bytes())
    try:
        public_key = base64.b64decode(key_payload["public_key_base64"], validate=True)
    except (KeyError, TypeError, ValueError) as error:
        raise PacedAggregationError("PUBLIC_KEY_INVALID") from error

    record_paths = sorted(batch.glob("run-*/real-model-runs.jsonl"))
    if len(record_paths) != 10:
        raise PacedAggregationError("EXPECTED_TEN_PACED_RECORDS")

    records: list[dict[str, Any]] = []
    response_ids: set[str] = set()
    incident_ids: set[str] = set()
    case_audits: list[dict[str, Any]] = []
    signed_exports_valid = 0
    seat_totals: dict[str, dict[str, int | float]] = defaultdict(
        lambda: {
            "calls": 0,
            "input_tokens": 0,
            "cached_input_tokens": 0,
            "output_tokens": 0,
            "latency_ms": 0,
            "cost_usd": 0.0,
            "schema_failures": 0,
        }
    )
    for expected_run, record_path in enumerate(record_paths, 1):
        lines = [line for line in record_path.read_text().splitlines() if line]
        if len(lines) != 1:
            raise PacedAggregationError("ONE_RECORD_PER_PACED_RUN_REQUIRED")
        record = json.loads(lines[0])
        if (
            record.get("run_number") != expected_run
            or record.get("state") != "VERIFIED"
            or record.get("qualifying") is not True
            or record.get("fresh_model_outputs") is not True
            or record.get("qualification_failures") != []
        ):
            raise PacedAggregationError("RUN_NOT_QUALIFYING")
        incident_id = record.get("incident_id")
        if not isinstance(incident_id, str) or incident_id in incident_ids:
            raise PacedAggregationError("INCIDENT_REUSED")
        incident_ids.add(incident_id)

        case_relative = record.get("case_artifact_path")
        if not isinstance(case_relative, str):
            raise PacedAggregationError("CASE_ARTIFACT_MISSING")
        case_path = root / case_relative
        _relative_file(case_path, root=root)
        case_bytes = case_path.read_bytes()
        if hashlib.sha256(case_bytes).hexdigest() != record.get("case_artifact_sha256"):
            raise PacedAggregationError("CASE_ARTIFACT_HASH_MISMATCH")
        verification = verify_export(case_bytes, public_key)
        if not verification.valid:
            raise PacedAggregationError("CASE_EXPORT_SIGNATURE_INVALID")
        signed_exports_valid += 1
        case_audits.append(
            _audit_case_file(
                case_bytes,
                incident_id=incident_id,
                run_number=expected_run,
            )
        )

        metrics = record.get("metrics")
        if not isinstance(metrics, list):
            raise PacedAggregationError("MODEL_METRICS_MISSING")
        for metric in metrics:
            if not isinstance(metric, dict):
                raise PacedAggregationError("MODEL_METRIC_INVALID")
            response_id = metric.get("response_id")
            if not isinstance(response_id, str) or not response_id:
                raise PacedAggregationError("MODEL_RESPONSE_ID_MISSING")
            if response_id in response_ids:
                raise PacedAggregationError("REUSED_MODEL_RESPONSE")
            response_ids.add(response_id)
            seat = metric.get("seat")
            if not isinstance(seat, str) or not seat:
                raise PacedAggregationError("MODEL_SEAT_MISSING")
            totals = seat_totals[seat]
            totals["calls"] += 1
            for name in (
                "input_tokens",
                "cached_input_tokens",
                "output_tokens",
                "latency_ms",
            ):
                value = metric.get(name)
                if not isinstance(value, int) or value < 0:
                    raise PacedAggregationError("MODEL_METRIC_INVALID")
                totals[name] += value
            cost = metric.get("cost_usd")
            if not isinstance(cost, (int, float)) or cost < 0:
                raise PacedAggregationError("MODEL_METRIC_INVALID")
            totals["cost_usd"] += float(cost)
            if metric.get("schema_valid") is not True:
                totals["schema_failures"] += 1
        records.append(record)

    combined = "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
        for record in records
    ).encode("ascii")
    total_input = sum(int(value["input_tokens"]) for value in seat_totals.values())
    total_cached = sum(int(value["cached_input_tokens"]) for value in seat_totals.values())
    report = {
        "batch_id": batch.name,
        "checked_at": _timestamp(checked_at or datetime.now(UTC)),
        "generator": GENERATOR,
        "machine_generated": True,
        "qualifying_runs": 10,
        "pass_rate": 1.0,
        "signed_exports_valid": signed_exports_valid,
        "unique_incident_ids": len(incident_ids) == 10,
        "unique_response_ids": True,
        "schema_failures": sum(int(value["schema_failures"]) for value in seat_totals.values()),
        "total_cost_usd": round(
            sum(float(value["cost_usd"]) for value in seat_totals.values()), 12
        ),
        "cached_input_ratio": 0.0 if total_input == 0 else total_cached / total_input,
        "seat_totals": dict(sorted(seat_totals.items())),
        "incident_ids": [record["incident_id"] for record in records],
        "preapproval_remand_runs": [
            audit["run_number"] for audit in case_audits if audit["preapproval_remands"] > 0
        ],
        "reasoning_escalations": sum(int(audit["reasoning_escalations"]) for audit in case_audits),
        "first_patch_failure_repair_pass_runs": [
            audit["run_number"]
            for audit in case_audits
            if audit["first_patch_failed"] and audit["repair_passed"]
        ],
        "abstain_runs": [audit["run_number"] for audit in case_audits if audit["abstain"]],
        "execution_failure_runs": [
            audit["run_number"] for audit in case_audits if audit["execution_failure_events"]
        ],
        "case_audits": case_audits,
    }
    combined_relative = (batch / "combined-real-model-runs.jsonl").relative_to(root)
    summary = {
        "format": "crosspatch.demo-readiness.v1",
        "status": "DEMO_READY",
        "reason": None,
        "required_runs": 10,
        "requested_runs": 10,
        "qualifying_runs": 10,
        "fresh_model_outputs_required": True,
        "prompt_cache_allowed": True,
        "run_artifacts": [
            {
                "artifact_path": combined_relative.as_posix(),
                "artifact_sha256": hashlib.sha256(combined).hexdigest(),
                "generator": "crosspatch.evals.real_model.LiveEvaluationClient.run_once",
                "provenance": "ten paced genuine-model run records",
            }
        ],
        "generated_at": report["checked_at"],
        "generator": GENERATOR,
        "module_generator": "crosspatch.evals.real_model.LiveEvaluationClient.run_once",
        "module_provenance": "machine-generated from genuine fresh-output end-to-end runs",
        "schema_version": 1,
        "machine_generated": True,
        "source": "OpenAI Responses API run records and signed case exports",
        "command": (
            "scripts/evaluate-demo-readiness.sh --paced-batch-dir "
            f"{batch.relative_to(root).as_posix()}"
        ),
        "checked_at": report["checked_at"],
        "mock_or_substitute_runs": 0,
        "runs_path": combined_relative.as_posix(),
        "batch_id": batch.name,
    }
    return {"combined_records": combined, "report": report, "summary": summary}


def _finalize_paced_batch(
    batch: Path,
    *,
    root: Path,
    summary_path: Path,
    report_path: Path,
    checked_at: str,
) -> None:
    """Atomically close the batch pointers after all gate artifacts exist."""

    manifest_path = batch / "batch-manifest.json"
    current_path = batch.parent / "current.json"
    _relative_file(manifest_path, root=root)
    _relative_file(current_path, root=root)
    _relative_file(summary_path, root=root)
    _relative_file(report_path, root=root)
    manifest = json.loads(manifest_path.read_bytes())
    current = json.loads(current_path.read_bytes())
    for document in (manifest, current):
        if (
            document.get("batch_id") != batch.name
            or document.get("completed_runs") != 10
            or document.get("next_run") is not None
            or document.get("status") != "GATE_AGGREGATING"
        ):
            raise PacedAggregationError("BATCH_MANIFEST_NOT_READY_TO_FINALIZE")

    manifest.update(
        {
            "status": "DEMO_READY",
            "updated_at": checked_at,
            "demo_readiness_path": summary_path.relative_to(root).as_posix(),
            "demo_readiness_sha256": hashlib.sha256(summary_path.read_bytes()).hexdigest(),
            "gate_report_path": report_path.relative_to(root).as_posix(),
            "gate_report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        }
    )
    atomic_json(manifest_path, manifest)
    current.update(
        {
            "status": "DEMO_READY",
            "updated_at": checked_at,
            "batch_manifest_path": manifest_path.relative_to(root).as_posix(),
            "batch_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        }
    )
    atomic_json(current_path, current)


def verify_sealed_paced_batch(batch: Path, *, root: Path = ROOT) -> dict[str, Any]:
    """Revalidate a completed paced batch without changing any artifact bytes."""

    root = root.resolve()
    batch = batch.resolve()
    manifest_path = batch / "batch-manifest.json"
    current_path = batch.parent / "current.json"
    _relative_file(manifest_path, root=root)
    _relative_file(current_path, root=root)
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    current = json.loads(current_path.read_bytes())
    if (
        manifest.get("batch_id") != batch.name
        or manifest.get("status") != "DEMO_READY"
        or manifest.get("completed_runs") != 10
        or manifest.get("requested_runs") != 10
        or manifest.get("next_run") is not None
        or current.get("batch_id") != batch.name
        or current.get("status") != "DEMO_READY"
        or current.get("completed_runs") != 10
        or current.get("next_run") is not None
    ):
        raise PacedAggregationError("SEALED_BATCH_STATE_INVALID")
    if current.get("batch_manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest():
        raise PacedAggregationError("SEALED_BATCH_MANIFEST_HASH_MISMATCH")
    if current.get("batch_manifest_path") != manifest_path.relative_to(root).as_posix():
        raise PacedAggregationError("SEALED_BATCH_MANIFEST_PATH_MISMATCH")

    def bound_file(path_field: str, hash_field: str) -> Path:
        relative = manifest.get(path_field)
        if not isinstance(relative, str):
            raise PacedAggregationError("SEALED_BATCH_BOUND_PATH_INVALID")
        path = root / relative
        _relative_file(path, root=root)
        if manifest.get(hash_field) != hashlib.sha256(path.read_bytes()).hexdigest():
            raise PacedAggregationError("SEALED_BATCH_BOUND_HASH_MISMATCH")
        return path

    summary_path = bound_file("demo_readiness_path", "demo_readiness_sha256")
    report_path = bound_file("gate_report_path", "gate_report_sha256")
    summary = json.loads(summary_path.read_bytes())
    report = json.loads(report_path.read_bytes())
    if summary.get("batch_id") != batch.name or summary.get("status") != "DEMO_READY":
        raise PacedAggregationError("SEALED_BATCH_SUMMARY_INVALID")
    checked_at = datetime.fromisoformat(
        str(report.get("checked_at", "")).replace("Z", "+00:00")
    )
    result = aggregate_paced_records(batch, root=root, checked_at=checked_at)
    combined_path = batch / "combined-real-model-runs.jsonl"
    _relative_file(combined_path, root=root)
    if combined_path.read_bytes() != result["combined_records"]:
        raise PacedAggregationError("SEALED_BATCH_COMBINED_RECORDS_CHANGED")
    if report != result["report"]:
        raise PacedAggregationError("SEALED_BATCH_REPORT_CHANGED")
    expected_summary = {
        **result["summary"],
        "gate_report_path": report_path.relative_to(root).as_posix(),
        "gate_report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
    }
    if summary != expected_summary:
        raise PacedAggregationError("SEALED_BATCH_SUMMARY_CHANGED")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument("--output", type=Path, default=ARTIFACT_DIR / "demo-readiness.json")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--paced-batch-dir", type=Path)
    modes.add_argument("--verify-sealed-batch-dir", type=Path)
    arguments = parser.parse_args()

    if arguments.verify_sealed_batch_dir is not None:
        batch = arguments.verify_sealed_batch_dir
        if not batch.is_absolute():
            batch = ROOT / batch
        try:
            summary = verify_sealed_paced_batch(batch, root=ROOT)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print(json.dumps({"status": "DEMO_READINESS_BLOCKED", "error": str(error)}))
            return 2
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    if arguments.paced_batch_dir is not None:
        batch = arguments.paced_batch_dir
        if not batch.is_absolute():
            batch = ROOT / batch
        batch = batch.resolve()
        try:
            result = aggregate_paced_records(batch, root=ROOT)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print(json.dumps({"status": "DEMO_READINESS_BLOCKED", "error": str(error)}))
            return 2
        combined_path = batch / "combined-real-model-runs.jsonl"
        combined_path.write_bytes(result["combined_records"])
        report_path = batch / "gate-report.json"
        atomic_json(report_path, result["report"])
        summary = {
            **result["summary"],
            "gate_report_path": report_path.relative_to(ROOT).as_posix(),
            "gate_report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
        }
        atomic_json(arguments.output, summary)
        _finalize_paced_batch(
            batch,
            root=ROOT,
            summary_path=arguments.output.resolve(),
            report_path=report_path,
            checked_at=result["report"]["checked_at"],
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    # Never let a previous environment's JSONL be mistaken for this evaluation.
    RUNS_PATH.unlink(missing_ok=True)
    summary = evaluate(
        GateConfiguration(
            runs=arguments.runs,
            fresh_output_required=True,
            output=RUNS_PATH,
        )
    )
    generated_at = str(summary.get("generated_at", ""))
    payload = {
        **summary,
        "schema_version": 1,
        "machine_generated": True,
        "generator": GENERATOR,
        "module_generator": summary.get("generator"),
        "module_provenance": summary.get("provenance"),
        "source": "OpenAI Responses API run records and signed case exports",
        "command": COMMAND.format(runs=arguments.runs),
        "checked_at": generated_at,
        "git_sha": current_git_sha(),
        "mock_or_substitute_runs": 0,
        "runs_path": str(RUNS_PATH.relative_to(ROOT)) if RUNS_PATH.is_file() else None,
        "source_sha256": release_source_sha256(),
    }
    atomic_json(arguments.output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("status") == "DEMO_READY" else 2


if __name__ == "__main__":
    sys.exit(main())
