from __future__ import annotations

import base64
import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from crosspatch.evals.real_model import build_run_record
from crosspatch.export.builder import CaseBinding, CaseExportBuilder, ExportArtifact
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[3]


def _module() -> Any:
    path = ROOT / "scripts" / "demo_readiness.py"
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("crosspatch_demo_readiness", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def _metric(seat: str, model: str, response_id: str) -> dict[str, object]:
    return {
        "seat": seat,
        "model": model,
        "effort": "none" if seat == "Bailiff" else "medium",
        "response_id": response_id,
        "latency_ms": 100,
        "input_tokens": 100,
        "cached_input_tokens": 16,
        "output_tokens": 20,
        "cost_usd": 0.001,
        "schema_valid": True,
        "failure_reason": None,
    }


def _paced_batch(tmp_path: Path, *, duplicate_response: bool = False) -> Path:
    batch = tmp_path / "batch"
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    batch.mkdir()
    (batch / "batch-manifest.json").write_text(
        json.dumps(
            {
                "batch_id": batch.name,
                "completed_runs": 10,
                "next_run": None,
                "requested_runs": 10,
                "status": "GATE_AGGREGATING",
                "machine_generated": True,
            }
        )
    )
    (tmp_path / "current.json").write_text(
        json.dumps(
            {
                "batch_id": batch.name,
                "completed_runs": 10,
                "next_run": None,
                "status": "GATE_AGGREGATING",
                "machine_generated": True,
            }
        )
    )
    (batch / "local-export-public-key.json").write_text(
        json.dumps({"public_key_base64": base64.b64encode(public).decode("ascii")})
    )
    builder = CaseExportBuilder(key)
    seats = (
        ("Prosecutor", "gpt-5.6-luna"),
        ("Inspector", "gpt-5.6-terra"),
        ("Counsel", "gpt-5.6-terra"),
        ("Magistrate", "gpt-5.6-sol"),
        ("Bailiff", "gpt-5.6-luna"),
    )
    for run_number in range(1, 11):
        incident_id = f"inc_{run_number}"
        remanded = run_number in {1, 4}
        case_file = {
            "incident": {"id": incident_id, "state": "VERIFIED"},
            "events": [
                {"type": "REASONING_ESCALATED"}
                for _ in range(2 if run_number == 4 else int(remanded))
            ]
            + [{"type": "VERIFIED"}],
            "verdicts": (
                ([{"verdict": "REMAND"}] * (2 if run_number == 4 else 1)) if remanded else []
            )
            + [{"verdict": "CLEAR"}],
            "warrants": [
                {
                    "approval_status": "APPROVED",
                    "consumption_status": "CONSUMED",
                    "execution_status": "EXECUTED",
                    "receipt_ids": [f"test_{run_number}"],
                }
            ],
            "seats": [],
        }
        archive = builder.build(
            CaseBinding(
                incident_id=incident_id,
                base_sha="a" * 40,
                verdict_sha256="b" * 64,
                warrant_sha256="c" * 64,
                receipt_sha256="d" * 64,
                timeline_head="e" * 64,
            ),
            (
                ExportArtifact(
                    path="case-file.json",
                    incident_id=incident_id,
                    kind="timeline",
                    data=json.dumps(case_file).encode(),
                    provenance="unit-test generated case file",
                ),
            ),
        )
        case_path = tmp_path / "cases" / f"{incident_id}.zip"
        case_path.parent.mkdir(exist_ok=True)
        case_path.write_bytes(archive)
        metrics = [
            _metric(
                seat,
                model,
                "resp_duplicate"
                if duplicate_response and run_number == 10 and seat == "Prosecutor"
                else f"resp_{run_number}_{seat.casefold()}",
            )
            for seat, model in seats
        ]
        if duplicate_response and run_number == 1:
            metrics[0]["response_id"] = "resp_duplicate"
        record = build_run_record(
            run_number=run_number,
            incident_id=incident_id,
            state="VERIFIED",
            duration_ms=1_000,
            metrics=metrics,
            case_artifact_path=case_path.relative_to(tmp_path).as_posix(),
            case_artifact_sha256=__import__("hashlib").sha256(archive).hexdigest(),
            case_export_verified=True,
            failure_reason=None,
        )
        run_dir = batch / f"run-{run_number:02d}"
        run_dir.mkdir()
        (run_dir / "real-model-runs.jsonl").write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        )
    return batch


def test_paced_aggregation_accepts_ten_fresh_signed_qualifying_runs(tmp_path: Path) -> None:
    module = _module()
    batch = _paced_batch(tmp_path)

    result = module.aggregate_paced_records(
        batch,
        root=tmp_path,
        checked_at=datetime(2026, 7, 14, tzinfo=UTC),
    )

    assert result["summary"]["status"] == "DEMO_READY"
    assert result["summary"]["qualifying_runs"] == 10
    assert result["summary"]["mock_or_substitute_runs"] == 0
    assert result["report"]["signed_exports_valid"] == 10
    assert result["report"]["unique_response_ids"] is True
    assert result["report"]["pass_rate"] == 1.0
    assert result["report"]["preapproval_remand_runs"] == [1, 4]
    assert result["report"]["reasoning_escalations"] == 3
    assert result["report"]["first_patch_failure_repair_pass_runs"] == []
    assert result["report"]["abstain_runs"] == []
    assert result["report"]["execution_failure_runs"] == []
    assert len(result["combined_records"].splitlines()) == 10


def test_paced_aggregation_rejects_response_reuse_across_runs(tmp_path: Path) -> None:
    module = _module()
    batch = _paced_batch(tmp_path, duplicate_response=True)

    with pytest.raises(module.PacedAggregationError, match="REUSED_MODEL_RESPONSE"):
        module.aggregate_paced_records(
            batch,
            root=tmp_path,
            checked_at=datetime(2026, 7, 14, tzinfo=UTC),
        )


def test_paced_cli_accepts_a_relative_batch_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    _paced_batch(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    output = tmp_path / "demo-readiness.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "demo_readiness.py",
            "--paced-batch-dir",
            "batch",
            "--output",
            str(output),
        ],
    )

    assert module.main() == 0
    assert json.loads(output.read_text())["status"] == "DEMO_READY"
    manifest = json.loads((tmp_path / "batch" / "batch-manifest.json").read_text())
    current = json.loads((tmp_path / "current.json").read_text())
    assert manifest["status"] == "DEMO_READY"
    assert current["status"] == "DEMO_READY"
    assert (
        current["batch_manifest_sha256"]
        == __import__("hashlib")
        .sha256((tmp_path / "batch" / "batch-manifest.json").read_bytes())
        .hexdigest()
    )


def test_completed_paced_batch_cannot_be_finalized_or_rewritten_again(
    tmp_path: Path,
) -> None:
    module = _module()
    batch = _paced_batch(tmp_path)
    summary = tmp_path / "demo-readiness.json"
    report = batch / "gate-report.json"
    summary.write_text("{}\n")
    report.write_text("{}\n")
    manifest_path = batch / "batch-manifest.json"
    current_path = tmp_path / "current.json"
    for path in (manifest_path, current_path):
        payload = json.loads(path.read_text())
        payload["status"] = "DEMO_READY"
        path.write_text(json.dumps(payload, sort_keys=True) + "\n")
    before = {path: path.read_bytes() for path in (manifest_path, current_path)}

    with pytest.raises(module.PacedAggregationError, match="NOT_READY_TO_FINALIZE"):
        module._finalize_paced_batch(
            batch,
            root=tmp_path,
            summary_path=summary,
            report_path=report,
            checked_at="2026-07-14T12:00:00Z",
        )

    assert {path: path.read_bytes() for path in before} == before


def test_sealed_paced_batch_verification_is_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    _paced_batch(tmp_path)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    output = tmp_path / "demo-readiness.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "demo_readiness.py",
            "--paced-batch-dir",
            "batch",
            "--output",
            str(output),
        ],
    )
    assert module.main() == 0
    before = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    monkeypatch.setattr(
        sys,
        "argv",
        ["demo_readiness.py", "--verify-sealed-batch-dir", "batch"],
    )
    assert module.main() == 0

    after = {
        path.relative_to(tmp_path): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    assert after == before
