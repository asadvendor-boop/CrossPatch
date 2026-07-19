from __future__ import annotations

from dataclasses import replace

import pytest
from crosspatch.domain.hashing import sha256_hex
from crosspatch.runner.catalog import ExecutionCatalog, OracleProfile
from crosspatch.runner.reproduction import ReproductionOutcome, ReproductionResult
from crosspatch.runner.results import TrustedObservation
from crosspatch.runner.supervisor import (
    BlackBoxVerification,
    CandidateAttempt,
    PostgresHttpBlackBoxVerifier,
    SupervisorChallenge,
    SupervisorPolicyViolation,
    TrustedProcessSupervisor,
)


def _attempt(plan_id: str) -> CandidateAttempt:
    return CandidateAttempt.model_validate(
        {
            "plan_id": plan_id,
            "candidate_uid": 10002,
            "runtime_id": "cp-runtime-123456",
            "pid_namespace_isolated": True,
            "workspace_read_only": True,
            "context_capability_absent": True,
            "external_receipt_authority": True,
            "exit_code": 0,
            "timed_out": False,
            "started_at": "2026-07-16T00:00:00Z",
            "finished_at": "2026-07-16T00:00:01Z",
            "stdout_sha256": "1" * 64,
            "stderr_sha256": "2" * 64,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "teardown_verified": True,
            "executor_boot_sha256": "3" * 64,
            "replacement_boot_sha256": "4" * 64,
        }
    )


def test_black_box_verification_requires_a_matching_observation_digest_pair() -> None:
    observation = TrustedObservation(
        counts={"receipts": 2, "jobs": 3, "deliveries": 4},
        response_statuses=(202, 200, 409),
    )
    base = {
        "verified": True,
        "code": "TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED",
        "observation_sha256": "9" * 64,
        "trusted_observation": observation,
    }

    with pytest.raises(ValueError, match="present together"):
        BlackBoxVerification.model_validate(base)
    with pytest.raises(ValueError, match="trusted observation digest"):
        BlackBoxVerification.model_validate(
            {**base, "trusted_observation_sha256": "0" * 64}
        )


@pytest.mark.asyncio
async def test_http_oracle_rejects_missing_profile_before_database_or_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = PostgresHttpBlackBoxVerifier(
        dsn="postgresql://oracle.invalid/crosspatch",
        victim_url="http://candidate",
    )
    plan = replace(
        ExecutionCatalog.default().resolve("victim.payload-equivalence.candidate"),
        oracle_profile=None,
    )
    monkeypatch.setattr(
        verifier,
        "_clear",
        lambda _event_id: pytest.fail("missing profile reached PostgreSQL"),
    )

    with pytest.raises(SupervisorPolicyViolation, match="trusted HTTP oracle"):
        await verifier.prepare(plan)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("plan_id", "statuses", "profile"),
    [
        (
            "victim.duplicate-race.candidate",
            (202, 200),
            OracleProfile.DUPLICATE_RACE,
        ),
        (
            "victim.payload-equivalence.candidate",
            (202, 200, 409),
            OracleProfile.PAYLOAD_EQUIVALENCE,
        ),
    ],
)
async def test_http_oracle_dispatches_and_hashes_the_bound_profile(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    plan_id: str,
    statuses: tuple[int, ...],
    profile: OracleProfile,
) -> None:
    verifier = PostgresHttpBlackBoxVerifier(
        dsn="postgresql://oracle.invalid/crosspatch",
        victim_url="http://candidate",
    )
    plan = ExecutionCatalog.default().resolve(plan_id)
    captured_hash_input: dict[str, object] = {}
    calls: list[OracleProfile] = []

    monkeypatch.setattr(verifier, "_clear", lambda _event_id: None)
    monkeypatch.setattr(verifier, "_counts", lambda _event_id: (1, 1, 1))

    async def exercise_race(_event_id: str, _secret: str) -> ReproductionResult:
        calls.append(OracleProfile.DUPLICATE_RACE)
        return ReproductionResult(
            outcome=ReproductionOutcome.PASSED,
            lock_state_reached=True,
            counts={"receipts": 1, "jobs": 1, "deliveries": 1},
            response_statuses=statuses,
            diagnostics=(),
        )

    async def exercise_payload(_event_id: str, _secret: str) -> ReproductionResult:
        calls.append(OracleProfile.PAYLOAD_EQUIVALENCE)
        return ReproductionResult(
            outcome=ReproductionOutcome.PASSED,
            lock_state_reached=True,
            counts={"receipts": 1, "jobs": 1, "deliveries": 1},
            response_statuses=statuses,
            diagnostics=(),
        )

    monkeypatch.setattr(verifier, "_exercise_race", exercise_race, raising=False)
    monkeypatch.setattr(
        verifier,
        "_exercise_payload_equivalence",
        exercise_payload,
        raising=False,
    )

    def capture_sha256(value: object) -> str:
        assert isinstance(value, dict)
        captured_hash_input.update(value)
        return "a" * 64

    monkeypatch.setattr("crosspatch.runner.supervisor.sha256_hex", capture_sha256)
    challenge = await verifier.prepare(plan)
    result = await verifier.verify(
        tmp_path,
        plan,
        challenge,
        _attempt(plan.plan_id),
    )

    assert result.verified is True
    assert calls == [profile]
    assert captured_hash_input["oracle_profile"] == profile.value
    assert captured_hash_input["expected_http_statuses"] == plan.expected_statuses
    assert captured_hash_input["http_statuses"] == statuses
    assert result.trusted_observation is not None
    assert result.trusted_observation.model_dump(mode="json") == {
        "counts": {"receipts": 1, "jobs": 1, "deliveries": 1},
        "response_statuses": list(statuses),
    }
    assert result.trusted_observation_sha256 == sha256_hex(
        result.trusted_observation.model_dump(mode="json")
    )


@pytest.mark.asyncio
async def test_supervisor_binds_observation_digest_in_verification_preimage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = tmp_path / "candidate-context.json"
    context.write_text("{}", encoding="utf-8")
    plan = ExecutionCatalog.default().resolve("victim.payload-equivalence.candidate")
    observation = TrustedObservation(
        counts={"receipts": 2, "jobs": 3, "deliveries": 4},
        response_statuses=(202, 200, 409),
    )
    observation_sha256 = sha256_hex(observation.model_dump(mode="json"))
    verification = BlackBoxVerification(
        verified=True,
        code="TRUSTED_HTTP_POSTGRES_INVARIANT_MATCHED",
        observation_sha256="9" * 64,
        trusted_observation=observation,
        trusted_observation_sha256=observation_sha256,
    )

    class Executor:
        candidate_uid = 10002
        pid_namespace_isolated = True
        workspace_read_only = True
        context_capability_absent = True
        external_receipt_authority = True

        async def execute(self, _workspace, _plan, _environment):
            return _attempt(plan.plan_id)

    class Verifier:
        async def prepare(self, _plan):
            return SupervisorChallenge(challenge_id="challenge-bound", environment={})

        async def verify(self, _workspace, _plan, _challenge, _attempt_value):
            return verification

    monkeypatch.setattr(
        "crosspatch.runner.supervisor._snapshot_context",
        lambda *_args, **_kwargs: {"sha256": "1" * 64},
    )
    monkeypatch.setattr(
        "crosspatch.runner.supervisor._snapshot_workspace",
        lambda *_args, **_kwargs: {"manifest_sha256": "2" * 64},
    )
    monkeypatch.setattr(
        "crosspatch.runner.supervisor.load_and_verify_candidate_context",
        lambda *_args, **_kwargs: None,
    )
    captured: list[object] = []

    def capture_sha256(value: object) -> str:
        captured.append(value)
        return sha256_hex(value)

    monkeypatch.setattr("crosspatch.runner.supervisor.sha256_hex", capture_sha256)
    receipt = await TrustedProcessSupervisor(
        executor=Executor(),
        verifier=Verifier(),
        supervisor_uid=10001,
    ).run(workspace, plan)

    preimage = next(
        value for value in captured if isinstance(value, dict) and "attempt" in value
    )
    assert preimage["trusted_observation_sha256"] == observation_sha256
    assert receipt.trusted_observation_sha256 == observation_sha256
    assert receipt.verification_sha256 == sha256_hex(preimage)


@pytest.mark.asyncio
@pytest.mark.parametrize("observed", [None, (1, 2), (-1, 1, 1), (True, 1, 1)])
async def test_http_oracle_omits_observation_when_database_counts_are_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    observed: object,
) -> None:
    verifier = PostgresHttpBlackBoxVerifier(
        dsn="postgresql://oracle.invalid/crosspatch",
        victim_url="http://candidate",
    )
    plan = ExecutionCatalog.default().resolve("victim.duplicate-race.candidate")
    monkeypatch.setattr(verifier, "_clear", lambda _event_id: None)
    monkeypatch.setattr(verifier, "_counts", lambda _event_id: observed)

    async def exercise(_event_id: str, _secret: str) -> ReproductionResult:
        return ReproductionResult(
            outcome=ReproductionOutcome.PASSED,
            lock_state_reached=True,
            counts={"receipts": 1, "jobs": 1, "deliveries": 1},
            response_statuses=(202, 200),
            diagnostics=(),
        )

    monkeypatch.setattr(verifier, "_exercise_race", exercise, raising=False)
    challenge = await verifier.prepare(plan)

    result = await verifier.verify(
        tmp_path,
        plan,
        challenge,
        _attempt(plan.plan_id),
    )

    assert result.verified is False
    assert result.code == "TRUSTED_HTTP_POSTGRES_INVARIANT_MISMATCH"
    assert result.trusted_observation is None
    assert result.trusted_observation_sha256 is None
