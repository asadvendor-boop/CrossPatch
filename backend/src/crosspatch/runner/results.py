"""Machine-generated deterministic runner receipts."""

from __future__ import annotations

import hmac
from datetime import UTC, datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

from crosspatch.domain.hashing import byte_sha256, sha256_hex
from crosspatch.runner.catalog import ExecutionPlan


class TrustedObservationCounts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    receipts: int = Field(ge=0, strict=True)
    jobs: int = Field(ge=0, strict=True)
    deliveries: int = Field(ge=0, strict=True)


HttpStatus = Annotated[int, Field(ge=100, le=599, strict=True)]


class TrustedObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    counts: TrustedObservationCounts
    response_statuses: tuple[HttpStatus, ...] = Field(min_length=1, max_length=32)


def trusted_observation_digest(observation: TrustedObservation) -> str:
    return sha256_hex(observation.model_dump(mode="json"))


def validate_trusted_observation_digest(
    observation: TrustedObservation | None,
    digest: str | None,
) -> None:
    if (observation is None) != (digest is None):
        raise ValueError("trusted observation and digest must be present together")
    if observation is not None and digest is not None and not hmac.compare_digest(
        trusted_observation_digest(observation),
        digest,
    ):
        raise ValueError("trusted observation digest mismatch")


class ProcessReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str
    plan_sha256: str
    argv_sha256: str
    exit_code: int | None
    timed_out: bool
    started_at: datetime
    finished_at: datetime
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    supervisor_verified: bool = False
    verification_code: str = "UNSUPERVISED_PROCESS_EXIT"
    verification_sha256: str = "0" * 64
    trusted_observation: TrustedObservation | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    trusted_observation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
        exclude_if=lambda value: value is None,
    )
    runner_request_sha256: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")
    runner_service_identity_sha256: str = Field(
        default="0" * 64, pattern=r"^[0-9a-f]{64}$"
    )
    workspace_provenance_sha256: str = Field(
        default="0" * 64, pattern=r"^[0-9a-f]{64}$"
    )
    job_provenance_sha256: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")
    candidate_executor_boot_sha256: str = Field(
        default="0" * 64, pattern=r"^[0-9a-f]{64}$"
    )
    candidate_executor_replacement_sha256: str = Field(
        default="0" * 64, pattern=r"^[0-9a-f]{64}$"
    )

    @model_validator(mode="after")
    def _trusted_observation_digest_matches(self) -> ProcessReceipt:
        validate_trusted_observation_digest(
            self.trusted_observation,
            self.trusted_observation_sha256,
        )
        return self

    @property
    def passed(self) -> bool:
        return (
            self.supervisor_verified
            and not self.timed_out
            and self.exit_code == 0
        )

    @classmethod
    def for_test(
        cls,
        *,
        plan: ExecutionPlan,
        exit_code: int = 0,
        trusted_observation: TrustedObservation | dict[str, object] | None = None,
    ) -> ProcessReceipt:
        now = datetime.now(UTC)
        observation = (
            None
            if trusted_observation is None
            else TrustedObservation.model_validate(trusted_observation)
        )
        return cls(
            plan_id=plan.plan_id,
            plan_sha256=plan.sha256,
            argv_sha256=sha256_hex(plan.argv),
            exit_code=exit_code,
            timed_out=False,
            started_at=now,
            finished_at=now,
            stdout_sha256=byte_sha256(b""),
            stderr_sha256=byte_sha256(b""),
            stdout_bytes=0,
            stderr_bytes=0,
            supervisor_verified=True,
            verification_code="TEST_SUPERVISOR_VERIFIED",
            verification_sha256="1" * 64,
            trusted_observation=observation,
            trusted_observation_sha256=(
                None if observation is None else trusted_observation_digest(observation)
            ),
        )
