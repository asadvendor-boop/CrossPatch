"""Closed enums shared by orchestration, storage, and UI contracts."""

from enum import StrEnum
from typing import Literal

ScenarioId = Literal["webhook-race", "webhook-payload-equivalence"]


class Seat(StrEnum):
    PROSECUTOR = "Prosecutor"
    INSPECTOR = "Inspector"
    COUNSEL = "Counsel"
    MAGISTRATE = "Magistrate"
    BAILIFF = "Bailiff"


class Effort(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"


class Verdict(StrEnum):
    CLEAR = "CLEAR"
    REMAND = "REMAND"
    BLOCK = "BLOCK"
    ABSTAIN = "ABSTAIN"


class IncidentState(StrEnum):
    OPEN = "OPEN"
    REPRODUCING = "REPRODUCING"
    EVIDENCE_READY = "EVIDENCE_READY"
    ANALYZING = "ANALYZING"
    PATCHING = "PATCHING"
    REVIEWING = "REVIEWING"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    TEST_FAILED = "TEST_FAILED"
    VERIFIED = "VERIFIED"
    BLOCKED = "BLOCKED"
    HUMAN_ESCALATION = "HUMAN_ESCALATION"


class RetryDisposition(StrEnum):
    MATERIAL = "MATERIAL"
    FAILED_RETRY_DUPLICATE = "FAILED_RETRY_DUPLICATE"


class MechanismCode(StrEnum):
    CHECK_THEN_INSERT_RACE = "CHECK_THEN_INSERT_RACE"
    LATE_RECEIPT_WRITE = "LATE_RECEIPT_WRITE"
    WORKER_RETRY_DUPLICATION = "WORKER_RETRY_DUPLICATION"
    PAYLOAD_ID_COLLISION = "PAYLOAD_ID_COLLISION"
