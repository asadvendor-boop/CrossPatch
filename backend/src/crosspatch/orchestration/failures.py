"""Closed model/SDK failure taxonomy used by fail-closed coordination."""

from __future__ import annotations

from agents.exceptions import (
    InputGuardrailTripwireTriggered,
    ModelBehaviorError,
    ModelRefusalError,
    OutputGuardrailTripwireTriggered,
    ToolInputGuardrailTripwireTriggered,
    ToolOutputGuardrailTripwireTriggered,
)
from openai import APIConnectionError, APITimeoutError


class OrchestrationFailure(RuntimeError):
    reason = "sdk_exception"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.reason)


class ModelRefusal(OrchestrationFailure):
    reason = "refusal"


class OutputCutoff(OrchestrationFailure):
    reason = "cutoff"


class TruncatedResponse(OrchestrationFailure):
    reason = "truncated"


class IncompleteResponse(OrchestrationFailure):
    reason = "incomplete_response"


class NetworkFailure(OrchestrationFailure):
    reason = "network_failure"


class InvalidSchema(OrchestrationFailure):
    reason = "invalid_schema"


class MissingEvidenceReference(OrchestrationFailure):
    reason = "missing_evidence_references"


class SDKException(OrchestrationFailure):
    reason = "sdk_exception"


class GuardrailStop(OrchestrationFailure):
    reason = "guardrail_stop"


class UnknownVerdict(OrchestrationFailure):
    reason = "unknown_verdict"

    def __init__(self, verdict: str) -> None:
        self.verdict = verdict
        super().__init__(f"unknown verdict: {verdict}")


class EscalationFailure(OrchestrationFailure):
    reason = "escalation_exhausted"


_GUARDRAIL_ERRORS = (
    InputGuardrailTripwireTriggered,
    OutputGuardrailTripwireTriggered,
    ToolInputGuardrailTripwireTriggered,
    ToolOutputGuardrailTripwireTriggered,
)


def failure_reason(error: Exception) -> str:
    if isinstance(error, OrchestrationFailure):
        return error.reason
    if isinstance(error, (TimeoutError, APITimeoutError)):
        return "timeout"
    if isinstance(error, APIConnectionError):
        return "network_failure"
    if isinstance(error, ModelRefusalError):
        return "refusal"
    if isinstance(error, _GUARDRAIL_ERRORS):
        return "guardrail_stop"
    if isinstance(error, ModelBehaviorError):
        return "invalid_schema"
    return "sdk_exception"
