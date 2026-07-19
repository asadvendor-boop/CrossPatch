from __future__ import annotations

import pytest
from crosspatch.agents.schemas import CounselOutput
from crosspatch.agents.schemas import TestIntention as AgentTestIntention
from crosspatch.domain.enums import Effort, Seat
from crosspatch.orchestration.escalation import (
    ESCALATION_EXPLANATION,
    DuplicateRetry,
    EscalationExhausted,
    EscalationTracker,
)


def counsel(diff: str, purpose: str = "prove idempotency") -> CounselOutput:
    return CounselOutput(
        normalized_diff=diff,
        test_intentions=(AgentTestIntention(catalog_id="victim.contract", purpose=purpose),),
        evidence_ids=("ev-1",),
    )


def test_remand_escalates_one_level_and_logs_the_exact_explanation() -> None:
    tracker = EscalationTracker()
    initial = counsel("--- a/a\n+++ b/a\n@@\n-old\n+new\n")
    tracker.record_initial("inc-1", Seat.COUNSEL, initial)

    decision = tracker.begin_escalation("inc-1", Seat.COUNSEL, reason="remand")
    tracker.accept_retry(
        "inc-1",
        Seat.COUNSEL,
        counsel("--- a/a\n+++ b/a\n@@\n-old\n+safer\n"),
    )

    assert decision.effort is Effort.HIGH
    assert decision.escalation_count == 1
    assert decision.explanation == ESCALATION_EXPLANATION
    assert ESCALATION_EXPLANATION == (
        "The room only thinks harder when the judge is unsatisfied."
    )


def test_paraphrase_only_retry_is_rejected_as_semantically_duplicate() -> None:
    tracker = EscalationTracker()
    initial = {
        "mechanism": "check then insert",
        "evidence_ids": ["ev-1"],
        "falsifiers": ["serialized delivery"],
    }
    tracker.record_initial("inc-1", Seat.INSPECTOR, initial)
    tracker.begin_escalation("inc-1", Seat.INSPECTOR, reason="test_failure")

    with pytest.raises(DuplicateRetry):
        tracker.accept_retry(
            "inc-1",
            Seat.INSPECTOR,
            {
                "mechanism": "insert only after checking",
                "evidence_ids": ["ev-1"],
                "falsifiers": ["serialized delivery"],
            },
        )


def test_agent_has_at_most_two_escalations_then_requires_human() -> None:
    tracker = EscalationTracker()
    tracker.record_initial("inc-1", Seat.INSPECTOR, {"mechanism": "a"})

    first = tracker.begin_escalation("inc-1", Seat.INSPECTOR, reason="remand")
    tracker.accept_retry("inc-1", Seat.INSPECTOR, {"mechanism": "b"})
    second = tracker.begin_escalation("inc-1", Seat.INSPECTOR, reason="remand")
    tracker.accept_retry("inc-1", Seat.INSPECTOR, {"mechanism": "c"})

    assert (first.effort, second.effort) == (Effort.HIGH, Effort.XHIGH)
    with pytest.raises(EscalationExhausted):
        tracker.begin_escalation("inc-1", Seat.INSPECTOR, reason="remand")


def test_restart_resumes_reserved_escalation_without_spending_another_level() -> None:
    tracker = EscalationTracker()
    initial = counsel("--- a/a\n+++ b/a\n@@\n-old\n+new\n")
    tracker.restore(
        "inc-1",
        Seat.COUNSEL,
        initial,
        effort=Effort.HIGH,
        escalation_count=1,
        retry_pending=True,
        pending_reason="test_failure",
    )

    resumed = tracker.resume_pending_escalation(
        "inc-1",
        Seat.COUNSEL,
        reason="test_failure",
    )

    assert (resumed.effort, resumed.escalation_count) == (Effort.HIGH, 1)


def test_bailiff_never_escalates() -> None:
    tracker = EscalationTracker()
    tracker.record_initial("inc-1", Seat.BAILIFF, {"warrant_id": "w-1"})
    with pytest.raises(EscalationExhausted):
        tracker.begin_escalation("inc-1", Seat.BAILIFF, reason="remand")
