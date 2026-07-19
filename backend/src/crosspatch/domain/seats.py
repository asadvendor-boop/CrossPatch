"""Exact immutable registry for the five model-driven seats."""

from dataclasses import dataclass

from crosspatch.domain.enums import Effort, Seat


@dataclass(frozen=True, slots=True)
class SeatSpec:
    seat: Seat
    model: str
    initial_effort: Effort
    effort_ladder: tuple[Effort, ...]
    role: str
    tier_rationale: str
    max_output_tokens: int
    max_escalations: int = 2
    human_escalation_only: bool = False


SEAT_SPECS = (
    SeatSpec(
        Seat.PROSECUTOR,
        "gpt-5.6-luna",
        Effort.LOW,
        (Effort.LOW, Effort.MEDIUM, Effort.HIGH),
        "Challenges causal claims and proposed patches.",
        "Fast adversarial review starts at the lowest effective effort.",
        max_output_tokens=3_072,
    ),
    SeatSpec(
        Seat.INSPECTOR,
        "gpt-5.6-terra",
        Effort.MEDIUM,
        (Effort.MEDIUM, Effort.HIGH, Effort.XHIGH),
        "Builds the evidence-linked failure mechanism.",
        "Balanced analysis for multi-source incident evidence.",
        max_output_tokens=3_072,
    ),
    SeatSpec(
        Seat.COUNSEL,
        "gpt-5.6-terra",
        Effort.MEDIUM,
        (Effort.MEDIUM, Effort.HIGH, Effort.XHIGH),
        "Proposes the smallest evidence-consistent diff.",
        "Balanced code reasoning with typed test intentions.",
        max_output_tokens=6_144,
    ),
    SeatSpec(
        Seat.MAGISTRATE,
        "gpt-5.6-sol",
        Effort.MEDIUM,
        (Effort.MEDIUM, Effort.HIGH, Effort.XHIGH),
        "Returns the fail-closed incident verdict.",
        "Highest-reliability review at the human authority boundary.",
        max_output_tokens=8_192,
        human_escalation_only=True,
    ),
    SeatSpec(
        Seat.BAILIFF,
        "gpt-5.6-luna",
        Effort.NONE,
        (Effort.NONE,),
        "Presents one approved warrant ID for execution.",
        "No reasoning is needed for a single deterministic broker call.",
        max_output_tokens=768,
        max_escalations=0,
    ),
)
