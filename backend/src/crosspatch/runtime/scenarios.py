"""Closed definitions for the bundled, server-owned incident scenarios."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, cast

from crosspatch.domain.enums import ScenarioId

ReproductionProfile = Literal["duplicate-race", "payload-equivalence"]
EvidenceProfile = Literal["standard", "instruction-like-log"]


@dataclass(frozen=True, slots=True)
class ScenarioDefinition:
    scenario_id: ScenarioId
    default_title: str
    affected_plan_id: str
    candidate_plan_id: str
    reproduction_profile: ReproductionProfile
    source_paths: tuple[str, ...]


_SOURCE_PATHS = (
    "victim/src/victim/app.py",
    "victim/src/victim/db.py",
    "victim/src/victim/webhooks.py",
    "victim/src/victim/worker.py",
)

OPERATOR_SCENARIOS = MappingProxyType(
    {
        "webhook-race": ScenarioDefinition(
            scenario_id="webhook-race",
            default_title="Duplicate order-paid delivery",
            affected_plan_id="victim.duplicate-race.affected",
            candidate_plan_id="victim.duplicate-race.candidate",
            reproduction_profile="duplicate-race",
            source_paths=_SOURCE_PATHS,
        ),
        "webhook-payload-equivalence": ScenarioDefinition(
            scenario_id="webhook-payload-equivalence",
            default_title="Equivalent webhook retry rejected",
            affected_plan_id="victim.payload-equivalence.affected",
            candidate_plan_id="victim.payload-equivalence.candidate",
            reproduction_profile="payload-equivalence",
            source_paths=_SOURCE_PATHS,
        ),
    }
)

LIVE_TRIAL_SCENARIOS = frozenset({"webhook-race"})
EVIDENCE_PROFILES = frozenset({"standard", "instruction-like-log"})


def require_operator_scenario(value: str) -> ScenarioDefinition:
    try:
        return OPERATOR_SCENARIOS[value]
    except KeyError as error:
        raise ValueError("unsupported incident scenario") from error


def require_live_trial_scenario(value: str) -> ScenarioDefinition:
    if value not in LIVE_TRIAL_SCENARIOS:
        raise ValueError("live trials support only the bundled webhook-race scenario")
    return require_operator_scenario(value)


def require_operator_evidence_profile(
    scenario: str,
    value: str,
) -> EvidenceProfile:
    if value not in EVIDENCE_PROFILES:
        raise ValueError("unsupported evidence profile")
    if value == "instruction-like-log" and scenario != "webhook-race":
        raise ValueError(
            "instruction-like-log evidence is supported only for webhook-race"
        )
    return cast(EvidenceProfile, value)


__all__ = [
    "LIVE_TRIAL_SCENARIOS",
    "OPERATOR_SCENARIOS",
    "EVIDENCE_PROFILES",
    "EvidenceProfile",
    "ReproductionProfile",
    "ScenarioDefinition",
    "ScenarioId",
    "require_live_trial_scenario",
    "require_operator_evidence_profile",
    "require_operator_scenario",
]
