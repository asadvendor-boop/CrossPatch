"""Immutable in-process domain records."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from crosspatch.domain.enums import IncidentState


@dataclass(frozen=True, slots=True)
class Incident:
    id: str
    title: str
    state: IncidentState
    event_chain_head: str | None = None


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    id: str
    incident_id: str
    sequence: int
    type: str
    actor: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str
    created_at: datetime
