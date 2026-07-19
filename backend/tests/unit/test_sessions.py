from __future__ import annotations

from pathlib import Path

import pytest
from crosspatch.domain.enums import Seat
from crosspatch.orchestration.sessions import IncidentSessionStore


@pytest.mark.asyncio
async def test_sessions_are_stable_per_incident_and_seat_but_isolated_across_scope(
    tmp_path: Path,
) -> None:
    store = IncidentSessionStore(tmp_path / "sessions.sqlite")
    inspector_a = store.for_seat("inc-a", Seat.INSPECTOR)

    assert store.for_seat("inc-a", Seat.INSPECTOR) is inspector_a
    assert store.for_seat("inc-a", Seat.COUNSEL).session_id != inspector_a.session_id
    assert store.for_seat("inc-b", Seat.INSPECTOR).session_id != inspector_a.session_id

    transition_a = store.for_transition("inc-a", Seat.INSPECTOR, Seat.PROSECUTOR)
    assert (
        store.for_transition("inc-a", Seat.INSPECTOR, Seat.PROSECUTOR)
        is transition_a
    )
    assert transition_a.session_id not in {
        inspector_a.session_id,
        store.for_seat("inc-a", Seat.PROSECUTOR).session_id,
    }
    assert (
        store.for_transition("inc-b", Seat.INSPECTOR, Seat.PROSECUTOR).session_id
        != transition_a.session_id
    )

    await store.close()
